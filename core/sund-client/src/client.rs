//! Sund's two planes, as a client.
//!
//! The server's API splits in two (`../../sund/docs/Sund-ImplementationGuide.md`
//! → API sketch), and so does this module, because the split *is* the privacy
//! property rather than an implementation detail:
//!
//! - **The management plane** — enrollment, the device list, invitations, key
//!   bundles, push endpoints, queue creation — is signed by the device's
//!   Ed25519 identity key and carries the device id in a header. The server
//!   knows exactly who is calling. [`DeviceClient`].
//! - **The transport plane** — send, receive, acknowledge, retire — is
//!   authenticated by *per-queue* keys and carries no device identity at all.
//!   That is what stops the server from linking a sender to a message.
//!   [`SundClient`] performs these, and it is deliberately the type that has no
//!   device identity to leak into them.
//!
//! [`SundClient`] therefore holds everything that needs no device identity —
//! the health probe, enrollment (which has no identity *yet*), and the whole
//! transport plane — and [`SundClient::device`] produces the signed half.
//!
//! Neither type keeps queue state. Which channel maps to which queue, and what
//! is bound where, belongs to [`crate::sund_transport`], because that is the
//! part the transport port has to present uniformly across backends.

use crate::http::{HttpClient, HttpError, HttpRequest, HttpResponse, Method, StampSource};
use crate::rfc3339;
use crate::sigauth::{
    DeviceKey, HEADER_DEVICE_ID, HEADER_NONCE, HEADER_SENDER_KEY, HEADER_SIGNATURE,
    HEADER_TIMESTAMP, QueueKey, RequestToSign,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// What a Sund call can fail with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SundError {
    /// The request never got an answer, or the server could not be verified.
    Http(HttpError),
    /// HTTP 401 — uniform by design on the server side: a missing header, a
    /// stale timestamp, an unknown or revoked device, a bad signature and a
    /// replayed nonce are one status, so a prober learns nothing from which.
    Unauthorized,
    /// HTTP 404 — the device, invitation, bundle or queue is gone, or was
    /// never visible to this caller, which the server does not distinguish.
    NotFound,
    /// HTTP 400, with the server's message.
    Rejected(String),
    /// HTTP 413 — over a size cap: 64 KiB for a queue payload, 8 KiB for a
    /// bundle.
    TooLarge,
    /// HTTP 507 — the queue owner's account is over its storage quota. Quota
    /// is attributed to the *recipient's* account, so this is the peer's
    /// ceiling, not the sender's.
    QuotaExceeded,
    /// Any other status, with the server's message if it sent one.
    Status {
        /// The HTTP status code.
        status: u16,
        /// The server's `error` field, or the raw body.
        message: String,
    },
    /// A 2xx whose body was not what the API promises. Kept distinct from a
    /// network error because it means the two repos have drifted — which is
    /// what the tier-2 contract suite exists to catch before a user does.
    Malformed(String),
}

impl std::fmt::Display for SundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(e) => write!(f, "{e}"),
            Self::Unauthorized => f.write_str("unauthorized"),
            Self::NotFound => f.write_str("not found"),
            Self::Rejected(m) => write!(f, "rejected: {m}"),
            Self::TooLarge => f.write_str("too large"),
            Self::QuotaExceeded => f.write_str("the recipient's account is over its storage quota"),
            Self::Status { status, message } => write!(f, "HTTP {status}: {message}"),
            Self::Malformed(detail) => write!(f, "unexpected response: {detail}"),
        }
    }
}

impl std::error::Error for SundError {}

impl From<HttpError> for SundError {
    fn from(error: HttpError) -> Self {
        Self::Http(error)
    }
}

/// What the server reports about itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ServerHealth {
    /// `"ok"` when the server is serving.
    pub status: String,
    /// The build under test, which the contract suite reports so a failure
    /// names the Sund commit it happened against.
    #[serde(default)]
    pub version: String,
}

/// Everything a device presents when it enrolls.
#[derive(Debug, Clone)]
pub struct Enrollment<'a> {
    /// The one-time invitation token, from the QR or from
    /// [`DeviceClient::create_invitation`].
    pub token: &'a str,
    /// The device's Ed25519 public key. The private half never leaves the
    /// device, and generating and storing it is the app layer's job.
    pub public_key: [u8; 32],
    /// Where to send wake-up pings, or empty for none. Payload-free: a ping
    /// only ever means "drain your queues".
    pub push_endpoint: &'a str,
    /// An opaque capability string the server stores and does not interpret.
    pub capabilities: &'a str,
}

/// The identity Sund hands back on enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    /// The device id, which every signed request names.
    pub device_id: String,
    /// The account the invitation belonged to — the family, in Family Beacon's
    /// vocabulary. Note that Sund's account membership is *not* the authority
    /// on family membership; see `docs/FamilyBeacon-Roster.md`.
    pub account_id: String,
}

/// One device as the server lists it.
///
/// The list is authoritative for locating key material and for revocation, and
/// **not** authoritative for who is in the family: a host who can write to the
/// database can add a row here, so admission requires a signed vouch carried
/// end-to-end (`docs/FamilyBeacon-Roster.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    /// The device id.
    pub id: String,
    /// The device's Ed25519 public key.
    pub public_key: [u8; 32],
    /// The wake-up endpoint the device registered, if any.
    pub push_endpoint: String,
    /// The opaque capability string the device enrolled with.
    pub capabilities: String,
    /// When the device enrolled.
    pub created: Option<SystemTime>,
    /// When the server last saw a signed request from it.
    pub last_seen: Option<SystemTime>,
    /// Whether the device has been revoked. Revoked devices stay listed so
    /// peers can see that a device was removed rather than merely vanishing.
    pub revoked: bool,
}

/// A freshly minted invitation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    /// The one-time token. This is the secret; it travels in the QR and is
    /// never returned by a listing.
    pub token: String,
    /// The non-secret id, for listing and for revoking the invitation before
    /// it is used.
    pub id: String,
    /// When it expires (Sund's default is 15 minutes).
    pub expires: Option<SystemTime>,
}

/// An outstanding invitation, as listed. Carries no token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationRecord {
    /// The invitation id.
    pub id: String,
    /// When it was minted.
    pub created: Option<SystemTime>,
    /// When it expires.
    pub expires: Option<SystemTime>,
}

/// A peer's opaque key bundle, exactly as it was published.
///
/// Sund stores and returns these verbatim and never interprets them — which is
/// also why one-time prekeys cannot be popped server-side, and why the session
/// layer runs in signed-fallback-key mode (CLAUDE.md decision #6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBundle {
    /// The bytes the peer published.
    pub bundle: Vec<u8>,
    /// When they were last updated.
    pub updated: Option<SystemTime>,
}

/// The two halves of a newly created queue.
///
/// The `recipient_id` stays on the owner's device; the `sender_id` is what
/// travels to the peer — in the pairing QR for the first channel, and inside an
/// already-encrypted message for every later one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueIds {
    /// Where the owner drains, acknowledges and retires. Never leaves the
    /// owner's device.
    pub recipient_id: String,
    /// Where the peer sends. Public to the peer, and to nobody else.
    pub sender_id: String,
}

/// One message to append to a queue.
#[derive(Debug, Clone)]
pub struct QueueMessage<'a> {
    /// Ciphertext. Sund caps a payload at 64 KiB and never reads one.
    pub payload: &'a [u8],
    /// How long the server should hold it. `None` takes Sund's default of 24
    /// hours; anything over 7 days is clamped to 7 days.
    pub ttl: Option<Duration>,
    /// Ask the server to hint urgency to the recipient's pinger. The server
    /// cannot tell an SOS from a battery update — it forwards the hint without
    /// reading anything.
    pub priority: bool,
    /// Send the per-queue sender key, binding it to this queue.
    ///
    /// True only on the first send to a queue that is still open: the first
    /// valid send binds the key and no later one may rebind it, which is what
    /// stops anyone who learns a `sender_id` from writing into the queue.
    pub bind_sender_key: bool,
}

/// One message as drained from a queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedMessage {
    /// The server's id, and the argument to acknowledge it.
    pub id: String,
    /// The ciphertext.
    pub payload: Vec<u8>,
    /// When the *server* received it — not when it was sent.
    pub received_at: Option<SystemTime>,
    /// When the server will drop it if it is still unacknowledged.
    pub expires: Option<SystemTime>,
}

/// A client for one Sund server, holding no device identity.
///
/// Cheap to clone: both halves are shared handles.
#[derive(Clone)]
pub struct SundClient {
    http: Arc<dyn HttpClient>,
    stamps: Arc<dyn StampSource>,
}

impl std::fmt::Debug for SundClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SundClient").finish_non_exhaustive()
    }
}

impl SundClient {
    /// Build a client over an HTTP implementation already bound to one server,
    /// and a source of timestamps and nonces.
    #[must_use]
    pub fn new(http: Arc<dyn HttpClient>, stamps: Arc<dyn StampSource>) -> Self {
        Self { http, stamps }
    }

    /// The signed half of the API, for an enrolled device.
    #[must_use]
    pub fn device(&self, device_id: impl Into<String>, key: DeviceKey) -> DeviceClient {
        DeviceClient {
            client: self.clone(),
            device_id: device_id.into(),
            key,
        }
    }

    /// `GET /health`. Unsigned, and the one call that says nothing about who is
    /// asking.
    ///
    /// # Errors
    ///
    /// Returns a [`SundError`] if the server is unreachable or unhealthy.
    pub fn health(&self) -> Result<ServerHealth, SundError> {
        let response = self.perform(HttpRequest::new(Method::Get, "/health"))?;
        parse_json(&response.body)
    }

    /// `POST /v1/devices/register`. The one unsigned management-plane route:
    /// the device has no identity yet, so the one-time token is the credential.
    ///
    /// A token is consumed by the first successful call. Presenting it again —
    /// or presenting one that expired or was revoked — is
    /// [`SundError::Unauthorized`], the same status as every other refusal.
    ///
    /// # Errors
    ///
    /// Returns a [`SundError`] if the token is not accepted or the server
    /// cannot be reached.
    pub fn register(&self, enrollment: &Enrollment<'_>) -> Result<Enrolled, SundError> {
        #[derive(Serialize)]
        struct Body<'a> {
            token: &'a str,
            public_key: String,
            push_endpoint: &'a str,
            capabilities: &'a str,
        }
        #[derive(Deserialize)]
        struct Reply {
            device_id: String,
            account_id: String,
        }

        let body = to_json(&Body {
            token: enrollment.token,
            public_key: BASE64.encode(enrollment.public_key),
            push_endpoint: enrollment.push_endpoint,
            capabilities: enrollment.capabilities,
        })?;
        let response = self.perform(json_request(Method::Post, "/v1/devices/register", body))?;
        let reply: Reply = parse_json(&response.body)?;
        Ok(Enrolled {
            device_id: reply.device_id,
            account_id: reply.account_id,
        })
    }

    // --- transport plane: authenticated by per-queue keys, no device id ------

    /// `POST /v1/send/{sender_id}`. Append a message to a peer's queue.
    ///
    /// # Errors
    ///
    /// Returns [`SundError::NotFound`] if the queue is unknown or retired,
    /// [`SundError::Unauthorized`] if the sender key does not match the one
    /// bound to the queue, [`SundError::TooLarge`] over 64 KiB, and
    /// [`SundError::QuotaExceeded`] when the recipient's account is full.
    pub fn send_to_queue(
        &self,
        sender_id: &str,
        key: &QueueKey,
        message: &QueueMessage<'_>,
    ) -> Result<String, SundError> {
        #[derive(Serialize)]
        struct Body {
            payload: String,
            ttl: u64,
            priority: bool,
        }
        #[derive(Deserialize)]
        struct Reply {
            message_id: String,
        }

        let path = format!("/v1/send/{}", path_segment(sender_id)?);
        let body = to_json(&Body {
            payload: BASE64.encode(message.payload),
            // Zero means "take the server's default"; the server clamps the
            // upper end, so a caller cannot ask a queue to hold a message
            // longer than Sund's ceiling.
            ttl: message.ttl.map_or(0, |ttl| ttl.as_secs()),
            priority: message.priority,
        })?;

        let mut request = json_request(Method::Post, path, body);
        if message.bind_sender_key {
            request = request.with_header(HEADER_SENDER_KEY, BASE64.encode(key.public_key()));
        }
        let response = self.perform_signed(request, key, None)?;
        let reply: Reply = parse_json(&response.body)?;
        Ok(reply.message_id)
    }

    /// `GET /v1/recv/{recipient_id}`. Drain a queue.
    ///
    /// Draining does not delete: messages stay until acknowledged, which is
    /// what makes delivery at-least-once and what lets a client that died
    /// mid-processing see them again.
    ///
    /// # Errors
    ///
    /// Returns [`SundError::NotFound`] if the queue is unknown or retired, and
    /// [`SundError::Unauthorized`] if the recipient key does not match.
    pub fn receive_from_queue(
        &self,
        recipient_id: &str,
        key: &QueueKey,
    ) -> Result<Vec<QueuedMessage>, SundError> {
        #[derive(Deserialize)]
        struct Reply {
            messages: Vec<MessageView>,
        }
        #[derive(Deserialize)]
        struct MessageView {
            id: String,
            payload: String,
            #[serde(default)]
            received_at: String,
            #[serde(default)]
            expires: String,
        }

        let path = format!("/v1/recv/{}", path_segment(recipient_id)?);
        let response = self.perform_signed(HttpRequest::new(Method::Get, path), key, None)?;
        let reply: Reply = parse_json(&response.body)?;
        reply
            .messages
            .into_iter()
            .map(|view| {
                Ok(QueuedMessage {
                    id: view.id,
                    payload: decode_base64(&view.payload, "payload")?,
                    received_at: rfc3339::parse(&view.received_at),
                    expires: rfc3339::parse(&view.expires),
                })
            })
            .collect()
    }

    /// `POST /v1/ack/{recipient_id}`. Delete messages that have been processed,
    /// returning how many the server actually removed.
    ///
    /// # Errors
    ///
    /// Returns a [`SundError`] if the queue is unknown, retired, or the key
    /// does not match.
    pub fn acknowledge(
        &self,
        recipient_id: &str,
        key: &QueueKey,
        ids: &[String],
    ) -> Result<usize, SundError> {
        #[derive(Serialize)]
        struct Body<'a> {
            ids: &'a [String],
        }
        #[derive(Deserialize)]
        struct Reply {
            deleted: usize,
        }

        let path = format!("/v1/ack/{}", path_segment(recipient_id)?);
        let body = to_json(&Body { ids })?;
        let response = self.perform_signed(json_request(Method::Post, path, body), key, None)?;
        let reply: Reply = parse_json(&response.body)?;
        Ok(reply.deleted)
    }

    /// `POST /v1/retire/{recipient_id}`. Retire a queue and drop what it holds.
    ///
    /// One-way, and server-side: this is the half of rotation that a serverless
    /// transport cannot do, and the reason Sund mode's revocation is stronger
    /// than Try mode's epoch rotation (`docs/FamilyBeacon-TryMode.md`).
    ///
    /// # Errors
    ///
    /// Returns a [`SundError`] if the queue is unknown, already retired, or the
    /// key does not match.
    pub fn retire_queue(&self, recipient_id: &str, key: &QueueKey) -> Result<(), SundError> {
        let path = format!("/v1/retire/{}", path_segment(recipient_id)?);
        self.perform_signed(HttpRequest::new(Method::Post, path), key, None)?;
        Ok(())
    }

    // --- plumbing -----------------------------------------------------------

    fn perform(&self, request: HttpRequest) -> Result<HttpResponse, SundError> {
        let response = self.http.execute(&request)?;
        check_status(response)
    }

    /// Sign and perform. `device_id` present means the management plane (the
    /// device id travels in a header and scopes the server's nonce cache);
    /// absent means the transport plane, where the queue id is the principal
    /// and no device identity is disclosed.
    fn perform_signed(
        &self,
        request: HttpRequest,
        key: &DeviceKey,
        device_id: Option<&str>,
    ) -> Result<HttpResponse, SundError> {
        let stamp = self.stamps.stamp();
        let to_sign = RequestToSign {
            method: request.method.as_str(),
            path: &request.path,
            timestamp: &stamp.timestamp,
            nonce: &stamp.nonce,
            body: &request.body,
        };
        let signature = key.sign(&to_sign);

        let mut request = request;
        if let Some(device_id) = device_id {
            request = request.with_header(HEADER_DEVICE_ID, device_id);
        }
        request = request
            .with_header(HEADER_TIMESTAMP, stamp.timestamp)
            .with_header(HEADER_NONCE, stamp.nonce)
            .with_header(HEADER_SIGNATURE, signature);
        self.perform(request)
    }
}

/// The signed half of the API: everything Sund authenticates by device
/// identity.
#[derive(Clone)]
pub struct DeviceClient {
    client: SundClient,
    device_id: String,
    key: DeviceKey,
}

impl std::fmt::Debug for DeviceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key is deliberately not printed.
        f.debug_struct("DeviceClient")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl DeviceClient {
    /// This device's id.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The unsigned half, for the transport plane and the health probe.
    #[must_use]
    pub fn transport(&self) -> &SundClient {
        &self.client
    }

    /// `GET /v1/devices`. Every device in the account, revoked ones included.
    ///
    /// # Errors
    ///
    /// Returns a [`SundError`] if the request is refused or the server is
    /// unreachable.
    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>, SundError> {
        #[derive(Deserialize)]
        struct Reply {
            devices: Vec<DeviceView>,
        }

        let response = self.signed(HttpRequest::new(Method::Get, "/v1/devices"))?;
        let reply: Reply = parse_json(&response.body)?;
        reply
            .devices
            .into_iter()
            .map(DeviceView::into_record)
            .collect()
    }

    /// `POST /v1/devices/{id}/revoke`. Remove a device from the account.
    ///
    /// Sund lets any device in an account revoke any other, including itself,
    /// and takes no position on policy. Family Beacon's own rule — no in-app
    /// admin, any active device may remove any other — is decided in
    /// `docs/FamilyBeacon-Roster.md`, and the removal that matters to the
    /// family is the ledgered, end-to-end one; this call is the server-side
    /// half that also kills the device's queues and push endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SundError::NotFound`] for an unknown device or one in another
    /// account, which the server does not distinguish.
    pub fn revoke_device(&self, device_id: &str) -> Result<(), SundError> {
        let path = format!("/v1/devices/{}/revoke", path_segment(device_id)?);
        self.signed(HttpRequest::new(Method::Post, path))?;
        Ok(())
    }

    /// `POST /v1/invitations`. Mint a one-time enrollment token.
    ///
    /// # Errors
    ///
    /// Returns a [`SundError`] if the request is refused.
    pub fn create_invitation(&self) -> Result<Invitation, SundError> {
        #[derive(Deserialize)]
        struct Reply {
            invitation_token: String,
            invitation_id: String,
            #[serde(default)]
            expires: String,
        }

        let response = self.signed(HttpRequest::new(Method::Post, "/v1/invitations"))?;
        let reply: Reply = parse_json(&response.body)?;
        Ok(Invitation {
            token: reply.invitation_token,
            id: reply.invitation_id,
            expires: rfc3339::parse(&reply.expires),
        })
    }

    /// `GET /v1/invitations`. Outstanding invitations, without their tokens.
    ///
    /// # Errors
    ///
    /// Returns a [`SundError`] if the request is refused.
    pub fn list_invitations(&self) -> Result<Vec<InvitationRecord>, SundError> {
        #[derive(Deserialize)]
        struct Reply {
            invitations: Vec<InvitationView>,
        }
        #[derive(Deserialize)]
        struct InvitationView {
            id: String,
            #[serde(default)]
            created: String,
            #[serde(default)]
            expires: String,
        }

        let response = self.signed(HttpRequest::new(Method::Get, "/v1/invitations"))?;
        let reply: Reply = parse_json(&response.body)?;
        Ok(reply
            .invitations
            .into_iter()
            .map(|view| InvitationRecord {
                id: view.id,
                created: rfc3339::parse(&view.created),
                expires: rfc3339::parse(&view.expires),
            })
            .collect())
    }

    /// `POST /v1/invitations/{id}/revoke`. Kill a mis-shared invitation before
    /// anyone uses it.
    ///
    /// # Errors
    ///
    /// Returns [`SundError::NotFound`] if it is unknown, already used or
    /// already revoked.
    pub fn revoke_invitation(&self, invitation_id: &str) -> Result<(), SundError> {
        let path = format!("/v1/invitations/{}/revoke", path_segment(invitation_id)?);
        self.signed(HttpRequest::new(Method::Post, path))?;
        Ok(())
    }

    /// `PUT /v1/me/bundle`. Publish this device's opaque key bundle, capped at
    /// 8 KiB.
    ///
    /// # Errors
    ///
    /// Returns [`SundError::TooLarge`] over the cap, or [`SundError::Rejected`]
    /// for an empty bundle.
    pub fn publish_bundle(&self, bundle: &[u8]) -> Result<(), SundError> {
        #[derive(Serialize)]
        struct Body {
            bundle: String,
        }

        let body = to_json(&Body {
            bundle: BASE64.encode(bundle),
        })?;
        self.signed(json_request(Method::Put, "/v1/me/bundle", body))?;
        Ok(())
    }

    /// `GET /v1/devices/{id}/bundle`. Fetch a peer's bundle so a session can be
    /// established while that peer is offline.
    ///
    /// # Errors
    ///
    /// Returns [`SundError::NotFound`] if the device is unknown, revoked, in
    /// another account, or has published nothing — the server does not say
    /// which.
    pub fn fetch_bundle(&self, device_id: &str) -> Result<KeyBundle, SundError> {
        #[derive(Deserialize)]
        struct Reply {
            bundle: String,
            #[serde(default)]
            updated: String,
        }

        let path = format!("/v1/devices/{}/bundle", path_segment(device_id)?);
        let response = self.signed(HttpRequest::new(Method::Get, path))?;
        let reply: Reply = parse_json(&response.body)?;
        Ok(KeyBundle {
            bundle: decode_base64(&reply.bundle, "bundle")?,
            updated: rfc3339::parse(&reply.updated),
        })
    }

    /// `PUT /v1/me/push`. Register where wake-up pings should go, or clear it
    /// with an empty string.
    ///
    /// # Errors
    ///
    /// Returns a [`SundError`] if the endpoint is over 2048 bytes or the
    /// request is refused.
    pub fn set_push_endpoint(&self, endpoint: &str) -> Result<(), SundError> {
        #[derive(Serialize)]
        struct Body<'a> {
            push_endpoint: &'a str,
        }

        let body = to_json(&Body {
            push_endpoint: endpoint,
        })?;
        self.signed(json_request(Method::Put, "/v1/me/push", body))?;
        Ok(())
    }

    /// `POST /v1/queues`. Create a queue owned by this device.
    ///
    /// This is the one route where the two planes meet: it is signed by device
    /// identity, because the server has to know whose quota the queue counts
    /// against and which device to wake when a message lands. Everything the
    /// queue then carries is transport-plane and unlinked from this call.
    ///
    /// The queue is created *open* — the first valid send binds the sender's
    /// per-queue key ([`QueueMessage::bind_sender_key`]).
    ///
    /// # Errors
    ///
    /// Returns a [`SundError`] if the request is refused.
    pub fn create_queue(&self, recipient_public_key: &[u8; 32]) -> Result<QueueIds, SundError> {
        #[derive(Serialize)]
        struct Body {
            recipient_key: String,
        }

        let body = to_json(&Body {
            recipient_key: BASE64.encode(recipient_public_key),
        })?;
        let response = self.signed(json_request(Method::Post, "/v1/queues", body))?;
        parse_json(&response.body)
    }

    fn signed(&self, request: HttpRequest) -> Result<HttpResponse, SundError> {
        self.client
            .perform_signed(request, &self.key, Some(&self.device_id))
    }
}

/// One device as the wire carries it.
#[derive(Deserialize)]
struct DeviceView {
    id: String,
    public_key: String,
    #[serde(default)]
    push_endpoint: String,
    #[serde(default)]
    capabilities: String,
    #[serde(default)]
    created: String,
    #[serde(default)]
    last_seen: String,
    #[serde(default)]
    revoked: bool,
}

impl DeviceView {
    fn into_record(self) -> Result<DeviceRecord, SundError> {
        let key = decode_base64(&self.public_key, "public_key")?;
        let public_key: [u8; 32] = key
            .try_into()
            .map_err(|_| SundError::Malformed("public_key is not 32 bytes".to_owned()))?;
        Ok(DeviceRecord {
            id: self.id,
            public_key,
            push_endpoint: self.push_endpoint,
            capabilities: self.capabilities,
            created: rfc3339::parse(&self.created),
            last_seen: rfc3339::parse(&self.last_seen),
            revoked: self.revoked,
        })
    }
}

fn json_request(method: Method, path: impl Into<String>, body: Vec<u8>) -> HttpRequest {
    HttpRequest::new(method, path)
        .with_header("Content-Type", "application/json")
        .with_body(body)
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, SundError> {
    serde_json::to_vec(value).map_err(|e| SundError::Malformed(format!("cannot encode: {e}")))
}

fn parse_json<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, SundError> {
    serde_json::from_slice(body).map_err(|e| SundError::Malformed(e.to_string()))
}

fn decode_base64(text: &str, field: &str) -> Result<Vec<u8>, SundError> {
    BASE64
        .decode(text)
        .map_err(|_| SundError::Malformed(format!("{field} is not base64")))
}

/// Guard an id before it becomes part of a signed path.
///
/// Ids come back from the server and go straight into the path a signature
/// covers, so anything that could change the path's shape — a slash, a query
/// separator, an escape — is refused rather than encoded. Sund's ids are short
/// opaque tokens; a value outside this set means the two repos disagree about
/// what an id is, and that is worth failing loudly.
fn path_segment(id: &str) -> Result<&str, SundError> {
    let ok = !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if ok {
        Ok(id)
    } else {
        Err(SundError::Malformed(format!(
            "`{id}` is not a usable path segment"
        )))
    }
}

/// Map a status onto meaning, once, so that no call site invents its own.
fn check_status(response: HttpResponse) -> Result<HttpResponse, SundError> {
    match response.status {
        200..=299 => Ok(response),
        400 => Err(SundError::Rejected(server_message(&response.body))),
        401 => Err(SundError::Unauthorized),
        404 => Err(SundError::NotFound),
        413 => Err(SundError::TooLarge),
        507 => Err(SundError::QuotaExceeded),
        status => Err(SundError::Status {
            status,
            message: server_message(&response.body),
        }),
    }
}

/// Sund's errors are `{"error": "…"}`; anything else is reported as it arrived.
fn server_message(body: &[u8]) -> String {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    serde_json::from_slice::<ErrorBody>(body).map_or_else(
        |_| String::from_utf8_lossy(body).trim().to_owned(),
        |parsed| parsed.error,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::testing::{FixedStamps, ScriptedHttp};
    use crate::sigauth::verify;

    fn client(http: ScriptedHttp) -> (SundClient, Arc<ScriptedHttp>) {
        let http = Arc::new(http);
        (SundClient::new(http.clone(), Arc::new(FixedStamps)), http)
    }

    fn device_key() -> DeviceKey {
        DeviceKey::from_seed(&[3u8; 32])
    }

    #[test]
    fn enrollment_sends_the_token_and_the_public_key_unsigned() {
        let (client, http) = client(ScriptedHttp::answering(
            201,
            r#"{"device_id":"dev_A","account_id":"acc_1"}"#,
        ));
        let key = device_key();
        let enrolled = client
            .register(&Enrollment {
                token: "inv_tok",
                public_key: key.public_key(),
                push_endpoint: "https://ntfy.example/up123",
                capabilities: "",
            })
            .expect("register");

        assert_eq!(enrolled.device_id, "dev_A");
        assert_eq!(enrolled.account_id, "acc_1");

        let request = http.last();
        assert_eq!(request.method, Method::Post);
        assert_eq!(request.path, "/v1/devices/register");
        // Unsigned: the device has no identity to sign with yet.
        let names: Vec<&str> = request.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(!names.contains(&HEADER_SIGNATURE));
        let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json body");
        assert_eq!(body["token"], "inv_tok");
        assert_eq!(body["public_key"], BASE64.encode(key.public_key()));
    }

    #[test]
    fn a_management_call_is_signed_over_its_own_method_path_and_body() {
        let (client, http) = client(ScriptedHttp::answering(200, r#"{"devices":[]}"#));
        let key = device_key();
        let device = client.device("dev_A", key.clone());
        device.list_devices().expect("list");

        let request = http.last();
        let headers: std::collections::HashMap<_, _> = request
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(headers.get(HEADER_DEVICE_ID), Some(&"dev_A"));

        let to_sign = RequestToSign {
            method: "GET",
            path: "/v1/devices",
            timestamp: headers["Sund-Timestamp"],
            nonce: headers["Sund-Nonce"],
            body: b"",
        };
        assert!(verify(
            &key.public_key(),
            &to_sign,
            headers[HEADER_SIGNATURE]
        ));
    }

    #[test]
    fn a_transport_call_carries_a_queue_signature_and_no_device_id() {
        // The point of the two planes: the server must not be able to link a
        // send to the device that made it.
        let (client, http) = client(ScriptedHttp::answering(202, r#"{"message_id":"m1"}"#));
        let queue_key = QueueKey::from_seed(&[9u8; 32]);
        client
            .send_to_queue(
                "snd_1",
                &queue_key,
                &QueueMessage {
                    payload: b"ciphertext",
                    ttl: Some(Duration::from_secs(600)),
                    priority: true,
                    bind_sender_key: true,
                },
            )
            .expect("send");

        let request = http.last();
        let headers: std::collections::HashMap<_, _> = request
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(request.path, "/v1/send/snd_1");
        assert!(
            !headers.contains_key(HEADER_DEVICE_ID),
            "no device identity"
        );
        assert_eq!(
            headers.get(HEADER_SENDER_KEY),
            Some(&BASE64.encode(queue_key.public_key()).as_str()),
            "the first send binds the sender key"
        );

        let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json");
        assert_eq!(body["ttl"], 600);
        assert_eq!(body["priority"], true);
        assert_eq!(body["payload"], BASE64.encode(b"ciphertext"));

        let to_sign = RequestToSign {
            method: "POST",
            path: "/v1/send/snd_1",
            timestamp: headers["Sund-Timestamp"],
            nonce: headers["Sund-Nonce"],
            body: &request.body,
        };
        assert!(verify(
            &queue_key.public_key(),
            &to_sign,
            headers[HEADER_SIGNATURE]
        ));
    }

    #[test]
    fn a_later_send_does_not_re_offer_the_sender_key() {
        let (client, http) = client(ScriptedHttp::answering(202, r#"{"message_id":"m2"}"#));
        client
            .send_to_queue(
                "snd_1",
                &QueueKey::from_seed(&[9u8; 32]),
                &QueueMessage {
                    payload: b"x",
                    ttl: None,
                    priority: false,
                    bind_sender_key: false,
                },
            )
            .expect("send");
        let request = http.last();
        assert!(
            !request
                .headers
                .iter()
                .any(|(name, _)| name == HEADER_SENDER_KEY)
        );
        let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json");
        assert_eq!(body["ttl"], 0, "no TTL means the server's default");
    }

    #[test]
    fn statuses_map_to_meanings_once() {
        let cases = [
            (
                400,
                r#"{"error":"empty payload"}"#,
                SundError::Rejected("empty payload".to_owned()),
            ),
            (401, r#"{"error":"unauthorized"}"#, SundError::Unauthorized),
            (404, r#"{"error":"no such queue"}"#, SundError::NotFound),
            (413, r#"{"error":"payload too large"}"#, SundError::TooLarge),
            (507, r#"{"error":"quota"}"#, SundError::QuotaExceeded),
            (
                500,
                r#"{"error":"internal error"}"#,
                SundError::Status {
                    status: 500,
                    message: "internal error".to_owned(),
                },
            ),
        ];
        for (status, body, want) in cases {
            let (client, _) = client(ScriptedHttp::answering(status, body));
            assert_eq!(
                client.health().expect_err("an error status"),
                want,
                "status {status}"
            );
        }
    }

    #[test]
    fn a_body_that_is_not_what_the_api_promises_is_reported_as_drift() {
        let (client, _) = client(ScriptedHttp::answering(200, r#"{"unexpected":true}"#));
        assert!(matches!(
            client.health().expect_err("a malformed body"),
            SundError::Malformed(_)
        ));
    }

    #[test]
    fn drained_messages_decode_payloads_and_timestamps() {
        let body = format!(
            r#"{{"messages":[{{"id":"m1","payload":"{}","received_at":"2026-07-24T09:00:00Z","expires":"2026-07-25T09:00:00Z"}}]}}"#,
            BASE64.encode(b"hello")
        );
        let (client, _) = client(ScriptedHttp::answering(200, &body));
        let messages = client
            .receive_from_queue("rcp_1", &QueueKey::from_seed(&[1u8; 32]))
            .expect("recv");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, b"hello");
        assert!(messages[0].received_at.is_some());
        assert!(messages[0].expires.is_some());
    }

    #[test]
    fn an_id_that_would_change_the_shape_of_a_signed_path_is_refused() {
        // A signature covers the path, so an id carrying a slash would sign one
        // request and send another.
        let (client, _) = client(ScriptedHttp::answering(200, "{}"));
        let key = QueueKey::from_seed(&[1u8; 32]);
        for id in ["", "../devices", "a/b", "a?b=1", "a b"] {
            assert!(matches!(
                client
                    .receive_from_queue(id, &key)
                    .expect_err("a refused id"),
                SundError::Malformed(_)
            ));
        }
    }
}
