//! The composition, behind one object.
//!
//! What [`Client`] holds is what
//! `contract-tests/tests/contract/membership.rs`'s `Member` struct holds —
//! "everything a phone would hold" — with the wiring that test performs moved
//! out of test code and into the shipping stack.

use std::sync::Arc;
use std::time::SystemTime;

use beacon_roster::Applied;
use beacon_roster::records::SelfDescription;
use beacon_roster::roster::{Roster, ServerDevice};
use sund_client::address::ServerAddress;
use sund_client::client::{DeviceClient, Enrollment, SundClient};
use sund_client::http::{HttpClient, StampSource};
use sund_client::outbox::Outbox;
use sund_client::rfc3339;
use sund_client::session::SessionManager;
use sund_client::session_store;
use sund_client::sund_transport::SundTransport;

use crate::error::ClientError;
use crate::seeds::Seeds;
use crate::state::{self, ClientState};
use crate::views::{MemberRow, ServerDeviceRow};

/// How a device describes itself to the family.
///
/// All three fields are self-asserted and authority for nothing — see
/// [`MemberRow`]. They are taken from the app rather than defaulted here because
/// seeding them would be inventing membership policy, and policy belongs to
/// `beacon-roster`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// Display label, e.g. "Emma's phone".
    pub display_name: String,
    /// Grouping label. Advisory: it never makes two devices one principal.
    pub member_group: String,
    /// Role label. Seeds UI defaults, confers no authority over another device.
    pub role: String,
}

/// One Family Beacon device: identity, roster, sessions, transport and outbox,
/// driven as one object.
///
/// Blocking throughout, and **never to be called from the main thread**.
pub struct Client {
    address: ServerAddress,
    account_id: String,
    device: DeviceClient,
    roster: Roster,
    sessions: SessionManager,
    transport: SundTransport,
    outbox: Outbox,
    pickle_key: [u8; 32],
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("device_id", &self.device.device_id())
            .field("server", &self.address.to_string())
            .field("members", &self.roster.active_count())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Enroll against a Sund server and found a family.
    ///
    /// Convenience over [`Self::enroll_with`] using the shipping HTTP client and
    /// the system clock. `address` is a `sund://host:port#fingerprint` or
    /// `sund+webpki://host[:port]` string.
    ///
    /// # Errors
    ///
    /// See [`Self::enroll_with`], plus [`ClientError::Address`] if the address
    /// string is not a Sund address.
    #[cfg(feature = "agent")]
    pub fn enroll(
        address: &str,
        invitation: &str,
        profile: &Profile,
        seeds: &Seeds,
        now: SystemTime,
    ) -> Result<Applied<Self>, ClientError> {
        let address = ServerAddress::parse(address)?;
        let (http, stamps) = agent_for(&address)?;
        Self::enroll_with(http, stamps, address, invitation, profile, seeds, now)
    }

    /// Enroll against a Sund server and found a family, over a supplied HTTP
    /// client.
    ///
    /// The constructor the web client and the tests use: a browser can implement
    /// neither pinning nor sockets, so it supplies its own `HttpClient` over
    /// `fetch()`.
    ///
    /// Founding, rather than joining, is deliberately all slice 0 does: joining
    /// an existing family is the pairing ceremony, and the founding device
    /// self-vouches, so the roster exists from the first run and the device list
    /// renders from real state rather than from a placeholder.
    ///
    /// # Errors
    ///
    /// [`ClientError::Unauthorized`] if the invitation was spent, expired or
    /// revoked; [`ClientError::ServerIdentity`] if the server could not be
    /// verified — which must never be shown as a connectivity failure; and any
    /// other [`ClientError`] the server or the session layer produces.
    pub fn enroll_with(
        http: Arc<dyn HttpClient>,
        stamps: Arc<dyn StampSource>,
        address: ServerAddress,
        invitation: &str,
        profile: &Profile,
        seeds: &Seeds,
        now: SystemTime,
    ) -> Result<Applied<Self>, ClientError> {
        let sund = SundClient::new(http, stamps);
        let device_key = seeds.device_key();
        let identity = seeds.identity_key();

        let enrolled = sund.register(&Enrollment {
            token: invitation,
            public_key: device_key.public_key(),
            // Push registration is the app layer's, and it lands with the wake
            // path rather than here. An empty endpoint means "no pings"; the
            // device drains on its own schedule until one is registered.
            push_endpoint: "",
            capabilities: "",
        })?;

        let device = sund.device(enrolled.device_id.clone(), device_key);
        let mut sessions = SessionManager::create(&enrolled.device_id, identity.clone());

        let timestamp = rfc3339::format(now);
        let founded = Roster::found(
            &SelfDescription {
                device_id: enrolled.device_id.clone(),
                display_name: profile.display_name.clone(),
                member_group: profile.member_group.clone(),
                role: profile.role.clone(),
                joined_at: timestamp.clone(),
            },
            &identity,
        );

        // Publish before the client is handed back, so a peer that is vouched for
        // tomorrow has key material to fetch today. The bundle carries key
        // material and no initiation address — grant-only, decision #6 — so
        // publishing it makes this device verifiable, not reachable.
        let bundle = sessions.publish_bundle(&timestamp)?;
        device.publish_bundle(&bundle.encode().map_err(|error| ClientError::Session {
            detail: error.to_string(),
        })?)?;

        let transport = SundTransport::new(device.clone());

        Ok(Applied {
            outcome: Self {
                address,
                account_id: enrolled.account_id,
                device,
                roster: founded.outcome,
                sessions,
                transport,
                outbox: Outbox::new(),
                pickle_key: seeds.pickle_key(),
            },
            ledger: founded.ledger,
        })
    }

    /// Reopen a device from its persisted state.
    ///
    /// The server address comes out of the blob rather than from the caller: it
    /// is part of the server's stored identity, and a client that let the address
    /// be supplied again on every open could be walked from pinned to WebPKI
    /// without anyone re-pairing.
    ///
    /// # Errors
    ///
    /// [`ClientError::State`] for a blob this build does not speak or one that
    /// does not parse, and [`ClientError::Session`] if the blob belongs to
    /// another device or the seeds do not match it.
    #[cfg(feature = "agent")]
    pub fn open(blob: &[u8], seeds: &Seeds) -> Result<Self, ClientError> {
        let state = state::decode(blob)?;
        let address = ServerAddress::parse(&state.server)?;
        let (http, stamps) = agent_for(&address)?;
        Self::restore(http, stamps, address, state, seeds)
    }

    /// Reopen a device from its persisted state, over a supplied HTTP client.
    ///
    /// # Errors
    ///
    /// As [`Self::open`].
    pub fn open_with(
        http: Arc<dyn HttpClient>,
        stamps: Arc<dyn StampSource>,
        blob: &[u8],
        seeds: &Seeds,
    ) -> Result<Self, ClientError> {
        let state = state::decode(blob)?;
        let address = ServerAddress::parse(&state.server)?;
        Self::restore(http, stamps, address, state, seeds)
    }

    fn restore(
        http: Arc<dyn HttpClient>,
        stamps: Arc<dyn StampSource>,
        address: ServerAddress,
        state: ClientState,
        seeds: &Seeds,
    ) -> Result<Self, ClientError> {
        let identity = seeds.identity_key();
        let pickle_key = seeds.pickle_key();

        // Checked before anything else is rebuilt: `import` refuses a store that
        // belongs to another device or was written under another identity, which
        // is what catches a blob restored onto the wrong device and a blob opened
        // with the wrong seeds. There is no equivalent local check on the
        // request-signing seed — a wrong one simply produces 401s — and that is
        // the honest limit rather than an oversight.
        let sessions = session_store::import(
            &state.sessions,
            &state.device_id,
            identity.clone(),
            &pickle_key,
        )?;

        let roster = Roster::import(&state.roster, &state.device_id).map_err(|error| {
            ClientError::State {
                detail: error.to_string(),
            }
        })?;
        // A roster without its own device is not a roster this client can act
        // from: every membership decision below is relative to `self`. Failing
        // here rather than returning an Option from `self_description` keeps a
        // corrupt blob loud instead of quietly rendering an empty family.
        if roster.record(&state.device_id).is_none() {
            return Err(ClientError::State {
                detail: format!("stored roster carries no record for `{}`", state.device_id),
            });
        }

        let outbox = Outbox::import(&state.outbox).map_err(|error| ClientError::State {
            detail: error.to_string(),
        })?;

        let sund = SundClient::new(http, stamps);
        let device = sund.device(state.device_id, seeds.device_key());
        let transport = SundTransport::new(device.clone());
        transport.import(state.channels);

        Ok(Self {
            address,
            account_id: state.account_id,
            device,
            roster,
            sessions,
            transport,
            outbox,
            pickle_key,
        })
    }

    /// Everything to persist, as one blob.
    ///
    /// Write it after any call that mutated state, **encrypted at rest**: the
    /// outbox seals at drain rather than at enqueue, so this contains message
    /// bodies in the clear. See [`crate::state`].
    ///
    /// # Errors
    ///
    /// [`ClientError::State`] if the state could not be serialised, which means
    /// a type below grew a field that does not encode.
    pub fn snapshot(&self) -> Result<Vec<u8>, ClientError> {
        state::encode(&ClientState {
            device_id: self.device.device_id().to_owned(),
            account_id: self.account_id.clone(),
            server: self.address.to_string(),
            roster: self.roster.export(),
            sessions: session_store::export(&self.sessions, &self.pickle_key),
            channels: self.transport.export(),
            outbox: self.outbox.export(),
        })
    }

    /// This device's Sund device id — the id every grant, channel and ledger
    /// entry names.
    #[must_use]
    pub fn device_id(&self) -> &str {
        self.device.device_id()
    }

    /// The Sund account the invitation belonged to.
    ///
    /// The family, in Family Beacon's vocabulary — but Sund's account membership
    /// is not the authority on family membership, so this is an operational
    /// identifier and never an answer to "who is in the family".
    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// The server this device is paired with, in its canonical form.
    #[must_use]
    pub fn server_address(&self) -> &ServerAddress {
        &self.address
    }

    /// This device's own row.
    #[must_use]
    pub fn self_description(&self) -> MemberRow {
        let id = self.device.device_id();
        let record = self
            .roster
            .record(id)
            .expect("checked when the client was constructed");
        MemberRow::from_record(record, id)
    }

    /// The family, per the roster: every device it carries, active or
    /// tombstoned, in id order.
    ///
    /// Local and offline. A signed vouch is why a device is in this list, and no
    /// server was asked.
    #[must_use]
    pub fn roster(&self) -> Vec<MemberRow> {
        let id = self.device.device_id();
        let mut rows: Vec<MemberRow> = self
            .roster
            .active()
            .into_iter()
            .map(|record| MemberRow::from_record(record, id))
            .collect();
        rows.extend(
            self.roster
                .tombstones()
                .into_iter()
                .filter_map(|tombstone| self.roster.record(&tombstone.subject))
                .map(|record| MemberRow::from_record(record, id)),
        );
        rows.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        rows
    }

    /// What Sund lists for this account, for reconciliation.
    ///
    /// A separate call from [`Self::roster`], and it stays separate: the two
    /// answer different questions, and a single `members()` that merged them
    /// would be the injected-device bug with a convenient name. A row here that
    /// the roster does not carry is a device nobody vouched for — the one place
    /// a host that writes to its own database becomes visible to the family.
    ///
    /// This is a read, not a reconciliation: applying the findings advances
    /// roster state and produces ledger entries, and it belongs with the UI that
    /// surfaces them (slice 1, `Roster::reconcile_server_list`).
    ///
    /// # Errors
    ///
    /// Any [`ClientError`] the server produces. [`ClientError::ServerIdentity`]
    /// must be rendered as an identity failure, never as "no connection".
    pub fn server_devices(&self) -> Result<Vec<ServerDeviceRow>, ClientError> {
        let listed = self.device.list_devices()?;
        Ok(listed
            .iter()
            .map(|record| ServerDeviceRow::from_record(record, self.roster.is_active(&record.id)))
            .collect())
    }

    /// The server's device list in the shape `beacon-roster` reconciles against.
    ///
    /// Separate from [`Self::server_devices`] because that one is for rendering
    /// and this one is for the state machine; slice 1's reconciliation path
    /// consumes it.
    ///
    /// # Errors
    ///
    /// As [`Self::server_devices`].
    pub fn server_device_list(&self) -> Result<Vec<ServerDevice>, ClientError> {
        Ok(self
            .device
            .list_devices()?
            .into_iter()
            .map(|record| ServerDevice {
                device_id: record.id,
                revoked: record.revoked,
            })
            .collect())
    }
}

/// How requests are performed, and where a signed request's timestamp and nonce
/// come from. The pair every constructor needs, and the pair the web client
/// substitutes wholesale.
#[cfg(feature = "agent")]
type Wiring = (Arc<dyn HttpClient>, Arc<dyn StampSource>);

/// Build the shipping HTTP client and stamp source for an address.
#[cfg(feature = "agent")]
fn agent_for(address: &ServerAddress) -> Result<Wiring, ClientError> {
    use sund_client::agent::{HttpAgent, SystemStamps};

    let agent = HttpAgent::new(address)?;
    Ok((Arc::new(agent), Arc::new(SystemStamps)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seeds::SEED_BYTES;
    use beacon_protocol::ledger::LedgerEvent;
    use std::sync::Mutex;
    use std::time::Duration;
    use sund_client::http::{HttpError, HttpRequest, HttpResponse, Stamp};

    /// A scripted [`HttpClient`]. `sund-client`'s own is `#[cfg(test)]`, so this
    /// crate carries its own rather than widening that crate's surface for a
    /// test double.
    #[derive(Debug, Default)]
    struct ScriptedHttp {
        seen: Mutex<Vec<HttpRequest>>,
        replies: Mutex<Vec<Result<HttpResponse, HttpError>>>,
    }

    impl ScriptedHttp {
        fn new(replies: Vec<Result<HttpResponse, HttpError>>) -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(Vec::new()),
                replies: Mutex::new(replies),
            })
        }

        fn paths(&self) -> Vec<String> {
            self.seen
                .lock()
                .expect("not poisoned")
                .iter()
                .map(|request| request.path.clone())
                .collect()
        }
    }

    impl HttpClient for ScriptedHttp {
        fn execute(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
            self.seen
                .lock()
                .expect("not poisoned")
                .push(request.clone());
            let mut replies = self.replies.lock().expect("not poisoned");
            if replies.is_empty() {
                return Err(HttpError::Protocol(format!(
                    "the script ran out at {} {}",
                    request.method, request.path
                )));
            }
            replies.remove(0)
        }
    }

    #[derive(Debug)]
    struct FixedStamps;

    impl StampSource for FixedStamps {
        fn stamp(&self) -> Stamp {
            Stamp {
                timestamp: "2026-07-27T10:00:00Z".to_owned(),
                nonce: "nonce".to_owned(),
            }
        }
    }

    fn ok(body: &str) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 200,
            body: body.as_bytes().to_vec(),
        })
    }

    fn address() -> ServerAddress {
        ServerAddress::parse(&format!("sund://beacon.example:5871#{}", "ab".repeat(32)))
            .expect("a pinned address")
    }

    fn seeds() -> Seeds {
        Seeds::from_parts([3u8; SEED_BYTES], [4u8; SEED_BYTES])
    }

    fn profile() -> Profile {
        Profile {
            display_name: "founder's phone".to_owned(),
            member_group: "founder".to_owned(),
            role: "adult".to_owned(),
        }
    }

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_784_000_000)
    }

    /// The two calls enrollment makes: register, then publish the bundle.
    fn enrollment_script() -> Vec<Result<HttpResponse, HttpError>> {
        vec![
            ok(r#"{"device_id":"dev_A","account_id":"acct_1"}"#),
            ok("{}"),
        ]
    }

    fn founded() -> (Applied<Client>, Arc<ScriptedHttp>) {
        let http = ScriptedHttp::new(enrollment_script());
        let applied = Client::enroll_with(
            http.clone(),
            Arc::new(FixedStamps),
            address(),
            "invite-token",
            &profile(),
            &seeds(),
            now(),
        )
        .expect("enrollment succeeds");
        (applied, http)
    }

    #[test]
    fn enrolling_founds_a_family_and_publishes_a_bundle() {
        let (applied, http) = founded();
        let client = applied.outcome;

        assert_eq!(client.device_id(), "dev_A");
        assert_eq!(client.account_id(), "acct_1");
        assert_eq!(
            http.paths(),
            vec!["/v1/devices/register", "/v1/me/bundle"],
            "the bundle is published before the client is handed back, so a \
             device vouched for tomorrow has key material to fetch today"
        );
    }

    #[test]
    fn the_founding_device_self_vouches_and_the_join_is_ledgered() {
        let (applied, _) = founded();

        let ledger = applied.ledger;
        assert!(
            ledger.iter().any(|entry| matches!(
                &entry.event,
                LedgerEvent::DeviceJoined { vouched_by } if vouched_by == "dev_A"
            )),
            "founding is a membership event and the ledger rule has no \
             exemptions: {ledger:?}"
        );

        let me = applied.outcome.self_description();
        assert_eq!(
            me.introduced_by, "dev_A",
            "the founding device self-vouches"
        );
        assert!(me.is_self);
        assert!(me.active);
        assert_eq!(me.display_name, "founder's phone");
        assert_eq!(
            me.joined_at, "2026-07-14T03:33:20Z",
            "the clock is the caller's, not one the core invented"
        );
    }

    #[test]
    fn the_roster_renders_from_real_state_after_founding() {
        let (applied, _) = founded();
        let rows = applied.outcome.roster();

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].device_id, "dev_A");
        assert!(
            !rows[0].identity_pk.is_empty(),
            "the identity key is the row's only security-bearing field"
        );
    }

    #[test]
    fn state_survives_being_force_stopped_and_reopened() {
        // Slice 0's definition of done, asserted without a device: enroll, write
        // the blob, drop everything, open it again with the same seeds.
        let (applied, _) = founded();
        let before = applied.outcome;
        let blob = before.snapshot().expect("snapshot");

        let after = Client::open_with(
            ScriptedHttp::new(Vec::new()),
            Arc::new(FixedStamps),
            &blob,
            &seeds(),
        )
        .expect("reopen");

        assert_eq!(after.device_id(), before.device_id());
        assert_eq!(after.account_id(), before.account_id());
        assert_eq!(after.roster(), before.roster());
        assert_eq!(
            after.server_address().to_string(),
            before.server_address().to_string(),
            "the address is stored whole: the trust mode is part of the \
             server's identity, not a connection-time detail"
        );
        assert_eq!(
            after.snapshot().expect("snapshot"),
            blob,
            "and the blob round-trips byte for byte"
        );
    }

    #[test]
    fn reopening_makes_no_request() {
        // The app opens on every cold start, including in a doze window with no
        // network. An open that talked to the server would make the ledger
        // screen unreachable exactly when the family most wants to read it.
        let (applied, _) = founded();
        let blob = applied.outcome.snapshot().expect("snapshot");

        let http = ScriptedHttp::new(Vec::new());
        Client::open_with(http.clone(), Arc::new(FixedStamps), &blob, &seeds())
            .expect("reopen offline");

        assert!(http.paths().is_empty(), "{:?}", http.paths());
    }

    #[test]
    fn a_blob_opened_with_the_wrong_identity_seed_is_refused() {
        let (applied, _) = founded();
        let blob = applied.outcome.snapshot().expect("snapshot");

        let wrong = Seeds::from_parts([3u8; SEED_BYTES], [99u8; SEED_BYTES]);
        let error = Client::open_with(
            ScriptedHttp::new(Vec::new()),
            Arc::new(FixedStamps),
            &blob,
            &wrong,
        )
        .expect_err("refused");

        assert!(matches!(error, ClientError::Session { .. }), "{error:?}");
    }

    #[test]
    fn the_snapshot_does_not_carry_the_seeds() {
        // They belong in the keystore. A blob that contained them would make the
        // platform's at-rest encryption the only thing between a backup and a
        // device's identity.
        let (applied, _) = founded();
        let blob = applied.outcome.snapshot().expect("snapshot");

        for seed in [seeds().device_seed(), seeds().identity_seed()] {
            assert!(
                !blob.windows(SEED_BYTES).any(|window| window == seed),
                "a seed is in the state blob"
            );
        }
    }

    #[test]
    fn a_server_device_the_roster_never_vouched_for_is_marked_unvouched() {
        // The injected-device signal, at the boundary where the app reads it: the
        // two lists stay two lists, and the row that is in one and not the other
        // is the one a UI has to surface.
        let (applied, _) = founded();
        let blob = applied.outcome.snapshot().expect("snapshot");

        let http = ScriptedHttp::new(vec![ok(r#"{"devices":[
                 {"id":"dev_A","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                  "push_endpoint":"","capabilities":"","revoked":false},
                 {"id":"dev_INJECTED","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                  "push_endpoint":"","capabilities":"","revoked":false}]}"#)]);
        let client = Client::open_with(http, Arc::new(FixedStamps), &blob, &seeds()).expect("open");

        let listed = client.server_devices().expect("list");
        let injected = listed
            .iter()
            .find(|row| row.device_id == "dev_INJECTED")
            .expect("the server lists it");

        assert!(
            !injected.vouched,
            "enrolling on the server is not joining the family"
        );
        assert!(
            listed
                .iter()
                .find(|row| row.device_id == "dev_A")
                .expect("and this device")
                .vouched
        );
    }

    #[test]
    fn a_pin_mismatch_during_enrollment_surfaces_as_an_identity_failure() {
        // The contract requirement carried all the way to the app-facing call.
        let http = ScriptedHttp::new(vec![Err(HttpError::Tls(
            "presented certificate does not match the pin".to_owned(),
        ))]);

        let error = Client::enroll_with(
            http,
            Arc::new(FixedStamps),
            address(),
            "invite-token",
            &profile(),
            &seeds(),
            now(),
        )
        .expect_err("refused");

        assert!(error.is_server_identity(), "{error:?}");
        assert!(
            !matches!(error, ClientError::Network { .. }),
            "an intercepting network must not look like an absent one"
        );
    }

    #[test]
    fn a_spent_invitation_is_refused_without_founding_anything() {
        let http = ScriptedHttp::new(vec![Ok(HttpResponse {
            status: 401,
            body: b"{}".to_vec(),
        })]);

        let error = Client::enroll_with(
            http.clone(),
            Arc::new(FixedStamps),
            address(),
            "spent-token",
            &profile(),
            &seeds(),
            now(),
        )
        .expect_err("refused");

        assert_eq!(error, ClientError::Unauthorized);
        assert_eq!(
            http.paths(),
            vec!["/v1/devices/register"],
            "nothing is published for a device that never enrolled"
        );
    }
}
