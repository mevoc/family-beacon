//! The transport port, over Sund queues.
//!
//! [`crate::transport::Transport`] presents one duplex `channel`. Sund has no
//! such thing: it has *two* one-way blind queues, each owned by the device that
//! drains it, each authenticated by its own key, and each rotated on its
//! owner's schedule (`../../sund/docs/Sund-ImplementationGuide.md`, Walkthrough
//! 2). This module is where that asymmetry is held, so that nothing above the
//! port has to know about it.
//!
//! ```text
//!   channel "dev_A:dev_B"
//!     inbound   queue we own      recipient_id + recipient key   recv/ack/retire
//!     outbound  queue the peer owns  their sender_id + our sender key   send
//! ```
//!
//! The two halves rotate independently, and that is not a detail this module
//! could smooth over even if it wanted to:
//!
//! - **We rotate our inbound queue** ([`SundTransport::rotate_inbound`]): the
//!   old queue is retired server-side, a new one is created, and the new
//!   `sender_id` has to reach the peer — over the existing session, as an
//!   ordinary message, because the server has no way to tell them.
//! - **The peer rotates theirs**: they send us a new `sender_id`, and we
//!   [`SundTransport::attach_outbound`] with a **fresh sender key**. A new queue
//!   is created *open*, and the first valid send binds the key permanently; a
//!   queue's bound key can never be replaced, so reusing the old key is not an
//!   optimisation, it is a 401.
//!
//! Nothing here generates keys or randomness. Seeds arrive from the app layer,
//! which is also what stores them — key storage is where the platforms
//! genuinely differ (Keystore, Secure Enclave, browser storage), and it is the
//! one thing this core must not decide for them.

use crate::client::{DeviceClient, QueueIds, QueueMessage, SundError};
use crate::sigauth::{DeviceKey, QueueKey};
use crate::transport::{
    ChannelId, Delivery, MessageId, Outbound, Priority, Subscription, Transport, TransportError,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// Where this device sends on a channel: the peer's queue, and the key we sign
/// to it with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundQueue {
    /// The peer's `sender_id`, learned from the pairing QR or from a message
    /// on the existing session.
    pub sender_id: String,
    /// The seed of the per-queue sender key. One queue, one key, forever.
    pub sender_seed: [u8; 32],
    /// Whether the key has been bound by a successful send. Sund binds on the
    /// first valid send and refuses to rebind; a client that offers the header
    /// again after binding is not wrong, but a client that offers a *different*
    /// key is refused.
    pub bound: bool,
}

/// One channel's persistent state.
///
/// Exported and restored by the app layer, which owns storage. **This carries
/// private key seeds**: it belongs wherever that platform keeps secrets, not in
/// ordinary preferences or a plain file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelRecord {
    /// The channel id the layers above use.
    pub channel: ChannelId,
    /// The seed of the key that drains, acknowledges and retires our queue.
    pub recipient_seed: [u8; 32],
    /// Our queue, once it exists on the server.
    pub inbound: Option<QueueIds>,
    /// The peer's queue, once we know where it is.
    pub outbound: Option<OutboundQueue>,
    /// Whether this channel has been retired. One-way.
    pub retired: bool,
}

/// The Sund implementation of the transport port.
///
/// Cheap to clone; clones share one channel table, so a background drain loop
/// and a foreground send can hold one each.
#[derive(Clone)]
pub struct SundTransport {
    device: DeviceClient,
    channels: Arc<Mutex<HashMap<ChannelId, ChannelRecord>>>,
}

impl std::fmt::Debug for SundTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SundTransport")
            .field("device", &self.device)
            .field("channels", &self.channel_ids())
            .finish()
    }
}

impl SundTransport {
    /// Build a transport for one enrolled device.
    #[must_use]
    pub fn new(device: DeviceClient) -> Self {
        Self {
            device,
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The device whose queues these are.
    ///
    /// The management plane stays reachable from here because the two are not
    /// separable in Sund mode: rotation creates queues, and removal revokes a
    /// device *and* takes its queues down. The roster layer needs both.
    #[must_use]
    pub fn device(&self) -> &DeviceClient {
        &self.device
    }

    /// Stage a channel this device will own the inbound half of.
    ///
    /// Local only — no request is made. [`Transport::open`] is what creates the
    /// queue on the server, which keeps the port's `open` meaning what it says
    /// on both backends. Declaring a channel that already exists changes
    /// nothing, so restoring state and then declaring is safe.
    pub fn declare(&self, channel: &ChannelId, recipient_seed: [u8; 32]) {
        let mut channels = self.locked();
        channels
            .entry(channel.clone())
            .or_insert_with(|| ChannelRecord {
                channel: channel.clone(),
                recipient_seed,
                inbound: None,
                outbound: None,
                retired: false,
            });
    }

    /// Point this channel's sends at the peer's queue.
    ///
    /// Call it once per peer queue: at pairing, with the `sender_id` from the
    /// QR, and again whenever the peer rotates and tells us the new one. Each
    /// call takes a fresh sender seed, because each peer queue binds exactly
    /// one sender key.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::UnknownChannel`] if the channel was never
    /// declared, or [`TransportError::Retired`] if it is retired.
    pub fn attach_outbound(
        &self,
        channel: &ChannelId,
        sender_id: impl Into<String>,
        sender_seed: [u8; 32],
    ) -> Result<(), TransportError> {
        let mut channels = self.locked();
        let record = live(&mut channels, channel)?;
        record.outbound = Some(OutboundQueue {
            sender_id: sender_id.into(),
            sender_seed,
            bound: false,
        });
        Ok(())
    }

    /// Our queue's ids, once [`Transport::open`] has created it.
    ///
    /// The `sender_id` half is what the peer needs; the `recipient_id` half
    /// never leaves this device.
    #[must_use]
    pub fn inbound(&self, channel: &ChannelId) -> Option<QueueIds> {
        self.locked()
            .get(channel)
            .and_then(|record| record.inbound.clone())
    }

    /// Rotate the inbound half: retire the queue we own and create a new one.
    ///
    /// Returns the new ids. The caller must deliver the new `sender_id` to the
    /// peer over the existing session — until it does, the peer keeps sending
    /// into a queue that no longer exists and those messages are lost, which is
    /// the ordinary consequence of a transport that is deliberately lossy.
    ///
    /// Undrained messages on the old queue are discarded: retirement drops what
    /// it holds. Drain before rotating if that matters.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::UnknownChannel`] or [`TransportError::Retired`]
    /// for a channel that cannot be rotated, or [`TransportError::Backend`] if
    /// the server refuses to create the replacement.
    pub fn rotate_inbound(
        &self,
        channel: &ChannelId,
        new_recipient_seed: [u8; 32],
    ) -> Result<QueueIds, TransportError> {
        let previous = {
            let mut channels = self.locked();
            let record = live(&mut channels, channel)?;
            record.inbound.clone()
        };

        if let Some(previous) = previous {
            let key = self.recipient_key(channel)?;
            match self
                .device
                .transport()
                .retire_queue(&previous.recipient_id, &key)
            {
                // Already gone server-side — a revoked device's queues are
                // retired for it — which is the state we were aiming for.
                Ok(()) | Err(SundError::NotFound) => {}
                Err(error) => return Err(backend(&error)),
            }
        }

        let ids = self.create_queue(&new_recipient_seed)?;
        let mut channels = self.locked();
        let record = live(&mut channels, channel)?;
        record.recipient_seed = new_recipient_seed;
        record.inbound = Some(ids.clone());
        Ok(ids)
    }

    /// Acknowledge several deliveries in one request.
    ///
    /// The port acknowledges one at a time because that is the smallest honest
    /// contract; over HTTP one round trip per message is a real cost on a
    /// phone, so batching is available to callers that have a batch.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] if the channel is unknown or retired, or
    /// the server refuses.
    pub fn acknowledge_all(
        &self,
        channel: &ChannelId,
        messages: &[MessageId],
    ) -> Result<(), TransportError> {
        if messages.is_empty() {
            return Ok(());
        }
        let recipient_id = self.recipient_id(channel)?;
        let key = self.recipient_key(channel)?;
        self.device
            .transport()
            .acknowledge(&recipient_id, &key, messages)
            .map_err(|error| self.channel_error(channel, &error))?;
        Ok(())
    }

    /// Every channel's state, for the app layer to persist.
    #[must_use]
    pub fn export(&self) -> Vec<ChannelRecord> {
        let mut records: Vec<ChannelRecord> = self.locked().values().cloned().collect();
        records.sort_by(|a, b| a.channel.cmp(&b.channel));
        records
    }

    /// Restore persisted state, replacing anything held for the same channels.
    pub fn import(&self, records: impl IntoIterator<Item = ChannelRecord>) {
        let mut channels = self.locked();
        for record in records {
            channels.insert(record.channel.clone(), record);
        }
    }

    /// The channels this transport knows about, retired ones included.
    #[must_use]
    pub fn channel_ids(&self) -> Vec<ChannelId> {
        let mut ids: Vec<ChannelId> = self.locked().keys().cloned().collect();
        ids.sort();
        ids
    }

    // --- plumbing -----------------------------------------------------------

    fn locked(&self) -> std::sync::MutexGuard<'_, HashMap<ChannelId, ChannelRecord>> {
        // A poisoned lock means a caller panicked while holding it; the panic
        // that follows is that failure, not a new one.
        self.channels.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn create_queue(&self, recipient_seed: &[u8; 32]) -> Result<QueueIds, TransportError> {
        let key = QueueKey::from_seed(recipient_seed);
        self.device
            .create_queue(&key.public_key())
            .map_err(|error| backend(&error))
    }

    fn recipient_key(&self, channel: &ChannelId) -> Result<QueueKey, TransportError> {
        let channels = self.locked();
        let record = channels
            .get(channel)
            .ok_or_else(|| TransportError::UnknownChannel(channel.clone()))?;
        Ok(DeviceKey::from_seed(&record.recipient_seed))
    }

    fn recipient_id(&self, channel: &ChannelId) -> Result<String, TransportError> {
        let mut channels = self.locked();
        let record = live(&mut channels, channel)?;
        record
            .inbound
            .as_ref()
            .map(|ids| ids.recipient_id.clone())
            // Declared but never opened: there is no queue to talk to yet.
            .ok_or_else(|| TransportError::UnknownChannel(channel.clone()))
    }

    /// Map a server error onto the port's vocabulary, in channel terms.
    ///
    /// A 404 on the transport plane means the queue is not there: we retired
    /// it, the peer rotated theirs, or a revocation took the owner's queues
    /// down. From the port's point of view those are one fact — this pipe is
    /// gone — and the layers above respond to it identically, by re-pairing or
    /// by waiting for the peer's new address.
    fn channel_error(&self, channel: &ChannelId, error: &SundError) -> TransportError {
        match error {
            SundError::NotFound => TransportError::Retired(channel.clone()),
            other => backend(other),
        }
    }
}

/// Look a channel up and refuse a retired one. Retirement is one-way, so this
/// is the single place that check has to be made.
fn live<'a>(
    channels: &'a mut HashMap<ChannelId, ChannelRecord>,
    channel: &ChannelId,
) -> Result<&'a mut ChannelRecord, TransportError> {
    let record = channels
        .get_mut(channel)
        .ok_or_else(|| TransportError::UnknownChannel(channel.clone()))?;
    if record.retired {
        return Err(TransportError::Retired(channel.clone()));
    }
    Ok(record)
}

fn backend(error: &SundError) -> TransportError {
    TransportError::Backend(error.to_string())
}

impl Transport for SundTransport {
    /// Create this channel's inbound queue, if it does not exist yet.
    ///
    /// The channel must have been declared first ([`SundTransport::declare`]),
    /// because a queue cannot be created without the key that will drain it,
    /// and this core does not mint keys.
    fn open(&self, channel: &ChannelId) -> Result<(), TransportError> {
        let seed = {
            let mut channels = self.locked();
            let record = live(&mut channels, channel)?;
            if record.inbound.is_some() {
                return Ok(());
            }
            record.recipient_seed
        };

        let ids = self.create_queue(&seed)?;
        let mut channels = self.locked();
        let record = live(&mut channels, channel)?;
        // Another caller may have opened it while the request was in flight;
        // the first result wins, and the queue this one created is simply never
        // used. Costing an empty queue is better than two callers disagreeing
        // about which one is ours.
        if record.inbound.is_none() {
            record.inbound = Some(ids);
        }
        Ok(())
    }

    /// Retire the queue this device owns and stop using the channel.
    ///
    /// Only our half: the peer's queue is theirs to retire, and a
    /// half-retired channel is exactly what it looks like — we will read
    /// nothing further, and our sends fail once they retire their side. The
    /// stronger removal, which kills a device's queues on the server, is
    /// [`crate::client::DeviceClient::revoke_device`].
    fn retire(&self, channel: &ChannelId) -> Result<(), TransportError> {
        let inbound = {
            let mut channels = self.locked();
            let record = live(&mut channels, channel)?;
            record.inbound.clone()
        };

        if let Some(inbound) = inbound {
            let key = self.recipient_key(channel)?;
            match self
                .device
                .transport()
                .retire_queue(&inbound.recipient_id, &key)
            {
                Ok(()) | Err(SundError::NotFound) => {}
                Err(error) => return Err(backend(&error)),
            }
        }

        let mut channels = self.locked();
        let record = channels
            .get_mut(channel)
            .ok_or_else(|| TransportError::UnknownChannel(channel.clone()))?;
        record.retired = true;
        Ok(())
    }

    fn send(&self, channel: &ChannelId, message: Outbound) -> Result<MessageId, TransportError> {
        let outbound = {
            let mut channels = self.locked();
            let record = live(&mut channels, channel)?;
            record
                .outbound
                .clone()
                // Declared, maybe open, but we do not know where the peer
                // reads: nothing can be sent yet.
                .ok_or_else(|| TransportError::UnknownChannel(channel.clone()))?
        };

        let key = QueueKey::from_seed(&outbound.sender_seed);
        let id = self
            .device
            .transport()
            .send_to_queue(
                &outbound.sender_id,
                &key,
                &QueueMessage {
                    payload: &message.ciphertext,
                    ttl: message.ttl,
                    priority: matches!(message.priority, Priority::High),
                    bind_sender_key: !outbound.bound,
                },
            )
            .map_err(|error| self.channel_error(channel, &error))?;

        if !outbound.bound {
            let mut channels = self.locked();
            if let Some(record) = channels.get_mut(channel)
                && let Some(existing) = record.outbound.as_mut()
                && existing.sender_id == outbound.sender_id
            {
                existing.bound = true;
            }
        }
        Ok(id)
    }

    /// Drain the queue once and hand the messages over one at a time.
    ///
    /// The drain happens here, in one request, rather than per delivery: the
    /// server returns everything unacknowledged in one response, and a phone
    /// woken by a ping wants one round trip, not one per message. A
    /// subscription is therefore a snapshot — messages that arrive after it
    /// show up on the next one.
    fn subscribe(&self, channel: &ChannelId) -> Result<Box<dyn Subscription>, TransportError> {
        let recipient_id = self.recipient_id(channel)?;
        let key = self.recipient_key(channel)?;
        let messages = self
            .device
            .transport()
            .receive_from_queue(&recipient_id, &key)
            .map_err(|error| self.channel_error(channel, &error))?;

        Ok(Box::new(SundSubscription {
            pending: messages
                .into_iter()
                .map(|message| Delivery {
                    id: message.id,
                    ciphertext: message.payload,
                    // Sund always sends this; if it ever does not, "now" is the
                    // only honest answer a client can give, and the protocol
                    // layer's own `sent` and `seq` are what freshness decisions
                    // actually rest on.
                    received_at: message
                        .received_at
                        .unwrap_or_else(std::time::SystemTime::now),
                })
                .collect(),
        }))
    }

    fn ack(&self, channel: &ChannelId, message: &MessageId) -> Result<(), TransportError> {
        self.acknowledge_all(channel, std::slice::from_ref(message))
    }
}

/// One drained batch, handed over one delivery at a time.
#[derive(Debug)]
struct SundSubscription {
    pending: VecDeque<Delivery>,
}

impl Subscription for SundSubscription {
    fn next_delivery(&mut self) -> Result<Option<Delivery>, TransportError> {
        Ok(self.pending.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::SundClient;
    use crate::http::testing::{FixedStamps, ScriptedHttp};
    use crate::http::{HttpResponse, StampSource};
    use crate::sigauth::{HEADER_SENDER_KEY, RequestToSign, verify};

    fn ok(body: &str) -> Result<HttpResponse, crate::http::HttpError> {
        Ok(HttpResponse {
            status: 200,
            body: body.as_bytes().to_vec(),
        })
    }

    fn transport(
        replies: Vec<Result<HttpResponse, crate::http::HttpError>>,
    ) -> (SundTransport, Arc<ScriptedHttp>) {
        let http = Arc::new(ScriptedHttp::new(replies));
        let stamps: Arc<dyn StampSource> = Arc::new(FixedStamps);
        let client = SundClient::new(http.clone(), stamps);
        let device = client.device("dev_A", DeviceKey::from_seed(&[1u8; 32]));
        (SundTransport::new(device), http)
    }

    fn channel() -> ChannelId {
        "dev_A:dev_B".to_owned()
    }

    #[test]
    fn opening_a_channel_creates_the_queue_this_device_drains() {
        let (transport, http) =
            transport(vec![ok(r#"{"recipient_id":"rcp_1","sender_id":"snd_1"}"#)]);
        transport.declare(&channel(), [7u8; 32]);
        transport.open(&channel()).expect("open");

        assert_eq!(
            transport.inbound(&channel()),
            Some(QueueIds {
                recipient_id: "rcp_1".to_owned(),
                sender_id: "snd_1".to_owned(),
            })
        );
        // Queue creation is the one transport-plane thing signed by device
        // identity, because the server has to know whose quota it counts against.
        let request = http.last();
        assert_eq!(request.path, "/v1/queues");
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| name == "Sund-Device-Id" && value == "dev_A")
        );

        // Idempotent: no second queue is created.
        transport.open(&channel()).expect("open again");
        assert_eq!(http.requests().len(), 1);
    }

    #[test]
    fn a_channel_must_be_declared_before_it_can_be_opened() {
        let (transport, _) = transport(vec![ok("{}")]);
        assert_eq!(
            transport.open(&channel()),
            Err(TransportError::UnknownChannel(channel()))
        );
    }

    #[test]
    fn the_first_send_binds_the_sender_key_and_later_ones_do_not() {
        let (transport, http) = transport(vec![ok(r#"{"message_id":"m1"}"#)]);
        transport.declare(&channel(), [7u8; 32]);
        transport
            .attach_outbound(&channel(), "snd_peer", [8u8; 32])
            .expect("attach");

        transport
            .send(&channel(), Outbound::new(b"one".to_vec()))
            .expect("first send");
        let first = http.last();
        assert_eq!(first.path, "/v1/send/snd_peer");
        let sender_key = first
            .headers
            .iter()
            .find(|(name, _)| name == HEADER_SENDER_KEY)
            .map(|(_, value)| value.clone());
        assert!(sender_key.is_some(), "the first send binds the key");

        transport
            .send(&channel(), Outbound::new(b"two".to_vec()))
            .expect("second send");
        let second = http.last();
        assert!(
            !second
                .headers
                .iter()
                .any(|(name, _)| name == HEADER_SENDER_KEY),
            "a bound queue does not re-offer the key"
        );

        // And what it signs with is the sender key, not the device key.
        let headers: HashMap<_, _> = second
            .headers
            .iter()
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect();
        let to_sign = RequestToSign {
            method: "POST",
            path: &second.path,
            timestamp: &headers["Sund-Timestamp"],
            nonce: &headers["Sund-Nonce"],
            body: &second.body,
        };
        assert!(verify(
            &QueueKey::from_seed(&[8u8; 32]).public_key(),
            &to_sign,
            &headers["Sund-Signature"]
        ));
    }

    #[test]
    fn sending_before_the_peers_queue_is_known_is_an_unknown_channel() {
        let (transport, _) = transport(vec![ok("{}")]);
        transport.declare(&channel(), [7u8; 32]);
        assert_eq!(
            transport.send(&channel(), Outbound::new(b"x".to_vec())),
            Err(TransportError::UnknownChannel(channel()))
        );
    }

    #[test]
    fn a_vanished_queue_reads_as_retirement() {
        // 404 on the transport plane: we retired it, the peer rotated, or a
        // revocation took the owner's queues down. One fact at the port.
        let (transport, _) = transport(vec![
            ok(r#"{"recipient_id":"rcp_1","sender_id":"snd_1"}"#),
            Ok(HttpResponse {
                status: 404,
                body: br#"{"error":"no such queue"}"#.to_vec(),
            }),
        ]);
        transport.declare(&channel(), [7u8; 32]);
        transport.open(&channel()).expect("open");
        assert!(matches!(
            transport.subscribe(&channel()),
            Err(TransportError::Retired(_))
        ));
    }

    #[test]
    fn rotation_retires_the_old_queue_and_returns_new_ids() {
        let (transport, http) = transport(vec![
            ok(r#"{"recipient_id":"rcp_1","sender_id":"snd_1"}"#),
            ok(r#"{"retired":true}"#),
            ok(r#"{"recipient_id":"rcp_2","sender_id":"snd_2"}"#),
        ]);
        transport.declare(&channel(), [7u8; 32]);
        transport.open(&channel()).expect("open");

        let fresh = transport
            .rotate_inbound(&channel(), [11u8; 32])
            .expect("rotate");
        assert_eq!(fresh.recipient_id, "rcp_2");
        assert_eq!(transport.inbound(&channel()), Some(fresh));

        let paths: Vec<String> = http.requests().into_iter().map(|r| r.path).collect();
        assert_eq!(paths, ["/v1/queues", "/v1/retire/rcp_1", "/v1/queues"]);

        // The new queue is drained with the new key, not the old one.
        let exported = transport.export();
        assert_eq!(exported[0].recipient_seed, [11u8; 32]);
    }

    #[test]
    fn retirement_is_one_way_and_local_state_says_so() {
        let (transport, _) = transport(vec![
            ok(r#"{"recipient_id":"rcp_1","sender_id":"snd_1"}"#),
            ok(r#"{"retired":true}"#),
        ]);
        transport.declare(&channel(), [7u8; 32]);
        transport.open(&channel()).expect("open");
        transport
            .attach_outbound(&channel(), "snd_peer", [8u8; 32])
            .expect("attach");
        transport.retire(&channel()).expect("retire");

        assert_eq!(
            transport.send(&channel(), Outbound::new(b"x".to_vec())),
            Err(TransportError::Retired(channel()))
        );
        assert!(matches!(
            transport.subscribe(&channel()),
            Err(TransportError::Retired(_))
        ));
        assert!(matches!(
            transport.open(&channel()),
            Err(TransportError::Retired(_))
        ));
    }

    #[test]
    fn a_drain_hands_messages_over_in_order_and_acks_them_in_one_request() {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"hello");
        let body = format!(
            r#"{{"messages":[{{"id":"m1","payload":"{encoded}","received_at":"2026-07-24T09:00:00Z","expires":"2026-07-25T09:00:00Z"}},{{"id":"m2","payload":"{encoded}","received_at":"2026-07-24T09:00:01Z","expires":"2026-07-25T09:00:01Z"}}]}}"#
        );
        let (transport, http) = transport(vec![
            ok(r#"{"recipient_id":"rcp_1","sender_id":"snd_1"}"#),
            ok(&body),
            ok(r#"{"deleted":2}"#),
        ]);
        transport.declare(&channel(), [7u8; 32]);
        transport.open(&channel()).expect("open");

        let mut subscription = transport.subscribe(&channel()).expect("subscribe");
        let mut ids = Vec::new();
        while let Some(delivery) = subscription.next_delivery().expect("delivery") {
            assert_eq!(delivery.ciphertext, b"hello");
            ids.push(delivery.id);
        }
        assert_eq!(ids, ["m1", "m2"]);

        transport.acknowledge_all(&channel(), &ids).expect("ack");
        let ack = http.last();
        assert_eq!(ack.path, "/v1/ack/rcp_1");
        let body: serde_json::Value = serde_json::from_slice(&ack.body).expect("json");
        assert_eq!(body["ids"][0], "m1");
        assert_eq!(body["ids"][1], "m2");
    }

    #[test]
    fn state_survives_an_export_and_import_round_trip() {
        let (original, _) = transport(vec![ok(r#"{"recipient_id":"rcp_1","sender_id":"snd_1"}"#)]);
        original.declare(&channel(), [7u8; 32]);
        original.open(&channel()).expect("open");
        original
            .attach_outbound(&channel(), "snd_peer", [8u8; 32])
            .expect("attach");

        let saved = original.export();
        let json = serde_json::to_vec(&saved).expect("serialise");
        let restored: Vec<ChannelRecord> = serde_json::from_slice(&json).expect("deserialise");

        let (fresh, _) = transport(vec![ok("{}")]);
        fresh.import(restored);
        assert_eq!(fresh.export(), saved);
        assert_eq!(fresh.channel_ids(), vec![channel()]);
    }
}
