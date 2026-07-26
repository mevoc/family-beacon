//! The outbox against a real relay, and against a real absence of one.
//!
//! The outbox exists for what happens while the network is gone, so the
//! interesting assertions need a network that goes. [`SwitchableHttp`] provides
//! it at the seam a phone actually experiences — the server is fine, this device
//! cannot reach it — while everything either side of that seam stays real: real
//! sessions, real queues, a real Sund on the other end.
//!
//! What this leg is for, over and above the unit tests: the unit suite drives the
//! outbox against an in-memory transport that fails on command, which proves the
//! *policy*. Only a real relay proves that a backlog queued during an outage
//! actually lands, in order, decryptable, on the far side — and that the
//! sealing-at-drain decision survives a session that was re-established while the
//! messages sat waiting.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use beacon_protocol::envelope::MessageType;
use beacon_protocol::{Outcome, receive};
use contract_tests::{Relay, SwitchableHttp, TestDevice, channel_id, for_each_relay, seed};
use sund_client::bundle::SignedBundle;
use sund_client::client::SundClient;
use sund_client::http::HttpClient;
use sund_client::identity::IdentityKey;
use sund_client::outbox::{DeferReason, DropReason, Enqueue, Outbox, OutboxSnapshot};
use sund_client::session::SessionManager;
use sund_client::sund_transport::SundTransport;
use sund_client::transport::{ChannelId, Priority, Transport};

const PUBLISHED: &str = "2026-07-26T10:00:00Z";
const NOON: u64 = 1_784_000_000;

fn at(offset: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(NOON + offset)
}

/// A sender whose network can be switched off, and the peer it talks to.
struct Pair {
    outbox: Outbox,
    sessions: SessionManager,
    transport: SundTransport,
    network: Arc<SwitchableHttp>,
    peer_sessions: SessionManager,
    peer_transport: SundTransport,
    peer_device: TestDevice,
    sender_id: String,
    peer_id: String,
    channel: ChannelId,
}

/// Two enrolled devices that have verified each other and share a channel, with
/// the sender's HTTP client behind a switch.
fn pair(relay: &Relay, label: &str) -> Pair {
    let sender = relay.enroll();
    let peer = relay.enroll();
    let (sender_id, peer_id) = (sender.device_id().to_owned(), peer.device_id().to_owned());

    let mut sender_sessions =
        SessionManager::create(&sender_id, IdentityKey::from_seed(&[1u8; 32]));
    let mut peer_sessions = SessionManager::create(&peer_id, IdentityKey::from_seed(&[2u8; 32]));

    // Publish and cross-verify bundles while the network is still up.
    for (device, sessions) in [(&sender, &mut sender_sessions), (&peer, &mut peer_sessions)] {
        let bundle = sessions.publish_bundle(PUBLISHED).expect("bundle");
        device
            .publish_bundle(&bundle.encode().expect("encode"))
            .expect("publish");
    }
    let sender_keys = SignedBundle::decode(&peer.fetch_bundle(&sender_id).expect("fetch").bundle)
        .expect("decode")
        .verify(&sender_id, sender_sessions.identity_public_key())
        .expect("verify");
    let peer_keys = SignedBundle::decode(&sender.fetch_bundle(&peer_id).expect("fetch").bundle)
        .expect("decode")
        .verify(&peer_id, peer_sessions.identity_public_key())
        .expect("verify");
    sender_sessions.learn_peer(peer_keys);
    peer_sessions.learn_peer(sender_keys);

    // The sender talks through a switch; the peer does not, so it can still read
    // its queue while the sender is "offline".
    let network = Arc::new(SwitchableHttp::new(relay.http()));
    let switched: Arc<dyn HttpClient> = network.clone();
    let sender_through_switch = relay.through(&sender, switched);
    let transport = SundTransport::new(sender_through_switch);
    let peer_transport = SundTransport::new(peer.device.clone());

    let channel = channel_id(label);
    transport.declare(&channel, seed());
    transport.open(&channel).expect("sender's queue");
    peer_transport.declare(&channel, seed());
    peer_transport.open(&channel).expect("peer's queue");
    let sender_ids = transport.inbound(&channel).expect("ids");
    let peer_ids = peer_transport.inbound(&channel).expect("ids");
    transport
        .attach_outbound(&channel, peer_ids.sender_id, seed())
        .expect("sender can send");
    peer_transport
        .attach_outbound(&channel, sender_ids.sender_id, seed())
        .expect("peer can send");

    Pair {
        outbox: Outbox::new(),
        sessions: sender_sessions,
        transport,
        network,
        peer_sessions,
        peer_transport,
        peer_device: peer,
        sender_id,
        peer_id,
        channel,
    }
}

impl Pair {
    fn queue(&mut self, plaintext: &[u8], now: SystemTime) {
        self.outbox
            .enqueue(
                &Enqueue {
                    channel: self.channel.clone(),
                    peer: self.peer_id.clone(),
                    plaintext,
                    priority: Priority::Normal,
                    ttl: None,
                    expires_at: None,
                    coalesce_key: None,
                },
                now,
            )
            .expect("enqueue");
    }

    /// Everything the peer can read and decrypt, as protocol outcomes.
    fn received(&mut self) -> Vec<Outcome> {
        let mut subscription = self
            .peer_transport
            .subscribe(&self.channel)
            .expect("subscribe");
        let mut ids = Vec::new();
        let mut frames = Vec::new();
        while let Some(delivery) = subscription.next_delivery().expect("next") {
            ids.push(delivery.id);
            frames.push(delivery.ciphertext);
        }
        drop(subscription);
        if !ids.is_empty() {
            self.peer_transport
                .acknowledge_all(&self.channel, &ids)
                .expect("ack");
        }
        frames
            .iter()
            .map(|frame| {
                let decrypted = self
                    .peer_sessions
                    .decrypt(&self.sender_id, frame)
                    .expect("decrypt");
                receive(&decrypted.plaintext, &decrypted.authenticated_sender).outcome
            })
            .collect()
    }
}

fn location(sender: &str, seq: u64) -> Vec<u8> {
    format!(
        r#"{{"v":1,"id":"loc-{seq}","seq":{seq},"type":"location",
             "sent":"2026-07-26T10:04:12Z","sender":"{sender}",
             "body":{{"lat":56,"lon":12,"accuracy_m":12,
                      "recorded_at":"2026-07-26T10:04:10Z"}}}}"#
    )
    .into_bytes()
}

fn sos(sender: &str, seq: u64) -> Vec<u8> {
    format!(
        r#"{{"v":1,"id":"sos-{seq}","seq":{seq},"type":"sos",
             "sent":"2026-07-26T10:04:12Z","sender":"{sender}",
             "body":{{"recorded_at":"2026-07-26T10:04:10Z"}}}}"#
    )
    .into_bytes()
}

#[test]
fn a_backlog_queued_offline_lands_in_order_when_the_network_returns() {
    for_each_relay(|relay| {
        let mut p = pair(relay, "outbox-backlog");
        let sender_id = p.sender_id.clone();

        p.network.go_offline();
        for seq in 1..=5u64 {
            p.queue(&sos(&sender_id, seq), at(seq));
        }

        let report = p
            .outbox
            .drain(&p.transport, &mut p.sessions, at(10), usize::MAX);
        assert!(report.sent.is_empty(), "{}: nothing goes out", relay.name);
        assert_eq!(report.deferred.len(), 5, "{}", relay.name);
        assert!(
            report
                .deferred
                .iter()
                .all(|d| matches!(d.reason, DeferReason::Unreachable(_))),
            "{}: an unreachable server is a deferral, not a loss",
            relay.name
        );
        assert_eq!(p.outbox.len(), 5, "{}: still queued", relay.name);
        assert!(p.received().is_empty(), "{}", relay.name);

        // The network comes back. One drain, past the backoff, and everything
        // lands — in order, decryptable, on a real relay.
        p.network.come_online();
        let report = p
            .outbox
            .drain(&p.transport, &mut p.sessions, at(10_000), usize::MAX);
        assert_eq!(report.sent.len(), 5, "{}", relay.name);
        assert!(p.outbox.is_empty(), "{}", relay.name);

        let received = p.received();
        assert_eq!(received.len(), 5, "{}", relay.name);
        for (index, outcome) in received.iter().enumerate() {
            match outcome {
                Outcome::Accepted(envelope) => {
                    assert_eq!(envelope.message_type, MessageType::Sos);
                    assert_eq!(
                        envelope.seq,
                        index as u64 + 1,
                        "{}: order held across the outage",
                        relay.name
                    );
                }
                other => panic!("{}: expected Accepted, got {other:?}", relay.name),
            }
        }
    });
}

#[test]
fn a_position_that_went_stale_during_the_outage_is_never_delivered() {
    // The rule the outbox exists to enforce, end to end: ARCHITECTURE says queue
    // location while offline, the protocol says a stale location is worse than
    // none, and what reconnecting licences is a *fresh* position.
    for_each_relay(|relay| {
        let mut p = pair(relay, "outbox-stale");
        let sender_id = p.sender_id.clone();
        p.network.go_offline();

        let stale = location(&sender_id, 1);
        p.outbox
            .enqueue(
                &Enqueue {
                    channel: p.channel.clone(),
                    peer: p.peer_id.clone(),
                    plaintext: &stale,
                    priority: Priority::Normal,
                    ttl: Some(Duration::from_secs(300)),
                    expires_at: Some(at(300)),
                    coalesce_key: Some("location".to_owned()),
                },
                at(0),
            )
            .expect("enqueue");

        p.network.come_online();
        let report = p
            .outbox
            .drain(&p.transport, &mut p.sessions, at(3600), usize::MAX);
        assert!(report.sent.is_empty(), "{}", relay.name);
        assert_eq!(report.dropped.len(), 1, "{}", relay.name);
        assert_eq!(report.dropped[0].reason, DropReason::Expired);
        assert!(
            p.received().is_empty(),
            "{}: an hour-old position never reaches the family",
            relay.name
        );
    });
}

#[test]
fn an_hour_of_queued_positions_drains_as_one() {
    for_each_relay(|relay| {
        let mut p = pair(relay, "outbox-coalesce");
        let sender_id = p.sender_id.clone();
        p.network.go_offline();

        for minute in 0..60u64 {
            let body = location(&sender_id, minute);
            p.outbox
                .enqueue(
                    &Enqueue {
                        channel: p.channel.clone(),
                        peer: p.peer_id.clone(),
                        plaintext: &body,
                        priority: Priority::Normal,
                        ttl: None,
                        expires_at: None,
                        coalesce_key: Some("location".to_owned()),
                    },
                    at(minute * 60),
                )
                .expect("enqueue");
        }
        assert_eq!(p.outbox.len(), 1, "{}: only the newest waits", relay.name);

        p.network.come_online();
        p.outbox
            .drain(&p.transport, &mut p.sessions, at(4000), usize::MAX);

        let received = p.received();
        assert_eq!(received.len(), 1, "{}", relay.name);
        match &received[0] {
            Outcome::Accepted(envelope) => assert_eq!(
                envelope.seq, 59,
                "{}: the current position, not the historical ones",
                relay.name
            ),
            other => panic!("{}: {other:?}", relay.name),
        }
    });
}

#[test]
fn an_sos_queued_behind_a_backlog_goes_out_first() {
    for_each_relay(|relay| {
        let mut p = pair(relay, "outbox-priority");
        let sender_id = p.sender_id.clone();
        p.network.go_offline();

        for seq in 1..=20u64 {
            p.queue(&location(&sender_id, seq), at(seq));
        }
        let alarm = sos(&sender_id, 99);
        p.outbox
            .enqueue(
                &Enqueue {
                    channel: p.channel.clone(),
                    peer: p.peer_id.clone(),
                    plaintext: &alarm,
                    priority: Priority::High,
                    ttl: None,
                    expires_at: None,
                    coalesce_key: None,
                },
                at(100),
            )
            .expect("enqueue");

        // The network returns and the device gets one send's worth of runtime.
        p.network.come_online();
        let report = p.outbox.drain(&p.transport, &mut p.sessions, at(10_000), 1);
        assert_eq!(report.sent.len(), 1, "{}", relay.name);

        let received = p.received();
        assert_eq!(received.len(), 1, "{}", relay.name);
        match &received[0] {
            Outcome::Accepted(envelope) => {
                assert_eq!(
                    envelope.message_type,
                    MessageType::Sos,
                    "{}: the alarm did not wait behind twenty positions",
                    relay.name
                );
            }
            other => panic!("{}: {other:?}", relay.name),
        }
    });
}

#[test]
fn a_backlog_survives_a_restart_during_the_outage() {
    // The sequence a phone actually performs: queue while offline, get killed,
    // come back, drain. All three stores have to survive it; this asserts the
    // outbox's part against a real relay.
    for_each_relay(|relay| {
        let mut p = pair(relay, "outbox-restart");
        let sender_id = p.sender_id.clone();
        p.network.go_offline();
        for seq in 1..=3u64 {
            p.queue(&sos(&sender_id, seq), at(seq));
        }

        let snapshot = p.outbox.export();
        let json = serde_json::to_vec(&snapshot).expect("serialises");
        let read_back: OutboxSnapshot = serde_json::from_slice(&json).expect("deserialises");
        let mut restored = Outbox::import(&read_back).expect("imports");

        p.network.come_online();
        let report = restored.drain(&p.transport, &mut p.sessions, at(10_000), usize::MAX);
        assert_eq!(report.sent.len(), 3, "{}", relay.name);
        assert_eq!(p.received().len(), 3, "{}", relay.name);
    });
}

#[test]
fn a_message_queued_before_a_session_was_re_established_still_lands() {
    // The payoff of sealing at drain rather than at enqueue. The peer reinstalls
    // while this device is offline; a queue of ciphertext would be undeliverable
    // garbage, and a queue of plaintext re-seals under the new session.
    for_each_relay(|relay| {
        let mut p = pair(relay, "outbox-resession");
        let sender_id = p.sender_id.clone();

        p.network.go_offline();
        p.queue(&sos(&sender_id, 1), at(0));

        // The peer reinstalls: a fresh Olm account under the same identity, and a
        // republished bundle. The sender re-learns it, which drops the old
        // session.
        let peer_identity = IdentityKey::from_seed(&[2u8; 32]);
        let mut reinstalled = SessionManager::create(&p.peer_id, peer_identity.clone());
        let bundle = reinstalled.publish_bundle(PUBLISHED).expect("bundle");
        let keys = bundle
            .verify(&p.peer_id, peer_identity.public_key())
            .expect("verify");
        p.sessions.learn_peer(keys);

        // A reinstalled device has to re-learn its peers too — it kept its
        // identity key and nothing else — so it fetches the sender's bundle from
        // the relay exactly as a fresh install would.
        let sender_keys = SignedBundle::decode(
            &p.peer_device
                .fetch_bundle(&sender_id)
                .expect("fetch the sender's bundle")
                .bundle,
        )
        .expect("decode")
        .verify(&sender_id, p.sessions.identity_public_key())
        .expect("verify");
        reinstalled.learn_peer(sender_keys);
        p.peer_sessions = reinstalled;

        p.network.come_online();
        let report = p
            .outbox
            .drain(&p.transport, &mut p.sessions, at(10_000), usize::MAX);
        assert_eq!(
            report.sent.len(),
            1,
            "{}: the queued message re-sealed under the new session",
            relay.name
        );

        let received = p.received();
        assert_eq!(received.len(), 1, "{}", relay.name);
        assert!(
            matches!(received[0], Outcome::Accepted(_)),
            "{}: and the peer could read it",
            relay.name
        );
    });
}

#[test]
fn a_queue_for_a_removed_device_is_dropped_rather_than_retried() {
    // The outbox half of a roster removal. A backlog that kept retrying would be
    // exactly the silent continuation ETHICS.md forbids.
    for_each_relay(|relay| {
        let mut p = pair(relay, "outbox-removed");
        let sender_id = p.sender_id.clone();
        p.network.go_offline();
        for seq in 1..=4u64 {
            p.queue(&location(&sender_id, seq), at(seq));
        }
        assert_eq!(p.outbox.pending_for(&p.peer_id), 4, "{}", relay.name);

        let dropped = p.outbox.forget_peer(&p.peer_id.clone());
        assert_eq!(dropped.len(), 4, "{}", relay.name);
        assert!(
            dropped
                .iter()
                .all(|d| d.reason == DropReason::PeerForgotten),
            "{}",
            relay.name
        );

        p.network.come_online();
        let report = p
            .outbox
            .drain(&p.transport, &mut p.sessions, at(10_000), usize::MAX);
        assert!(report.is_empty(), "{}", relay.name);
        assert!(
            p.received().is_empty(),
            "{}: nothing reaches a removed device",
            relay.name
        );
    });
}

#[test]
fn a_retired_queue_discards_its_backlog_instead_of_delivering_it_stale() {
    for_each_relay(|relay| {
        let mut p = pair(relay, "outbox-retired");
        let sender_id = p.sender_id.clone();
        p.network.go_offline();
        for seq in 1..=3u64 {
            p.queue(&location(&sender_id, seq), at(seq));
        }

        // The peer rotates the queue it drains, which retires the old one
        // server-side. The sender's backlog is addressed to an address that no
        // longer exists.
        p.network.come_online();
        p.peer_transport
            .rotate_inbound(&p.channel, seed())
            .expect("rotate");

        let report = p
            .outbox
            .drain(&p.transport, &mut p.sessions, at(10_000), usize::MAX);
        assert!(report.sent.is_empty(), "{}", relay.name);
        assert_eq!(
            report.dropped.len(),
            3,
            "{}: the whole backlog, not just the entry that discovered it",
            relay.name
        );
        assert!(
            report
                .dropped
                .iter()
                .all(|d| d.reason == DropReason::ChannelRetired),
            "{}",
            relay.name
        );
        assert!(p.outbox.is_empty(), "{}", relay.name);
    });
}

#[test]
fn the_switch_really_does_take_the_network_away() {
    // A test harness that quietly did nothing would make every assertion above
    // vacuous, so the switch itself is asserted against the real relay.
    for_each_relay(|relay| {
        let device = relay.enroll();
        let network = Arc::new(SwitchableHttp::new(relay.http()));
        let switched: Arc<dyn HttpClient> = network.clone();
        let client = SundClient::new(switched, Arc::new(sund_client::agent::SystemStamps));

        assert!(client.health().is_ok(), "{}: online", relay.name);
        network.go_offline();
        assert!(client.health().is_err(), "{}: offline", relay.name);
        network.come_online();
        assert!(client.health().is_ok(), "{}: online again", relay.name);
        drop(device);
    });
}
