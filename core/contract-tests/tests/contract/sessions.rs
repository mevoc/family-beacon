//! Session crypto against a real relay: bundles through Sund's dead drop, and
//! an envelope that comes back out of a real queue as plaintext.
//!
//! This is the leg that makes `docs/FamilyBeacon-Sessions.md` more than a
//! design. Everything the unit tests assert about the ratchet holds against an
//! in-memory transport by construction; what only a real Sund can prove is that
//! the *dead drop* behaves like one — that a bundle published through
//! `PUT /v1/me/bundle` comes back byte-identical from
//! `GET /v1/devices/{id}/bundle`, that the server neither interprets nor
//! normalises it, and that a revoked device's bundle stops being served.
//!
//! The other reason this leg exists is that it drives the entire stack in one
//! test: `beacon-protocol` builds an envelope, the session layer seals it, a
//! real Sund queue carries it, and the receiving side hands
//! `beacon_protocol::receive` an `authenticated_sender` that came from the
//! session rather than from the message. Nothing is mocked between the two
//! envelopes.
//!
//! Where the roster would sit, these tests substitute the test's own knowledge:
//! `verify` is called with the identity key the peer actually holds, which in a
//! shipping client arrives in a signed vouch (`docs/FamilyBeacon-Roster.md`).
//! That substitution is the *only* thing standing in for a real component here,
//! and it stands in for the one component that does not exist yet.

use beacon_protocol::envelope::MessageType;
use beacon_protocol::{Outcome, receive};
use contract_tests::{Relay, TestDevice, channel_id, for_each_relay, seed};
use sund_client::bundle::SignedBundle;
use sund_client::client::SundError;
use sund_client::identity::IdentityKey;
use sund_client::session::SessionManager;
use sund_client::session_store::{export, import};
use sund_client::sund_transport::SundTransport;
use sund_client::transport::{ChannelId, Outbound, Transport};

const PICKLE_KEY: [u8; 32] = [7u8; 32];

/// One end of a conversation: an enrolled device, its session state, and the
/// transport it talks through.
struct Member {
    device: TestDevice,
    sessions: SessionManager,
    transport: SundTransport,
    identity: IdentityKey,
}

impl Member {
    fn id(&self) -> String {
        self.device.device_id().to_owned()
    }
}

/// Enroll a device and give it an identity key and a session manager.
fn member(relay: &Relay, identity_seed: u8) -> Member {
    let device = relay.enroll();
    let identity = IdentityKey::from_seed(&[identity_seed; 32]);
    let sessions = SessionManager::create(device.device_id(), identity.clone());
    let transport = SundTransport::new(device.device.clone());
    Member {
        device,
        sessions,
        transport,
        identity,
    }
}

/// Publish `member`'s bundle to the relay, exactly as a client would.
fn publish(member: &mut Member) -> SignedBundle {
    let bundle = member
        .sessions
        .publish_bundle("2026-07-26T10:00:00Z")
        .expect("build and sign a bundle");
    member
        .device
        .publish_bundle(&bundle.encode().expect("encode"))
        .expect("publish to the relay");
    bundle
}

/// Fetch `peer`'s bundle through the relay and verify it against the identity
/// key the roster would have vouched for.
fn fetch_and_learn(learner: &mut Member, peer: &Member) {
    let fetched = learner
        .device
        .fetch_bundle(&peer.id())
        .expect("fetch the peer's bundle");
    let signed = SignedBundle::decode(&fetched.bundle).expect("decode what the relay served");
    let keys = signed
        .verify(&peer.id(), peer.identity.public_key())
        .expect("the bundle verifies against the vouched identity");
    learner.sessions.learn_peer(keys);
}

/// A duplex channel between two members: Walkthrough 2, minus the QR.
fn pair_channel(a: &Member, b: &Member, channel: &ChannelId) {
    a.transport.declare(channel, seed());
    a.transport.open(channel).expect("a's queue");
    b.transport.declare(channel, seed());
    b.transport.open(channel).expect("b's queue");

    let a_ids = a.transport.inbound(channel).expect("a's ids");
    let b_ids = b.transport.inbound(channel).expect("b's ids");
    a.transport
        .attach_outbound(channel, b_ids.sender_id, seed())
        .expect("a sends to b");
    b.transport
        .attach_outbound(channel, a_ids.sender_id, seed())
        .expect("b sends to a");
}

/// Two members who have published, verified and paired — the state the roster
/// hands the session layer at the end of a join.
fn conversing(relay: &Relay, channel: &ChannelId) -> (Member, Member) {
    let mut a = member(relay, 1);
    let mut b = member(relay, 2);
    publish(&mut a);
    publish(&mut b);
    fetch_and_learn(&mut a, &b);
    fetch_and_learn(&mut b, &a);
    pair_channel(&a, &b, channel);
    (a, b)
}

/// Drain one channel and hand every frame to the session layer, acknowledging
/// as it goes.
fn drain_decrypt(reader: &mut Member, sender_id: &str, channel: &ChannelId) -> Vec<Vec<u8>> {
    let mut subscription = reader.transport.subscribe(channel).expect("subscribe");
    let mut ids = Vec::new();
    let mut frames = Vec::new();
    while let Some(delivery) = subscription.next_delivery().expect("next delivery") {
        ids.push(delivery.id);
        frames.push(delivery.ciphertext);
    }
    drop(subscription);

    let out = frames
        .iter()
        .map(|frame| {
            let decrypted = reader
                .sessions
                .decrypt(sender_id, frame)
                .expect("decrypt a frame that came off a real queue");
            assert_eq!(
                decrypted.authenticated_sender, sender_id,
                "the session names the channel's owner as the sender"
            );
            decrypted.plaintext
        })
        .collect();

    if !ids.is_empty() {
        reader
            .transport
            .acknowledge_all(channel, &ids)
            .expect("ack what was drained");
    }
    out
}

fn location_envelope(sender: &str, seq: u64) -> Vec<u8> {
    let json = format!(
        r#"{{"v":1,"id":"contract-{seq}","seq":{seq},"type":"location",
             "sent":"2026-07-26T10:04:12Z","sender":"{sender}",
             "body":{{"lat":56,"lon":12,"accuracy_m":12,
                      "recorded_at":"2026-07-26T10:04:10Z"}}}}"#
    );
    json.into_bytes()
}

#[test]
fn a_published_bundle_comes_back_byte_identical() {
    // Sund's Architecture Principle in one assertion: the bundle store is a
    // dead drop. If the server ever parsed, re-encoded or normalised the blob,
    // every signature over it would break — and it would break here first.
    for_each_relay(|relay| {
        let mut alice = member(relay, 1);
        let published = publish(&mut alice);
        let expected = published.encode().expect("encode");

        let bob = member(relay, 2);
        let fetched = bob
            .device
            .fetch_bundle(&alice.id())
            .expect("fetch alice's bundle");

        assert_eq!(
            fetched.bundle, expected,
            "{}: the relay must serve the exact bytes it was given",
            relay.name
        );
        assert!(
            fetched.updated.is_some(),
            "{}: the relay reports when the bundle was stored",
            relay.name
        );
    });
}

#[test]
fn a_bundle_fetched_through_the_relay_verifies_against_the_vouched_identity() {
    for_each_relay(|relay| {
        let mut alice = member(relay, 1);
        publish(&mut alice);
        let bob = member(relay, 2);

        let fetched = bob.device.fetch_bundle(&alice.id()).expect("fetch");
        let signed = SignedBundle::decode(&fetched.bundle).expect("decode");

        let keys = signed
            .verify(&alice.id(), alice.identity.public_key())
            .unwrap_or_else(|e| panic!("{}: {e}", relay.name));
        assert_eq!(keys.device_id, alice.id());
        assert_eq!(
            keys.curve25519,
            alice.sessions.curve25519_key(),
            "{}: the key material is alice's own",
            relay.name
        );

        // And the case that matters: the same bytes, checked against an identity
        // key the family never vouched for, must not verify. This is what a
        // dishonest host's injected device looks like from the client side.
        let attacker = IdentityKey::from_seed(&[0xEE; 32]);
        assert!(
            signed.verify(&alice.id(), attacker.public_key()).is_err(),
            "{}: a bundle must not verify against an unvouched identity",
            relay.name
        );
    });
}

#[test]
fn an_envelope_survives_the_whole_stack() {
    // envelope → session → real Sund queue → session → envelope, with the
    // sender attributed by the session layer rather than by the message.
    for_each_relay(|relay| {
        let channel = channel_id("session-envelope");
        let (mut alice, mut bob) = conversing(relay, &channel);
        let alice_id = alice.id();

        let plaintext = location_envelope(&alice_id, 412);
        let frame = alice
            .sessions
            .encrypt(&bob.id(), &plaintext)
            .expect("encrypt");

        // Nothing recognisable crosses the relay.
        assert_ne!(frame, plaintext, "{}", relay.name);
        assert!(
            !String::from_utf8_lossy(&frame).contains("location"),
            "{}: the message type must not be visible on the wire",
            relay.name
        );

        alice
            .transport
            .send(&channel, Outbound::new(frame))
            .expect("send through the relay");

        let received = drain_decrypt(&mut bob, &alice_id, &channel);
        assert_eq!(received.len(), 1, "{}", relay.name);

        // The receive path, driven with the sender the *session* authenticated.
        let reception = receive(&received[0], &alice_id);
        match &reception.outcome {
            Outcome::Accepted(envelope) => {
                assert_eq!(envelope.message_type, MessageType::Location);
                assert_eq!(envelope.seq, 412);
                assert_eq!(envelope.sender, alice_id);
            }
            other => panic!("{}: expected Accepted, got {other:?}", relay.name),
        }
        assert_eq!(reception.ledger.peer, alice_id);
    });
}

#[test]
fn a_forged_sender_is_caught_after_decryption() {
    // The envelope's `sender` is attribution, not trust. A member who lies about
    // it in a message that is otherwise perfectly encrypted must be rejected —
    // and the rejection is what reaches the ledger.
    for_each_relay(|relay| {
        let channel = channel_id("session-forgery");
        let (mut alice, mut bob) = conversing(relay, &channel);
        let alice_id = alice.id();

        let lying = location_envelope("dev_SOMEONE_ELSE", 1);
        let frame = alice.sessions.encrypt(&bob.id(), &lying).expect("encrypt");
        alice
            .transport
            .send(&channel, Outbound::new(frame))
            .expect("send");

        let received = drain_decrypt(&mut bob, &alice_id, &channel);
        let reception = receive(&received[0], &alice_id);
        assert!(
            matches!(reception.outcome, Outcome::Rejected(_)),
            "{}: a forged sender must be rejected",
            relay.name
        );
    });
}

#[test]
fn a_conversation_ratchets_in_both_directions_through_the_relay() {
    for_each_relay(|relay| {
        let channel = channel_id("session-ratchet");
        let (mut alice, mut bob) = conversing(relay, &channel);
        let (alice_id, bob_id) = (alice.id(), bob.id());

        for seq in 1..=3u64 {
            let frame = alice
                .sessions
                .encrypt(&bob_id, &location_envelope(&alice_id, seq))
                .expect("alice encrypts");
            alice
                .transport
                .send(&channel, Outbound::new(frame))
                .expect("alice sends");
            let got = drain_decrypt(&mut bob, &alice_id, &channel);
            assert_eq!(got.len(), 1, "{}: round {seq}", relay.name);

            let reply = bob
                .sessions
                .encrypt(&alice_id, &location_envelope(&bob_id, seq))
                .expect("bob encrypts");
            bob.transport
                .send(&channel, Outbound::new(reply))
                .expect("bob sends");
            let back = drain_decrypt(&mut alice, &bob_id, &channel);
            assert_eq!(back.len(), 1, "{}: round {seq} reply", relay.name);
        }
    });
}

#[test]
fn session_state_survives_a_restart_alongside_channel_state() {
    // Two stores, written by two layers, restored independently: the app layer
    // has to persist both, and neither is any use without the other. Worth one
    // real-relay test because it is the sequence a phone actually performs on
    // every cold start.
    for_each_relay(|relay| {
        let channel = channel_id("session-restart");
        let (mut alice, mut bob) = conversing(relay, &channel);
        let (alice_id, bob_id) = (alice.id(), bob.id());

        // Open the session, then send something that will still be queued when
        // Bob "restarts".
        let opener = alice
            .sessions
            .encrypt(&bob_id, &location_envelope(&alice_id, 1))
            .expect("encrypt");
        alice
            .transport
            .send(&channel, Outbound::new(opener))
            .expect("send");
        assert_eq!(drain_decrypt(&mut bob, &alice_id, &channel).len(), 1);

        let in_flight = alice
            .sessions
            .encrypt(&bob_id, &location_envelope(&alice_id, 2))
            .expect("encrypt");
        alice
            .transport
            .send(&channel, Outbound::new(in_flight))
            .expect("send");

        // Bob's process dies. Both layers export; both come back.
        let session_store = export(&bob.sessions, &PICKLE_KEY);
        let channel_store = bob.transport.export();

        let restarted_transport = SundTransport::new(bob.device.device.clone());
        restarted_transport.import(channel_store);
        let restarted_sessions = import(
            &session_store,
            &bob_id,
            IdentityKey::from_seed(&[2u8; 32]),
            &PICKLE_KEY,
        )
        .expect("import the session store");

        let mut restarted = Member {
            device: bob.device,
            sessions: restarted_sessions,
            transport: restarted_transport,
            identity: bob.identity,
        };

        let received = drain_decrypt(&mut restarted, &alice_id, &channel);
        assert_eq!(received.len(), 1, "{}", relay.name);
        let reception = receive(&received[0], &alice_id);
        match &reception.outcome {
            Outcome::Accepted(envelope) => assert_eq!(envelope.seq, 2),
            other => panic!("{}: expected Accepted, got {other:?}", relay.name),
        }
    });
}

#[test]
fn a_session_is_unaffected_by_the_queue_underneath_it_rotating() {
    // The seam working as intended: queue rotation is a transport concern, and
    // the ratchet must neither notice nor need re-establishing. If these ever
    // become coupled, `docs/FamilyBeacon-Sessions.md`'s layering claim is wrong.
    for_each_relay(|relay| {
        let channel = channel_id("session-rotation");
        let (mut alice, mut bob) = conversing(relay, &channel);
        let (alice_id, bob_id) = (alice.id(), bob.id());

        let first = alice
            .sessions
            .encrypt(&bob_id, &location_envelope(&alice_id, 1))
            .expect("encrypt");
        alice
            .transport
            .send(&channel, Outbound::new(first))
            .expect("send");
        assert_eq!(drain_decrypt(&mut bob, &alice_id, &channel).len(), 1);

        // Bob rotates the queue he drains and tells Alice the new address.
        let fresh = bob
            .transport
            .rotate_inbound(&channel, seed())
            .expect("rotate");
        alice
            .transport
            .attach_outbound(&channel, fresh.sender_id, seed())
            .expect("attach");

        let after = alice
            .sessions
            .encrypt(&bob_id, &location_envelope(&alice_id, 2))
            .expect("encrypt");
        alice
            .transport
            .send(&channel, Outbound::new(after))
            .expect("send after rotation");

        let received = drain_decrypt(&mut bob, &alice_id, &channel);
        assert_eq!(received.len(), 1, "{}", relay.name);
        let reception = receive(&received[0], &alice_id);
        match &reception.outcome {
            Outcome::Accepted(envelope) => assert_eq!(
                envelope.seq, 2,
                "{}: the same session continued across the rotation",
                relay.name
            ),
            other => panic!("{}: expected Accepted, got {other:?}", relay.name),
        }
    });
}

#[test]
fn a_rotated_bundle_replaces_the_published_one_without_disturbing_the_session() {
    // Weekly fallback rotation, through the relay. Peers re-fetch and re-learn;
    // an established ratchet must not care.
    for_each_relay(|relay| {
        let channel = channel_id("session-fallback");
        let (mut alice, mut bob) = conversing(relay, &channel);
        let (alice_id, bob_id) = (alice.id(), bob.id());

        let opener = alice
            .sessions
            .encrypt(&bob_id, &location_envelope(&alice_id, 1))
            .expect("encrypt");
        alice
            .transport
            .send(&channel, Outbound::new(opener))
            .expect("send");
        assert_eq!(drain_decrypt(&mut bob, &alice_id, &channel).len(), 1);

        let before = alice
            .device
            .fetch_bundle(&alice_id)
            .expect("fetch own bundle");

        let rotated = alice
            .sessions
            .rotate_fallback_key("2026-08-02T10:00:00Z")
            .expect("rotate");
        alice
            .device
            .publish_bundle(&rotated.encode().expect("encode"))
            .expect("republish");

        let after = bob
            .device
            .fetch_bundle(&alice_id)
            .expect("fetch the rotated bundle");
        assert_ne!(
            after.bundle, before.bundle,
            "{}: rotation must change the published bytes",
            relay.name
        );

        // Bob re-learns and the conversation continues on the same session.
        fetch_and_learn(&mut bob, &alice);
        let next = alice
            .sessions
            .encrypt(&bob_id, &location_envelope(&alice_id, 2))
            .expect("encrypt");
        alice
            .transport
            .send(&channel, Outbound::new(next))
            .expect("send");

        let received = drain_decrypt(&mut bob, &alice_id, &channel);
        assert_eq!(received.len(), 1, "{}", relay.name);
    });
}

#[test]
fn a_revoked_devices_bundle_stops_being_served() {
    // Sund's revocation clears the bundle, which is the server-side half of a
    // roster removal — the stronger implementation `docs/FamilyBeacon-TryMode.md`
    // says Sund mode should also use, not rely on alone.
    for_each_relay(|relay| {
        let mut doomed = member(relay, 3);
        publish(&mut doomed);
        let doomed_id = doomed.id();

        let observer = member(relay, 4);
        observer
            .device
            .fetch_bundle(&doomed_id)
            .expect("the bundle is served before revocation");

        relay
            .founder()
            .revoke_device(&doomed_id)
            .expect("revoke the device");

        assert!(
            matches!(
                observer.device.fetch_bundle(&doomed_id),
                Err(SundError::NotFound)
            ),
            "{}: a revoked device's bundle must stop being served",
            relay.name
        );
    });
}

#[test]
fn a_bundle_over_sunds_cap_is_refused_by_the_relay() {
    // Ours is a couple of hundred bytes, so this asserts the cap is where the
    // client believes it is rather than testing our own format.
    for_each_relay(|relay| {
        let device = relay.enroll();
        let oversized = vec![b'x'; 9 * 1024];
        assert!(
            device.publish_bundle(&oversized).is_err(),
            "{}: the relay must refuse an oversized bundle",
            relay.name
        );
    });
}

#[test]
fn a_device_that_published_nothing_is_indistinguishable_from_one_that_does_not_exist() {
    // Sund deliberately does not say which. Worth pinning, because a client that
    // treated the two differently would leak the device list to a peer.
    for_each_relay(|relay| {
        let silent = relay.enroll();
        let observer = relay.enroll();

        let unpublished = observer.fetch_bundle(silent.device_id());
        let nonexistent = observer.fetch_bundle("dev_does_not_exist");
        assert!(
            matches!(unpublished, Err(SundError::NotFound)),
            "{}: a device with no bundle is NotFound",
            relay.name
        );
        assert!(
            matches!(nonexistent, Err(SundError::NotFound)),
            "{}: an unknown device is NotFound",
            relay.name
        );
    });
}

#[test]
fn an_envelope_from_an_unlearned_peer_is_refused_rather_than_attributed() {
    // The session layer's half of "the server's device list is not the authority
    // on membership": a device that enrolled and paired can still not be
    // attributed until a verified bundle has been learned for it.
    for_each_relay(|relay| {
        let channel = channel_id("session-stranger");
        let mut alice = member(relay, 1);
        let mut stranger = member(relay, 5);
        publish(&mut alice);
        publish(&mut stranger);

        // The stranger learns Alice and can encrypt to her; Alice never learned
        // the stranger.
        fetch_and_learn(&mut stranger, &alice);
        pair_channel(&alice, &stranger, &channel);

        let frame = stranger
            .sessions
            .encrypt(&alice.id(), &location_envelope(&stranger.id(), 1))
            .expect("the stranger can encrypt");
        stranger
            .transport
            .send(&channel, Outbound::new(frame))
            .expect("and send");

        let mut subscription = alice.transport.subscribe(&channel).expect("subscribe");
        let delivery = subscription
            .next_delivery()
            .expect("next delivery")
            .expect("a frame arrived");
        drop(subscription);

        assert!(
            alice
                .sessions
                .decrypt(&stranger.id(), &delivery.ciphertext)
                .is_err(),
            "{}: an unlearned peer must not be decryptable",
            relay.name
        );
    });
}
