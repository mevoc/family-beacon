//! A family that actually forms, against a real relay.
//!
//! Every other leg in this suite wires devices together with test code. This one
//! does not: devices found a family, vouch for each other, adopt rosters, pair on
//! the strength of a vouch, exchange encrypted envelopes, and evict each other —
//! with a real Sund carrying all of it. It is the first test in the repo where
//! the whole client stack runs as a client would run it.
//!
//! Two things only a real server can falsify are the reason it exists:
//!
//! 1. **A device can enroll on the server without being in the family.** The
//!    roster's central claim is that Sund's device list is not the authority on
//!    membership, and the only honest way to test it is to put a device in that
//!    list that nobody vouched for. That is
//!    [`an_enrolled_device_nobody_vouched_for_is_never_admitted`], and it is the
//!    injected-device scenario from `docs/FamilyBeacon-Roster.md` performed
//!    end-to-end rather than described.
//! 2. **The roster is what a fetched bundle gets checked against.** In the
//!    sessions leg the expected identity key came from the test. Here it comes
//!    from `Roster::identity_of`, which is where a shipping client gets it, and a
//!    device that is not an active member yields no key at all.

use std::time::{Duration, SystemTime};

use beacon_protocol::roster::RemovalReason;
use beacon_protocol::{Outcome, receive};
use beacon_roster::records::SelfDescription;
use beacon_roster::roster::{Admission, Removal, Roster, ServerDevice, ServerFinding};
use contract_tests::{Relay, TestDevice, channel_id, for_each_relay, seed};
use sund_client::bundle::SignedBundle;
use sund_client::identity::IdentityKey;
use sund_client::session::SessionManager;
use sund_client::sund_transport::SundTransport;
use sund_client::transport::{ChannelId, Outbound, Transport};

const JOINED: &str = "2026-07-26T10:00:00Z";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_784_000_000)
}

/// One family member: a Sund device, an identity, a roster, sessions and a
/// transport. Everything a phone would hold.
struct Member {
    device: TestDevice,
    identity: IdentityKey,
    roster: Roster,
    sessions: SessionManager,
    transport: SundTransport,
}

impl Member {
    fn id(&self) -> String {
        self.device.device_id().to_owned()
    }

    /// Publish this device's bundle to the relay.
    fn publish(&mut self) {
        let bundle = self
            .sessions
            .publish_bundle(JOINED)
            .expect("build and sign a bundle");
        self.device
            .publish_bundle(&bundle.encode().expect("encode"))
            .expect("publish");
    }

    /// Fetch a peer's bundle and verify it **against the roster's vouched
    /// identity key** — the whole point of the roster existing.
    fn learn(&mut self, peer_id: &str) {
        let expected = self
            .roster
            .identity_of(peer_id)
            .expect("an active member has a vouched identity key");
        let fetched = self.device.fetch_bundle(peer_id).expect("fetch");
        let signed = SignedBundle::decode(&fetched.bundle).expect("decode");
        let keys = signed
            .verify(peer_id, expected)
            .expect("the bundle matches what the family vouched for");
        self.sessions.learn_peer(keys);
    }
}

/// Enroll a device and give it an identity and an empty session manager.
fn enroll(
    relay: &Relay,
    seed_byte: u8,
) -> (TestDevice, IdentityKey, SessionManager, SundTransport) {
    let device = relay.enroll();
    let identity = IdentityKey::from_seed(&[seed_byte; 32]);
    let sessions = SessionManager::create(device.device_id(), identity.clone());
    let transport = SundTransport::new(device.device.clone());
    (device, identity, sessions, transport)
}

/// The founding device of a family.
fn found(relay: &Relay, seed_byte: u8) -> Member {
    let (device, identity, sessions, transport) = enroll(relay, seed_byte);
    let description = SelfDescription {
        device_id: device.device_id().to_owned(),
        display_name: "founder's phone".to_owned(),
        member_group: "founder".to_owned(),
        role: "adult".to_owned(),
        joined_at: JOINED.to_owned(),
    };
    let roster = Roster::found(&description, &identity).outcome;
    let mut member = Member {
        device,
        identity,
        roster,
        sessions,
        transport,
    };
    member.publish();
    member
}

/// Run the join ceremony: `introducer` vouches for a newly enrolled device, which
/// adopts the introducer's roster. This is `docs/FamilyBeacon-Roster.md` →
/// Admission, steps 1–2 and 6, with Sund's invitation standing in for the QR.
fn join(relay: &Relay, introducer: &mut Member, seed_byte: u8) -> Member {
    let (device, identity, sessions, transport) = enroll(relay, seed_byte);
    let description = SelfDescription {
        device_id: device.device_id().to_owned(),
        display_name: format!("{}'s phone", device.device_id()),
        member_group: device.device_id().to_owned(),
        role: "adult".to_owned(),
        joined_at: JOINED.to_owned(),
    };
    let subject = description.subject(identity.public_key().to_base64());

    // The introducer vouches, and admits the joiner to its own roster.
    let vouch = introducer
        .roster
        .vouch_for(&subject, &introducer.identity)
        .expect("vouch");
    assert_eq!(
        introducer
            .roster
            .receive_introduce(&vouch, &introducer.id(), now())
            .outcome,
        Admission::Admitted
    );

    // The joiner adopts the introducer's roster. Physical co-presence — here, the
    // single-use invitation — is what authenticates the introducer's record.
    let introducer_record = introducer
        .roster
        .record(&introducer.id())
        .expect("the introducer knows itself")
        .clone();
    let adopted = Roster::adopt(
        device.device_id(),
        &introducer_record,
        introducer
            .roster
            .active()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>(),
        introducer
            .roster
            .tombstones()
            .into_iter()
            .cloned()
            .collect::<Vec<_>>(),
        introducer.roster.epoch(),
        &vouch,
    )
    .expect("adopt the introducer's roster");

    let mut member = Member {
        device,
        identity,
        roster: adopted.outcome,
        sessions,
        transport,
    };
    member.publish();
    member
}

/// Establish the duplex channel between two members and open sessions both ways.
///
/// The address exchange is the grant-only relay of
/// `docs/FamilyBeacon-Roster.md` steps 5a–5c collapsed into test code: each side
/// mints the queue it drains and the ids are handed over. What is *not* collapsed
/// is the key verification — that goes through the roster.
fn pair(a: &mut Member, b: &mut Member, channel: &ChannelId) {
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

    let (a_id, b_id) = (a.id(), b.id());
    a.learn(&b_id);
    b.learn(&a_id);
}

/// Send one already-encoded plaintext from `from` to `to` and return what the
/// receiver's protocol layer concluded.
fn exchange(from: &mut Member, to: &mut Member, channel: &ChannelId, plaintext: &[u8]) -> Outcome {
    let to_id = to.id();
    let frame = from.sessions.encrypt(&to_id, plaintext).expect("encrypt");
    from.transport
        .send(channel, Outbound::new(frame))
        .expect("send");

    let from_id = from.id();
    let mut subscription = to.transport.subscribe(channel).expect("subscribe");
    let delivery = subscription
        .next_delivery()
        .expect("next delivery")
        .expect("a frame arrived");
    drop(subscription);
    to.transport
        .acknowledge_all(channel, &[delivery.id])
        .expect("ack");

    let decrypted = to
        .sessions
        .decrypt(&from_id, &delivery.ciphertext)
        .expect("decrypt");
    receive(&decrypted.plaintext, &decrypted.authenticated_sender).outcome
}

fn member_info(sender: &str, seq: u64) -> Vec<u8> {
    format!(
        r#"{{"v":1,"id":"m-{seq}","seq":{seq},"type":"member_info",
             "sent":"2026-07-26T10:04:12Z","sender":"{sender}",
             "body":{{"display_name":"Emma's phone"}}}}"#
    )
    .into_bytes()
}

#[test]
fn a_family_forms_and_its_members_can_talk() {
    for_each_relay(|relay| {
        let mut alice = found(relay, 1);
        let mut bob = join(relay, &mut alice, 2);

        assert_eq!(alice.roster.active_count(), 2, "{}", relay.name);
        assert_eq!(bob.roster.active_count(), 2, "{}", relay.name);
        assert!(bob.roster.is_active(&alice.id()));
        assert_eq!(
            bob.roster
                .record(&bob.id())
                .expect("own record")
                .introduced_by,
            alice.id(),
            "{}: the joiner's record names who vouched",
            relay.name
        );

        let channel = channel_id("family-talk");
        pair(&mut alice, &mut bob, &channel);

        let alice_id = alice.id();
        let outcome = exchange(&mut alice, &mut bob, &channel, &member_info(&alice_id, 1));
        assert!(
            matches!(outcome, Outcome::Accepted(_)),
            "{}: {outcome:?}",
            relay.name
        );
    });
}

#[test]
fn a_bundle_is_verified_against_the_roster_not_the_server() {
    // The integration point that matters: the expected identity key comes from
    // `Roster::identity_of`, and a device the roster does not carry as active
    // yields none — so there is no path from "the server lists it" to key
    // material a client will use.
    for_each_relay(|relay| {
        let mut alice = found(relay, 1);
        let bob = join(relay, &mut alice, 2);

        assert_eq!(
            alice.roster.identity_of(&bob.id()).expect("vouched key"),
            bob.identity.public_key(),
            "{}",
            relay.name
        );

        // A device that enrolled on the same server but joined no family.
        let outsider = relay.enroll();
        assert!(
            alice.roster.identity_of(outsider.device_id()).is_none(),
            "{}: enrolling is not joining",
            relay.name
        );
    });
}

#[test]
fn an_enrolled_device_nobody_vouched_for_is_never_admitted() {
    // The injected-device scenario, performed rather than described. A host that
    // can write to Sund's database can put a device in the account; this asserts
    // that every family member sees it as an anomaly and none of them pairs with
    // it. Enrolling through an invitation is the *stronger* version of the
    // attack — the device is genuinely in the account, not merely claimed.
    for_each_relay(|relay| {
        let mut alice = found(relay, 1);
        let bob = join(relay, &mut alice, 2);
        let injected = relay.enroll();

        let listed: Vec<ServerDevice> = alice
            .device
            .list_devices()
            .expect("list devices")
            .into_iter()
            .map(|record| ServerDevice {
                device_id: record.id,
                revoked: record.revoked,
            })
            .collect();
        assert!(
            listed.iter().any(|d| d.device_id == injected.device_id()),
            "{}: precondition — the injected device really is in the account",
            relay.name
        );

        let applied = alice.roster.reconcile_server_list(&listed);
        assert!(
            applied.outcome.contains(&ServerFinding::Unvouched {
                device_id: injected.device_id().to_owned()
            }),
            "{}: an unvouched device must be surfaced, not admitted",
            relay.name
        );
        assert!(
            !alice.roster.is_active(injected.device_id()),
            "{}",
            relay.name
        );
        assert!(
            alice.roster.identity_of(injected.device_id()).is_none(),
            "{}: and no key material is handed out for it",
            relay.name
        );

        // Bob reaches the same conclusion independently, which is what makes it
        // visible to the *family* rather than to one device.
        assert!(
            !bob.roster.is_active(injected.device_id()),
            "{}",
            relay.name
        );
        assert!(
            applied
                .ledger
                .iter()
                .any(|entry| entry.event
                    == beacon_protocol::ledger::LedgerEvent::UnvouchedDeviceListed),
            "{}: and it is ledgered",
            relay.name
        );
    });
}

#[test]
fn a_third_member_is_admitted_on_a_vouch_carried_end_to_end() {
    // Step 3 of admission over a real encrypted channel: Alice vouches for Carol,
    // and Bob — who has never met Carol — admits her because the vouch verifies
    // against the key Bob already holds for Alice.
    for_each_relay(|relay| {
        let mut alice = found(relay, 1);
        let mut bob = join(relay, &mut alice, 2);
        let channel = channel_id("vouch-broadcast");
        pair(&mut alice, &mut bob, &channel);

        // Carol enrolls and Alice vouches for her.
        let (carol_device, carol_identity, _sessions, _transport) = enroll(relay, 3);
        let carol_description = SelfDescription {
            device_id: carol_device.device_id().to_owned(),
            display_name: "Carol's phone".to_owned(),
            member_group: "Carol".to_owned(),
            role: "child".to_owned(),
            joined_at: JOINED.to_owned(),
        };
        let subject = carol_description.subject(carol_identity.public_key().to_base64());
        let vouch = alice
            .roster
            .vouch_for(&subject, &alice.identity)
            .expect("vouch");
        alice.roster.receive_introduce(&vouch, &alice.id(), now());

        // The vouch travels to Bob inside an encrypted envelope.
        let alice_id = alice.id();
        let envelope = format!(
            r#"{{"v":1,"id":"intro-1","seq":9,"type":"roster_introduce",
                 "sent":"2026-07-26T10:05:00Z","sender":"{alice_id}","body":{}}}"#,
            serde_json::to_string(&vouch).expect("serialise the vouch")
        );
        let outcome = exchange(&mut alice, &mut bob, &channel, envelope.as_bytes());
        let body = match outcome {
            Outcome::Accepted(envelope) => envelope.body,
            other => panic!("{}: expected Accepted, got {other:?}", relay.name),
        };

        let carried: beacon_protocol::roster::RosterIntroduce =
            serde_json::from_value(body).expect("the vouch survived the round trip");
        let applied = bob.roster.receive_introduce(&carried, &alice_id, now());
        assert_eq!(applied.outcome, Admission::Admitted, "{}", relay.name);
        assert!(bob.roster.is_active(carol_device.device_id()));
        assert_eq!(
            bob.roster
                .identity_of(carol_device.device_id())
                .expect("key"),
            carol_identity.public_key(),
            "{}: Bob can now verify Carol's bundle without ever meeting her",
            relay.name
        );
    });
}

#[test]
fn a_removal_travels_and_takes_the_server_side_with_it() {
    // The "stronger implementation" the layering promises: the tombstone is the
    // client-side half, and Sund's revoke is the half that locks the device out.
    for_each_relay(|relay| {
        let mut alice = found(relay, 1);
        let mut bob = join(relay, &mut alice, 2);
        let channel = channel_id("removal");
        pair(&mut alice, &mut bob, &channel);

        // Alice removes Bob, locally and on the server.
        let removal = alice
            .roster
            .remove(
                &bob.id(),
                RemovalReason::Lost,
                "2026-07-26T11:00:00Z",
                &alice.identity,
                now(),
            )
            .expect("removal");
        assert_eq!(alice.roster.epoch(), 1, "{}", relay.name);
        assert!(!alice.roster.is_active(&bob.id()));

        alice
            .device
            .revoke_device(&bob.id())
            .expect("the server-side half");

        // Bob is told, over the channel that still exists at the moment of
        // sending. He records it without erasing his own record.
        let alice_id = alice.id();
        let applied = bob
            .roster
            .receive_remove(&removal.outcome, &alice_id, now());
        assert_eq!(applied.outcome, Removal::AboutSelf, "{}", relay.name);
        assert_eq!(bob.roster.removed_me_by(), vec![alice_id.as_str()]);

        // And the server really has locked him out.
        assert!(
            bob.device.list_devices().is_err(),
            "{}: a revoked device's signed requests fail from that moment",
            relay.name
        );

        // Alice's own view agrees with the server's.
        let listed: Vec<ServerDevice> = alice
            .device
            .list_devices()
            .expect("list")
            .into_iter()
            .map(|record| ServerDevice {
                device_id: record.id,
                revoked: record.revoked,
            })
            .collect();
        // Bob is revoked on the server *and* tombstoned in the roster, so the two
        // agree and there is nothing to report about him. In particular he is not
        // an `Unvouched` finding: that variant means "a device exists that nobody
        // vouched for", and Bob was vouched for — he was then removed, which is a
        // different sentence entirely.
        //
        // Asserted about Bob rather than about the whole list, because this suite
        // shares one Sund account across every leg: devices enrolled by other
        // tests are genuinely unvouched from Alice's point of view, and reporting
        // them is the roster behaving correctly.
        let bob_id = bob.id();
        let findings = alice.roster.reconcile_server_list(&listed);
        assert!(
            !findings.outcome.iter().any(|finding| matches!(
                finding,
                ServerFinding::Unvouched { device_id } if *device_id == bob_id
            )),
            "{}: a removed member is not an injected device",
            relay.name
        );
        assert!(
            alice.roster.tombstone(&bob_id).is_some(),
            "{}: the tombstone is what says why he is gone",
            relay.name
        );
    });
}

#[test]
fn a_removed_member_can_no_longer_be_learned_or_addressed() {
    // The session layer's half of a removal: once the roster stops carrying a
    // device as active, there is no key to verify its bundle against, so the
    // pairing path closes on its own rather than by a separate check.
    for_each_relay(|relay| {
        let mut alice = found(relay, 1);
        let bob = join(relay, &mut alice, 2);

        alice
            .roster
            .remove(
                &bob.id(),
                RemovalReason::Removed,
                "2026-07-26T11:00:00Z",
                &alice.identity,
                now(),
            )
            .expect("removal");

        assert!(
            alice.roster.identity_of(&bob.id()).is_none(),
            "{}: no vouched key means no verifiable bundle",
            relay.name
        );
        // The bundle is still *served* — Sund does not know about the roster —
        // which is precisely why the check lives on the client.
        assert!(
            alice.device.fetch_bundle(&bob.id()).is_ok(),
            "{}: the server still has it, and that is not what decides",
            relay.name
        );
    });
}

#[test]
fn roster_state_survives_a_restart_beside_the_other_two_stores() {
    // Three layers, three stores, all of which an app must persist together: the
    // roster, the sessions and the channels. This asserts the roster's part
    // against a relay so the sequence is the real one.
    for_each_relay(|relay| {
        let mut alice = found(relay, 1);
        let bob = join(relay, &mut alice, 2);

        let snapshot = alice.roster.export();
        let json = serde_json::to_vec(&snapshot).expect("serialises");
        let read_back = serde_json::from_slice(&json).expect("deserialises");
        let restored = Roster::import(&read_back, &alice.id()).expect("imports");

        assert_eq!(restored, alice.roster, "{}", relay.name);
        assert_eq!(
            restored.identity_of(&bob.id()).expect("key"),
            bob.identity.public_key(),
            "{}: a restored roster can still verify bundles",
            relay.name
        );
    });
}
