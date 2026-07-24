//! The transport port's promises, asserted twice: once against the in-memory
//! transport the unit tests use, once against real Sund queues.
//!
//! This is the point of having a port at all. `docs/FamilyBeacon-TryMode.md`
//! defers the second *shipping* backend but fixes the seam now, and a seam with
//! one set of assertions applied to every implementation is what stops the port
//! from quietly meaning "whatever Sund happens to do". When `ntfy-client`
//! arrives it joins this function, not a new one.

use contract_tests::{Relay, channel_id, for_each_relay, seed};
use sund_client::memory::MemoryTransport;
use sund_client::sund_transport::SundTransport;
use sund_client::transport::{ChannelId, Outbound, Priority, Transport, TransportError};

/// Two endpoints of one channel: what `a` sends, `b` reads.
struct Pair {
    a: Box<dyn Transport>,
    b: Box<dyn Transport>,
    channel: ChannelId,
    /// A channel id that no endpoint has ever declared or opened.
    unknown: ChannelId,
}

fn drain(transport: &dyn Transport, channel: &ChannelId) -> Vec<(String, Vec<u8>)> {
    let mut subscription = transport.subscribe(channel).expect("subscribe");
    let mut out = Vec::new();
    while let Some(delivery) = subscription.next_delivery().expect("next delivery") {
        out.push((delivery.id, delivery.ciphertext));
    }
    out
}

/// Everything the port promises, in the vocabulary of the port alone.
fn assert_port_contract(name: &str, pair: &Pair) {
    let Pair {
        a,
        b,
        channel,
        unknown,
    } = pair;

    // 1. A message crosses, unchanged.
    a.send(channel, Outbound::new(b"one".to_vec()))
        .unwrap_or_else(|e| panic!("{name}: send: {e}"));
    let first = drain(b.as_ref(), channel);
    assert_eq!(first.len(), 1, "{name}: one message was sent");
    assert_eq!(first[0].1, b"one", "{name}: ciphertext is carried verbatim");

    // 2. Delivery is at-least-once: unacknowledged means undelivered.
    let repeat = drain(b.as_ref(), channel);
    assert_eq!(
        repeat.len(),
        1,
        "{name}: an unacknowledged message must come back"
    );
    b.ack(channel, &first[0].0)
        .unwrap_or_else(|e| panic!("{name}: ack: {e}"));
    assert!(
        drain(b.as_ref(), channel).is_empty(),
        "{name}: an acknowledged message must not come back"
    );

    // 3. Order holds within a channel.
    for n in 0u8..5 {
        a.send(channel, Outbound::new(vec![n]))
            .unwrap_or_else(|e| panic!("{name}: send {n}: {e}"));
    }
    let ordered = drain(b.as_ref(), channel);
    let payloads: Vec<u8> = ordered.iter().map(|(_, body)| body[0]).collect();
    assert_eq!(payloads, vec![0, 1, 2, 3, 4], "{name}: per-channel order");
    for (id, _) in &ordered {
        b.ack(channel, id).expect("ack");
    }

    // 4. Priority and TTL are accepted at the port. What they *do* differs by
    //    backend — Sund forwards a wake-up hint it cannot read — but neither
    //    may refuse them.
    a.send(
        channel,
        Outbound::new(b"urgent".to_vec())
            .with_priority(Priority::High)
            .with_ttl(std::time::Duration::from_secs(3600)),
    )
    .unwrap_or_else(|e| panic!("{name}: priority send: {e}"));
    assert_eq!(drain(b.as_ref(), channel).len(), 1);

    // 5. An unknown channel is refused rather than invented.
    assert!(
        matches!(
            a.send(unknown, Outbound::new(b"x".to_vec())),
            Err(TransportError::UnknownChannel(_))
        ),
        "{name}: sending on an unknown channel"
    );
    assert!(
        matches!(b.subscribe(unknown), Err(TransportError::UnknownChannel(_))),
        "{name}: subscribing to an unknown channel"
    );

    // 6. Retirement is one-way, and the other end finds out by failing.
    b.retire(channel)
        .unwrap_or_else(|e| panic!("{name}: retire: {e}"));
    assert!(
        matches!(b.subscribe(channel), Err(TransportError::Retired(_))),
        "{name}: a retired channel cannot be read"
    );
    assert!(
        matches!(
            a.send(channel, Outbound::new(b"too late".to_vec())),
            Err(TransportError::Retired(_))
        ),
        "{name}: sending into a retired channel"
    );
}

#[test]
fn the_in_memory_transport_keeps_the_ports_promises() {
    // The transport the unit tests above this port are written against. If it
    // ever diverges from the real one, everything those tests vouch for is
    // vouching for the wrong thing.
    let shared = MemoryTransport::new();
    let channel = channel_id("memory");
    shared.open(&channel).expect("open");

    assert_port_contract(
        "memory",
        &Pair {
            a: Box::new(shared.clone()),
            b: Box::new(shared),
            channel,
            unknown: channel_id("memory-unknown"),
        },
    );
}

#[test]
fn sund_queues_keep_the_ports_promises() {
    for_each_relay(|relay| {
        let channel = channel_id("sund");
        let (alice, bob) = paired_transports(relay, &channel);

        assert_port_contract(
            relay.name,
            &Pair {
                a: Box::new(alice),
                b: Box::new(bob),
                channel,
                unknown: channel_id("sund-unknown"),
            },
        );
    });
}

/// Two devices with a duplex channel between them: Walkthrough 2, minus the QR.
///
/// Returns `(alice, bob)`, where alice's sends land in bob's queue.
fn paired_transports(relay: &Relay, channel: &ChannelId) -> (SundTransport, SundTransport) {
    let alice = SundTransport::new(relay.enroll().device.clone());
    let bob = SundTransport::new(relay.enroll().device.clone());

    // Each device creates the queue it will drain…
    alice.declare(channel, seed());
    alice.open(channel).expect("alice's queue");
    bob.declare(channel, seed());
    bob.open(channel).expect("bob's queue");

    // …and hands its `sender_id` to the other. In a real pairing this crosses
    // in the QR (the first channel) or inside an already-encrypted message
    // (every later one); the server never carries it in the clear.
    let alice_ids = alice.inbound(channel).expect("alice's ids");
    let bob_ids = bob.inbound(channel).expect("bob's ids");
    alice
        .attach_outbound(channel, bob_ids.sender_id, seed())
        .expect("alice sends to bob");
    bob.attach_outbound(channel, alice_ids.sender_id, seed())
        .expect("bob sends to alice");

    (alice, bob)
}

#[test]
fn rotating_a_queue_moves_the_channel_without_re_pairing_the_devices() {
    for_each_relay(|relay| {
        let channel = channel_id("rotation");
        let (alice, bob) = paired_transports(relay, &channel);

        alice
            .send(&channel, Outbound::new(b"before".to_vec()))
            .expect("send before rotation");

        // Bob rotates the queue he owns. Undrained messages go with it — the
        // transport is deliberately lossy, and rotation is one of the places
        // that bites.
        let fresh = bob
            .rotate_inbound(&channel, seed())
            .expect("rotate bob's inbound queue");
        assert_ne!(
            fresh.sender_id,
            alice.inbound(&channel).expect("alice's ids").sender_id
        );

        // Until Alice hears about it, her sends land nowhere — and they fail
        // loudly rather than being silently dropped.
        assert!(
            matches!(
                alice.send(&channel, Outbound::new(b"stale".to_vec())),
                Err(TransportError::Retired(_))
            ),
            "{}: sending into a rotated-away queue",
            relay.name
        );

        // Bob tells her the new address over the session that still works, and
        // the channel continues — with a fresh sender key, because the new
        // queue binds one of its own.
        alice
            .attach_outbound(&channel, fresh.sender_id, seed())
            .expect("attach the new queue");
        alice
            .send(&channel, Outbound::new(b"after".to_vec()))
            .expect("send after rotation");

        let delivered = drain(&bob, &channel);
        assert_eq!(delivered.len(), 1, "{}: only the new queue", relay.name);
        assert_eq!(delivered[0].1, b"after");
        bob.acknowledge_all(
            &channel,
            &delivered.into_iter().map(|(id, _)| id).collect::<Vec<_>>(),
        )
        .expect("ack");
    });
}

#[test]
fn channel_state_can_be_persisted_and_resumed() {
    for_each_relay(|relay| {
        let channel = channel_id("resume");
        let (alice, bob) = paired_transports(relay, &channel);
        alice
            .send(&channel, Outbound::new(b"across a restart".to_vec()))
            .expect("send");

        // What an app stores between process lifetimes. Rebuilding the
        // transport from it must produce a client that can still drain — the
        // queue, its key and the bound-sender state all survive.
        let saved = bob.export();
        let restarted = SundTransport::new(bob.device().clone());
        restarted.import(saved);

        let delivered = drain(&restarted, &channel);
        assert_eq!(delivered.len(), 1, "{}", relay.name);
        assert_eq!(delivered[0].1, b"across a restart");
        restarted
            .acknowledge_all(&channel, &[delivered[0].0.clone()])
            .expect("ack after the restart");
    });
}
