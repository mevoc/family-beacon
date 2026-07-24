//! Queue lifecycle: creation, sender-key binding, drain, acknowledge, the size
//! caps, and retirement.
//!
//! These go through [`SundClient`]'s transport-plane calls rather than through
//! the transport port, because what is under test here is the wire contract
//! itself. The port's own promises are asserted in `port.rs`, over the same
//! server.

use contract_tests::{for_each_relay, seed};
use std::time::Duration;
use sund_client::client::{QueueMessage, SundError};
use sund_client::sigauth::QueueKey;

/// A queue owned by a freshly enrolled device, with the key that drains it.
struct Queue {
    recipient_id: String,
    sender_id: String,
    recipient_key: QueueKey,
}

fn queue(relay: &contract_tests::Relay) -> Queue {
    let owner = relay.enroll();
    let recipient_key = QueueKey::from_seed(&seed());
    let ids = owner
        .create_queue(&recipient_key.public_key())
        .expect("create a queue");
    Queue {
        recipient_id: ids.recipient_id,
        sender_id: ids.sender_id,
        recipient_key,
    }
}

fn message(payload: &[u8]) -> QueueMessage<'_> {
    QueueMessage {
        payload,
        ttl: Some(Duration::from_secs(600)),
        priority: false,
        bind_sender_key: false,
    }
}

#[test]
fn a_message_survives_send_drain_and_acknowledge() {
    for_each_relay(|relay| {
        let queue = queue(relay);
        let sender = QueueKey::from_seed(&seed());

        let id = relay
            .client()
            .send_to_queue(
                &queue.sender_id,
                &sender,
                &QueueMessage {
                    bind_sender_key: true,
                    ..message(b"ciphertext")
                },
            )
            .expect("send");

        let drained = relay
            .client()
            .receive_from_queue(&queue.recipient_id, &queue.recipient_key)
            .expect("drain");
        assert_eq!(drained.len(), 1, "{}", relay.name);
        assert_eq!(drained[0].id, id);
        assert_eq!(drained[0].payload, b"ciphertext");
        assert!(drained[0].received_at.is_some());
        assert!(drained[0].expires.is_some());

        // Draining does not delete: at-least-once is the contract, and a client
        // that died between drain and processing must see the message again.
        let again = relay
            .client()
            .receive_from_queue(&queue.recipient_id, &queue.recipient_key)
            .expect("drain again");
        assert_eq!(
            again.len(),
            1,
            "{}: unacknowledged must redeliver",
            relay.name
        );

        let deleted = relay
            .client()
            .acknowledge(&queue.recipient_id, &queue.recipient_key, &[id])
            .expect("ack");
        assert_eq!(deleted, 1);
        assert!(
            relay
                .client()
                .receive_from_queue(&queue.recipient_id, &queue.recipient_key)
                .expect("drain after ack")
                .is_empty()
        );
    });
}

#[test]
fn order_holds_within_a_queue() {
    for_each_relay(|relay| {
        let queue = queue(relay);
        let sender = QueueKey::from_seed(&seed());

        for n in 0u8..5 {
            relay
                .client()
                .send_to_queue(
                    &queue.sender_id,
                    &sender,
                    &QueueMessage {
                        bind_sender_key: n == 0,
                        ..message(&[n])
                    },
                )
                .expect("send");
        }

        let drained = relay
            .client()
            .receive_from_queue(&queue.recipient_id, &queue.recipient_key)
            .expect("drain");
        let order: Vec<u8> = drained.iter().map(|m| m.payload[0]).collect();
        assert_eq!(order, vec![0, 1, 2, 3, 4], "{}", relay.name);
    });
}

#[test]
fn the_first_send_binds_the_sender_key_and_nobody_else_may_write() {
    for_each_relay(|relay| {
        let queue = queue(relay);
        let sender = QueueKey::from_seed(&seed());

        relay
            .client()
            .send_to_queue(
                &queue.sender_id,
                &sender,
                &QueueMessage {
                    bind_sender_key: true,
                    ..message(b"first")
                },
            )
            .expect("the binding send");

        // Knowing the sender_id is not enough after the binding send — which is
        // what makes it safe for the id to travel in a QR.
        let stranger = QueueKey::from_seed(&seed());
        assert_eq!(
            relay
                .client()
                .send_to_queue(
                    &queue.sender_id,
                    &stranger,
                    &QueueMessage {
                        bind_sender_key: true,
                        ..message(b"intruder")
                    },
                )
                .err(),
            Some(SundError::Unauthorized),
            "{}: a bound queue may not be rebound",
            relay.name
        );

        // The bound sender keeps writing, with no header at all.
        relay
            .client()
            .send_to_queue(&queue.sender_id, &sender, &message(b"second"))
            .expect("the bound sender continues");
    });
}

#[test]
fn the_recipient_key_is_what_authorises_draining() {
    for_each_relay(|relay| {
        let queue = queue(relay);
        let stranger = QueueKey::from_seed(&seed());
        assert_eq!(
            relay
                .client()
                .receive_from_queue(&queue.recipient_id, &stranger)
                .err(),
            Some(SundError::Unauthorized),
            "{}: the recipient id is not a capability by itself",
            relay.name
        );
        assert_eq!(
            relay
                .client()
                .acknowledge(&queue.recipient_id, &stranger, &[])
                .err(),
            Some(SundError::Unauthorized)
        );
        assert_eq!(
            relay
                .client()
                .retire_queue(&queue.recipient_id, &stranger)
                .err(),
            Some(SundError::Unauthorized)
        );
    });
}

#[test]
fn retirement_drops_the_queue_and_everything_in_it() {
    for_each_relay(|relay| {
        let queue = queue(relay);
        let sender = QueueKey::from_seed(&seed());
        relay
            .client()
            .send_to_queue(
                &queue.sender_id,
                &sender,
                &QueueMessage {
                    bind_sender_key: true,
                    ..message(b"undelivered")
                },
            )
            .expect("send");

        relay
            .client()
            .retire_queue(&queue.recipient_id, &queue.recipient_key)
            .expect("retire");

        // One-way, and the server enforces it — the half of rotation a
        // serverless transport cannot do.
        for outcome in [
            relay
                .client()
                .receive_from_queue(&queue.recipient_id, &queue.recipient_key)
                .err(),
            relay
                .client()
                .retire_queue(&queue.recipient_id, &queue.recipient_key)
                .err(),
            relay
                .client()
                .send_to_queue(&queue.sender_id, &sender, &message(b"too late"))
                .err(),
        ] {
            assert_eq!(outcome, Some(SundError::NotFound), "{}", relay.name);
        }
    });
}

#[test]
fn the_payload_caps_are_where_the_server_says_they_are() {
    for_each_relay(|relay| {
        let queue = queue(relay);
        let sender = QueueKey::from_seed(&seed());

        // 64 KiB exactly is fine; one byte more is not. The cap matters to the
        // layers above because an envelope that grows past it stops being
        // deliverable, and this is where that number is fixed.
        let at_cap = vec![7u8; 64 << 10];
        relay
            .client()
            .send_to_queue(
                &queue.sender_id,
                &sender,
                &QueueMessage {
                    bind_sender_key: true,
                    ..message(&at_cap)
                },
            )
            .expect("64 KiB is accepted");

        let over_cap = vec![7u8; (64 << 10) + 1];
        assert_eq!(
            relay
                .client()
                .send_to_queue(&queue.sender_id, &sender, &message(&over_cap))
                .err(),
            Some(SundError::TooLarge),
            "{}: 64 KiB is the payload ceiling",
            relay.name
        );

        assert!(matches!(
            relay
                .client()
                .send_to_queue(&queue.sender_id, &sender, &message(b""))
                .err(),
            Some(SundError::Rejected(_)),
        ));
    });
}

#[test]
fn queues_do_not_see_each_other() {
    for_each_relay(|relay| {
        let first = queue(relay);
        let second = queue(relay);
        let sender = QueueKey::from_seed(&seed());

        relay
            .client()
            .send_to_queue(
                &first.sender_id,
                &sender,
                &QueueMessage {
                    bind_sender_key: true,
                    ..message(b"for the first")
                },
            )
            .expect("send");

        assert!(
            relay
                .client()
                .receive_from_queue(&second.recipient_id, &second.recipient_key)
                .expect("drain the other queue")
                .is_empty(),
            "{}: queues are separate pipes",
            relay.name
        );
    });
}

#[test]
fn an_unknown_queue_is_a_404_in_every_direction() {
    for_each_relay(|relay| {
        let key = QueueKey::from_seed(&seed());
        assert_eq!(
            relay.client().receive_from_queue("rcp_nothing", &key).err(),
            Some(SundError::NotFound),
            "{}",
            relay.name
        );
        assert_eq!(
            relay
                .client()
                .send_to_queue(
                    "snd_nothing",
                    &key,
                    &QueueMessage {
                        bind_sender_key: true,
                        ..message(b"x")
                    }
                )
                .err(),
            Some(SundError::NotFound)
        );
    });
}

#[test]
fn revoking_a_device_takes_its_queues_with_it() {
    for_each_relay(|relay| {
        let owner = relay.enroll();
        let recipient_key = QueueKey::from_seed(&seed());
        let ids = owner
            .create_queue(&recipient_key.public_key())
            .expect("create a queue");
        let sender = QueueKey::from_seed(&seed());
        relay
            .client()
            .send_to_queue(
                &ids.sender_id,
                &sender,
                &QueueMessage {
                    bind_sender_key: true,
                    ..message(b"before the revocation")
                },
            )
            .expect("send");

        relay
            .founder()
            .revoke_device(owner.device_id())
            .expect("revoke the owner");

        // This is the server-side half of removal: a stolen phone stops being
        // able to read, and the family's later traffic has nowhere to land on
        // it. The end-to-end half — the ledgered removal the family sees — is
        // the roster layer's, above this crate.
        assert_eq!(
            relay
                .client()
                .receive_from_queue(&ids.recipient_id, &recipient_key)
                .err(),
            Some(SundError::NotFound),
            "{}: a revoked device's queues are retired with it",
            relay.name
        );
        assert_eq!(
            relay
                .client()
                .send_to_queue(&ids.sender_id, &sender, &message(b"after"))
                .err(),
            Some(SundError::NotFound)
        );
    });
}
