//! An in-memory [`Transport`], for tests.
//!
//! This is the transport port's second job, and the reason
//! `docs/FamilyBeacon-TryMode.md` says to define the port now even though its
//! second *real* implementation is deferred: pairing, session lifecycle,
//! outbox/retry, dedupe and rotation can all be exercised with no server at
//! all, in milliseconds, which is what tier 1 of
//! `docs/FamilyBeacon-Testing.md` requires.
//!
//! It models the awkward parts of the contract rather than an idealised one —
//! at-least-once redelivery of anything unacknowledged, per-channel ordering
//! and nothing across channels. Code that passes against a transport which
//! never redelivers is code that has not met the real one.

use crate::transport::{
    ChannelId, Delivery, MessageId, Outbound, Subscription, Transport, TransportError,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

#[derive(Debug, Clone)]
struct Stored {
    id: MessageId,
    ciphertext: Vec<u8>,
    received_at: SystemTime,
}

#[derive(Debug, Default)]
struct Channel {
    pending: Vec<Stored>,
    retired: bool,
}

#[derive(Debug, Default)]
struct State {
    channels: HashMap<ChannelId, Channel>,
    next_id: u64,
}

/// An in-process transport. Cloning shares one backing store, so two clones can
/// stand in for two devices on the same channel.
#[derive(Debug, Clone, Default)]
pub struct MemoryTransport {
    state: Arc<Mutex<State>>,
}

impl MemoryTransport {
    /// A transport with no channels.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many messages are waiting unacknowledged on a channel.
    ///
    /// For assertions about retry and dedupe; not part of the port.
    pub fn pending(&self, channel: &ChannelId) -> usize {
        self.locked()
            .channels
            .get(channel)
            .map_or(0, |c| c.pending.len())
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned lock means a test panicked while holding it; the panic
        // that follows here is the same failure, not a new one.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with_channel<T>(
        &self,
        channel: &ChannelId,
        f: impl FnOnce(&mut Channel) -> Result<T, TransportError>,
    ) -> Result<T, TransportError> {
        let mut state = self.locked();
        let entry = state
            .channels
            .get_mut(channel)
            .ok_or_else(|| TransportError::UnknownChannel(channel.clone()))?;
        if entry.retired {
            return Err(TransportError::Retired(channel.clone()));
        }
        f(entry)
    }
}

impl Transport for MemoryTransport {
    fn open(&self, channel: &ChannelId) -> Result<(), TransportError> {
        let mut state = self.locked();
        match state.channels.get(channel) {
            Some(existing) if existing.retired => Err(TransportError::Retired(channel.clone())),
            Some(_) => Ok(()),
            None => {
                state.channels.insert(channel.clone(), Channel::default());
                Ok(())
            }
        }
    }

    fn retire(&self, channel: &ChannelId) -> Result<(), TransportError> {
        let mut state = self.locked();
        let entry = state
            .channels
            .get_mut(channel)
            .ok_or_else(|| TransportError::UnknownChannel(channel.clone()))?;
        entry.retired = true;
        entry.pending.clear();
        Ok(())
    }

    fn send(&self, channel: &ChannelId, message: Outbound) -> Result<MessageId, TransportError> {
        // The TTL and priority are accepted and dropped: this backend has no
        // clock to expire against and nobody to wake. Expiry is real in both
        // shipping backends, and the layers above must treat a gap as ordinary
        // — which the redelivery and ordering behaviour below already forces.
        let mut state = self.locked();
        state.next_id += 1;
        let id = format!("m{}", state.next_id);
        let entry = state
            .channels
            .get_mut(channel)
            .ok_or_else(|| TransportError::UnknownChannel(channel.clone()))?;
        if entry.retired {
            return Err(TransportError::Retired(channel.clone()));
        }
        entry.pending.push(Stored {
            id: id.clone(),
            ciphertext: message.ciphertext,
            received_at: SystemTime::now(),
        });
        Ok(id)
    }

    fn subscribe(&self, channel: &ChannelId) -> Result<Box<dyn Subscription>, TransportError> {
        self.with_channel(channel, |_| Ok(()))?;
        Ok(Box::new(MemorySubscription {
            transport: self.clone(),
            channel: channel.clone(),
            cursor: 0,
        }))
    }

    fn ack(&self, channel: &ChannelId, message: &MessageId) -> Result<(), TransportError> {
        self.with_channel(channel, |entry| {
            entry.pending.retain(|m| &m.id != message);
            Ok(())
        })
    }
}

/// A cursor over one channel's pending messages.
#[derive(Debug)]
struct MemorySubscription {
    transport: MemoryTransport,
    channel: ChannelId,
    cursor: usize,
}

impl Subscription for MemorySubscription {
    fn next_delivery(&mut self) -> Result<Option<Delivery>, TransportError> {
        let cursor = self.cursor;
        let next = self.transport.with_channel(&self.channel, |entry| {
            Ok(entry.pending.get(cursor).cloned())
        })?;
        Ok(next.map(|stored| {
            self.cursor += 1;
            Delivery {
                id: stored.id,
                ciphertext: stored.ciphertext,
                received_at: stored.received_at,
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::Priority;

    fn channel() -> ChannelId {
        "dev_A:dev_B".to_owned()
    }

    fn drain(sub: &mut dyn Subscription) -> Vec<Delivery> {
        let mut out = Vec::new();
        while let Some(d) = sub.next_delivery().expect("subscription") {
            out.push(d);
        }
        out
    }

    #[test]
    fn a_message_round_trips() {
        let t = MemoryTransport::new();
        t.open(&channel()).expect("open");
        let id = t
            .send(&channel(), Outbound::new(b"ciphertext".to_vec()))
            .expect("send");

        let mut sub = t.subscribe(&channel()).expect("subscribe");
        let got = drain(sub.as_mut());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, id);
        assert_eq!(got[0].ciphertext, b"ciphertext");
    }

    #[test]
    fn delivery_is_at_least_once_until_acknowledged() {
        let t = MemoryTransport::new();
        t.open(&channel()).expect("open");
        let id = t
            .send(&channel(), Outbound::new(b"one".to_vec()))
            .expect("send");

        // A subscription that reads but never acks — the process died, the
        // battery ran out — must see it again next time.
        let mut first = t.subscribe(&channel()).expect("subscribe");
        assert_eq!(drain(first.as_mut()).len(), 1);
        let mut second = t.subscribe(&channel()).expect("subscribe");
        assert_eq!(drain(second.as_mut()).len(), 1, "unacked must redeliver");

        t.ack(&channel(), &id).expect("ack");
        let mut third = t.subscribe(&channel()).expect("subscribe");
        assert!(drain(third.as_mut()).is_empty());
        assert_eq!(t.pending(&channel()), 0);
    }

    #[test]
    fn order_holds_within_a_channel() {
        let t = MemoryTransport::new();
        t.open(&channel()).expect("open");
        for n in 0..5u8 {
            t.send(&channel(), Outbound::new(vec![n])).expect("send");
        }
        let mut sub = t.subscribe(&channel()).expect("subscribe");
        let got: Vec<u8> = drain(sub.as_mut())
            .into_iter()
            .map(|d| d.ciphertext[0])
            .collect();
        assert_eq!(got, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn channels_do_not_see_each_other() {
        let t = MemoryTransport::new();
        let (a, b) = ("dev_A:dev_B".to_owned(), "dev_A:dev_C".to_owned());
        t.open(&a).expect("open");
        t.open(&b).expect("open");
        t.send(&a, Outbound::new(b"for B".to_vec())).expect("send");

        let mut sub_b = t.subscribe(&b).expect("subscribe");
        assert!(drain(sub_b.as_mut()).is_empty());
        assert_eq!(t.pending(&a), 1);
    }

    #[test]
    fn sending_to_an_unopened_channel_fails() {
        let t = MemoryTransport::new();
        assert_eq!(
            t.send(&channel(), Outbound::new(b"x".to_vec())),
            Err(TransportError::UnknownChannel(channel()))
        );
    }

    #[test]
    fn retirement_is_one_way_and_drops_what_was_queued() {
        let t = MemoryTransport::new();
        t.open(&channel()).expect("open");
        t.send(&channel(), Outbound::new(b"x".to_vec()))
            .expect("send");
        t.retire(&channel()).expect("retire");

        assert_eq!(t.pending(&channel()), 0);
        assert_eq!(
            t.send(&channel(), Outbound::new(b"y".to_vec())),
            Err(TransportError::Retired(channel()))
        );
        assert!(matches!(
            t.subscribe(&channel()),
            Err(TransportError::Retired(_))
        ));
        assert!(matches!(
            t.open(&channel()),
            Err(TransportError::Retired(_))
        ));
    }

    #[test]
    fn opening_twice_is_not_an_error() {
        let t = MemoryTransport::new();
        t.open(&channel()).expect("open");
        t.open(&channel()).expect("open again");
    }

    #[test]
    fn priority_and_ttl_are_accepted_at_the_port() {
        let t = MemoryTransport::new();
        t.open(&channel()).expect("open");
        let sos = Outbound::new(b"sos".to_vec())
            .with_priority(Priority::High)
            .with_ttl(std::time::Duration::from_secs(3600));
        t.send(&channel(), sos).expect("send");
        assert_eq!(t.pending(&channel()), 1);
    }
}
