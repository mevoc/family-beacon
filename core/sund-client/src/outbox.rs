//! The offline outbox: what a device does with messages it cannot send yet.
//!
//! `ARCHITECTURE.md` → Offline Philosophy asks for graceful degradation —
//! "store location updates while offline, synchronize automatically when
//! connectivity returns". `docs/FamilyBeacon-Protocol.md` says of the same
//! message type: "a stale location is worse than none."
//!
//! Taken literally, those two instructions contradict each other. Queue location
//! updates for three hours and flush them on reconnect, and a family watching
//! the map sees a burst of positions from a morning that is over — which is
//! precisely what the design guide forbids ("never fabricates freshness"). This
//! module is where the contradiction is resolved, and the resolution is the
//! reason it is not simply a `Vec` of pending sends:
//!
//! - **Entries expire.** An entry past its [`Enqueue::expires_at`] is dropped,
//!   not sent. Reconnecting does not licence delivering a stale position; it
//!   licences delivering a *fresh* one.
//! - **Entries supersede.** A newer location for the same peer replaces the one
//!   queued behind it ([`Enqueue::coalesce_key`]), so an hour offline drains as
//!   one current position rather than sixty historical ones.
//! - **Entries without an expiry are durable** and are retried until they land.
//!   An SOS, a tombstone, a consent revocation: late is bad, lost is worse.
//!
//! Which of the three a message gets is the caller's decision, because this
//! crate does not know what a message *means*. `beacon-protocol` knows that
//! `location` is state and `sos` is an event; the outbox knows only that one
//! entry carries an expiry and a coalescing key and the other does not.
//!
//! # Plaintext in, ciphertext at the last moment
//!
//! The queue holds **plaintext**, and encryption happens in [`Outbox::drain`].
//! The alternative — sealing at enqueue — looks tidier and is wrong here:
//!
//! - A queued ciphertext is bound to the session that produced it. If the peer
//!   reinstalls while this device is offline, every queued message becomes
//!   undecryptable garbage that will be delivered and rejected. Encrypting at
//!   drain re-seals under whatever session is current, so a
//!   [`SessionError::SessionLost`](crate::session::SessionError::SessionLost)
//!   costs a re-establishment and nothing else.
//! - Sealing advances the ratchet for messages that may never be sent. Every
//!   expired location would leave a skipped key behind it.
//!
//! The cost is real and worth stating plainly: **the outbox holds message bodies
//! in the clear on the device.** That is the same trust boundary the app layer
//! already lives on — it stores positions, geofences and a ledger — and it is
//! why [`OutboxSnapshot`] is documented as belonging wherever the platform keeps
//! sensitive state, not in a cache directory. End-to-end encryption is a claim
//! about the *server*; the device has always been trusted, and a stolen device is
//! what the ratchet's post-compromise recovery is for.
//!
//! # The core still owns no clock and no loop
//!
//! `now` is an argument to everything that needs it and [`Outbox::drain`] sends
//! at most what the caller allows. WorkManager and BGTask decide when this runs;
//! this module decides only what is worth sending when it does.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::session::{SessionError, SessionManager};
use crate::transport::{ChannelId, MessageId, Outbound, Priority, Transport, TransportError};

/// The store format version.
pub const SNAPSHOT_VERSION: u8 = 1;

/// How many entries one channel may hold before enqueueing starts failing.
///
/// A build-time constant, like the roster's caps and for the same reason: it
/// exists to fail honestly rather than to be tuned. At the app's location cadence
/// this is hours of backlog, and a device that has queued this much has a problem
/// the outbox cannot fix by growing.
pub const MAX_QUEUED_PER_CHANNEL: usize = 200;

/// Backoff after a failed attempt, capped.
///
/// Doubling from 30 seconds to 15 minutes. The ceiling is chosen to match the
/// shortest interval a platform background scheduler will honour — backing off
/// further than the caller's own cadence would just add latency to a retry the
/// caller was going to make anyway.
const BACKOFF_BASE: Duration = Duration::from_secs(30);
const BACKOFF_CEILING: Duration = Duration::from_secs(15 * 60);

fn backoff_for(attempts: u32) -> Duration {
    BACKOFF_BASE
        .saturating_mul(1u32.checked_shl(attempts.min(16)).unwrap_or(u32::MAX))
        .min(BACKOFF_CEILING)
}

/// One message handed to the outbox.
#[derive(Debug, Clone)]
pub struct Enqueue<'a> {
    /// The channel it belongs to.
    pub channel: ChannelId,
    /// The peer whose session seals it at drain time.
    pub peer: String,
    /// The envelope, in the clear.
    pub plaintext: &'a [u8],
    /// Wake-up urgency, passed through to the port.
    pub priority: Priority,
    /// The backend's hold time, passed through to the port.
    pub ttl: Option<Duration>,
    /// When this entry stops being worth sending.
    ///
    /// `None` makes it **durable**: retried until it lands, however long that
    /// takes. Use it for anything whose loss is worse than its lateness — an
    /// SOS, a tombstone, a consent change. Use an expiry for anything that
    /// describes *now*, because a position from an hour ago is not a late
    /// position, it is a wrong one.
    pub expires_at: Option<SystemTime>,
    /// Replaces any queued entry on the same channel with the same key.
    ///
    /// The mechanism that turns an hour of queued locations into one current
    /// position. Only for messages that describe state; an event that supersedes
    /// another event is a design error, not a coalescing opportunity.
    pub coalesce_key: Option<String>,
}

/// Why an entry could not be queued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueError {
    /// The channel is at [`MAX_QUEUED_PER_CHANNEL`] and nothing in it could be
    /// dropped to make room, because every queued entry is durable.
    ///
    /// Deliberately an error rather than a silent eviction: dropping a durable
    /// message to make room for another is a decision no library should make on
    /// the caller's behalf.
    Full {
        /// The channel that is full.
        channel: ChannelId,
    },
}

impl std::fmt::Display for EnqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full { channel } => write!(
                f,
                "channel `{channel}` holds {MAX_QUEUED_PER_CHANNEL} undeliverable messages"
            ),
        }
    }
}

impl std::error::Error for EnqueueError {}

/// Why an entry left the queue without being sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    /// Its expiry passed. The ordinary outcome for a position that went stale
    /// while the network was gone, and the whole point of having expiries.
    Expired,
    /// A newer entry with the same coalescing key replaced it.
    Superseded,
    /// The channel was retired, so nothing will ever be deliverable on it. The
    /// pair has to be re-established before anything can be sent.
    ChannelRetired,
    /// The channel is unknown to the transport — never opened, or opened by an
    /// installation whose state is gone.
    ChannelUnknown,
    /// The peer was forgotten, typically because the roster removed it.
    PeerForgotten,
}

impl std::fmt::Display for DropReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Expired => "it went stale before the network came back",
            Self::Superseded => "a newer message replaced it",
            Self::ChannelRetired => "the channel was retired",
            Self::ChannelUnknown => "the channel is not open",
            Self::PeerForgotten => "the device is no longer in the family",
        };
        f.write_str(text)
    }
}

/// Why an entry stayed in the queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferReason {
    /// The backend refused or was unreachable. Retried with backoff.
    Unreachable(String),
    /// The session with this peer must be re-established before anything can be
    /// sealed for it.
    ///
    /// Actionable rather than fatal, and the reason the queue holds plaintext:
    /// once the caller re-establishes, the same entry seals under the new
    /// session and goes out unchanged.
    SessionLost,
    /// No verified key material for the peer yet — its bundle has not been
    /// fetched and verified against the roster.
    PeerUnknown,
    /// A session exists in neither direction, so there is nothing to seal with.
    NoSession,
}

impl std::fmt::Display for DeferReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(detail) => write!(f, "the server could not be reached: {detail}"),
            Self::SessionLost => write!(f, "the secure session needs re-establishing"),
            Self::PeerUnknown => write!(f, "this device's keys have not been verified yet"),
            Self::NoSession => write!(f, "no secure session with this device yet"),
        }
    }
}

/// One message that went out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    /// The outbox's id for the entry.
    pub id: u64,
    /// The channel it went out on.
    pub channel: ChannelId,
    /// The peer it was sealed for.
    pub peer: String,
    /// The backend's id, for acknowledging or correlating.
    pub message_id: MessageId,
    /// How long it waited, which is what a staleness UI wants to know.
    pub queued_for: Duration,
}

/// One message that left the queue unsent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    /// The outbox's id for the entry.
    pub id: u64,
    /// The channel.
    pub channel: ChannelId,
    /// The peer.
    pub peer: String,
    /// Why.
    pub reason: DropReason,
}

/// One message that stayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferred {
    /// The outbox's id for the entry.
    pub id: u64,
    /// The channel.
    pub channel: ChannelId,
    /// The peer.
    pub peer: String,
    /// Why.
    pub reason: DeferReason,
    /// How many attempts this entry has now had.
    pub attempts: u32,
}

/// What one drain did.
///
/// The outbox produces no ledger entries of its own: `beacon-protocol` owns the
/// ledger and sits *above* this crate, so a report is what crosses the boundary
/// and the caller turns it into the sentences a person reads. The rule that every
/// message produces an entry is satisfied there, with the type names this crate
/// deliberately does not know.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Messages that went out.
    pub sent: Vec<Sent>,
    /// Messages that left the queue unsent.
    pub dropped: Vec<Dropped>,
    /// Messages still waiting, with the reason for the most recent attempt.
    pub deferred: Vec<Deferred>,
}

impl DrainReport {
    /// Whether anything at all happened.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sent.is_empty() && self.dropped.is_empty() && self.deferred.is_empty()
    }

    /// Peers whose sessions the caller must re-establish before the next drain.
    #[must_use]
    pub fn needs_session(&self) -> Vec<&str> {
        let mut peers: Vec<&str> = self
            .deferred
            .iter()
            .filter(|entry| {
                matches!(
                    entry.reason,
                    DeferReason::SessionLost | DeferReason::NoSession
                )
            })
            .map(|entry| entry.peer.as_str())
            .collect();
        peers.sort_unstable();
        peers.dedup();
        peers
    }
}

/// One queued message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    id: u64,
    channel: ChannelId,
    peer: String,
    plaintext: Vec<u8>,
    high_priority: bool,
    ttl_secs: Option<u64>,
    expires_at_secs: Option<u64>,
    coalesce_key: Option<String>,
    enqueued_at_secs: u64,
    attempts: u32,
    not_before_secs: u64,
}

impl Entry {
    fn priority(&self) -> Priority {
        if self.high_priority {
            Priority::High
        } else {
            Priority::Normal
        }
    }

    fn is_durable(&self) -> bool {
        self.expires_at_secs.is_none()
    }

    fn expired_at(&self, now: u64) -> bool {
        self.expires_at_secs.is_some_and(|at| now >= at)
    }
}

/// The persisted form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxSnapshot {
    /// Store format version.
    pub v: u8,
    /// The next entry id, so ids stay unique across restarts.
    next_id: u64,
    /// The queued entries, in order.
    entries: Vec<Entry>,
}

/// Why a snapshot could not be restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// A version this build does not speak.
    UnsupportedVersion {
        /// The version found.
        found: u8,
    },
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => write!(f, "unsupported outbox version {found}"),
        }
    }
}

impl std::error::Error for SnapshotError {}

/// Messages waiting to go out.
///
/// Ordering is per-channel FIFO, with one exception that is deliberate: a
/// high-priority entry drains ahead of normal ones on the same channel. An SOS
/// must not sit behind forty queued locations, and the receiver already tolerates
/// reordering — `seq` gaps mean loss or expiry, and arriving out of order is
/// neither.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outbox {
    entries: Vec<Entry>,
    next_id: u64,
}

impl Outbox {
    /// An empty outbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many messages are waiting.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether anything is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many messages are waiting for one peer.
    #[must_use]
    pub fn pending_for(&self, peer: &str) -> usize {
        self.entries.iter().filter(|e| e.peer == peer).count()
    }

    /// Queue a message.
    ///
    /// Supersedes any queued entry on the same channel with the same coalescing
    /// key, and reports what it replaced.
    ///
    /// # Errors
    ///
    /// Returns [`EnqueueError::Full`] when the channel is at
    /// [`MAX_QUEUED_PER_CHANNEL`] and every entry on it is durable.
    pub fn enqueue(
        &mut self,
        message: &Enqueue<'_>,
        now: SystemTime,
    ) -> Result<(u64, Option<Dropped>), EnqueueError> {
        let mut superseded = None;

        if let Some(key) = &message.coalesce_key {
            if let Some(index) = self
                .entries
                .iter()
                .position(|e| e.channel == message.channel && e.coalesce_key.as_ref() == Some(key))
            {
                let old = self.entries.remove(index);
                superseded = Some(Dropped {
                    id: old.id,
                    channel: old.channel,
                    peer: old.peer,
                    reason: DropReason::Superseded,
                });
            }
        }

        if superseded.is_none() {
            let queued = self
                .entries
                .iter()
                .filter(|e| e.channel == message.channel)
                .count();
            if queued >= MAX_QUEUED_PER_CHANNEL {
                // Make room by dropping the oldest entry that was allowed to go
                // stale. Never a durable one: that decision is the caller's.
                let oldest = self
                    .entries
                    .iter()
                    .position(|e| e.channel == message.channel && !e.is_durable());
                match oldest {
                    Some(index) => {
                        let old = self.entries.remove(index);
                        superseded = Some(Dropped {
                            id: old.id,
                            channel: old.channel,
                            peer: old.peer,
                            reason: DropReason::Expired,
                        });
                    }
                    None => {
                        return Err(EnqueueError::Full {
                            channel: message.channel.clone(),
                        });
                    }
                }
            }
        }

        let id = self.next_id;
        self.next_id += 1;
        let seconds = unix_seconds(now);
        self.entries.push(Entry {
            id,
            channel: message.channel.clone(),
            peer: message.peer.clone(),
            plaintext: message.plaintext.to_vec(),
            high_priority: message.priority == Priority::High,
            ttl_secs: message.ttl.map(|ttl| ttl.as_secs()),
            expires_at_secs: message.expires_at.map(unix_seconds),
            coalesce_key: message.coalesce_key.clone(),
            enqueued_at_secs: seconds,
            attempts: 0,
            not_before_secs: seconds,
        });
        Ok((id, superseded))
    }

    /// Send what is due, up to `budget` messages.
    ///
    /// The budget is the caller's schedule showing through: a background wake-up
    /// with thirty seconds of runtime should not try to flush an hour of backlog
    /// and be killed halfway. Pass [`usize::MAX`] to drain everything.
    ///
    /// Expired entries are dropped **before** any send is attempted, so a long
    /// offline stretch costs one pass over the queue rather than a burst of
    /// stale traffic.
    pub fn drain(
        &mut self,
        transport: &dyn Transport,
        sessions: &mut SessionManager,
        now: SystemTime,
        budget: usize,
    ) -> DrainReport {
        let mut report = DrainReport::default();
        let seconds = unix_seconds(now);

        // 1. Expiry, first and unconditionally. Reconnecting is not a licence to
        //    deliver a position from an hour ago.
        self.entries.retain(|entry| {
            if entry.expired_at(seconds) {
                report.dropped.push(Dropped {
                    id: entry.id,
                    channel: entry.channel.clone(),
                    peer: entry.peer.clone(),
                    reason: DropReason::Expired,
                });
                false
            } else {
                true
            }
        });

        // 2. What is due, urgent first, then oldest first.
        let mut due: Vec<usize> = (0..self.entries.len())
            .filter(|&index| self.entries[index].not_before_secs <= seconds)
            .collect();
        due.sort_by_key(|&index| {
            let entry = &self.entries[index];
            (!entry.high_priority, entry.enqueued_at_secs, entry.id)
        });
        due.truncate(budget);

        let mut sent_ids = Vec::new();
        let mut dropped_ids = Vec::new();
        // Channels that have already failed this pass: one unreachable server
        // means every entry behind it is unreachable too, and hammering it would
        // burn the budget and the battery for a known answer.
        let mut failed_channels: BTreeMap<ChannelId, DeferReason> = BTreeMap::new();

        for index in due {
            let entry = &self.entries[index];

            if let Some(reason) = failed_channels.get(&entry.channel) {
                report.deferred.push(Deferred {
                    id: entry.id,
                    channel: entry.channel.clone(),
                    peer: entry.peer.clone(),
                    reason: reason.clone(),
                    attempts: entry.attempts,
                });
                continue;
            }

            let sealed = match sessions.encrypt(&entry.peer, &entry.plaintext) {
                Ok(frame) => frame,
                Err(error) => {
                    let reason = match error {
                        SessionError::SessionLost { .. } => DeferReason::SessionLost,
                        SessionError::UnknownPeer(_) => DeferReason::PeerUnknown,
                        SessionError::NoSession(_) => DeferReason::NoSession,
                        other => DeferReason::Unreachable(other.to_string()),
                    };
                    report.deferred.push(Deferred {
                        id: entry.id,
                        channel: entry.channel.clone(),
                        peer: entry.peer.clone(),
                        reason,
                        attempts: entry.attempts + 1,
                    });
                    let entry = &mut self.entries[index];
                    entry.attempts += 1;
                    entry.not_before_secs = seconds + backoff_for(entry.attempts).as_secs();
                    continue;
                }
            };

            let mut outbound = Outbound::new(sealed).with_priority(entry.priority());
            if let Some(ttl) = entry.ttl_secs {
                outbound = outbound.with_ttl(Duration::from_secs(ttl));
            }

            match transport.send(&entry.channel, outbound) {
                Ok(message_id) => {
                    report.sent.push(Sent {
                        id: entry.id,
                        channel: entry.channel.clone(),
                        peer: entry.peer.clone(),
                        message_id,
                        queued_for: Duration::from_secs(
                            seconds.saturating_sub(entry.enqueued_at_secs),
                        ),
                    });
                    sent_ids.push(entry.id);
                }
                // Terminal: nothing on this channel will ever be deliverable
                // until the pair is re-established, so holding the backlog only
                // guarantees it is stale when it finally goes.
                Err(TransportError::Retired(_)) => {
                    report.dropped.push(Dropped {
                        id: entry.id,
                        channel: entry.channel.clone(),
                        peer: entry.peer.clone(),
                        reason: DropReason::ChannelRetired,
                    });
                    dropped_ids.push(entry.id);
                    failed_channels.insert(entry.channel.clone(), DeferReason::NoSession);
                }
                Err(TransportError::UnknownChannel(_)) => {
                    report.dropped.push(Dropped {
                        id: entry.id,
                        channel: entry.channel.clone(),
                        peer: entry.peer.clone(),
                        reason: DropReason::ChannelUnknown,
                    });
                    dropped_ids.push(entry.id);
                    failed_channels.insert(entry.channel.clone(), DeferReason::NoSession);
                }
                Err(TransportError::Backend(detail)) => {
                    let reason = DeferReason::Unreachable(detail);
                    report.deferred.push(Deferred {
                        id: entry.id,
                        channel: entry.channel.clone(),
                        peer: entry.peer.clone(),
                        reason: reason.clone(),
                        attempts: entry.attempts + 1,
                    });
                    failed_channels.insert(entry.channel.clone(), reason);
                    let entry = &mut self.entries[index];
                    entry.attempts += 1;
                    entry.not_before_secs = seconds + backoff_for(entry.attempts).as_secs();
                }
            }
        }

        // A retired or unknown channel takes its whole backlog with it, not only
        // the entry that discovered it.
        let dead: Vec<ChannelId> = failed_channels
            .iter()
            .filter(|(_, reason)| **reason == DeferReason::NoSession)
            .map(|(channel, _)| channel.clone())
            .collect();
        for channel in dead {
            let reason = if report
                .dropped
                .iter()
                .any(|d| d.channel == channel && d.reason == DropReason::ChannelRetired)
            {
                DropReason::ChannelRetired
            } else {
                DropReason::ChannelUnknown
            };
            self.entries.retain(|entry| {
                if entry.channel == channel && !dropped_ids.contains(&entry.id) {
                    report.dropped.push(Dropped {
                        id: entry.id,
                        channel: entry.channel.clone(),
                        peer: entry.peer.clone(),
                        reason: reason.clone(),
                    });
                    // Its deferred record, if this pass made one, is superseded
                    // by the drop.
                    report.deferred.retain(|d| d.id != entry.id);
                    false
                } else {
                    true
                }
            });
        }

        self.entries
            .retain(|entry| !sent_ids.contains(&entry.id) && !dropped_ids.contains(&entry.id));
        report
    }

    /// Drop everything queued for a peer.
    ///
    /// The outbox half of a roster removal: a removed device must stop being sent
    /// to immediately, and a backlog that keeps retrying would be exactly the
    /// silent continuation ETHICS.md forbids.
    pub fn forget_peer(&mut self, peer: &str) -> Vec<Dropped> {
        let mut dropped = Vec::new();
        self.entries.retain(|entry| {
            if entry.peer == peer {
                dropped.push(Dropped {
                    id: entry.id,
                    channel: entry.channel.clone(),
                    peer: entry.peer.clone(),
                    reason: DropReason::PeerForgotten,
                });
                false
            } else {
                true
            }
        });
        dropped
    }

    /// The persisted form.
    ///
    /// **Holds plaintext message bodies.** Store it where the platform keeps
    /// sensitive state — the same place as the ledger and the session store — and
    /// not in a cache directory.
    #[must_use]
    pub fn export(&self) -> OutboxSnapshot {
        OutboxSnapshot {
            v: SNAPSHOT_VERSION,
            next_id: self.next_id,
            entries: self.entries.clone(),
        }
    }

    /// Restore from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::UnsupportedVersion`] for a future store.
    pub fn import(snapshot: &OutboxSnapshot) -> Result<Self, SnapshotError> {
        if snapshot.v != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion { found: snapshot.v });
        }
        Ok(Self {
            entries: snapshot.entries.clone(),
            next_id: snapshot.next_id,
        })
    }
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKey;
    use crate::memory::MemoryTransport;

    const NOON: u64 = 1_784_000_000;

    fn at(offset: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(NOON + offset)
    }

    /// Two managers that have verified each other, and the transport between
    /// them.
    struct Fixture {
        outbox: Outbox,
        sessions: SessionManager,
        peer: SessionManager,
        transport: MemoryTransport,
        channel: ChannelId,
    }

    fn fixture() -> Fixture {
        let mut a = SessionManager::create("dev_A", IdentityKey::from_seed(&[1u8; 32]));
        let mut b = SessionManager::create("dev_B", IdentityKey::from_seed(&[2u8; 32]));
        let a_bundle = a.publish_bundle("2026-07-26T10:00:00Z").expect("bundle");
        let b_bundle = b.publish_bundle("2026-07-26T10:00:00Z").expect("bundle");
        a.learn_peer(
            b_bundle
                .verify("dev_B", b.identity_public_key())
                .expect("verifies"),
        );
        b.learn_peer(
            a_bundle
                .verify("dev_A", a.identity_public_key())
                .expect("verifies"),
        );

        let transport = MemoryTransport::new();
        let channel: ChannelId = "pair".to_owned();
        transport.open(&channel).expect("open");

        Fixture {
            outbox: Outbox::new(),
            sessions: a,
            peer: b,
            transport,
            channel,
        }
    }

    fn message<'a>(f: &Fixture, plaintext: &'a [u8]) -> Enqueue<'a> {
        Enqueue {
            channel: f.channel.clone(),
            peer: "dev_B".to_owned(),
            plaintext,
            priority: Priority::Normal,
            ttl: None,
            expires_at: None,
            coalesce_key: None,
        }
    }

    /// Read everything the peer can decrypt off the channel.
    fn received(f: &mut Fixture) -> Vec<Vec<u8>> {
        let mut subscription = f.transport.subscribe(&f.channel).expect("subscribe");
        let mut out = Vec::new();
        while let Some(delivery) = subscription.next_delivery().expect("next") {
            let decrypted = f
                .peer
                .decrypt("dev_A", &delivery.ciphertext)
                .expect("decrypt");
            out.push(decrypted.plaintext);
        }
        out
    }

    #[test]
    fn a_queued_message_goes_out_on_the_next_drain() {
        let mut f = fixture();
        f.outbox
            .enqueue(&message(&f, b"hello"), at(0))
            .expect("enqueue");
        assert_eq!(f.outbox.len(), 1);

        let report = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(1), usize::MAX);
        assert_eq!(report.sent.len(), 1);
        assert_eq!(report.sent[0].queued_for, Duration::from_secs(1));
        assert!(f.outbox.is_empty(), "a sent message leaves the queue");
        assert_eq!(received(&mut f), vec![b"hello".to_vec()]);
    }

    #[test]
    fn order_within_a_channel_is_preserved() {
        let mut f = fixture();
        for n in 0..5u8 {
            f.outbox
                .enqueue(&message(&f, &[n]), at(u64::from(n)))
                .expect("enqueue");
        }
        f.outbox
            .drain(&f.transport, &mut f.sessions, at(10), usize::MAX);
        assert_eq!(
            received(&mut f),
            vec![vec![0], vec![1], vec![2], vec![3], vec![4]]
        );
    }

    #[test]
    fn a_stale_entry_is_dropped_rather_than_delivered_late() {
        // The rule the whole module exists for. ARCHITECTURE says to queue
        // location while offline; the protocol says a stale location is worse
        // than none. Reconnecting is a licence to send a *fresh* position.
        let mut f = fixture();
        let mut stale = message(&f, b"position at 10:00");
        stale.expires_at = Some(at(60));
        f.outbox.enqueue(&stale, at(0)).expect("enqueue");

        let report = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(3600), usize::MAX);
        assert!(report.sent.is_empty(), "an hour late is not worth sending");
        assert_eq!(report.dropped.len(), 1);
        assert_eq!(report.dropped[0].reason, DropReason::Expired);
        assert!(received(&mut f).is_empty(), "nothing reached the peer");
        assert!(f.outbox.is_empty());
    }

    #[test]
    fn an_entry_still_inside_its_expiry_is_sent() {
        let mut f = fixture();
        let mut fresh = message(&f, b"position");
        fresh.expires_at = Some(at(600));
        f.outbox.enqueue(&fresh, at(0)).expect("enqueue");

        let report = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(300), usize::MAX);
        assert_eq!(report.sent.len(), 1);
        assert!(report.dropped.is_empty());
    }

    #[test]
    fn a_durable_entry_survives_any_amount_of_offline() {
        // An SOS, a tombstone, a consent revocation: late is bad, lost is worse.
        let mut f = fixture();
        f.outbox
            .enqueue(&message(&f, b"sos"), at(0))
            .expect("enqueue");
        let report = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(86_400 * 7), usize::MAX);
        assert_eq!(report.sent.len(), 1, "a week later, still worth sending");
        assert!(report.dropped.is_empty());
    }

    #[test]
    fn a_newer_state_message_supersedes_the_one_queued_behind_it() {
        // An hour offline drains as one current position, not sixty historical
        // ones.
        let mut f = fixture();
        for n in 0..10u8 {
            let body = [n];
            let mut update = message(&f, &body);
            update.coalesce_key = Some("location".to_owned());
            let (_, superseded) = f
                .outbox
                .enqueue(&update, at(u64::from(n) * 60))
                .expect("enqueue");
            if n > 0 {
                assert_eq!(
                    superseded.expect("the previous one").reason,
                    DropReason::Superseded
                );
            }
            assert_eq!(f.outbox.len(), 1, "only ever one position waiting");
        }

        f.outbox
            .drain(&f.transport, &mut f.sessions, at(600), usize::MAX);
        assert_eq!(
            received(&mut f),
            vec![vec![9]],
            "the newest position, and only it"
        );
    }

    #[test]
    fn coalescing_is_per_channel_and_per_key() {
        let mut f = fixture();
        let other: ChannelId = "other".to_owned();
        f.transport.open(&other).expect("open");

        let mut location = message(&f, b"location");
        location.coalesce_key = Some("location".to_owned());
        f.outbox.enqueue(&location, at(0)).expect("enqueue");

        let mut battery = message(&f, b"battery");
        battery.coalesce_key = Some("battery".to_owned());
        f.outbox.enqueue(&battery, at(1)).expect("enqueue");

        let mut elsewhere = message(&f, b"location elsewhere");
        elsewhere.channel = other;
        elsewhere.coalesce_key = Some("location".to_owned());
        f.outbox.enqueue(&elsewhere, at(2)).expect("enqueue");

        assert_eq!(
            f.outbox.len(),
            3,
            "different keys and different channels do not collide"
        );
    }

    #[test]
    fn an_event_without_a_coalescing_key_is_never_superseded() {
        let mut f = fixture();
        for n in 0..3u8 {
            f.outbox
                .enqueue(&message(&f, &[n]), at(u64::from(n)))
                .expect("enqueue");
        }
        assert_eq!(f.outbox.len(), 3, "events accumulate; state does not");
    }

    #[test]
    fn an_urgent_message_drains_ahead_of_a_backlog() {
        // An SOS must not sit behind forty queued locations.
        let mut f = fixture();
        for n in 0..40u8 {
            f.outbox
                .enqueue(&message(&f, &[n]), at(u64::from(n)))
                .expect("enqueue");
        }
        let mut sos = message(&f, b"sos");
        sos.priority = Priority::High;
        f.outbox.enqueue(&sos, at(100)).expect("enqueue");

        let report = f.outbox.drain(&f.transport, &mut f.sessions, at(200), 1);
        assert_eq!(report.sent.len(), 1);
        let delivered = received(&mut f);
        assert_eq!(
            delivered,
            vec![b"sos".to_vec()],
            "the urgent one went first despite being queued last"
        );
    }

    #[test]
    fn the_budget_bounds_one_pass() {
        // A background wake-up with thirty seconds of runtime must not try to
        // flush an hour of backlog and be killed halfway.
        let mut f = fixture();
        for n in 0..10u8 {
            f.outbox
                .enqueue(&message(&f, &[n]), at(u64::from(n)))
                .expect("enqueue");
        }
        let report = f.outbox.drain(&f.transport, &mut f.sessions, at(20), 3);
        assert_eq!(report.sent.len(), 3);
        assert_eq!(f.outbox.len(), 7, "the rest waits for the next pass");
    }

    #[test]
    fn an_unreachable_backend_defers_and_backs_off() {
        let mut f = fixture();
        // A channel the memory transport does not know: its sends fail.
        let missing: ChannelId = "not-open".to_owned();
        let mut message = message(&f, b"queued");
        message.channel = missing;
        f.outbox.enqueue(&message, at(0)).expect("enqueue");

        let report = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(1), usize::MAX);
        assert_eq!(report.dropped.len(), 1);
        assert_eq!(report.dropped[0].reason, DropReason::ChannelUnknown);
        assert!(
            f.outbox.is_empty(),
            "an unknown channel is terminal, not a retry"
        );
    }

    #[test]
    fn a_retired_channel_takes_its_whole_backlog_with_it() {
        // Holding a backlog for a channel nothing will ever be deliverable on
        // only guarantees it is stale when the pair is re-established.
        let mut f = fixture();
        for n in 0..5u8 {
            f.outbox
                .enqueue(&message(&f, &[n]), at(u64::from(n)))
                .expect("enqueue");
        }
        f.transport.retire(&f.channel).expect("retire");

        let report = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(10), usize::MAX);
        assert_eq!(report.dropped.len(), 5, "all five, not just the first");
        assert!(
            report
                .dropped
                .iter()
                .all(|d| d.reason == DropReason::ChannelRetired)
        );
        assert!(f.outbox.is_empty());
    }

    #[test]
    fn an_unknown_peer_defers_rather_than_dropping() {
        // The bundle has not been verified yet. The message is still worth
        // sending once it has been, so it waits.
        let mut f = fixture();
        let mut stranger = message(&f, b"for a stranger");
        stranger.peer = "dev_NEW".to_owned();
        f.outbox.enqueue(&stranger, at(0)).expect("enqueue");

        let report = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(1), usize::MAX);
        assert_eq!(report.deferred.len(), 1);
        assert_eq!(report.deferred[0].reason, DeferReason::PeerUnknown);
        assert_eq!(f.outbox.len(), 1, "still queued");
        assert_eq!(report.needs_session(), Vec::<&str>::new());
    }

    #[test]
    fn a_backed_off_entry_is_not_retried_until_it_is_due() {
        let mut f = fixture();
        let mut stranger = message(&f, b"x");
        stranger.peer = "dev_NEW".to_owned();
        f.outbox.enqueue(&stranger, at(0)).expect("enqueue");

        let first = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(1), usize::MAX);
        assert_eq!(first.deferred[0].attempts, 1);

        let immediately = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(2), usize::MAX);
        assert!(
            immediately.is_empty(),
            "backoff means the next pass skips it entirely"
        );

        let later = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(1000), usize::MAX);
        assert_eq!(later.deferred.len(), 1, "and picks it up when due");
        assert_eq!(later.deferred[0].attempts, 2);
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_for(0), Duration::from_secs(30));
        assert_eq!(backoff_for(1), Duration::from_secs(60));
        assert_eq!(backoff_for(2), Duration::from_secs(120));
        assert_eq!(
            backoff_for(30),
            BACKOFF_CEILING,
            "never longer than the caller's own cadence"
        );
    }

    #[test]
    fn expiry_is_evaluated_before_anything_is_sent() {
        // A long offline stretch costs one pass over the queue, not a burst of
        // stale traffic followed by a cleanup.
        let mut f = fixture();
        for n in 0..5u8 {
            let body = [n];
            let mut stale = message(&f, &body);
            stale.expires_at = Some(at(60));
            f.outbox.enqueue(&stale, at(0)).expect("enqueue");
        }
        f.outbox
            .enqueue(&message(&f, b"durable"), at(0))
            .expect("enqueue");

        let report = f
            .outbox
            .drain(&f.transport, &mut f.sessions, at(3600), usize::MAX);
        assert_eq!(report.dropped.len(), 5);
        assert_eq!(report.sent.len(), 1);
        assert_eq!(received(&mut f), vec![b"durable".to_vec()]);
    }

    #[test]
    fn forgetting_a_peer_empties_its_backlog() {
        // The outbox half of a roster removal: a removed device must stop being
        // sent to immediately.
        let mut f = fixture();
        for n in 0..3u8 {
            f.outbox
                .enqueue(&message(&f, &[n]), at(u64::from(n)))
                .expect("enqueue");
        }
        let dropped = f.outbox.forget_peer("dev_B");
        assert_eq!(dropped.len(), 3);
        assert!(
            dropped
                .iter()
                .all(|d| d.reason == DropReason::PeerForgotten)
        );
        assert!(f.outbox.is_empty());
        assert_eq!(f.outbox.pending_for("dev_B"), 0);
    }

    #[test]
    fn a_channel_full_of_durable_messages_refuses_rather_than_evicting_one() {
        // Dropping a durable message to make room for another is a decision no
        // library should make on the caller's behalf.
        let mut f = fixture();
        for n in 0..MAX_QUEUED_PER_CHANNEL {
            f.outbox
                .enqueue(&message(&f, b"durable"), at(n as u64))
                .expect("enqueue");
        }
        assert_eq!(
            f.outbox.enqueue(&message(&f, b"one more"), at(9999)),
            Err(EnqueueError::Full {
                channel: f.channel.clone()
            })
        );
    }

    #[test]
    fn a_full_channel_evicts_a_stale_tolerant_entry_to_make_room() {
        let mut f = fixture();
        let mut expiring = message(&f, b"position");
        expiring.expires_at = Some(at(100_000));
        f.outbox.enqueue(&expiring, at(0)).expect("enqueue");
        for n in 1..MAX_QUEUED_PER_CHANNEL {
            f.outbox
                .enqueue(&message(&f, b"durable"), at(n as u64))
                .expect("enqueue");
        }

        let (_, evicted) = f
            .outbox
            .enqueue(&message(&f, b"one more"), at(9999))
            .expect("room was made");
        assert_eq!(
            evicted.expect("something was evicted").reason,
            DropReason::Expired,
            "the entry that was allowed to go stale goes first"
        );
        assert_eq!(f.outbox.len(), MAX_QUEUED_PER_CHANNEL);
    }

    #[test]
    fn the_queue_survives_a_restart() {
        let mut f = fixture();
        f.outbox
            .enqueue(&message(&f, b"across a restart"), at(0))
            .expect("enqueue");

        let snapshot = f.outbox.export();
        let json = serde_json::to_vec(&snapshot).expect("serialises");
        let read_back: OutboxSnapshot = serde_json::from_slice(&json).expect("deserialises");
        let mut restored = Outbox::import(&read_back).expect("imports");

        let report = restored.drain(&f.transport, &mut f.sessions, at(1), usize::MAX);
        assert_eq!(report.sent.len(), 1);
        assert_eq!(received(&mut f), vec![b"across a restart".to_vec()]);
    }

    #[test]
    fn ids_do_not_repeat_across_a_restart() {
        let mut f = fixture();
        let (first, _) = f
            .outbox
            .enqueue(&message(&f, b"a"), at(0))
            .expect("enqueue");
        let mut restored = Outbox::import(&f.outbox.export()).expect("imports");
        let (second, _) = restored
            .enqueue(&message(&f, b"b"), at(1))
            .expect("enqueue");
        assert_ne!(first, second);
    }

    #[test]
    fn a_future_snapshot_version_is_refused() {
        let outbox = Outbox::new();
        let mut snapshot = outbox.export();
        snapshot.v += 1;
        assert!(matches!(
            Outbox::import(&snapshot),
            Err(SnapshotError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn a_restored_queue_still_holds_plaintext_which_is_the_documented_cost() {
        // Asserted rather than only described, because it is the tradeoff that
        // buys re-sealing after a session is lost — and whoever changes it should
        // have to change this test and read why.
        let mut f = fixture();
        f.outbox
            .enqueue(&message(&f, b"57.7089,11.9746"), at(0))
            .expect("enqueue");

        let snapshot = f.outbox.export();
        assert_eq!(
            snapshot.entries[0].plaintext, b"57.7089,11.9746",
            "the body is in the snapshot in the clear: store it accordingly"
        );
    }
}
