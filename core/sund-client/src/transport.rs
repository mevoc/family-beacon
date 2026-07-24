//! The transport port.
//!
//! Narrow on purpose. It carries what `docs/FamilyBeacon-Protocol.md` →
//! Transport assumptions asks for and nothing more:
//!
//! ```text
//! send(channel, ciphertext, priority, ttl) → message_id
//! subscribe(channel) → stream of (message_id, ciphertext, received_at)
//! ack(channel, message_id)
//! channel lifecycle: open(channel), retire(channel)
//! ```
//!
//! Two things it deliberately does **not** carry:
//!
//! - **Sund's management plane** — device registry, key bundles, invitations,
//!   server-enforced revocation. ntfy has no analogue for any of it, and
//!   widening the port until both backends fit would design Sund mode down to
//!   the weaker backend's level. Membership lives above the port, in the roster
//!   layer, and Sund mode implements that same logic *more strongly* by also
//!   using its management plane (`docs/FamilyBeacon-TryMode.md` → The rule that
//!   keeps this honest).
//! - **A loop of its own.** [`Subscription`] is pulled, not pushed. The core has
//!   to be drivable from outside — WorkManager on Android, BGTask on iOS — and
//!   a callback-shaped stream is also the part of the UniFFI surface that
//!   generates worst (CLAUDE.md decision #6, "Known costs, accepted"). A caller
//!   that wants a background loop builds one around this; the core does not
//!   assume it may run whenever it likes.
//!
//! Delivery through any implementation is at-least-once and per-channel
//! ordered; cross-channel order is undefined. The protocol's dedupe ids and
//! sequence numbers absorb the difference, so this port does not try to.

use std::time::{Duration, SystemTime};

/// A duplex channel between two devices. Its concrete form is the backend's
/// business: a Sund queue pair, or an ntfy topic.
pub type ChannelId = String;

/// A backend-assigned message identifier, used to acknowledge.
pub type MessageId = String;

/// The wake-up urgency a sender attaches to a message.
///
/// Sund's wire form is one bit, not a scale — the server never reads payloads,
/// so it cannot know a message is an SOS and simply forwards the hint to the
/// pinger. The protocol's "maximum priority" for `sos` and "high priority" for
/// `attention` therefore both land on [`Priority::High`]; what separates them
/// is the TTL (an hour-old "call me now" is noise; an SOS gets the maximum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Priority {
    /// No wake-up hint.
    #[default]
    Normal,
    /// Ask the backend to wake the recipient now.
    High,
}

/// One outbound message.
#[derive(Debug, Clone)]
pub struct Outbound {
    /// Ciphertext from the session layer. The port never sees plaintext.
    pub ciphertext: Vec<u8>,
    /// Wake-up urgency.
    pub priority: Priority,
    /// How long the backend should hold the message. `None` takes the
    /// backend's default. A short TTL is a feature for location — a stale
    /// position is worse than none — and expiry shows up as a `seq` gap.
    pub ttl: Option<Duration>,
}

impl Outbound {
    /// An ordinary message with the backend's default TTL.
    pub fn new(ciphertext: Vec<u8>) -> Self {
        Self {
            ciphertext,
            priority: Priority::Normal,
            ttl: None,
        }
    }

    /// Ask the backend to wake the recipient.
    #[must_use]
    pub fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Bound how long the backend holds the message.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

/// One inbound message, as the backend hands it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The backend's id for this message; the argument to [`Transport::ack`].
    pub id: MessageId,
    /// Ciphertext for the session layer.
    pub ciphertext: Vec<u8>,
    /// When the *backend* received it, which is not when it was sent. Clock
    /// skew and queue latency both live in that gap, so freshness decisions
    /// belong to the protocol layer's `sent` and `seq`, not to this field.
    pub received_at: SystemTime,
}

/// What can go wrong at the port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// No such channel, or it was never opened.
    UnknownChannel(ChannelId),
    /// The channel was retired. Retirement is one-way.
    Retired(ChannelId),
    /// Anything backend-specific: HTTP status, socket error, ntfy cache miss.
    Backend(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownChannel(c) => write!(f, "unknown channel `{c}`"),
            Self::Retired(c) => write!(f, "channel `{c}` is retired"),
            Self::Backend(detail) => write!(f, "transport backend: {detail}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// A pull-based stream of deliveries on one channel.
pub trait Subscription {
    /// Take the next delivery, or `None` when the channel has nothing waiting.
    ///
    /// Never blocks: the caller owns the schedule. Messages stay pending until
    /// [`Transport::ack`] takes them, so a delivery that is dropped — process
    /// killed, battery died — comes back on the next subscription.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] if the channel went away underneath the
    /// subscription.
    fn next_delivery(&mut self) -> Result<Option<Delivery>, TransportError>;
}

/// The port itself. `sund-client` is one implementation; `ntfy-client` (Try
/// mode, deferred until Sund mode works end to end) is the other, and an
/// in-memory one ([`crate::memory`]) is what makes the layers above testable
/// with no server at all.
pub trait Transport {
    /// Establish a channel. Idempotent: opening an open channel is not an error.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] if the backend refuses, or if the channel
    /// was already retired.
    fn open(&self, channel: &ChannelId) -> Result<(), TransportError>;

    /// Retire a channel and discard what it holds. One-way, and in Sund mode it
    /// is also enforced server-side — the stronger half of the same operation.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] if the channel is unknown.
    fn retire(&self, channel: &ChannelId) -> Result<(), TransportError>;

    /// Enqueue a message.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] if the channel is unknown or retired, or
    /// the backend rejects the message.
    fn send(&self, channel: &ChannelId, message: Outbound) -> Result<MessageId, TransportError>;

    /// Begin pulling deliveries.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] if the channel is unknown or retired.
    fn subscribe(&self, channel: &ChannelId) -> Result<Box<dyn Subscription>, TransportError>;

    /// Acknowledge a delivery so it is not redelivered.
    ///
    /// # Errors
    ///
    /// Returns a [`TransportError`] if the channel is unknown or retired.
    fn ack(&self, channel: &ChannelId, message: &MessageId) -> Result<(), TransportError>;
}
