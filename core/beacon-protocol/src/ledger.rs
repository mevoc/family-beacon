//! The transparency ledger: the protocol-level half of the ethical line.
//!
//! `docs/FamilyBeacon-Protocol.md` → Design constraints states the rule without
//! an exception: every message sent or received produces an entry, and *a type
//! that "shouldn't be shown to the user" is a design smell*. ETHICS.md carries
//! the same rule for the server side — no query about a device may be invisible
//! to that device.
//!
//! This module is the vocabulary, not the storage. Persistence belongs to the
//! app layer, which owns the platform's database; the core's job is to make it
//! impossible to handle a message without producing the entry that names it.
//! That is why the receive path returns [`crate::Reception`] — outcome and
//! ledger entry together — rather than letting a caller take one and skip the
//! other.

use crate::consent::{DenyReason, Feature};
use crate::envelope::{MessageType, RejectReason};

/// Which way a ledgered event moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Arrived from a peer.
    Inbound,
    /// Left for a peer.
    Outbound,
    /// Neither: a decision this device made about a peer, such as a revocation.
    Local,
}

/// What happened, in terms a person can be shown.
#[derive(Debug, Clone, PartialEq)]
pub enum LedgerEvent {
    /// A message of a known type was accepted.
    Received {
        /// The type that arrived.
        message_type: MessageType,
    },
    /// A message this build does not understand arrived. Ledgered by name so
    /// the user can be told what to do about it ("app update needed?"); the
    /// body is dropped and nothing is acknowledged.
    ReceivedUnknownType {
        /// The wire type string, verbatim.
        wire_type: String,
    },
    /// A message was refused at the boundary.
    Rejected {
        /// Why.
        reason: RejectReason,
    },
    /// A message left this device.
    Sent {
        /// The type that was sent.
        message_type: MessageType,
    },
    /// The producer refused to emit, which is where consent is enforced.
    SendRefused {
        /// What the app tried to send.
        message_type: MessageType,
        /// Why the protocol layer refused.
        reason: DenyReason,
    },
    /// This device's own user changed a grant.
    ConsentChanged {
        /// The feature.
        feature: Feature,
        /// Whether it is now granted.
        granted: bool,
    },
    /// A peer advertised the state of a grant it holds — informational, and
    /// enforced by that peer refusing to emit, never by this device.
    PeerAdvertisedConsent {
        /// The feature.
        feature: Feature,
        /// Whether the peer says it is granted.
        granted: bool,
    },
}

/// One entry in the device's activity log.
///
/// Deliberately free of a timestamp field: the clock is the app layer's, and a
/// core that invented its own would produce entries that disagree with the rest
/// of the device's log.
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerEntry {
    /// Which way it moved.
    pub direction: Direction,
    /// The device at the other end.
    pub peer: String,
    /// The envelope id, where the event has one.
    pub message_id: Option<String>,
    /// What happened.
    pub event: LedgerEvent,
}

impl LedgerEntry {
    /// An inbound entry.
    pub fn inbound(peer: &str, message_id: Option<String>, event: LedgerEvent) -> Self {
        Self {
            direction: Direction::Inbound,
            peer: peer.to_owned(),
            message_id,
            event,
        }
    }

    /// An outbound entry.
    pub fn outbound(peer: &str, message_id: Option<String>, event: LedgerEvent) -> Self {
        Self {
            direction: Direction::Outbound,
            peer: peer.to_owned(),
            message_id,
            event,
        }
    }

    /// A local decision about a peer.
    pub fn local(peer: &str, event: LedgerEvent) -> Self {
        Self {
            direction: Direction::Local,
            peer: peer.to_owned(),
            message_id: None,
            event,
        }
    }
}
