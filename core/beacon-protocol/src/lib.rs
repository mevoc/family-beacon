//! Family Beacon's own protocol layer: envelope codec, message types, the
//! consent state machine and the transparency ledger's vocabulary.
//!
//! Specified in `docs/FamilyBeacon-Protocol.md`. Everything here sits *above*
//! the transport port, which means it is identical in Sund mode and in Try
//! mode — envelope, consent and ledger alike (`docs/FamilyBeacon-TryMode.md` →
//! Where the seam goes). Nothing in this crate knows what a server is.
//!
//! The crate holds no family membership **state**: that is the roster layer of
//! `docs/FamilyBeacon-Roster.md`, implemented in the `beacon-roster` crate. What
//! does live here is that layer's wire vocabulary ([`roster`]) — because the
//! registry is one list, and because the payloads its signatures cover are
//! exactly the kind of thing three implementations must agree on byte-for-byte.
//! Verifying one of those signatures needs an Ed25519 key, canonical JSON and a
//! local roster to check the introducer against; none of that belongs to this
//! crate, and keeping it out is what lets this crate stay serde-only.
//!
//! ```
//! use beacon_protocol::{Reception, receive};
//! use beacon_protocol::consent::{ConsentState, Emission, SendDecision};
//! use beacon_protocol::envelope::{Envelope, MessageType};
//!
//! // The producer decides before anything leaves the device.
//! let consent = ConsentState::new();
//! let decision = consent.may_send(Emission::Message(&MessageType::Location), "dev_B");
//! assert!(matches!(decision, SendDecision::Deny(_))); // default deny
//!
//! // The receiver always gets an outcome and a ledger entry together.
//! let wire = br#"{"v":1,"id":"m1","seq":1,"type":"sos","sent":"2026-07-19T10:04:12Z",
//!                 "sender":"dev_A","body":{"recorded_at":"2026-07-19T10:04:10Z"}}"#;
//! let Reception { outcome, ledger } = receive(wire, "dev_A");
//! assert!(outcome.envelope().is_some());
//! assert_eq!(ledger.peer, "dev_A");
//! ```

pub mod consent;
pub mod envelope;
pub mod ledger;
pub mod roster;

use envelope::{Envelope, RejectReason};
use ledger::{LedgerEntry, LedgerEvent};

/// What the receive path concluded about one inbound plaintext.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// A known type, structurally valid, from the device the session
    /// authenticated.
    Accepted(Envelope),
    /// A type this build does not understand. The envelope is returned with its
    /// body dropped: the ledger names what arrived, nothing is acknowledged,
    /// and the app must not treat this as an error.
    UnknownType(Envelope),
    /// Refused at the boundary.
    Rejected(RejectReason),
}

impl Outcome {
    /// The envelope, for the two outcomes that have one.
    pub fn envelope(&self) -> Option<&Envelope> {
        match self {
            Self::Accepted(e) | Self::UnknownType(e) => Some(e),
            Self::Rejected(_) => None,
        }
    }
}

/// An outcome and the ledger entry that must accompany it.
///
/// The two travel together on purpose. The ledger rule has no exemptions, so
/// the receive path does not offer a way to obtain the outcome without also
/// obtaining the entry — a caller can still fail to persist it, but not without
/// visibly dropping it on the floor.
#[derive(Debug, Clone, PartialEq)]
pub struct Reception {
    /// What was concluded.
    pub outcome: Outcome,
    /// What to write to the device's activity log.
    pub ledger: LedgerEntry,
}

/// Decode, validate and attribute one inbound plaintext.
///
/// `authenticated_sender` is the device the *session layer* authenticated —
/// vodozemac's, in the shipping stack. The envelope's own `sender` field is
/// attribution after decryption, never the source of trust, so the two are
/// compared here and a mismatch is rejected and ledgered.
pub fn receive(plaintext: &[u8], authenticated_sender: &str) -> Reception {
    let envelope = match Envelope::decode(plaintext) {
        Ok(e) => e,
        Err(reason) => return rejected(authenticated_sender, None, reason),
    };

    if let Err(reason) = envelope.check_sender(authenticated_sender) {
        return rejected(authenticated_sender, Some(envelope.id.clone()), reason);
    }

    let id = envelope.id.clone();
    if envelope.message_type.is_known() {
        let message_type = envelope.message_type.clone();
        Reception {
            outcome: Outcome::Accepted(envelope),
            ledger: LedgerEntry::inbound(
                authenticated_sender,
                Some(id),
                LedgerEvent::Received { message_type },
            ),
        }
    } else {
        let wire_type = envelope.message_type.as_str().to_owned();
        Reception {
            outcome: Outcome::UnknownType(envelope.without_body()),
            ledger: LedgerEntry::inbound(
                authenticated_sender,
                Some(id),
                LedgerEvent::ReceivedUnknownType { wire_type },
            ),
        }
    }
}

fn rejected(peer: &str, message_id: Option<String>, reason: RejectReason) -> Reception {
    Reception {
        outcome: Outcome::Rejected(reason.clone()),
        ledger: LedgerEntry::inbound(peer, message_id, LedgerEvent::Rejected { reason }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envelope::MessageType;

    fn wire(message_type: &str, sender: &str) -> Vec<u8> {
        format!(
            r#"{{"v":1,"id":"m1","seq":7,"type":"{message_type}",
                 "sent":"2026-07-19T10:04:12Z","sender":"{sender}","body":{{"x":1}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn a_known_type_is_accepted_and_ledgered() {
        let r = receive(&wire("location", "dev_A"), "dev_A");
        assert!(matches!(r.outcome, Outcome::Accepted(_)));
        assert_eq!(
            r.ledger.event,
            LedgerEvent::Received {
                message_type: MessageType::Location
            }
        );
        assert_eq!(r.ledger.message_id.as_deref(), Some("m1"));
    }

    #[test]
    fn an_unknown_type_is_ledgered_by_name_and_its_body_dropped() {
        let r = receive(&wire("presence", "dev_A"), "dev_A");
        match &r.outcome {
            Outcome::UnknownType(e) => {
                assert_eq!(e.body, serde_json::json!({}));
                assert_eq!(e.seq, 7, "attribution survives so staleness still works");
            }
            other => panic!("expected UnknownType, got {other:?}"),
        }
        assert_eq!(
            r.ledger.event,
            LedgerEvent::ReceivedUnknownType {
                wire_type: "presence".into()
            }
        );
    }

    #[test]
    fn a_forged_sender_is_rejected_and_ledgered() {
        let r = receive(&wire("location", "dev_A"), "dev_B");
        assert!(matches!(r.outcome, Outcome::Rejected(_)));
        assert!(matches!(
            r.ledger.event,
            LedgerEvent::Rejected {
                reason: RejectReason::SenderMismatch { .. }
            }
        ));
        assert_eq!(r.ledger.peer, "dev_B", "ledgered against who actually sent");
    }

    #[test]
    fn garbage_still_produces_a_ledger_entry() {
        // The rule has no exemptions, including for input that never parsed.
        let r = receive(b"not an envelope", "dev_A");
        assert!(matches!(r.outcome, Outcome::Rejected(_)));
        assert!(matches!(
            r.ledger.event,
            LedgerEvent::Rejected {
                reason: RejectReason::Malformed(_)
            }
        ));
        assert_eq!(r.ledger.message_id, None);
    }
}
