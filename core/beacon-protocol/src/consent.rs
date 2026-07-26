//! The consent state machine, normative in `docs/FamilyBeacon-Protocol.md`.
//!
//! Consent is not UI polish on top of the protocol; it is enforced *at the
//! sender, in the protocol layer*. Data for a feature without a grant never
//! leaves the device — which is why this type answers a question about
//! emission ([`ConsentState::may_send`]) rather than exposing a policy the app
//! layer is trusted to consult.
//!
//! Two sets, not one. Most features are outbound: this device grants an
//! observer the right to see something of its own. `attention` inverts the
//! roles — the grant is held by the party being reached — but not the rule:
//! the peer still enforces it by refusing to emit, so this device must track
//! what peers have advertised *to* it as well as what it has issued.

use crate::envelope::MessageType;
use crate::ledger::{LedgerEntry, LedgerEvent};
use std::collections::HashSet;

/// A grantable feature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Feature {
    /// Position sharing.
    Location,
    /// Battery level sharing.
    Battery,
    /// Geofence crossing reports.
    Geofence,
    /// Inbound: permission for a peer to interrupt this device.
    Attention,
    /// Delivery and seen reporting for routine messages. A feature in its own
    /// right because "seen" tracking of location updates is
    /// surveillance-adjacent; both directions are aware of it.
    Receipts,
    /// A feature name this build does not know, kept so a grant from a newer
    /// peer round-trips rather than being silently dropped.
    Unknown(String),
}

impl Feature {
    /// The wire string for this feature.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Location => "location",
            Self::Battery => "battery",
            Self::Geofence => "geofence",
            Self::Attention => "attention",
            Self::Receipts => "receipts",
            Self::Unknown(s) => s,
        }
    }
}

impl From<&str> for Feature {
    fn from(s: &str) -> Self {
        match s {
            "location" => Self::Location,
            "battery" => Self::Battery,
            "geofence" => Self::Geofence,
            "attention" => Self::Attention,
            "receipts" => Self::Receipts,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

/// What the app layer is asking to emit.
///
/// A receipt is not gated by its own type but by what it is a receipt *for*:
/// receipts are mandatory for the urgent and consent types and opt-in for
/// everything else. Making the subject an argument keeps that from becoming a
/// caller convention nobody enforces.
#[derive(Debug, Clone, Copy)]
pub enum Emission<'a> {
    /// An ordinary message of this type.
    Message(&'a MessageType),
    /// A receipt for a message of this type.
    ReceiptFor(&'a MessageType),
}

/// The producer's answer.
#[derive(Debug, Clone, PartialEq)]
pub enum SendDecision {
    /// Emission is permitted.
    Allow,
    /// Emission is refused, with a reason fit for the ledger.
    Deny(DenyReason),
}

impl SendDecision {
    /// Whether emission is permitted.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Why the producer refused to emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// This device has not granted the observer the feature.
    NoGrant {
        /// The feature that would be needed.
        feature: Feature,
    },
    /// The recipient has not advertised the inbound allow this type needs.
    /// Only `attention` works this way in v1.
    NoInboundAllow {
        /// The feature that would be needed.
        feature: Feature,
    },
    /// A type this build does not understand. A client never emits one: the
    /// unknown-type tolerance is a *receiving* rule.
    UnknownType {
        /// The wire type string.
        wire_type: String,
    },
}

/// Per-peer consent, as held by one device.
#[derive(Debug, Clone, Default)]
pub struct ConsentState {
    /// Grants this device has issued: the peer may observe the feature.
    issued: HashSet<(Feature, String)>,
    /// Allows a peer has advertised to this device, for inbound features.
    advertised: HashSet<(Feature, String)>,
}

impl ConsentState {
    /// A fresh pairing.
    ///
    /// Default deny: nothing is shared, and the only things that flow are
    /// `member_info`, roster traffic and the ability to receive `sos` — which
    /// is mandatory precisely because it reports the sender's own situation
    /// rather than demanding the recipient's attention. `attention` is *not*
    /// part of a fresh pairing and must be granted like anything else.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grant `feature` to `peer`. Returns the entry the caller must ledger.
    pub fn grant(&mut self, feature: Feature, peer: &str) -> LedgerEntry {
        self.issued.insert((feature.clone(), peer.to_owned()));
        LedgerEntry::local(
            peer,
            LedgerEvent::ConsentChanged {
                feature,
                granted: true,
            },
        )
    }

    /// Revoke `feature` from `peer`. Returns the entry the caller must ledger.
    ///
    /// Takes effect locally and immediately. The `consent_update` message that
    /// follows informs the peer's UI; it does not implement the revocation, and
    /// revocation can never be blocked, delayed or made invisible by the
    /// observer.
    pub fn revoke(&mut self, feature: Feature, peer: &str) -> LedgerEntry {
        self.issued.remove(&(feature.clone(), peer.to_owned()));
        LedgerEntry::local(
            peer,
            LedgerEvent::ConsentChanged {
                feature,
                granted: false,
            },
        )
    }

    /// Record a `consent_update` received from `peer`.
    ///
    /// Informational for outbound features — the peer's own enforcement is what
    /// matters — and load-bearing for inbound ones, where this is the allow
    /// that lets this device emit.
    pub fn record_peer_advertisement(
        &mut self,
        feature: Feature,
        peer: &str,
        granted: bool,
    ) -> LedgerEntry {
        let key = (feature.clone(), peer.to_owned());
        if granted {
            self.advertised.insert(key);
        } else {
            self.advertised.remove(&key);
        }
        LedgerEntry::inbound(
            peer,
            None,
            LedgerEvent::PeerAdvertisedConsent { feature, granted },
        )
    }

    /// Whether this device has granted `feature` to `peer`.
    pub fn has_granted(&self, feature: &Feature, peer: &str) -> bool {
        self.issued.contains(&(feature.clone(), peer.to_owned()))
    }

    /// Whether `peer` has advertised an inbound allow for `feature`.
    pub fn peer_allows(&self, feature: &Feature, peer: &str) -> bool {
        self.advertised
            .contains(&(feature.clone(), peer.to_owned()))
    }

    /// The enforcement point: may this device emit to `peer`?
    pub fn may_send(&self, emission: Emission<'_>, peer: &str) -> SendDecision {
        match emission {
            Emission::Message(message_type) => self.may_send_message(message_type, peer),
            Emission::ReceiptFor(subject) => {
                // Mandatory for the types whose sender needs to know what
                // happened; opt-in for everything else, because "seen" tracking
                // of routine updates is a feature, not a default.
                if matches!(
                    subject,
                    MessageType::Sos
                        | MessageType::SosClear
                        | MessageType::Attention
                        | MessageType::ConsentUpdate
                ) {
                    SendDecision::Allow
                } else {
                    self.require_grant(Feature::Receipts, peer)
                }
            }
        }
    }

    fn may_send_message(&self, message_type: &MessageType, peer: &str) -> SendDecision {
        match message_type {
            // Never consent-gated. sos and sos_clear override sharing for their
            // own content and reception is mandatory; membership is the
            // precondition for features rather than a feature; member_info is
            // self-asserted labels; consent_update and config_update are the
            // machinery consent itself runs on.
            MessageType::Sos
            | MessageType::SosClear
            | MessageType::MemberInfo
            | MessageType::ConsentUpdate
            | MessageType::ConfigUpdate
            | MessageType::RosterIntroduce
            | MessageType::RosterRemove
            | MessageType::RosterSync
            | MessageType::ChannelOffer => SendDecision::Allow,

            MessageType::Location => self.require_grant(Feature::Location, peer),
            MessageType::Battery => self.require_grant(Feature::Battery, peer),
            MessageType::GeofenceEvent => self.require_grant(Feature::Geofence, peer),

            // The inverted one. The recipient holds the allow; the sender
            // refuses to emit without it. What the receiver additionally does
            // at delivery — presenting an allowed attention without the ringer
            // override when its interruption budget is spent, and saying so in
            // the receipt — is the receiver's policy and lives in the app layer.
            MessageType::Attention => {
                if self.peer_allows(&Feature::Attention, peer) {
                    SendDecision::Allow
                } else {
                    SendDecision::Deny(DenyReason::NoInboundAllow {
                        feature: Feature::Attention,
                    })
                }
            }

            MessageType::Receipt => self.require_grant(Feature::Receipts, peer),

            MessageType::Unknown(wire_type) => SendDecision::Deny(DenyReason::UnknownType {
                wire_type: wire_type.clone(),
            }),
        }
    }

    fn require_grant(&self, feature: Feature, peer: &str) -> SendDecision {
        if self.has_granted(&feature, peer) {
            SendDecision::Allow
        } else {
            SendDecision::Deny(DenyReason::NoGrant { feature })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "dev_B";

    fn may(state: &ConsentState, t: MessageType) -> SendDecision {
        state.may_send(Emission::Message(&t), PEER)
    }

    #[test]
    fn a_fresh_pairing_shares_nothing() {
        let state = ConsentState::new();
        assert_eq!(
            may(&state, MessageType::Location),
            SendDecision::Deny(DenyReason::NoGrant {
                feature: Feature::Location
            })
        );
        assert_eq!(
            may(&state, MessageType::Battery),
            SendDecision::Deny(DenyReason::NoGrant {
                feature: Feature::Battery
            })
        );
        assert_eq!(
            may(&state, MessageType::GeofenceEvent),
            SendDecision::Deny(DenyReason::NoGrant {
                feature: Feature::Geofence
            })
        );
    }

    #[test]
    fn sos_and_membership_flow_without_a_grant() {
        let state = ConsentState::new();
        for t in [
            MessageType::Sos,
            MessageType::SosClear,
            MessageType::MemberInfo,
            MessageType::ConsentUpdate,
            MessageType::RosterIntroduce,
            MessageType::RosterRemove,
            MessageType::RosterSync,
        ] {
            assert!(
                may(&state, t.clone()).is_allowed(),
                "{t:?} must not be gated"
            );
        }
    }

    #[test]
    fn granting_and_revoking_moves_the_enforcement_point() {
        let mut state = ConsentState::new();
        let entry = state.grant(Feature::Location, PEER);
        assert_eq!(
            entry.event,
            LedgerEvent::ConsentChanged {
                feature: Feature::Location,
                granted: true
            }
        );
        assert!(may(&state, MessageType::Location).is_allowed());

        state.revoke(Feature::Location, PEER);
        assert!(!may(&state, MessageType::Location).is_allowed());
    }

    #[test]
    fn grants_are_per_peer() {
        let mut state = ConsentState::new();
        state.grant(Feature::Location, PEER);
        let other = state.may_send(Emission::Message(&MessageType::Location), "dev_C");
        assert!(!other.is_allowed());
    }

    #[test]
    fn attention_needs_the_recipients_allow_not_the_senders_grant() {
        let mut state = ConsentState::new();
        assert_eq!(
            may(&state, MessageType::Attention),
            SendDecision::Deny(DenyReason::NoInboundAllow {
                feature: Feature::Attention
            })
        );

        // Granting it outbound is the wrong lever and must change nothing.
        state.grant(Feature::Attention, PEER);
        assert!(!may(&state, MessageType::Attention).is_allowed());

        // The recipient advertising the allow is the right one.
        state.record_peer_advertisement(Feature::Attention, PEER, true);
        assert!(may(&state, MessageType::Attention).is_allowed());

        // And it is revocable at the recipient, like any other.
        state.record_peer_advertisement(Feature::Attention, PEER, false);
        assert!(!may(&state, MessageType::Attention).is_allowed());
    }

    #[test]
    fn receipts_are_mandatory_for_urgent_types_and_opt_in_otherwise() {
        let mut state = ConsentState::new();
        for subject in [
            MessageType::Sos,
            MessageType::SosClear,
            MessageType::Attention,
            MessageType::ConsentUpdate,
        ] {
            assert!(
                state
                    .may_send(Emission::ReceiptFor(&subject), PEER)
                    .is_allowed(),
                "receipt for {subject:?} is mandatory"
            );
        }

        assert!(
            !state
                .may_send(Emission::ReceiptFor(&MessageType::Location), PEER)
                .is_allowed(),
            "seen-tracking routine location updates must be opt-in"
        );
        state.grant(Feature::Receipts, PEER);
        assert!(
            state
                .may_send(Emission::ReceiptFor(&MessageType::Location), PEER)
                .is_allowed()
        );
    }

    #[test]
    fn unknown_types_are_never_emitted() {
        let state = ConsentState::new();
        assert_eq!(
            may(&state, MessageType::Unknown("presence".into())),
            SendDecision::Deny(DenyReason::UnknownType {
                wire_type: "presence".into()
            })
        );
    }
}
