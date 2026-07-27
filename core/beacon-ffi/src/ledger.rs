//! The transparency ledger's vocabulary, as the app renders it.
//!
//! This module is the largest thing in the crate and it is all mirror. That is
//! deliberate: the ledger rule has no exemptions, so every event the core can
//! produce must be nameable on the far side of the FFI, and a binding that
//! flattened these into a string plus a bag of fields would push the sentence
//! back into the app — where three platforms would write three versions of it.
//!
//! Every conversion below is a total match. A variant added to `beacon-protocol`
//! is therefore a compile error here rather than an event the user never sees,
//! which is the property worth having: the alternative to duplication is not
//! "no duplication", it is a `_ => Other` arm that silently swallows the next
//! message type somebody adds.

use beacon_protocol::consent::{DenyReason, Feature};
use beacon_protocol::envelope::{MessageType, RejectReason};
use beacon_protocol::ledger::{Direction, LedgerEntry, LedgerEvent};
use beacon_protocol::roster::RemovalReason;

/// Which way a ledgered event moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DirectionView {
    /// Arrived from a peer.
    Inbound,
    /// Left for a peer.
    Outbound,
    /// Neither: a decision this device made about a peer.
    Local,
}

/// A v1 message type, or the wire string of one this build does not know.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MessageTypeView {
    /// Position report.
    Location,
    /// Battery level and charging state.
    Battery,
    /// Broadcast about the sender's own situation. Reception is mandatory.
    Sos,
    /// Stands down a previous SOS on every device.
    SosClear,
    /// Directed "contact me urgently" nudge.
    Attention,
    /// Geofence crossing.
    GeofenceEvent,
    /// Advertises a grant or revocation.
    ConsentUpdate,
    /// Shared configuration.
    ConfigUpdate,
    /// Self-asserted display labels.
    MemberInfo,
    /// Signed vouch admitting a device.
    RosterIntroduce,
    /// Signed tombstone removing a device.
    RosterRemove,
    /// Periodic full-roster digest.
    RosterSync,
    /// Hands a peer the queue address it needs to reach this device.
    ChannelOffer,
    /// Delivery/seen reporting.
    Receipt,
    /// A type this build does not know, named so the ledger can still say what
    /// arrived — "app update needed?" rather than silence.
    Unknown {
        /// The wire type string, verbatim.
        wire_type: String,
    },
}

impl From<MessageType> for MessageTypeView {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::Location => Self::Location,
            MessageType::Battery => Self::Battery,
            MessageType::Sos => Self::Sos,
            MessageType::SosClear => Self::SosClear,
            MessageType::Attention => Self::Attention,
            MessageType::GeofenceEvent => Self::GeofenceEvent,
            MessageType::ConsentUpdate => Self::ConsentUpdate,
            MessageType::ConfigUpdate => Self::ConfigUpdate,
            MessageType::MemberInfo => Self::MemberInfo,
            MessageType::RosterIntroduce => Self::RosterIntroduce,
            MessageType::RosterRemove => Self::RosterRemove,
            MessageType::RosterSync => Self::RosterSync,
            MessageType::ChannelOffer => Self::ChannelOffer,
            MessageType::Receipt => Self::Receipt,
            MessageType::Unknown(wire_type) => Self::Unknown { wire_type },
        }
    }
}

/// A shareable feature, or the wire name of one this build does not know.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FeatureView {
    /// Position sharing.
    Location,
    /// Battery level sharing.
    Battery,
    /// Geofence crossing reports.
    Geofence,
    /// Inbound: permission for a peer to interrupt this device.
    Attention,
    /// Delivery and seen reporting.
    Receipts,
    /// A feature name this build does not know, kept so a grant from a newer
    /// peer round-trips rather than being silently dropped.
    Unknown {
        /// The wire feature name, verbatim.
        name: String,
    },
}

impl From<Feature> for FeatureView {
    fn from(value: Feature) -> Self {
        match value {
            Feature::Location => Self::Location,
            Feature::Battery => Self::Battery,
            Feature::Geofence => Self::Geofence,
            Feature::Attention => Self::Attention,
            Feature::Receipts => Self::Receipts,
            Feature::Unknown(name) => Self::Unknown { name },
        }
    }
}

/// Why the producer refused to emit.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum DenyReasonView {
    /// This device has not granted the peer the feature.
    NoGrant {
        /// The feature that would be needed.
        feature: FeatureView,
    },
    /// The recipient has not advertised the inbound allow this type needs.
    NoInboundAllow {
        /// The feature that would be needed.
        feature: FeatureView,
    },
    /// A type this build does not understand. A client never emits one.
    UnknownType {
        /// The wire type string.
        wire_type: String,
    },
}

impl From<DenyReason> for DenyReasonView {
    fn from(value: DenyReason) -> Self {
        match value {
            DenyReason::NoGrant { feature } => Self::NoGrant {
                feature: feature.into(),
            },
            DenyReason::NoInboundAllow { feature } => Self::NoInboundAllow {
                feature: feature.into(),
            },
            DenyReason::UnknownType { wire_type } => Self::UnknownType { wire_type },
        }
    }
}

/// Why a message was refused at the boundary.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum RejectReasonView {
    /// Not parseable as an envelope at all.
    Malformed {
        /// What went wrong.
        detail: String,
    },
    /// A breaking envelope version this build cannot read.
    UnsupportedVersion {
        /// The version found on the wire.
        found: u8,
    },
    /// A required string field was present but empty.
    EmptyField {
        /// Which field.
        field: String,
    },
    /// `body` was not a JSON object.
    BodyNotObject,
    /// `sent` was not a well-formed RFC 3339 instant.
    BadTimestamp {
        /// What was found.
        value: String,
    },
    /// The claimed sender is not the device the session authenticated.
    ///
    /// Worth showing plainly: it is the shape a forged attribution takes.
    SenderMismatch {
        /// The `sender` field's claim.
        claimed: String,
        /// The device the session layer actually authenticated.
        authenticated: String,
    },
}

impl From<RejectReason> for RejectReasonView {
    fn from(value: RejectReason) -> Self {
        match value {
            RejectReason::Malformed(detail) => Self::Malformed { detail },
            RejectReason::UnsupportedVersion { found } => Self::UnsupportedVersion { found },
            // `&'static str` is not a bindable type, so this is the one field
            // that changes shape rather than merely moving.
            RejectReason::EmptyField(field) => Self::EmptyField {
                field: field.to_owned(),
            },
            RejectReason::BodyNotObject => Self::BodyNotObject,
            RejectReason::BadTimestamp(value) => Self::BadTimestamp { value },
            RejectReason::SenderMismatch {
                claimed,
                authenticated,
            } => Self::SenderMismatch {
                claimed,
                authenticated,
            },
        }
    }
}

/// Why a device was removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RemovalReasonView {
    /// The device removed itself and left.
    Left,
    /// Another device removed it.
    Removed,
    /// Removed as lost or stolen.
    Lost,
}

impl From<RemovalReason> for RemovalReasonView {
    fn from(value: RemovalReason) -> Self {
        match value {
            RemovalReason::Left => Self::Left,
            RemovalReason::Removed => Self::Removed,
            RemovalReason::Lost => Self::Lost,
        }
    }
}

/// What happened, in terms a person can be shown.
///
/// The rule of thumb `docs/FamilyBeacon-Roster.md` states, and the reason the
/// membership events are separate variants rather than one `MembershipChanged`:
/// **if it changes who can reach you, it is a ledger event with a sentence a
/// person can read.** None of them may be aggregated away in the UI.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum LedgerEventView {
    /// A message of a known type was accepted.
    Received {
        /// The type that arrived.
        message_type: MessageTypeView,
    },
    /// A message this build does not understand arrived. Its body was dropped
    /// and nothing was acknowledged.
    ReceivedUnknownType {
        /// The wire type string, verbatim.
        wire_type: String,
    },
    /// A message was refused at the boundary.
    Rejected {
        /// Why.
        reason: RejectReasonView,
    },
    /// A message left this device.
    Sent {
        /// The type that was sent.
        message_type: MessageTypeView,
    },
    /// The producer refused to emit, which is where consent is enforced.
    SendRefused {
        /// What the app tried to send.
        message_type: MessageTypeView,
        /// Why the protocol layer refused.
        reason: DenyReasonView,
    },
    /// This device's own user changed a grant.
    ConsentChanged {
        /// The feature.
        feature: FeatureView,
        /// Whether it is now granted.
        granted: bool,
    },
    /// A peer advertised the state of a grant it holds — informational, and
    /// enforced by that peer refusing to emit, never by this device.
    PeerAdvertisedConsent {
        /// The feature.
        feature: FeatureView,
        /// Whether the peer says it is granted.
        granted: bool,
    },
    /// A device was admitted to the family, and who vouched for it.
    DeviceJoined {
        /// The device that vouched. Equals the joined device itself only for the
        /// founding device, which self-vouches.
        vouched_by: String,
    },
    /// A device was removed, by whom and for which stated reason.
    DeviceRemoved {
        /// The device that signed the tombstone.
        removed_by: String,
        /// The stated reason.
        reason: RemovalReasonView,
    },
    /// A vouch was refused.
    VouchRejected {
        /// Why, in terms that can be shown.
        reason: String,
    },
    /// A vouch exceeded the introducer's churn budget and is held for this
    /// device's own user to approve.
    AdmissionHeld {
        /// How many membership events that introducer signed inside the window —
        /// the number to put in the sentence: "Dad's phone has added or removed
        /// 6 devices today — admit Emma's tablet?"
        events_in_window: u32,
    },
    /// A held admission was resolved by this device's user.
    AdmissionResolved {
        /// Whether it was admitted.
        admitted: bool,
    },
    /// A device exists on the server that no family member vouched for.
    ///
    /// The injected-device signal — the one place a dishonest host becomes
    /// visible to the family. Never an admission.
    UnvouchedDeviceListed,
    /// The epoch advanced, which every removal causes.
    EpochBumped {
        /// The epoch now established.
        epoch: u64,
    },
    /// This device and a peer hold removals for each other.
    ///
    /// Surfaced, never resolved: there is no principled winner, and an automatic
    /// tie-break would let a device manufacture the outcome.
    FamilySplit {
        /// The device on the other side of the split.
        counterpart: String,
    },
    /// A pair channel became usable in one direction.
    ChannelEstablished {
        /// Whether this device can now *send* to the peer, as opposed to the
        /// peer having been given the address to send here.
        outbound: bool,
    },
    /// A channel offer was refused.
    ChannelOfferRefused {
        /// Why, in terms that can be shown.
        reason: String,
    },
    /// A peer changed one of its self-asserted labels.
    LabelsChanged {
        /// Which label: `display_name`, `member_group` or `role`.
        field: String,
        /// What it is now.
        value: String,
    },
}

impl From<LedgerEvent> for LedgerEventView {
    fn from(value: LedgerEvent) -> Self {
        match value {
            LedgerEvent::Received { message_type } => Self::Received {
                message_type: message_type.into(),
            },
            LedgerEvent::ReceivedUnknownType { wire_type } => {
                Self::ReceivedUnknownType { wire_type }
            }
            LedgerEvent::Rejected { reason } => Self::Rejected {
                reason: reason.into(),
            },
            LedgerEvent::Sent { message_type } => Self::Sent {
                message_type: message_type.into(),
            },
            LedgerEvent::SendRefused {
                message_type,
                reason,
            } => Self::SendRefused {
                message_type: message_type.into(),
                reason: reason.into(),
            },
            LedgerEvent::ConsentChanged { feature, granted } => Self::ConsentChanged {
                feature: feature.into(),
                granted,
            },
            LedgerEvent::PeerAdvertisedConsent { feature, granted } => {
                Self::PeerAdvertisedConsent {
                    feature: feature.into(),
                    granted,
                }
            }
            LedgerEvent::DeviceJoined { vouched_by } => Self::DeviceJoined { vouched_by },
            LedgerEvent::DeviceRemoved { removed_by, reason } => Self::DeviceRemoved {
                removed_by,
                reason: reason.into(),
            },
            LedgerEvent::VouchRejected { reason } => Self::VouchRejected { reason },
            LedgerEvent::AdmissionHeld { events_in_window } => Self::AdmissionHeld {
                // A count of membership events inside a rolling day, bounded by
                // the churn budget. `usize` is not a bindable type and the
                // saturation point is orders of magnitude above the cap.
                events_in_window: u32::try_from(events_in_window).unwrap_or(u32::MAX),
            },
            LedgerEvent::AdmissionResolved { admitted } => Self::AdmissionResolved { admitted },
            LedgerEvent::UnvouchedDeviceListed => Self::UnvouchedDeviceListed,
            LedgerEvent::EpochBumped { epoch } => Self::EpochBumped { epoch },
            LedgerEvent::FamilySplit { counterpart } => Self::FamilySplit { counterpart },
            LedgerEvent::ChannelEstablished { outbound } => Self::ChannelEstablished { outbound },
            LedgerEvent::ChannelOfferRefused { reason } => Self::ChannelOfferRefused { reason },
            LedgerEvent::LabelsChanged { field, value } => Self::LabelsChanged {
                field: field.to_owned(),
                value,
            },
        }
    }
}

/// One entry for the device's activity log.
///
/// Carries no timestamp: the clock is the app's, and a core that invented its
/// own would write entries that disagree with the rest of the device's log. The
/// app stamps each entry as it appends it to Room.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LedgerEntryView {
    /// Which way it moved.
    pub direction: DirectionView,
    /// The device at the other end.
    pub peer: String,
    /// The envelope id, where the event has one.
    pub message_id: Option<String>,
    /// What happened.
    pub event: LedgerEventView,
}

impl From<LedgerEntry> for LedgerEntryView {
    fn from(entry: LedgerEntry) -> Self {
        Self {
            direction: match entry.direction {
                Direction::Inbound => DirectionView::Inbound,
                Direction::Outbound => DirectionView::Outbound,
                Direction::Local => DirectionView::Local,
            },
            peer: entry.peer,
            message_id: entry.message_id,
            event: entry.event.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_crosses_with_its_event_intact() {
        let crossed = LedgerEntryView::from(LedgerEntry::local(
            "dev_A",
            LedgerEvent::DeviceJoined {
                vouched_by: "dev_A".to_owned(),
            },
        ));

        assert_eq!(crossed.direction, DirectionView::Local);
        assert_eq!(crossed.peer, "dev_A");
        assert_eq!(crossed.message_id, None);
        assert_eq!(
            crossed.event,
            LedgerEventView::DeviceJoined {
                vouched_by: "dev_A".to_owned()
            }
        );
    }

    #[test]
    fn an_unknown_message_type_keeps_its_wire_string() {
        // The whole point of the Unknown variant: the ledger can still name what
        // arrived, so the user can be told an update might be needed instead of
        // being shown nothing.
        let crossed = MessageTypeView::from(MessageType::Unknown("presence".to_owned()));
        assert_eq!(
            crossed,
            MessageTypeView::Unknown {
                wire_type: "presence".to_owned()
            }
        );
    }

    #[test]
    fn a_forged_attribution_crosses_with_both_names() {
        // A rejection the user should be able to read in full: which device
        // claimed to be the sender, and which one actually was.
        let crossed = LedgerEntryView::from(LedgerEntry::inbound(
            "dev_B",
            Some("m1".to_owned()),
            LedgerEvent::Rejected {
                reason: RejectReason::SenderMismatch {
                    claimed: "dev_A".to_owned(),
                    authenticated: "dev_B".to_owned(),
                },
            },
        ));

        match crossed.event {
            LedgerEventView::Rejected {
                reason:
                    RejectReasonView::SenderMismatch {
                        claimed,
                        authenticated,
                    },
            } => {
                assert_eq!(claimed, "dev_A");
                assert_eq!(authenticated, "dev_B");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_static_field_name_survives_as_an_owned_string() {
        let crossed = RejectReasonView::from(RejectReason::EmptyField("sender"));
        assert_eq!(
            crossed,
            RejectReasonView::EmptyField {
                field: "sender".to_owned()
            }
        );
    }
}
