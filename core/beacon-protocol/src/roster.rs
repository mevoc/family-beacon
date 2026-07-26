//! The roster's wire types and the exact payloads its signatures cover.
//!
//! `docs/FamilyBeacon-Roster.md` → Wire types specifies three message types, and
//! that document is explicit about where they belong: "the three types above
//! belong in [the protocol spec's] registry, and its test vectors must cover the
//! vouch and removal signatures". So the *types* live here, beside the registry
//! entry that names them, and the **state machine does not** — that is
//! `beacon-roster`, which is the layer the same document keeps separate on
//! purpose.
//!
//! The split is not arbitrary. What lives here is data with no dependency beyond
//! serde; verifying a vouch needs an Ed25519 key, canonical JSON and a local
//! roster to check the introducer against, none of which this crate has or should
//! acquire. What this module *does* own is the thing three implementations must
//! agree on byte-for-byte: the shape of each message, and precisely which fields
//! each signature covers. Those are the [`VouchPayload`], [`RemovalPayload`] and
//! [`SyncPayload`] views below, and they exist as separate types so that "what is
//! signed" is a thing you can read rather than a convention in a function
//! somewhere.
//!
//! None of these three types is consent-gated. Membership is not a shareable
//! feature — it is the precondition for having features — and all three are
//! ledgered like everything else.

use serde::{Deserialize, Serialize};

/// Whether a device is currently in the family.
///
/// A removed record is *kept*, not deleted: `docs/FamilyBeacon-Roster.md` wants
/// the family's history to stay readable in the ledger, and a roster that forgot
/// a removal would re-admit the device on the next reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceState {
    /// In the family.
    Active,
    /// Tombstoned. Permanent for this device id.
    Removed,
}

/// Why a device left the family.
///
/// The distinction is for the person reading the ledger, not for the state
/// machine — all three produce the same tombstone and the same irreversibility.
/// "Emma's phone was removed by Dad's phone" needs the reason to be a sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RemovalReason {
    /// The device removed itself and left. Never counts against a churn budget.
    Left,
    /// Another device removed it.
    Removed,
    /// Removed as lost or stolen. The case that must never be delayed by a rate
    /// limiter.
    Lost,
}

impl RemovalReason {
    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Removed => "removed",
            Self::Lost => "lost",
        }
    }
}

/// The device being vouched for, as the vouch describes it.
///
/// `identity_pk` is the only security-bearing field. `display_name`,
/// `member_group` and `role` are self-asserted labels that confer nothing — a
/// device that calls itself "Mum's phone" gains no authority, and a `role` never
/// grants power over another device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VouchedSubject {
    /// The subject's transport-layer device id.
    pub device_id: String,
    /// The subject's protocol identity key, base64. See
    /// `docs/FamilyBeacon-Sessions.md` — this is *not* its Sund request-signing
    /// key, and this vouch is the only thing binding it to `device_id`.
    pub identity_pk: String,
    /// Self-asserted display label.
    pub display_name: String,
    /// Self-asserted grouping label. Advisory, unverified, and never read by
    /// anything security-relevant.
    pub member_group: String,
    /// Self-asserted role label. Seeds defaults; confers no authority.
    pub role: String,
    /// RFC 3339 UTC.
    pub joined_at: String,
}

/// `roster_introduce` — the only path into a roster.
///
/// "I authenticated this device in person, and I am putting my name on it."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterIntroduce {
    /// Who is being admitted.
    pub subject: VouchedSubject,
    /// The introducer's epoch at the time of vouching.
    pub epoch: u64,
    /// Base64 Ed25519 signature by the **introducer's** identity key over
    /// [`VouchPayload`].
    pub vouch: String,
}

/// `roster_remove` — a tombstone, irreversible for the named device id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterRemove {
    /// The device being removed.
    pub subject: String,
    /// Why.
    pub reason: RemovalReason,
    /// RFC 3339 UTC.
    pub removed_at: String,
    /// The epoch this removal establishes.
    pub epoch: u64,
    /// Base64 Ed25519 signature by the remover's identity key over
    /// [`RemovalPayload`].
    pub sig: String,
}

/// One device as `roster_sync` reports it.
///
/// Deliberately three fields. Sync spreads knowledge of *removals* quickly and
/// knowledge of additions only as confirmation of a vouch the receiver can
/// verify, so it carries no labels and no vouch — there is nothing here a
/// receiver could mistake for an admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncDevice {
    /// The device id.
    pub device_id: String,
    /// Its identity key, base64.
    pub identity_pk: String,
    /// Active or removed.
    pub state: DeviceState,
}

/// `roster_sync` — the whole roster, because a family roster is small.
///
/// Tens of entries at most, so there is no delta protocol and none is wanted.
/// Sent on reconnect, on wake and periodically; a digest that matches locally
/// makes it a no-op, which is the common case and the reason it can run often.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterSync {
    /// The sender's current epoch.
    pub epoch: u64,
    /// Every device the sender knows, **sorted by `device_id`**. The ordering is
    /// part of the format: the digest is computed over it, so two senders with
    /// the same knowledge must produce the same bytes.
    pub devices: Vec<SyncDevice>,
    /// Lowercase hex SHA-256 over the canonical encoding of [`SyncPayload`].
    pub digest: String,
}

/// Exactly what a vouch signs.
///
/// A view rather than a copy, so it cannot drift from the message it describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct VouchPayload<'a> {
    /// The subject being vouched for.
    pub subject: &'a VouchedSubject,
    /// The introducer's epoch.
    pub epoch: u64,
}

impl RosterIntroduce {
    /// The payload this message's `vouch` must verify over.
    #[must_use]
    pub fn payload(&self) -> VouchPayload<'_> {
        VouchPayload {
            subject: &self.subject,
            epoch: self.epoch,
        }
    }
}

/// Exactly what a removal signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RemovalPayload<'a> {
    /// The device being removed.
    pub subject: &'a str,
    /// Why.
    pub reason: RemovalReason,
    /// When.
    pub removed_at: &'a str,
    /// The epoch this removal establishes.
    pub epoch: u64,
}

impl RosterRemove {
    /// The payload this message's `sig` must verify over.
    #[must_use]
    pub fn payload(&self) -> RemovalPayload<'_> {
        RemovalPayload {
            subject: &self.subject,
            reason: self.reason,
            removed_at: &self.removed_at,
            epoch: self.epoch,
        }
    }
}

/// Exactly what a sync digest covers.
///
/// Note what is absent: the digest is **not** a signature. A sync rides an
/// authenticated session, so the sender is already known; the digest exists so a
/// receiver whose roster already matches can stop immediately. Nothing is
/// admitted on the strength of a sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SyncPayload<'a> {
    /// The sender's epoch.
    pub epoch: u64,
    /// The sender's devices, sorted by id.
    pub devices: &'a [SyncDevice],
}

impl RosterSync {
    /// The payload this message's `digest` is computed over.
    #[must_use]
    pub fn payload(&self) -> SyncPayload<'_> {
        SyncPayload {
            epoch: self.epoch,
            devices: &self.devices,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::MessageType;

    #[test]
    fn the_three_types_are_in_the_registry_under_these_names() {
        // The registry is one list; this is the assertion that keeps the two
        // halves of that claim honest.
        assert!(MessageType::from("roster_introduce").is_known());
        assert!(MessageType::from("roster_remove").is_known());
        assert!(MessageType::from("roster_sync").is_known());
        assert_eq!(MessageType::RosterIntroduce.as_str(), "roster_introduce");
        assert_eq!(MessageType::RosterRemove.as_str(), "roster_remove");
        assert_eq!(MessageType::RosterSync.as_str(), "roster_sync");
    }

    #[test]
    fn removal_reasons_use_their_wire_strings() {
        for (reason, wire) in [
            (RemovalReason::Left, "left"),
            (RemovalReason::Removed, "removed"),
            (RemovalReason::Lost, "lost"),
        ] {
            assert_eq!(reason.as_str(), wire);
            assert_eq!(
                serde_json::to_value(reason).expect("serialises"),
                serde_json::json!(wire)
            );
        }
    }

    #[test]
    fn device_state_uses_its_wire_strings() {
        assert_eq!(
            serde_json::to_value(DeviceState::Active).expect("serialises"),
            serde_json::json!("active")
        );
        assert_eq!(
            serde_json::to_value(DeviceState::Removed).expect("serialises"),
            serde_json::json!("removed")
        );
    }

    fn subject() -> VouchedSubject {
        VouchedSubject {
            device_id: "dev_B".into(),
            identity_pk: "cGs=".into(),
            display_name: "Emma's phone".into(),
            member_group: "Emma".into(),
            role: "child".into(),
            joined_at: "2026-07-26T10:00:00Z".into(),
        }
    }

    #[test]
    fn a_vouch_payload_covers_the_subject_and_the_epoch_and_not_the_signature() {
        let message = RosterIntroduce {
            subject: subject(),
            epoch: 3,
            vouch: "signature".into(),
        };
        let signed = serde_json::to_value(message.payload()).expect("serialises");
        assert_eq!(signed["epoch"], 3);
        assert_eq!(signed["subject"]["device_id"], "dev_B");
        assert!(
            signed.get("vouch").is_none(),
            "a signature cannot cover itself"
        );
    }

    #[test]
    fn a_removal_payload_covers_every_field_but_the_signature() {
        let message = RosterRemove {
            subject: "dev_B".into(),
            reason: RemovalReason::Lost,
            removed_at: "2026-07-26T11:00:00Z".into(),
            epoch: 4,
            sig: "signature".into(),
        };
        let signed = serde_json::to_value(message.payload()).expect("serialises");
        assert_eq!(signed["subject"], "dev_B");
        assert_eq!(signed["reason"], "lost");
        assert_eq!(signed["removed_at"], "2026-07-26T11:00:00Z");
        assert_eq!(signed["epoch"], 4);
        assert!(signed.get("sig").is_none());
    }

    #[test]
    fn a_sync_payload_covers_the_epoch_and_the_device_list() {
        let message = RosterSync {
            epoch: 2,
            devices: vec![SyncDevice {
                device_id: "dev_A".into(),
                identity_pk: "cGs=".into(),
                state: DeviceState::Active,
            }],
            digest: "deadbeef".into(),
        };
        let covered = serde_json::to_value(message.payload()).expect("serialises");
        assert_eq!(covered["epoch"], 2);
        assert_eq!(covered["devices"][0]["state"], "active");
        assert!(covered.get("digest").is_none());
    }

    #[test]
    fn the_wire_types_round_trip() {
        let message = RosterIntroduce {
            subject: subject(),
            epoch: 1,
            vouch: "sig".into(),
        };
        let json = serde_json::to_string(&message).expect("serialises");
        let back: RosterIntroduce = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, message);
    }
}
