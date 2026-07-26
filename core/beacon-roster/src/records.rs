//! What a device holds locally: device records, tombstones, and the epoch.
//!
//! `docs/FamilyBeacon-Roster.md` → Roster state. The shapes are small; what
//! matters about them is which fields mean anything.
//!
//! **`identity_pk` is the only security-bearing field.** `display_name`,
//! `member_group` and `role` are self-asserted by the device they describe and
//! are authority for nothing. A device that renames itself "Mum's phone" gains
//! nothing, a `member_group` is never consulted by a grant or a channel, and a
//! `role` never confers power over another device — there is no in-app admin, and
//! that is the roster's whole position on roles.

use beacon_protocol::roster::{DeviceState, RemovalReason, VouchedSubject};
use serde::{Deserialize, Serialize};

/// One device in the family, as this device knows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Transport-layer id: a Sund device id, or in Try mode the id minted at
    /// join.
    pub device_id: String,
    /// The device's protocol identity key, base64.
    ///
    /// Nothing cryptographically binds this to `device_id` — the vouch is the
    /// binding. Sund ties the same id to a transport key it lists; when the two
    /// disagree the roster wins, and the disagreement is the injected-device
    /// signal.
    pub identity_pk: String,
    /// Self-asserted display label.
    pub display_name: String,
    /// Self-asserted grouping label. Advisory; never presented as an assurance
    /// that two devices belong to one person, because nothing checks that.
    pub member_group: String,
    /// Self-asserted role label. Seeds defaults, confers no authority.
    pub role: String,
    /// RFC 3339 UTC.
    pub joined_at: String,
    /// The device that vouched. Equals `device_id` for the founding device,
    /// which self-vouches.
    pub introduced_by: String,
    /// Active, or tombstoned.
    pub state: DeviceState,
}

impl DeviceRecord {
    /// Build the record a verified vouch establishes.
    #[must_use]
    pub fn from_vouch(subject: &VouchedSubject, introduced_by: &str) -> Self {
        Self {
            device_id: subject.device_id.clone(),
            identity_pk: subject.identity_pk.clone(),
            display_name: subject.display_name.clone(),
            member_group: subject.member_group.clone(),
            role: subject.role.clone(),
            joined_at: subject.joined_at.clone(),
            introduced_by: introduced_by.to_owned(),
            state: DeviceState::Active,
        }
    }

    /// Whether this device is currently in the family.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state == DeviceState::Active
    }
}

/// A removal record. Permanent for the named device id.
///
/// Never garbage collected within the family's life: a roster that forgets a
/// removal re-admits the removed device on the next reconciliation, which is
/// precisely the failure a lost-phone removal must not have.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// The device removed.
    pub subject: String,
    /// The stated reason.
    pub reason: RemovalReason,
    /// RFC 3339 UTC.
    pub removed_at: String,
    /// The device that signed the removal.
    pub removed_by: String,
    /// The epoch this removal established.
    pub epoch: u64,
}

/// How this device describes itself when founding a family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfDescription {
    /// This device's transport-layer id.
    pub device_id: String,
    /// Self-asserted display label.
    pub display_name: String,
    /// Self-asserted grouping label.
    pub member_group: String,
    /// Self-asserted role label.
    pub role: String,
    /// RFC 3339 UTC.
    pub joined_at: String,
}

impl SelfDescription {
    /// The vouch subject describing this device, given its identity key.
    #[must_use]
    pub fn subject(&self, identity_pk: String) -> VouchedSubject {
        VouchedSubject {
            device_id: self.device_id.clone(),
            identity_pk,
            display_name: self.display_name.clone(),
            member_group: self.member_group.clone(),
            role: self.role.clone(),
            joined_at: self.joined_at.clone(),
        }
    }
}
