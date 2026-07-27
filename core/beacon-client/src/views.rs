//! The value types the app renders.
//!
//! Flat, owned and free of borrows, because everything here crosses the FFI in
//! the next step and `beacon-ffi` is supposed to hold no decision a test could
//! fail on. Nothing in this module is state: these are projections of what the
//! layers below already hold.
//!
//! The one thing to keep straight is which list means what. [`MemberRow`] comes
//! from the roster — a signed vouch is why a device is in it. [`ServerDeviceRow`]
//! comes from Sund's device list, which is authoritative for revocation and for
//! locating key material and is **not** authoritative for who is in the family
//! (`docs/FamilyBeacon-Roster.md`). A device in the second list and not the first
//! is the injected-device signal, and a UI that merged them would hide it.

use std::time::SystemTime;

use beacon_roster::DeviceRecord;
use sund_client::client::DeviceRecord as ServerDeviceRecord;

/// One device in the family, as the roster knows it.
///
/// `identity_pk` is the only security-bearing field. `display_name`,
/// `member_group` and `role` are self-asserted by the device they describe and
/// are authority for nothing — a device that renames itself "Mum's phone" gains
/// nothing by it, and `role` never confers power over another device, because
/// there is no in-app admin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRow {
    /// The device's transport-layer id.
    pub device_id: String,
    /// The device's protocol identity key, base64. The value a bundle is
    /// verified against.
    pub identity_pk: String,
    /// Self-asserted display label.
    pub display_name: String,
    /// Self-asserted grouping label. Advisory, and never to be presented as an
    /// assurance that two devices belong to one person: nothing checks that.
    pub member_group: String,
    /// Self-asserted role label. Seeds defaults, confers no authority.
    pub role: String,
    /// RFC 3339 UTC.
    pub joined_at: String,
    /// The device that vouched. Equals `device_id` for the founding device,
    /// which self-vouches.
    pub introduced_by: String,
    /// Whether the device is currently in the family, as opposed to tombstoned.
    pub active: bool,
    /// Whether this row is the device the app is running on.
    pub is_self: bool,
}

impl MemberRow {
    pub(crate) fn from_record(record: &DeviceRecord, self_id: &str) -> Self {
        Self {
            device_id: record.device_id.clone(),
            identity_pk: record.identity_pk.clone(),
            display_name: record.display_name.clone(),
            member_group: record.member_group.clone(),
            role: record.role.clone(),
            joined_at: record.joined_at.clone(),
            introduced_by: record.introduced_by.clone(),
            active: record.is_active(),
            is_self: record.device_id == self_id,
        }
    }
}

/// One device as **the server** lists it.
///
/// Deliberately a different type from [`MemberRow`], with no `display_name` and
/// no identity key: there is nothing here a client may trust about who is in the
/// family. It is for reconciliation — showing the user that the server carries a
/// device the family never vouched for, which is the one place a dishonest host
/// becomes visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerDeviceRow {
    /// The device id.
    pub device_id: String,
    /// Whether the server has revoked it. Revoked devices stay listed so peers
    /// can see that a device was removed rather than merely vanishing.
    pub revoked: bool,
    /// Whether the roster carries this device as an active member.
    ///
    /// `false` with `revoked: false` is the injected-device signal.
    pub vouched: bool,
    /// When the server last saw a signed request from it.
    pub last_seen: Option<SystemTime>,
}

impl ServerDeviceRow {
    pub(crate) fn from_record(record: &ServerDeviceRecord, vouched: bool) -> Self {
        Self {
            device_id: record.id.clone(),
            revoked: record.revoked,
            vouched,
            last_seen: record.last_seen,
        }
    }
}
