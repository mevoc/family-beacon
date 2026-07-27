//! The value types the app receives, and the one it hands back.

use beacon_client::{MemberRow, ServerDeviceRow};

/// A device's two Ed25519 seeds, crossing the boundary as bytes.
///
/// The app generates these once with [`crate::generate_seeds`] and writes both
/// into the platform keystore — Android Keystore, iOS Keychain — never into the
/// state blob and never into ordinary preferences. Losing them is losing the
/// device's identity: there is no recovery path, and the device has to be
/// re-admitted to the family with a fresh vouch.
///
/// Two seeds rather than one is the point, not an accident:
/// `device` signs HTTP requests to the server, `identity` is the roster's
/// `identity_pk` and signs bundles, vouches and tombstones. Nothing
/// cryptographically binds them — the vouch is the binding — which is what
/// limits a dishonest host to adding a row it can never make anyone believe.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SeedsView {
    /// The request-signing seed. 32 bytes.
    pub device: Vec<u8>,
    /// The protocol-identity seed. 32 bytes.
    pub identity: Vec<u8>,
}

impl From<beacon_client::Seeds> for SeedsView {
    fn from(seeds: beacon_client::Seeds) -> Self {
        Self {
            device: seeds.device_seed().to_vec(),
            identity: seeds.identity_seed().to_vec(),
        }
    }
}

impl SeedsView {
    /// Rebuild the core's seeds, checking both lengths.
    ///
    /// The check itself lives in `beacon-client`, so what a wrong length means
    /// is decided by a crate with tests rather than here.
    pub(crate) fn to_seeds(&self) -> Result<beacon_client::Seeds, crate::ClientException> {
        Ok(beacon_client::Seeds::from_slices(
            &self.device,
            &self.identity,
        )?)
    }
}

/// How this device describes itself to the family.
///
/// All three are self-asserted and authority for nothing. A device that renames
/// itself "Mum's phone" gains nothing by it, `member_group` never makes two
/// devices one principal, and `role` never confers power over another device —
/// there is no in-app admin.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ProfileView {
    /// Display label, e.g. "Emma's phone".
    pub display_name: String,
    /// Grouping label. Advisory only.
    pub member_group: String,
    /// Role label. Seeds UI defaults, confers no authority.
    pub role: String,
}

impl From<ProfileView> for beacon_client::Profile {
    fn from(profile: ProfileView) -> Self {
        Self {
            display_name: profile.display_name,
            member_group: profile.member_group,
            role: profile.role,
        }
    }
}

/// One device in the family, **as the roster knows it**.
///
/// A signed vouch is why a row is here. Contrast [`ServerDeviceRowView`], which
/// is what the server lists and is not authority for membership.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct MemberRowView {
    /// The device's transport-layer id. The principal that grants, channels and
    /// ledger entries all name.
    pub device_id: String,
    /// The device's protocol identity key, base64. The row's only
    /// security-bearing field, and the value a bundle is verified against.
    pub identity_pk: String,
    /// Self-asserted display label.
    pub display_name: String,
    /// Self-asserted grouping label.
    pub member_group: String,
    /// Self-asserted role label.
    pub role: String,
    /// RFC 3339 UTC.
    pub joined_at: String,
    /// The device that vouched. Equals `device_id` for the founding device.
    pub introduced_by: String,
    /// Whether the device is currently in the family, as opposed to tombstoned.
    pub active: bool,
    /// Whether this row is the device the app is running on.
    pub is_self: bool,
}

impl From<MemberRow> for MemberRowView {
    fn from(row: MemberRow) -> Self {
        Self {
            device_id: row.device_id,
            identity_pk: row.identity_pk,
            display_name: row.display_name,
            member_group: row.member_group,
            role: row.role,
            joined_at: row.joined_at,
            introduced_by: row.introduced_by,
            active: row.active,
            is_self: row.is_self,
        }
    }
}

/// One device **as the server lists it**.
///
/// Deliberately a different type from [`MemberRowView`], with no display name
/// and no identity key: there is nothing here a client may trust about who is in
/// the family. A row with `vouched == false` and `revoked == false` is a device
/// nobody in the family vouched for — the injected-device signal, and the one
/// place a host that writes to its own database becomes visible.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerDeviceRowView {
    /// The device id.
    pub device_id: String,
    /// Whether the server has revoked it. Revoked devices stay listed so peers
    /// can see that a device was removed rather than merely vanishing.
    pub revoked: bool,
    /// Whether the roster carries this device as an active member.
    pub vouched: bool,
    /// When the server last saw a signed request from it.
    pub last_seen: Option<std::time::SystemTime>,
}

impl From<ServerDeviceRow> for ServerDeviceRowView {
    fn from(row: ServerDeviceRow) -> Self {
        Self {
            device_id: row.device_id,
            revoked: row.revoked,
            vouched: row.vouched,
            last_seen: row.last_seen,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_client::Seeds;

    #[test]
    fn seeds_round_trip_through_the_boundary_shape() {
        let original = Seeds::from_parts([5u8; 32], [6u8; 32]);
        let crossed = SeedsView::from(original.clone());

        assert_eq!(crossed.device.len(), 32);
        assert_eq!(crossed.identity.len(), 32);
        assert_eq!(crossed.to_seeds().expect("accepted"), original);
    }

    #[test]
    fn a_wrong_length_seed_is_refused_at_the_boundary() {
        let crossed = SeedsView {
            device: vec![5u8; 32],
            identity: vec![6u8; 31],
        };

        let error = crossed.to_seeds().expect_err("refused");
        assert!(
            matches!(error, crate::ClientException::State { .. }),
            "{error:?}"
        );
    }
}
