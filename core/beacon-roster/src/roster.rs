//! The membership state machine.
//!
//! `docs/FamilyBeacon-Roster.md`, in code. Two properties shape every method
//! here, and both are worth having in mind before changing anything:
//!
//! **The server's device list is not the authority on membership.** Admission
//! requires a signed vouch from an existing member, carried end-to-end. An
//! abusive host can add a row to Sund's `devices` table; a client that admitted
//! peers from that list would pair with an injected device. So no method here
//! admits anything on the strength of a server list — [`Roster::reconcile_server_list`]
//! can only report, mark unreachable, or take capability away.
//!
//! **Removal is fail-safe and admission is fail-dangerous.** That asymmetry is
//! why the two paths differ everywhere they differ: removals apply immediately
//! even when over budget, tombstones win over records regardless of epoch, and a
//! device may always remove itself; admissions are refused on any doubt and held
//! for a human when an introducer looks like it is churning.
//!
//! There is deliberately **no admin.** Any active device may remove any other,
//! including one that has been in the family longer. Concentrating removal in an
//! admin would hand the wrong person a lock in the abusive-member case; the
//! permissive rule's failure mode is eviction — loud, ledgered and recoverable by
//! re-pairing — and the restrictive rule's is a person trapped in a family they
//! cannot alter.

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use beacon_protocol::ledger::{LedgerEntry, LedgerEvent};
use beacon_protocol::roster::{
    DeviceState, RemovalReason, RosterIntroduce, RosterRemove, RosterSync, SyncDevice,
    VouchedSubject,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use sund_client::canonical::to_canonical_json;
use sund_client::identity::{IdentityKey, IdentityPublicKey, SignaturePurpose};

use crate::churn::ChurnLog;
use crate::records::{DeviceRecord, SelfDescription, Tombstone};

/// The maximum number of *active* devices in one family.
///
/// A build-time constant, not a configuration key. It sizes the two things that
/// grow: full-mesh pairing at N·(N−1) channels (380 at the cap) and `roster_sync`
/// at O(N) per sync. Twenty is comfortably above any real family and comfortably
/// below where either becomes a design problem, so the constant exists to fail
/// honestly rather than to be tuned.
///
/// Tombstoned devices do not count. Enforcement is at admission, with a plain
/// message on both screens — never by silently dropping traffic or degrading
/// sync, because a family that hits the cap must be told, not left to discover it
/// as flakiness.
pub const MAX_ACTIVE_DEVICES: usize = 20;

/// The store format version.
pub const SNAPSHOT_VERSION: u8 = 1;

/// An outcome and the ledger entries that must accompany it.
///
/// Same discipline as `beacon_protocol::Reception`, and for the same reason: the
/// ledger rule has no exemptions, so there is no way to obtain the outcome
/// without also obtaining the entries. A caller can still fail to persist them,
/// but not without visibly dropping them on the floor.
#[derive(Debug, Clone, PartialEq)]
pub struct Applied<T> {
    /// What happened.
    pub outcome: T,
    /// What to write to the device's activity log.
    pub ledger: Vec<LedgerEntry>,
}

/// Why a vouch was refused.
///
/// Each variant carries what a sentence needs, because
/// `docs/FamilyBeacon-Roster.md` → Ledgering asks for "a vouch was rejected, and
/// why" in terms a person can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VouchRefusal {
    /// The introducer is not an active member of this device's roster. A vouch
    /// from a removed device carries no authority.
    IntroducerNotActive {
        /// The device that signed.
        introducer: String,
    },
    /// The subject already has a tombstone. This is the rule that stops a removed
    /// device being quietly reintroduced by a member who missed the removal.
    SubjectTombstoned {
        /// The device the vouch names.
        subject: String,
    },
    /// A device vouched for itself. Only the founding device may do that, and
    /// only when founding.
    SelfVouch {
        /// The device that tried.
        subject: String,
    },
    /// Admitting would exceed [`MAX_ACTIVE_DEVICES`].
    SizeCapReached {
        /// How many active devices there already are.
        active: usize,
    },
    /// The vouch signature did not verify against the introducer's identity key.
    BadSignature,
    /// An identity key in the vouch was not a usable Ed25519 public key.
    MalformedIdentityKey,
    /// The vouch names an identity key that contradicts the one already held for
    /// this device.
    ///
    /// Not treated as a label update: `identity_pk` is the security-bearing
    /// field, and a peer re-keying itself has to re-join rather than be silently
    /// updated.
    IdentityChanged {
        /// The device whose key would have changed.
        subject: String,
    },
}

impl std::fmt::Display for VouchRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IntroducerNotActive { introducer } => {
                write!(f, "`{introducer}` is not an active member")
            }
            Self::SubjectTombstoned { subject } => {
                write!(f, "`{subject}` was removed from this family before")
            }
            Self::SelfVouch { subject } => write!(f, "`{subject}` vouched for itself"),
            Self::SizeCapReached { active } => write!(
                f,
                "the family already has {active} devices, the maximum is {MAX_ACTIVE_DEVICES}"
            ),
            Self::BadSignature => write!(f, "the vouch signature did not verify"),
            Self::MalformedIdentityKey => write!(f, "the vouch carried an unusable identity key"),
            Self::IdentityChanged { subject } => {
                write!(f, "`{subject}` presented a different identity key")
            }
        }
    }
}

/// What happened to a vouch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The device is now an active member.
    Admitted,
    /// Already an active member with the same identity key. Idempotent: a
    /// re-broadcast vouch is ordinary, not an error.
    AlreadyKnown,
    /// The introducer is over its churn budget, so the vouch is quarantined for
    /// this device's own user to approve. See [`Roster::held_admissions`].
    Held {
        /// The count that triggered it, for the sentence to show.
        events_in_window: usize,
    },
    /// Refused.
    Refused(VouchRefusal),
}

/// Why a removal was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemovalRefusal {
    /// The remover is not an active member.
    RemoverNotActive {
        /// The device that signed.
        remover: String,
    },
    /// The signature did not verify against the remover's identity key.
    BadSignature,
}

impl std::fmt::Display for RemovalRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RemoverNotActive { remover } => {
                write!(f, "`{remover}` is not an active member")
            }
            Self::BadSignature => write!(f, "the removal signature did not verify"),
        }
    }
}

/// What happened to a removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Removal {
    /// Tombstoned. The caller must now retire channels with the subject and drop
    /// every grant naming it, in both directions.
    Applied,
    /// Already tombstoned. Removal is monotonic; there is no un-remove.
    AlreadyRemoved,
    /// The removal names this device. Recorded and surfaced — a removed device
    /// must never simply discover it has gone quiet — but this device does not
    /// tombstone itself.
    AboutSelf,
    /// Refused.
    Refused(RemovalRefusal),
}

/// A vouch waiting for this device's user to decide.
///
/// Keeps the introducer with the message: the record a later approval writes must
/// name who vouched, and re-deriving that from the message alone is impossible —
/// the introducer is the *authenticated sender*, which the message never carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldAdmission {
    /// The vouch as it arrived.
    pub message: RosterIntroduce,
    /// The device that vouched, as the session authenticated it.
    pub introducer: String,
    /// The count that triggered the hold, for the sentence to show.
    pub events_in_window: usize,
}

/// What a `roster_sync` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sync {
    /// The digest matched: nothing to do. The common case, and the reason sync
    /// can run often and cheaply.
    InSync,
    /// The sender is not an active member, so its view of the family carries no
    /// weight. Refused before anything is merged.
    Refused {
        /// The device that sent it.
        sender: String,
    },
    /// Merged.
    Merged {
        /// Removals learned from this sync and applied locally.
        removals_applied: usize,
        /// Devices the sender knows and this device has never seen.
        ///
        /// **Not admissions.** An anomaly to ledger and show while waiting for a
        /// vouch: sync spreads knowledge of removals quickly and knowledge of
        /// additions only as confirmation of a vouch that can be verified.
        anomalies: Vec<String>,
    },
    /// The digest did not match the contents. A malformed sync, not a merge.
    BadDigest,
}

/// One device as the server lists it, for [`Roster::reconcile_server_list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerDevice {
    /// The device id.
    pub device_id: String,
    /// Whether the server says it is revoked.
    pub revoked: bool,
}

/// What comparing the roster against the server's device list revealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerFinding {
    /// Server: revoked. Roster: active. Capability taken away, so applied.
    RevokedByServer {
        /// The device.
        device_id: String,
    },
    /// Server: listed. Roster: active. Normal — pair using its bundle, verifying
    /// the retrieved key material against the roster's `identity_pk`.
    Normal {
        /// The device.
        device_id: String,
    },
    /// Server: listed. Roster: unknown. **Do not admit.**
    ///
    /// The injected-device signal, and the one place a dishonest host becomes
    /// visible to the family.
    Unvouched {
        /// The device.
        device_id: String,
    },
    /// Server: absent. Roster: active. Revoked server-side, or the list is being
    /// manipulated. Surfaced; never tombstoned on this evidence alone.
    Unreachable {
        /// The device.
        device_id: String,
    },
}

/// The persisted form of a roster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterSnapshot {
    /// Store format version.
    pub v: u8,
    /// The device this roster belongs to.
    pub self_id: String,
    /// Device records, by id.
    pub devices: Vec<DeviceRecord>,
    /// Tombstones, by subject.
    pub tombstones: Vec<Tombstone>,
    /// The current epoch.
    pub epoch: u64,
    /// The churn budget's accounting.
    pub churn: ChurnLog,
    /// Vouches held for approval.
    pub held: Vec<HeldAdmission>,
    /// Peers this device has been told removed it.
    pub removed_me: Vec<String>,
}

/// Why a snapshot could not be restored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotError {
    /// A version this build does not speak.
    UnsupportedVersion {
        /// The version found.
        found: u8,
    },
    /// The snapshot belongs to a different device.
    WrongDevice {
        /// The device restoring.
        expected: String,
        /// The device that wrote it.
        found: String,
    },
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => write!(f, "unsupported roster version {found}"),
            Self::WrongDevice { expected, found } => {
                write!(f, "roster belongs to `{found}`, restoring as `{expected}`")
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

/// This device's view of who is in the family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roster {
    self_id: String,
    devices: BTreeMap<String, DeviceRecord>,
    tombstones: BTreeMap<String, Tombstone>,
    epoch: u64,
    churn: ChurnLog,
    held: BTreeMap<String, HeldAdmission>,
    removed_me: BTreeSet<String>,
}

impl Roster {
    // ---- construction -----------------------------------------------------

    /// Found a family. The founding device self-vouches at epoch 0.
    ///
    /// Its identity key is the family's first root of trust, and this is the one
    /// self-vouch the state machine accepts — see [`VouchRefusal::SelfVouch`] for
    /// every other case. The self-vouch is **not** counted against the churn
    /// budget: it is not churn inflicted on anyone.
    ///
    /// `docs/FamilyBeacon-Roster.md` open item 5 notes that a family's entire
    /// trust structure therefore roots in one QR-less act, and that whether a
    /// second device should co-sign the founding record is undecided. Nothing here
    /// forecloses that: adding a co-signature later changes how this record is
    /// *established*, not what it is.
    #[must_use]
    pub fn found(me: &SelfDescription, identity: &IdentityKey) -> Applied<Self> {
        let record = DeviceRecord {
            device_id: me.device_id.clone(),
            identity_pk: identity.public_key().to_base64(),
            display_name: me.display_name.clone(),
            member_group: me.member_group.clone(),
            role: me.role.clone(),
            joined_at: me.joined_at.clone(),
            introduced_by: me.device_id.clone(),
            state: DeviceState::Active,
        };
        let ledger = vec![LedgerEntry::local(
            &me.device_id,
            LedgerEvent::DeviceJoined {
                vouched_by: me.device_id.clone(),
            },
        )];
        let mut devices = BTreeMap::new();
        devices.insert(me.device_id.clone(), record);

        Applied {
            outcome: Self {
                self_id: me.device_id.clone(),
                devices,
                tombstones: BTreeMap::new(),
                epoch: 0,
                churn: ChurnLog::new(),
                held: BTreeMap::new(),
                removed_me: BTreeSet::new(),
            },
            ledger,
        }
    }

    /// Adopt the introducer's roster after the QR ceremony — the joining
    /// device's side of admission.
    ///
    /// `introducer` comes from the QR, where **physical co-presence is the
    /// authentication**; this layer adds no ceremony of its own and weakens
    /// neither mode's. The vouch is then verified against that co-present key, so
    /// a joiner never takes its own membership on the introducer's unsupported
    /// word.
    ///
    /// The snapshot the introducer sends is adopted wholesale — every record and
    /// every tombstone — because the joiner has no prior state to merge against
    /// and no independent way to check any of it. That is the same trust the QR
    /// already established, not an extension of it.
    ///
    /// # Errors
    ///
    /// Returns [`VouchRefusal`] if the vouch does not verify against the
    /// introducer's key, does not name this device, or names a tombstoned device.
    pub fn adopt(
        self_id: &str,
        introducer: &DeviceRecord,
        their_devices: Vec<DeviceRecord>,
        their_tombstones: Vec<Tombstone>,
        their_epoch: u64,
        vouch_for_me: &RosterIntroduce,
    ) -> Result<Applied<Self>, VouchRefusal> {
        if vouch_for_me.subject.device_id != self_id {
            return Err(VouchRefusal::SelfVouch {
                subject: vouch_for_me.subject.device_id.clone(),
            });
        }
        let introducer_key = parse_identity(&introducer.identity_pk)?;
        verify_vouch(&introducer_key, vouch_for_me)?;

        let tombstones: BTreeMap<String, Tombstone> = their_tombstones
            .into_iter()
            .map(|tombstone| (tombstone.subject.clone(), tombstone))
            .collect();
        if tombstones.contains_key(self_id) {
            return Err(VouchRefusal::SubjectTombstoned {
                subject: self_id.to_owned(),
            });
        }

        let mut ledger = Vec::new();
        let mut devices: BTreeMap<String, DeviceRecord> = BTreeMap::new();
        for record in their_devices {
            ledger.push(LedgerEntry::inbound(
                &record.device_id,
                None,
                LedgerEvent::DeviceJoined {
                    vouched_by: record.introduced_by.clone(),
                },
            ));
            devices.insert(record.device_id.clone(), record);
        }

        // This device's own record, as the vouch describes it.
        let mine = DeviceRecord::from_vouch(&vouch_for_me.subject, &introducer.device_id);
        ledger.push(LedgerEntry::local(
            self_id,
            LedgerEvent::DeviceJoined {
                vouched_by: introducer.device_id.clone(),
            },
        ));
        devices.insert(self_id.to_owned(), mine);
        devices
            .entry(introducer.device_id.clone())
            .or_insert_with(|| introducer.clone());

        Ok(Applied {
            outcome: Self {
                self_id: self_id.to_owned(),
                devices,
                tombstones,
                epoch: their_epoch,
                churn: ChurnLog::new(),
                held: BTreeMap::new(),
                removed_me: BTreeSet::new(),
            },
            ledger,
        })
    }

    // ---- queries ----------------------------------------------------------

    /// The device this roster belongs to.
    #[must_use]
    pub fn self_id(&self) -> &str {
        &self.self_id
    }

    /// The current epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Active devices, in id order.
    #[must_use]
    pub fn active(&self) -> Vec<&DeviceRecord> {
        self.devices
            .values()
            .filter(|record| record.is_active())
            .collect()
    }

    /// How many devices are active.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.devices
            .values()
            .filter(|record| record.is_active())
            .count()
    }

    /// Whether a device is an active member.
    #[must_use]
    pub fn is_active(&self, device_id: &str) -> bool {
        self.devices
            .get(device_id)
            .is_some_and(DeviceRecord::is_active)
    }

    /// One device's record, active or removed.
    #[must_use]
    pub fn record(&self, device_id: &str) -> Option<&DeviceRecord> {
        self.devices.get(device_id)
    }

    /// One device's tombstone, if it has one.
    #[must_use]
    pub fn tombstone(&self, device_id: &str) -> Option<&Tombstone> {
        self.tombstones.get(device_id)
    }

    /// Every tombstone, in subject order.
    #[must_use]
    pub fn tombstones(&self) -> Vec<&Tombstone> {
        self.tombstones.values().collect()
    }

    /// A device's verified identity key, for handing to the session layer.
    ///
    /// The value a bundle must be checked against — never the server's device
    /// list. Returns `None` for a device that is not an active member, which is
    /// the point: there is no path from "the server lists it" to a key this
    /// method will hand out.
    #[must_use]
    pub fn identity_of(&self, device_id: &str) -> Option<IdentityPublicKey> {
        let record = self.devices.get(device_id)?;
        if !record.is_active() {
            return None;
        }
        IdentityPublicKey::from_base64(&record.identity_pk).ok()
    }

    /// Vouches held for this device's user to approve, in subject order.
    #[must_use]
    pub fn held_admissions(&self) -> Vec<&HeldAdmission> {
        self.held.values().collect()
    }

    /// Peers that have told this device it was removed.
    #[must_use]
    pub fn removed_me_by(&self) -> Vec<&str> {
        self.removed_me.iter().map(String::as_str).collect()
    }

    /// Devices this roster and that device hold removals for each other.
    ///
    /// Mutual eviction, detected locally and needing no coordination.
    /// `docs/FamilyBeacon-Roster.md` is explicit that this is **surfaced, never
    /// resolved**: there is no principled winner, and any automatic tie-break —
    /// earlier timestamp, lower device id, larger surviving partition — would let
    /// a device manufacture the outcome by choosing its clock, its id or its
    /// moment. Worse, it would resolve silently an event that is almost always a
    /// human conflict.
    #[must_use]
    pub fn splits(&self) -> Vec<&str> {
        self.removed_me
            .iter()
            .filter(|peer| self.tombstones.contains_key(*peer))
            .map(String::as_str)
            .collect()
    }

    // ---- producing messages ----------------------------------------------

    /// Build a vouch admitting `subject` — the introducer's side.
    ///
    /// The size cap is checked here as well as at every verifier, so the
    /// introducer's screen can say why rather than leaving the joiner to watch
    /// nothing happen.
    ///
    /// # Errors
    ///
    /// Returns [`VouchRefusal::SizeCapReached`] if admitting would exceed
    /// [`MAX_ACTIVE_DEVICES`], [`VouchRefusal::SubjectTombstoned`] for a device
    /// that was removed before, or [`VouchRefusal::MalformedIdentityKey`] if the
    /// subject's key is unusable.
    pub fn vouch_for(
        &self,
        subject: &VouchedSubject,
        identity: &IdentityKey,
    ) -> Result<RosterIntroduce, VouchRefusal> {
        if self.tombstones.contains_key(&subject.device_id) {
            return Err(VouchRefusal::SubjectTombstoned {
                subject: subject.device_id.clone(),
            });
        }
        parse_identity(&subject.identity_pk)?;
        if !self.is_active(&subject.device_id) && self.active_count() >= MAX_ACTIVE_DEVICES {
            return Err(VouchRefusal::SizeCapReached {
                active: self.active_count(),
            });
        }

        let payload = beacon_protocol::roster::VouchPayload {
            subject,
            epoch: self.epoch,
        };
        let vouch = identity
            .sign(SignaturePurpose::Vouch, &payload)
            .map_err(|_| VouchRefusal::MalformedIdentityKey)?;
        Ok(RosterIntroduce {
            subject: subject.clone(),
            epoch: self.epoch,
            vouch,
        })
    }

    /// Remove a device, producing the tombstone to broadcast.
    ///
    /// Applies locally before returning: the caller then broadcasts the message,
    /// retires its channels with the subject and drops every grant naming it in
    /// both directions. Those grants are not suspended and do not resurrect.
    ///
    /// A device removing **itself** is always permitted and never counted against
    /// the churn budget — this is the roster-layer form of "the app can be
    /// disabled or uninstalled at any time", and no configuration, role or peer
    /// may block it.
    ///
    /// # Errors
    ///
    /// Returns [`RemovalRefusal::RemoverNotActive`] if this device is not itself
    /// an active member, because a removed device's removals carry no authority.
    pub fn remove(
        &mut self,
        subject: &str,
        reason: RemovalReason,
        removed_at: &str,
        identity: &IdentityKey,
        now: SystemTime,
    ) -> Result<Applied<RosterRemove>, RemovalRefusal> {
        if !self.is_active(&self.self_id.clone()) {
            return Err(RemovalRefusal::RemoverNotActive {
                remover: self.self_id.clone(),
            });
        }

        let epoch = self.epoch + 1;
        let payload = beacon_protocol::roster::RemovalPayload {
            subject,
            reason,
            removed_at,
            epoch,
        };
        let sig = identity
            .sign(SignaturePurpose::Removal, &payload)
            .map_err(|_| RemovalRefusal::BadSignature)?;
        let message = RosterRemove {
            subject: subject.to_owned(),
            reason,
            removed_at: removed_at.to_owned(),
            epoch,
            sig,
        };

        // A device removing itself is not churn inflicted on the family.
        let self_removal = subject == self.self_id;
        if !self_removal {
            let signed_at = timestamp_or(removed_at, now);
            self.churn.record(&self.self_id.clone(), signed_at, now);
        }

        let ledger =
            self.apply_tombstone(subject, reason, removed_at, &self.self_id.clone(), epoch);
        Ok(Applied {
            outcome: message,
            ledger,
        })
    }

    /// Build a `roster_sync` describing this roster.
    #[must_use]
    pub fn sync(&self) -> RosterSync {
        let devices = self.sync_devices();
        let digest = digest_of(self.epoch, &devices);
        RosterSync {
            epoch: self.epoch,
            devices,
            digest,
        }
    }

    fn sync_devices(&self) -> Vec<SyncDevice> {
        // BTreeMap iteration is already device_id order, which the format
        // requires: the digest is computed over the list, so two senders with the
        // same knowledge must produce the same bytes.
        self.devices
            .values()
            .map(|record| SyncDevice {
                device_id: record.device_id.clone(),
                identity_pk: record.identity_pk.clone(),
                state: record.state,
            })
            .collect()
    }

    // ---- receiving messages ----------------------------------------------

    /// Apply a `roster_introduce` from `introducer`.
    ///
    /// `introducer` is the device the *session* authenticated. The envelope layer
    /// has already refused a message whose claimed `sender` disagrees with the
    /// session, which is the roster spec's sender-mismatch rule; this method takes
    /// the authenticated value and never reads a claimed one.
    pub fn receive_introduce(
        &mut self,
        message: &RosterIntroduce,
        introducer: &str,
        now: SystemTime,
    ) -> Applied<Admission> {
        let subject_id = message.subject.device_id.clone();

        // Order matters: cheap structural refusals first, signature last, so a
        // forged vouch for a tombstoned device is reported as the tombstone it
        // violates rather than as a signature failure.
        if !self.is_active(introducer) {
            return self.refuse_vouch(
                &subject_id,
                VouchRefusal::IntroducerNotActive {
                    introducer: introducer.to_owned(),
                },
            );
        }
        if self.tombstones.contains_key(&subject_id) {
            return self.refuse_vouch(
                &subject_id,
                VouchRefusal::SubjectTombstoned {
                    subject: subject_id.clone(),
                },
            );
        }
        if subject_id == introducer {
            return self.refuse_vouch(
                &subject_id,
                VouchRefusal::SelfVouch {
                    subject: subject_id.clone(),
                },
            );
        }
        if let Some(existing) = self.devices.get(&subject_id) {
            if existing.identity_pk != message.subject.identity_pk {
                return self.refuse_vouch(
                    &subject_id,
                    VouchRefusal::IdentityChanged {
                        subject: subject_id.clone(),
                    },
                );
            }
        }
        if !self.is_active(&subject_id) && self.active_count() >= MAX_ACTIVE_DEVICES {
            return self.refuse_vouch(
                &subject_id,
                VouchRefusal::SizeCapReached {
                    active: self.active_count(),
                },
            );
        }

        let introducer_key = match self
            .identity_of(introducer)
            .ok_or(VouchRefusal::MalformedIdentityKey)
        {
            Ok(key) => key,
            Err(refusal) => return self.refuse_vouch(&subject_id, refusal),
        };
        if let Err(refusal) = verify_vouch(&introducer_key, message) {
            return self.refuse_vouch(&subject_id, refusal);
        }
        if let Err(refusal) = parse_identity(&message.subject.identity_pk) {
            return self.refuse_vouch(&subject_id, refusal);
        }

        if self.is_active(&subject_id) {
            // A re-broadcast vouch for a device already admitted with the same
            // key. Idempotent, and not charged to the introducer's budget: it
            // costs the family nothing.
            return Applied {
                outcome: Admission::AlreadyKnown,
                ledger: Vec::new(),
            };
        }

        // The budget is checked before the event is recorded, so the Nth vouch of
        // the day is admitted and the (N+1)th is held.
        if self.churn.would_exceed(introducer, now) {
            let events_in_window = self.churn.count_in_window(introducer, now);
            self.held.insert(
                subject_id.clone(),
                HeldAdmission {
                    message: message.clone(),
                    introducer: introducer.to_owned(),
                    events_in_window,
                },
            );
            return Applied {
                outcome: Admission::Held { events_in_window },
                ledger: vec![LedgerEntry::inbound(
                    &subject_id,
                    None,
                    LedgerEvent::AdmissionHeld { events_in_window },
                )],
            };
        }

        let signed_at = timestamp_or(&message.subject.joined_at, now);
        self.churn.record(introducer, signed_at, now);
        let ledger = self.admit(&message.subject, introducer);
        Applied {
            outcome: Admission::Admitted,
            ledger,
        }
    }

    /// Approve a held admission.
    ///
    /// The quarantine's exit. Approving does **not** charge the introducer's
    /// budget: the human has already made the decision the budget exists to
    /// prompt, and charging it would make the next honest admission look worse
    /// for having been approved.
    pub fn approve_held(&mut self, subject: &str) -> Applied<Option<Admission>> {
        let Some(held) = self.held.remove(subject) else {
            return Applied {
                outcome: None,
                ledger: Vec::new(),
            };
        };

        // The introducer may have been removed while the vouch sat in
        // quarantine, in which case the human is approving something that no
        // longer has an author. Re-check rather than trust the held copy: the
        // refusal rules are the same ones a fresh vouch would face.
        if !self.is_active(&held.introducer) {
            let refusal = VouchRefusal::IntroducerNotActive {
                introducer: held.introducer.clone(),
            };
            let mut ledger = vec![LedgerEntry::inbound(
                subject,
                None,
                LedgerEvent::AdmissionResolved { admitted: false },
            )];
            ledger.push(LedgerEntry::inbound(
                subject,
                None,
                LedgerEvent::VouchRejected {
                    reason: refusal.to_string(),
                },
            ));
            return Applied {
                outcome: Some(Admission::Refused(refusal)),
                ledger,
            };
        }
        if self.tombstones.contains_key(subject) {
            let refusal = VouchRefusal::SubjectTombstoned {
                subject: subject.to_owned(),
            };
            let ledger = vec![
                LedgerEntry::inbound(
                    subject,
                    None,
                    LedgerEvent::AdmissionResolved { admitted: false },
                ),
                LedgerEntry::inbound(
                    subject,
                    None,
                    LedgerEvent::VouchRejected {
                        reason: refusal.to_string(),
                    },
                ),
            ];
            return Applied {
                outcome: Some(Admission::Refused(refusal)),
                ledger,
            };
        }

        let mut ledger = vec![LedgerEntry::inbound(
            subject,
            None,
            LedgerEvent::AdmissionResolved { admitted: true },
        )];
        ledger.extend(self.admit(&held.message.subject, &held.introducer));
        Applied {
            outcome: Some(Admission::Admitted),
            ledger,
        }
    }

    /// Deny a held admission and discard it.
    pub fn deny_held(&mut self, subject: &str) -> Applied<bool> {
        if self.held.remove(subject).is_none() {
            return Applied {
                outcome: false,
                ledger: Vec::new(),
            };
        }
        Applied {
            outcome: true,
            ledger: vec![LedgerEntry::inbound(
                subject,
                None,
                LedgerEvent::AdmissionResolved { admitted: false },
            )],
        }
    }

    /// Apply a `roster_remove` from `remover`.
    ///
    /// Applies immediately even when the remover is over its churn budget. The
    /// budget counts removals — churn is introduce and remove in a loop, and
    /// budgeting only admissions would miss half the cycle — but it never refuses
    /// one: a stolen-phone removal must not be delayed by a rate limiter,
    /// whatever else that device has been doing.
    pub fn receive_remove(
        &mut self,
        message: &RosterRemove,
        remover: &str,
        now: SystemTime,
    ) -> Applied<Removal> {
        // A removal naming *this* device is handled before the active-remover
        // check, and deliberately accepted from a device this roster has already
        // removed.
        //
        // Mutual eviction is the reason. If Alice removes Bob and Bob removes
        // Alice in ignorance of each other, then by the time Bob's removal
        // reaches Alice, Bob is already inactive in Alice's roster — so requiring
        // an active remover here would make Alice refuse it, and she would never
        // learn she had been evicted. `docs/FamilyBeacon-Roster.md` requires both
        // tombstones to stand and requires the removed device to be *told*: "it
        // must never simply discover it has gone quiet."
        //
        // Accepting it is safe because it grants the remover nothing. It records
        // an informational fact about this device's own standing, takes no
        // capability from anyone else, and still requires a signature that
        // verifies against the key this roster already holds for that device — so
        // a stranger cannot forge it.
        if message.subject == self.self_id {
            return self.receive_removal_of_self(message, remover);
        }

        if !self.is_active(remover) {
            let refusal = RemovalRefusal::RemoverNotActive {
                remover: remover.to_owned(),
            };
            return Applied {
                outcome: Removal::Refused(refusal.clone()),
                ledger: vec![LedgerEntry::inbound(
                    &message.subject,
                    None,
                    LedgerEvent::VouchRejected {
                        reason: refusal.to_string(),
                    },
                )],
            };
        }
        let Some(remover_key) = self.identity_of(remover) else {
            let refusal = RemovalRefusal::BadSignature;
            return Applied {
                outcome: Removal::Refused(refusal.clone()),
                ledger: vec![LedgerEntry::inbound(
                    &message.subject,
                    None,
                    LedgerEvent::VouchRejected {
                        reason: refusal.to_string(),
                    },
                )],
            };
        };
        if remover_key
            .verify(SignaturePurpose::Removal, &message.payload(), &message.sig)
            .is_err()
        {
            return Applied {
                outcome: Removal::Refused(RemovalRefusal::BadSignature),
                ledger: vec![LedgerEntry::inbound(
                    &message.subject,
                    None,
                    LedgerEvent::VouchRejected {
                        reason: RemovalRefusal::BadSignature.to_string(),
                    },
                )],
            };
        }

        // Counted, never refused.
        let signed_at = timestamp_or(&message.removed_at, now);
        if message.subject != remover {
            self.churn.record(remover, signed_at, now);
        }

        if self.tombstones.contains_key(&message.subject) {
            return Applied {
                outcome: Removal::AlreadyRemoved,
                ledger: Vec::new(),
            };
        }

        let ledger = self.apply_tombstone(
            &message.subject,
            message.reason,
            &message.removed_at,
            remover,
            message.epoch,
        );
        Applied {
            outcome: Removal::Applied,
            ledger,
        }
    }

    /// Merge a `roster_sync` from `sender`.
    ///
    /// The merge rules, in the order they matter:
    ///
    /// 1. **Tombstones win over device records, always and regardless of epoch.**
    ///    A device the sender reports as removed is removed locally. That is the
    ///    same authority a signed `roster_remove` from that sender would carry —
    ///    any active device may remove any other — so accepting it from a sync
    ///    grants no power the sender did not already have, and it is what makes a
    ///    lost-phone removal reliable in a family whose devices are rarely all
    ///    online at once.
    /// 2. Epoch is `max(local, received)`. It orders removals for Try mode's topic
    ///    derivation; it is not a vector clock and does not arbitrate content.
    /// 3. A device the sender knows and this device does not is an **anomaly, not
    ///    an admission**.
    pub fn receive_sync(&mut self, message: &RosterSync, sender: &str) -> Applied<Sync> {
        if digest_of(message.epoch, &message.devices) != message.digest {
            return Applied {
                outcome: Sync::BadDigest,
                ledger: Vec::new(),
            };
        }
        if !self.is_active(sender) {
            return Applied {
                outcome: Sync::Refused {
                    sender: sender.to_owned(),
                },
                ledger: Vec::new(),
            };
        }
        if message.epoch == self.epoch && message.devices == self.sync_devices() {
            return Applied {
                outcome: Sync::InSync,
                ledger: Vec::new(),
            };
        }

        let mut ledger = Vec::new();
        let mut anomalies = Vec::new();
        let mut removals_applied = 0usize;

        for reported in &message.devices {
            match self.devices.get(&reported.device_id) {
                None => {
                    if !self.tombstones.contains_key(&reported.device_id) {
                        anomalies.push(reported.device_id.clone());
                        ledger.push(LedgerEntry::inbound(
                            &reported.device_id,
                            None,
                            LedgerEvent::VouchRejected {
                                reason: format!(
                                    "`{sender}` knows `{}`, which no vouch has admitted here",
                                    reported.device_id
                                ),
                            },
                        ));
                    }
                }
                Some(_) if reported.state == DeviceState::Removed => {
                    if reported.device_id == self.self_id {
                        self.removed_me.insert(sender.to_owned());
                        ledger.extend(self.split_ledger(sender));
                    } else if !self.tombstones.contains_key(&reported.device_id) {
                        removals_applied += 1;
                        let epoch = self.epoch.max(message.epoch);
                        ledger.extend(self.apply_tombstone(
                            &reported.device_id.clone(),
                            RemovalReason::Removed,
                            "",
                            sender,
                            epoch,
                        ));
                    }
                }
                Some(_) => {}
            }
        }

        if message.epoch > self.epoch {
            self.epoch = message.epoch;
            ledger.push(LedgerEntry::inbound(
                sender,
                None,
                LedgerEvent::EpochBumped { epoch: self.epoch },
            ));
        }

        Applied {
            outcome: Sync::Merged {
                removals_applied,
                anomalies,
            },
            ledger,
        }
    }

    /// Record a peer's change to its own advisory labels.
    ///
    /// A device may only change **its own** labels, which is the whole of the
    /// authentication here: `member_info` from a device with no roster record is
    /// dropped like a message from a stranger, and one device may never relabel
    /// another.
    pub fn update_labels(
        &mut self,
        device_id: &str,
        display_name: Option<&str>,
        member_group: Option<&str>,
        role: Option<&str>,
    ) -> Applied<bool> {
        let Some(record) = self.devices.get_mut(device_id) else {
            return Applied {
                outcome: false,
                ledger: Vec::new(),
            };
        };
        let mut ledger = Vec::new();
        for (field, new, current) in [
            ("display_name", display_name, &mut record.display_name),
            ("member_group", member_group, &mut record.member_group),
            ("role", role, &mut record.role),
        ] {
            if let Some(new) = new {
                if new != current.as_str() {
                    *current = new.to_owned();
                    ledger.push(LedgerEntry::inbound(
                        device_id,
                        None,
                        LedgerEvent::LabelsChanged {
                            field,
                            value: new.to_owned(),
                        },
                    ));
                }
            }
        }
        Applied {
            outcome: !ledger.is_empty(),
            ledger,
        }
    }

    /// Compare this roster against the server's device list — Sund mode only.
    ///
    /// The list is authoritative for **removal and for key-material location**,
    /// never for admission. Exactly one of the four cases mutates: a device the
    /// server says is revoked has had its capability taken away, which the server
    /// genuinely can do. The rest report.
    ///
    /// Note what a revoked device does *not* get: a tombstone. The spec's wording
    /// is "treat as removed", and a permanent tombstone would let a host that
    /// revokes everyone destroy a family's roster irreversibly — re-admission
    /// requires a fresh device id, so a lying host could force a whole family to
    /// re-pair from nothing. Deactivating the record instead keeps the honest case
    /// identical (the device is gone, loudly) while leaving the dishonest case
    /// recoverable by a fresh vouch. See `docs/FamilyBeacon-Roster.md` → Sund
    /// mode, where this reading is recorded.
    pub fn reconcile_server_list(
        &mut self,
        listed: &[ServerDevice],
    ) -> Applied<Vec<ServerFinding>> {
        let mut findings = Vec::new();
        let mut ledger = Vec::new();
        let mut seen = BTreeSet::new();

        for device in listed {
            seen.insert(device.device_id.clone());
            let known = self.devices.get(&device.device_id);
            match (device.revoked, known) {
                (true, Some(record)) if record.is_active() => {
                    findings.push(ServerFinding::RevokedByServer {
                        device_id: device.device_id.clone(),
                    });
                    if let Some(record) = self.devices.get_mut(&device.device_id) {
                        record.state = DeviceState::Removed;
                    }
                    ledger.push(LedgerEntry::local(
                        &device.device_id,
                        LedgerEvent::DeviceRemoved {
                            removed_by: "server".to_owned(),
                            reason: RemovalReason::Removed,
                        },
                    ));
                }
                (_, None) => {
                    findings.push(ServerFinding::Unvouched {
                        device_id: device.device_id.clone(),
                    });
                    ledger.push(LedgerEntry::local(
                        &device.device_id,
                        LedgerEvent::UnvouchedDeviceListed,
                    ));
                }
                (false, Some(record)) if record.is_active() => {
                    findings.push(ServerFinding::Normal {
                        device_id: device.device_id.clone(),
                    });
                }
                // Revoked-and-already-removed, or listed-and-already-removed:
                // nothing to say. The roster already agrees.
                (_, Some(_)) => {}
            }
        }

        for record in self.devices.values() {
            if record.is_active() && !seen.contains(&record.device_id) {
                findings.push(ServerFinding::Unreachable {
                    device_id: record.device_id.clone(),
                });
            }
        }

        Applied {
            outcome: findings,
            ledger,
        }
    }

    // ---- persistence ------------------------------------------------------

    /// The persisted form.
    #[must_use]
    pub fn export(&self) -> RosterSnapshot {
        RosterSnapshot {
            v: SNAPSHOT_VERSION,
            self_id: self.self_id.clone(),
            devices: self.devices.values().cloned().collect(),
            tombstones: self.tombstones.values().cloned().collect(),
            epoch: self.epoch,
            churn: self.churn.clone(),
            held: self.held.values().cloned().collect(),
            removed_me: self.removed_me.iter().cloned().collect(),
        }
    }

    /// Restore from a snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] for a future version or another device's roster.
    pub fn import(snapshot: &RosterSnapshot, self_id: &str) -> Result<Self, SnapshotError> {
        if snapshot.v != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion { found: snapshot.v });
        }
        if snapshot.self_id != self_id {
            return Err(SnapshotError::WrongDevice {
                expected: self_id.to_owned(),
                found: snapshot.self_id.clone(),
            });
        }
        Ok(Self {
            self_id: self_id.to_owned(),
            devices: snapshot
                .devices
                .iter()
                .map(|record| (record.device_id.clone(), record.clone()))
                .collect(),
            tombstones: snapshot
                .tombstones
                .iter()
                .map(|tombstone| (tombstone.subject.clone(), tombstone.clone()))
                .collect(),
            epoch: snapshot.epoch,
            churn: snapshot.churn.clone(),
            held: snapshot
                .held
                .iter()
                .map(|held| (held.message.subject.device_id.clone(), held.clone()))
                .collect(),
            removed_me: snapshot.removed_me.iter().cloned().collect(),
        })
    }

    // ---- internals --------------------------------------------------------

    /// Being told this device has been removed.
    ///
    /// Recorded and surfaced; this device does **not** tombstone itself, because
    /// a device that erased its own record could not show its user what happened —
    /// and the user's actual question ("am I still connected to my daughter?") is
    /// only answerable from a roster that still exists.
    fn receive_removal_of_self(
        &mut self,
        message: &RosterRemove,
        remover: &str,
    ) -> Applied<Removal> {
        // The remover's *recorded* key, active or not: see the note at the call
        // site for why a removed device's removal of us is still evidence.
        let Some(key) = self
            .devices
            .get(remover)
            .and_then(|record| IdentityPublicKey::from_base64(&record.identity_pk).ok())
        else {
            return Applied {
                outcome: Removal::Refused(RemovalRefusal::RemoverNotActive {
                    remover: remover.to_owned(),
                }),
                ledger: vec![LedgerEntry::inbound(
                    &message.subject,
                    None,
                    LedgerEvent::VouchRejected {
                        reason: format!("`{remover}` is not in this family"),
                    },
                )],
            };
        };
        if key
            .verify(SignaturePurpose::Removal, &message.payload(), &message.sig)
            .is_err()
        {
            return Applied {
                outcome: Removal::Refused(RemovalRefusal::BadSignature),
                ledger: vec![LedgerEntry::inbound(
                    &message.subject,
                    None,
                    LedgerEvent::VouchRejected {
                        reason: RemovalRefusal::BadSignature.to_string(),
                    },
                )],
            };
        }

        self.removed_me.insert(remover.to_owned());
        self.epoch = self.epoch.max(message.epoch);
        let mut ledger = vec![LedgerEntry::inbound(
            remover,
            None,
            LedgerEvent::DeviceRemoved {
                removed_by: remover.to_owned(),
                reason: message.reason,
            },
        )];
        ledger.extend(self.split_ledger(remover));
        Applied {
            outcome: Removal::AboutSelf,
            ledger,
        }
    }

    fn admit(&mut self, subject: &VouchedSubject, introduced_by: &str) -> Vec<LedgerEntry> {
        let record = DeviceRecord::from_vouch(subject, introduced_by);
        let entry = LedgerEntry::inbound(
            &subject.device_id,
            None,
            LedgerEvent::DeviceJoined {
                vouched_by: introduced_by.to_owned(),
            },
        );
        self.devices.insert(subject.device_id.clone(), record);
        vec![entry]
    }

    fn refuse_vouch(&mut self, subject: &str, refusal: VouchRefusal) -> Applied<Admission> {
        let entry = LedgerEntry::inbound(
            subject,
            None,
            LedgerEvent::VouchRejected {
                reason: refusal.to_string(),
            },
        );
        Applied {
            outcome: Admission::Refused(refusal),
            ledger: vec![entry],
        }
    }

    /// Record a tombstone, deactivate the record and bump the epoch.
    fn apply_tombstone(
        &mut self,
        subject: &str,
        reason: RemovalReason,
        removed_at: &str,
        removed_by: &str,
        epoch: u64,
    ) -> Vec<LedgerEntry> {
        self.tombstones.insert(
            subject.to_owned(),
            Tombstone {
                subject: subject.to_owned(),
                reason,
                removed_at: removed_at.to_owned(),
                removed_by: removed_by.to_owned(),
                epoch,
            },
        );
        if let Some(record) = self.devices.get_mut(subject) {
            record.state = DeviceState::Removed;
        }
        // A removed device's churn history is no longer anyone's concern, and
        // keeping it would let a re-admitted id inherit a stranger's budget.
        self.churn.forget(subject);
        self.held.remove(subject);

        self.epoch = self.epoch.max(epoch);
        let mut ledger = vec![
            LedgerEntry::inbound(
                subject,
                None,
                LedgerEvent::DeviceRemoved {
                    removed_by: removed_by.to_owned(),
                    reason,
                },
            ),
            LedgerEntry::local(subject, LedgerEvent::EpochBumped { epoch: self.epoch }),
        ];
        ledger.extend(self.split_ledger(subject));
        ledger
    }

    /// One entry per newly-visible mutual eviction involving `peer`.
    fn split_ledger(&self, peer: &str) -> Vec<LedgerEntry> {
        if self.removed_me.contains(peer) && self.tombstones.contains_key(peer) {
            vec![LedgerEntry::local(
                peer,
                LedgerEvent::FamilySplit {
                    counterpart: peer.to_owned(),
                },
            )]
        } else {
            Vec::new()
        }
    }
}

fn parse_identity(encoded: &str) -> Result<IdentityPublicKey, VouchRefusal> {
    IdentityPublicKey::from_base64(encoded).map_err(|_| VouchRefusal::MalformedIdentityKey)
}

fn verify_vouch(
    introducer: &IdentityPublicKey,
    message: &RosterIntroduce,
) -> Result<(), VouchRefusal> {
    introducer
        .verify(SignaturePurpose::Vouch, &message.payload(), &message.vouch)
        .map_err(|_| VouchRefusal::BadSignature)
}

/// Lowercase hex SHA-256 over the canonical encoding of the sync payload.
fn digest_of(epoch: u64, devices: &[SyncDevice]) -> String {
    let payload = beacon_protocol::roster::SyncPayload { epoch, devices };
    let canonical = to_canonical_json(&payload).unwrap_or_default();
    let digest = Sha256::digest(&canonical);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Parse a signed timestamp, falling back to `now` when it is unreadable.
///
/// A malformed timestamp must not become a way to escape the churn budget, so an
/// unparseable one is treated as "just happened" rather than as "long ago".
fn timestamp_or(text: &str, now: SystemTime) -> SystemTime {
    sund_client::rfc3339::parse(text).unwrap_or(now)
}
