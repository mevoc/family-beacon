//! Family Beacon's membership layer: who is in the family, and how that changes.
//!
//! Specified in `docs/FamilyBeacon-Roster.md`. The layer decision #8 pushed above
//! the transport port and decision #9 then specified: membership, introductions
//! and revocation policy, held as explicit client-side state.
//!
//! It exists as its own layer for one reason and turns out to have a better one.
//! The stated reason is portability: Sund has a management plane — device
//! registry, key bundles, invitations, server-enforced revocation — and ntfy has
//! no analogue for any of it, so rather than widening the transport port until
//! both backends fit, membership becomes client-side logic that both modes run,
//! with Sund mode implementing it *more strongly* by additionally using its
//! management plane. The better reason, discovered in writing the spec: **the
//! server's device list cannot be the authority on who is in the family.** An
//! abusive host can add a row to the `devices` table, and a client that admitted
//! peers on the strength of `GET /v1/devices` would pair with an injected device —
//! defeating the E2EE stance not by breaking crypto but by being introduced as a
//! legitimate peer.
//!
//! ```text
//!   beacon-protocol       envelope codec, message types, consent, ledger
//!   ──────────────────────────────────────────────────────────────────
//!   THIS CRATE            membership state, admission, removal, merge
//!   ──────────────────────────────────────────────────────────────────
//!   session crypto        identity keys, bundles, the ratchet
//!   ──────────────────────────────────────────────────────────────────
//!   transport port        send / subscribe / ack / channel lifecycle
//! ```
//!
//! The crate depends on `beacon-protocol` for the wire types and the ledger
//! vocabulary, and on `sund-client` for identity keys, canonical JSON and bundle
//! verification. Neither is a layering inversion: the roster spec is explicit
//! that "the roster's wire messages are ordinary beacon-protocol types … the layer
//! boundary is one of state and policy, not of encoding", and the parts of
//! `sund-client` used here all sit above the transport port. No HTTP client comes
//! with them — the roster makes no requests.
//!
//! # What to read first
//!
//! Four decisions in [`roster`] carry most of the design, and each is chosen
//! against a specific abuse case rather than for elegance:
//!
//! - **The consent principal is a device, not a person.** Members are a grouping
//!   for display. A grant to a person silently extends to hardware you have never
//!   seen; a grant to a device is a grant to a thing that can be held up and
//!   pointed at.
//! - **Admission needs a signed vouch, never a server list.**
//! - **There is no admin.** Any active device may remove any other, and a device
//!   may always remove itself. Concentrating removal would hand the wrong person a
//!   lock in the abusive-member case.
//! - **Abuse is bounded by two build-time constants**, not configuration:
//!   [`roster::MAX_ACTIVE_DEVICES`] and
//!   [`churn::MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY`].
//!
//! # What this crate does not do
//!
//! It holds state and decides policy. It does not send, encrypt, persist or
//! schedule anything: the caller wraps produced messages in envelopes, hands them
//! to the session layer, and stores [`roster::RosterSnapshot`] wherever the
//! platform keeps data. Nor does it own a clock — every method that needs the time
//! takes it as an argument, exactly as the layers below do.
//!
//! One thing it deliberately leaves to the caller: acting on a removal. When
//! [`roster::Removal::Applied`] comes back, the caller must retire its channels
//! with that device and drop every grant naming it in both directions. The roster
//! cannot do either — consent and transport are not its state — so the ledger
//! entry is the record and the caller is the mechanism.

pub mod churn;
pub mod records;
pub mod roster;

pub use churn::{CHURN_WINDOW, ChurnLog, MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY};
pub use records::{DeviceRecord, SelfDescription, Tombstone};
pub use roster::{
    Admission, Applied, HeldAdmission, MAX_ACTIVE_DEVICES, Removal, RemovalRefusal, Roster,
    RosterSnapshot, ServerDevice, ServerFinding, SnapshotError, Sync, VouchRefusal,
};
