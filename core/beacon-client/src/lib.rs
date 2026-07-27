//! The Family Beacon client, composed.
//!
//! Every layer below this one is a library that holds state and decides policy
//! and does nothing else: `beacon-protocol` will not send, `beacon-roster` will
//! not encrypt, `sund-client` does not know what a family is. Something has to
//! wire them together — publish a bundle, fetch a peer's, verify it against the
//! roster's vouched key, learn it, open a channel, seal, send — and until this
//! crate existed that wiring lived only in
//! `contract-tests/tests/contract/membership.rs`.
//!
//! Leaving it there would put it in Kotlin, then in Swift, then in TypeScript:
//! three implementations of the sequence that decides whether a bundle is
//! trusted, which is exactly the failure mode CLAUDE.md decision #6 rejected
//! per-platform native to avoid. So the composition is a crate, and the app
//! layer drives one object.
//!
//! ```text
//!   app layer            UI · location · push · scheduling · storage
//!   ───────────────────────────────────────────────────────────────
//!   beacon-ffi           uniffi scaffolding; cdylib, no logic (not yet built)
//!   ───────────────────────────────────────────────────────────────
//!   THIS CRATE           the composition, behind one `Client`
//!   ───────────────────────────────────────────────────────────────
//!   beacon-protocol · beacon-roster · sund-client
//! ```
//!
//! # What this crate owns
//!
//! - **The composition**, behind [`Client`].
//! - **The state blob**: [`Client::open`] from bytes, [`Client::snapshot`] back
//!   to bytes. See [`state`] for the encoding and why it is versioned from the
//!   first byte.
//! - **One error enum the app can switch on** ([`ClientError`]), with the
//!   pin-mismatch distinction preserved as its own variant — see below.
//!
//! # What it must not own
//!
//! A thread, a clock it invented, a scheduler, or any policy that belongs to a
//! layer below. Every method that needs the time takes it as an argument,
//! exactly as `beacon-roster` and `sund-client` do; the core is driven from
//! WorkManager and BGTask rather than owning a loop. Nothing here is async and
//! nothing takes a callback: every entry point below is blocking, which is what
//! keeps the UniFFI surface plain (decision #6, "Known costs, accepted").
//!
//! **Nothing in this API may be called from the main thread.** Enforced by
//! convention in slice 0 and by the app's repository layer from slice 1 on.
//!
//! # The one error whose wording is a security property
//!
//! [`ClientError::ServerIdentity`] is not a connectivity failure and must never
//! be rendered as one. `sund-client`'s pinned mode surfaces a pin mismatch as an
//! `io::Error` wrapping a `rustls::Error`, and a client that reported it as a
//! network blip would make an intercepting network indistinguishable from an
//! absent one — which the pinning contract (§8.3) forbids outright. The variant
//! is separate here so the app can render "this is not the server you paired
//! with", and [`ClientError::is_server_identity`] exists so that check cannot be
//! written as a string match.
//!
//! # Slice 0's surface, and what is deliberately not in it
//!
//! `docs/FamilyBeacon-AndroidPlan.md` sketches the API and says outright that it
//! is "a first cut, to be refined against the pairing flow rather than designed
//! ahead of it". What slice 0 ships is enrollment, persistence and the two
//! membership views:
//!
//! - [`Client::enroll`] · [`Client::open`] · [`Client::snapshot`]
//! - [`Client::self_description`] · [`Client::roster`] ·
//!   [`Client::server_devices`]
//!
//! [`Client::roster`] and [`Client::server_devices`] are two calls, not one, and
//! that is the roster spec's central claim made visible in the type system: a
//! single `members()` that quietly merged them would be the injected-device bug
//! with a convenient name.
//!
//! Two sketched methods are held back to slice 1, both because building them now
//! would mean guessing at the pairing flow:
//!
//! - **`drain()`** — the pull step needs a channel-to-peer binding to know whose
//!   session decrypts a delivery, and `sund_transport::ChannelRecord`
//!   deliberately does not carry one. The pairing ceremony is what establishes
//!   that binding, so it is pairing's state to define. The composition already
//!   holds and persists the sessions, the channels and the outbox, so slice 1
//!   adds methods rather than fields.
//! - **`pump_outbox()`** — `outbox::DrainReport` carries no plaintext, so a
//!   drain cannot say which message type went out, and a send path that cannot
//!   produce `LedgerEvent::Sent` would be an exemption in a ledger rule that has
//!   none. It lands with the enqueue path that knows the type, which is the
//!   first slice with something to send.

pub mod client;
pub mod error;
pub mod seeds;
pub mod state;
pub mod views;

pub use client::{Client, Profile};
pub use error::ClientError;
pub use seeds::{SEED_BYTES, Seeds};
pub use state::STATE_VERSION;
pub use views::{MemberRow, ServerDeviceRow};

/// An outcome and the ledger entries that must accompany it.
///
/// Re-exported from `beacon-roster` rather than redefined: the ledger rule is
/// one rule, and every layer that produces entries hands them back in the same
/// shape. Anything on [`Client`] that changes membership state returns one of
/// these, so a caller can fail to persist the entries only by visibly dropping
/// them on the floor.
pub use beacon_roster::Applied;

/// One entry in the device's activity log.
///
/// Re-exported so the app layer can name the type without depending on
/// `beacon-protocol` directly. Deliberately carries no timestamp: the clock is
/// the app's, and a core that invented its own would write entries that disagree
/// with the rest of the device's log.
pub use beacon_protocol::ledger::{Direction, LedgerEntry, LedgerEvent};

/// The parsed server address and its transport-trust mode.
///
/// Re-exported because it is part of the app's vocabulary: the mode is part of
/// the server's identity, not a connection-time detail, and switching modes
/// re-pairs every device.
pub use sund_client::address::{ServerAddress, TrustMode};
