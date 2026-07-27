//! UniFFI scaffolding over `beacon-client`.
//!
//! The crate that turns the composed client into a Kotlin, Swift and TypeScript
//! API. It holds **shape translation and nothing else** — no orchestration, no
//! policy, no validation that decides anything. That constraint is the reason
//! the split exists at all (`docs/FamilyBeacon-AndroidPlan.md` → The facade
//! crate): `beacon-client` stays pure Rust so tier 3 can drive it headlessly
//! without going through a binding, and this crate is supposed to contain no
//! decision a test could fail on.
//!
//! The test of whether that constraint is holding: every function here is a
//! call into `beacon-client` wrapped in `From` conversions. When something in
//! this crate starts wanting an `if`, it belongs one layer down.
//!
//! # Why there are mirror types at all
//!
//! Everything crossing the boundary is redeclared here — `MemberRowView`,
//! `LedgerEventView`, `ClientException` and the rest — rather than exported from
//! the crates that own them. Three reasons, in order of weight:
//!
//! 1. **`beacon-client` must not depend on `uniffi`.** A `#[derive(uniffi::…)]`
//!    on the core's own types would put the binding generator in the dependency
//!    tree of every consumer, including the headless test tier that exists to
//!    prove the core needs no binding.
//! 2. **Some shapes are not bindable.** `[u8; 32]` seeds, `&'static str` field
//!    names, `usize` counts and the generic `Applied<T>` all have to change form.
//!    Doing that in one place, explicitly, beats discovering it per platform.
//! 3. **Drift becomes a compile error.** Every conversion is a total match, so a
//!    variant added to `beacon-protocol` breaks this crate rather than becoming
//!    an event the user is never shown. That property is worth more than the
//!    duplication costs — the alternative to mirroring is not "no mirroring", it
//!    is a `_ =>` arm that silently swallows the next message type somebody adds.
//!
//! # The three rules the app layer inherits
//!
//! - **Nothing here may be called from the main thread.** Every entry point
//!   blocks; none is async and none takes a callback. The core is driven from
//!   WorkManager and BGTask.
//! - **Persist [`BeaconClient::snapshot`] encrypted at rest**, and never in a
//!   cache directory. The outbox seals at drain rather than at enqueue, so the
//!   blob holds message bodies in the clear.
//! - **The two seeds go in the platform keystore, not in the blob.** See
//!   [`SeedsView`].
//!
//! # Generating the bindings
//!
//! The generator is a binary target in this crate rather than a
//! `cargo install`-ed tool, so its version cannot drift from the `uniffi`
//! dependency it has to agree with:
//!
//! ```text
//! cargo run --bin uniffi-bindgen -- generate \
//!     --library target/<triple>/<profile>/libbeacon_ffi.so \
//!     --language kotlin --out-dir <build dir>
//! ```
//!
//! The generated Kotlin goes into a build-directory source set and is **not**
//! committed: committed bindings rot against the Rust they claim to bind.

uniffi::setup_scaffolding!("beacon");

pub mod client;
pub mod error;
pub mod ledger;
pub mod views;

pub use client::{BeaconClient, Enrolled, enroll, generate_seeds, open};
pub use error::ClientException;
pub use ledger::{
    DenyReasonView, DirectionView, FeatureView, LedgerEntryView, LedgerEventView, MessageTypeView,
    RejectReasonView, RemovalReasonView,
};
pub use views::{MemberRowView, ProfileView, SeedsView, ServerDeviceRowView};
