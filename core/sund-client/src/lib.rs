//! The client half of Sund: app-agnostic, and deliberately ignorant of
//! families, locations and anything else Family Beacon cares about.
//!
//! `docs/FamilyBeacon-Protocol.md` → Layering puts identity and request
//! signing, enrollment, pairing, session crypto, queue lifecycle and rotation,
//! the offline outbox and push registration in this crate, and everything
//! Family-Beacon-specific in `beacon-protocol` above it. The split exists so
//! this crate can be reused by any project that adopts Sund as a backend — and
//! the discipline that keeps it honest is simple: if a type here mentions a
//! family, a member or a location, it is in the wrong crate.
//!
//! What is here today is the part the rest is built on:
//!
//! - [`sigauth`] — the canonical signed-request form, byte-for-byte agreed
//!   with Sund's Go implementation.
//! - [`transport`] — the port: `send` / `subscribe` / `ack` / channel
//!   lifecycle, and nothing of Sund's management plane.
//! - [`memory`] — an in-memory implementation of the port, which is what lets
//!   the layers above be tested with no server at all.
//!
//! Still to come, in the order the testing strategy needs them: the HTTP
//! implementation of the port against a real relay (tier 2's contract suite),
//! enrollment and queue lifecycle, then session crypto by vodozemac.

pub mod memory;
pub mod sigauth;
pub mod transport;
