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
//! ```text
//!   beacon-protocol         above this crate: envelope, consent, ledger
//!   ────────────────────────────────────────────────────────────────────
//!   identity · bundle       who a device is · how peers learn its keys
//!   session · session_store the double ratchet, and what persists of it
//!   canonical               the encoding every signature is computed over
//!   ────────────────────────────────────────────────────────────────────
//!   transport               the port …………………………………………… transport
//!   sund_transport          … implemented over Sund queues
//!   client                  the two planes: DeviceClient / SundClient
//!   sigauth · address       what is signed · who is trusted
//!   http                    the seam: HttpRequest in, HttpResponse out
//!   agent                   the shipping implementation (feature `agent`)
//! ```
//!
//! Three design points worth knowing before adding to any of it:
//!
//! - **The transport port is pulled, not pushed** ([`transport`]). The core has
//!   to be drivable from outside — WorkManager, BGTask — and it never assumes
//!   it may run whenever it likes.
//! - **Trust is a property of the client, not of the call** ([`address`],
//!   [`agent`]). An [`http::HttpClient`] is bound to one server address, so the
//!   verification mode cannot be forgotten on one request out of forty.
//! - **The session layer knows nothing about Sund.** [`identity`], [`bundle`],
//!   [`canonical`], [`session`] and [`session_store`] sit *above* the transport
//!   port and touch no type from [`client`]: a bundle reaches a peer as opaque
//!   bytes, which is all Sund's dead-drop promises and all ntfy could ever
//!   offer. They live in this crate because
//!   `docs/FamilyBeacon-Protocol.md` → Layering puts session crypto here, and
//!   they are written so that Try mode's `ntfy-client` can consume them
//!   unchanged — if that ever wants them without the Sund half, the extraction
//!   is a file move rather than a redesign. Spec:
//!   `docs/FamilyBeacon-Sessions.md`.

pub mod address;
#[cfg(feature = "agent")]
pub mod agent;
pub mod bundle;
pub mod canonical;
pub mod client;
pub mod http;
pub mod identity;
pub mod memory;
pub mod rfc3339;
pub mod session;
pub mod session_store;
pub mod sigauth;
pub mod sund_transport;
pub mod transport;
