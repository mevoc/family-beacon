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
//!   transport               the port …………………………………………… transport
//!   sund_transport          … implemented over Sund queues
//!   client                  the two planes: DeviceClient / SundClient
//!   sigauth · address       what is signed · who is trusted
//!   http                    the seam: HttpRequest in, HttpResponse out
//!   agent                   the shipping implementation (feature `agent`)
//! ```
//!
//! Two design points worth knowing before adding to any of it:
//!
//! - **The transport port is pulled, not pushed** ([`transport`]). The core has
//!   to be drivable from outside — WorkManager, BGTask — and it never assumes
//!   it may run whenever it likes.
//! - **Trust is a property of the client, not of the call** ([`address`],
//!   [`agent`]). An [`http::HttpClient`] is bound to one server address, so the
//!   verification mode cannot be forgotten on one request out of forty.
//!
//! Still to come: session crypto by vodozemac, which slots in above
//! [`sund_transport`] — this crate carries ciphertext and does not make it.

pub mod address;
#[cfg(feature = "agent")]
pub mod agent;
pub mod client;
pub mod http;
pub mod memory;
mod rfc3339;
pub mod sigauth;
pub mod sund_transport;
pub mod transport;
