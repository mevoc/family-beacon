//! The state blob: snapshot in, snapshot out.
//!
//! `docs/FamilyBeacon-AndroidPlan.md` → State and persistence fixes the shape,
//! and the reasoning is worth keeping next to the code:
//!
//! - **No callback interfaces across the FFI.** UniFFI's friction concentrates
//!   on async and callbacks (decision #6), and a storage trait implemented in
//!   Kotlin and called back into from inside a ratchet step is the worst version
//!   of that. Every layer below is already snapshot-shaped —
//!   `RosterSnapshot`, `SessionStore`, `ChannelRecord`, `OutboxSnapshot` — so
//!   the boundary follows the shape the core already has.
//! - **Protocol state is one opaque blob.** At family scale — 20 devices, a
//!   handful of sessions, a short outbox — this is kilobytes, and a whole-blob
//!   rewrite is the right trade against a fine-grained persistence API that
//!   would have to be re-specified for every future message type.
//! - **Versioned from the first byte.** Literally: [`STATE_VERSION`] is byte
//!   zero, ahead of the encoding, and [`decode`] refuses a version it does not
//!   know rather than guessing. Putting it outside the encoding is what makes a
//!   future move to a compact binary form a version bump rather than a sniff.
//! - **The ledger is not in here.** It is the one piece of state that grows
//!   without bound and the one the UI needs to query, filter and page — Room's
//!   job, not a blob's. The core hands entries out as values and the app appends
//!   them.
//!
//! # Encoding — settled here (open question 2)
//!
//! **JSON, behind the version byte.** Every layer already exports a
//! serde-serialisable snapshot and `serde_json` is already in the workspace, so
//! JSON costs nothing and buys a state blob that is legible in a test failure
//! and diffable between two devices that disagree. A compact binary encoding
//! would save bytes that, at this size, nobody is paying for; if that ever stops
//! being true, the version byte is how it changes.
//!
//! # What the app must do with it
//!
//! Write it after any call that mutated it, **encrypted at rest** — an
//! `EncryptedFile` or a keystore-wrapped key over app-private storage, never a
//! cache directory. That is not belt-and-braces: the outbox queues plaintext and
//! seals at drain (`core/README.md`), so this blob contains message bodies in
//! the clear, which for Family Beacon means positions.
//!
//! The session pickles inside are separately encrypted under a key derived from
//! the identity seed ([`crate::Seeds`]), so a leaked blob still yields no
//! session state — but it does yield the outbox, which is why the paragraph
//! above is a requirement and not a suggestion.

use beacon_roster::RosterSnapshot;
use serde::{Deserialize, Serialize};
use sund_client::outbox::OutboxSnapshot;
use sund_client::session_store::SessionStore;
use sund_client::sund_transport::ChannelRecord;

use crate::error::ClientError;

/// The blob format version, and byte zero of every blob.
pub const STATE_VERSION: u8 = 1;

/// Everything a device must carry across a restart, except the ledger and the
/// two seeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClientState {
    /// This device's Sund device id.
    pub device_id: String,
    /// The Sund account the invitation belonged to — the family, in Family
    /// Beacon's vocabulary, and **not** the authority on family membership.
    pub account_id: String,
    /// The server address in its canonical form, which round-trips through
    /// `ServerAddress::parse`.
    ///
    /// Stored whole, because the trust mode is part of the server's identity
    /// rather than a connection-time detail: a client that re-derived the mode
    /// from a host name could be walked from pinned to WebPKI without anyone
    /// re-pairing, and the two modes are a re-pairing migration apart.
    pub server: String,
    /// The membership state machine's state.
    pub roster: RosterSnapshot,
    /// The Olm account and every peer session, pickled.
    pub sessions: SessionStore,
    /// Per-channel queue state. **Carries private key seeds.**
    pub channels: Vec<ChannelRecord>,
    /// Messages that have not gone out yet. **Holds plaintext.**
    pub outbox: OutboxSnapshot,
}

/// Serialise a blob: the version byte, then the encoding.
pub(crate) fn encode(state: &ClientState) -> Result<Vec<u8>, ClientError> {
    let mut bytes = Vec::with_capacity(1024);
    bytes.push(STATE_VERSION);
    serde_json::to_writer(&mut bytes, state)?;
    Ok(bytes)
}

/// Read a blob, refusing anything this build does not speak.
pub(crate) fn decode(bytes: &[u8]) -> Result<ClientState, ClientError> {
    let (version, body) = bytes.split_first().ok_or_else(|| ClientError::State {
        detail: "the stored state is empty".to_owned(),
    })?;

    if *version != STATE_VERSION {
        // Refuse rather than guess. A blob from a newer build is the field's
        // downgrade path, and a client that tried to parse one would be deciding
        // what a format it has never seen means.
        return Err(ClientError::State {
            detail: format!(
                "stored state is version {version}, and this build speaks {STATE_VERSION}"
            ),
        });
    }

    Ok(serde_json::from_slice(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A blob whose sub-snapshots are the real ones, built the cheap way: an
    /// empty roster snapshot is not constructible from outside `beacon-roster`,
    /// so the round-trip tests that need one go through `Client` instead
    /// (`client::tests`). What is asserted here is the framing.
    fn blob(version: u8, body: &str) -> Vec<u8> {
        let mut bytes = vec![version];
        bytes.extend_from_slice(body.as_bytes());
        bytes
    }

    #[test]
    fn an_unknown_version_is_refused_before_anything_is_parsed() {
        let error = decode(&blob(STATE_VERSION + 1, "not even json")).expect_err("refused");
        match error {
            ClientError::State { detail } => {
                assert!(detail.contains("version"), "{detail}");
            }
            other => panic!("expected State, got {other:?}"),
        }
    }

    #[test]
    fn a_version_zero_blob_is_refused_rather_than_treated_as_absent() {
        // Zero is what an over-eager "initialise to empty" produces, and it must
        // not be mistaken for a valid first version.
        assert!(decode(&blob(0, "{}")).is_err());
    }

    #[test]
    fn an_empty_blob_is_an_error_not_a_panic() {
        let error = decode(&[]).expect_err("refused");
        assert!(matches!(error, ClientError::State { .. }), "{error:?}");
    }

    #[test]
    fn a_truncated_body_is_an_error_not_a_panic() {
        let error = decode(&blob(STATE_VERSION, r#"{"device_id":"dev_"#)).expect_err("refused");
        assert!(matches!(error, ClientError::State { .. }), "{error:?}");
    }
}
