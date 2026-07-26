//! Persisting the session layer across process death.
//!
//! Two shapes were possible and only one fits this codebase. The core could own
//! a database, or it could hand the app layer a blob and let the platform put it
//! where secrets go — Keystore, Secure Enclave, browser storage.
//! [`crate::sigauth::DeviceKey::from_seed`] already made that choice for key
//! seeds and [`crate::sund_transport::SundTransport::export`] made it for channel
//! state, so this module makes the same one: export a serialisable value, import
//! it back, and never touch the filesystem.
//!
//! ## Why the blob is encrypted here anyway
//!
//! Olm pickles contain private keys, and unlike a key *seed* they are large,
//! long-lived and change on every message. Handing them out in the clear would
//! make correct storage the app layer's problem on three platforms; vodozemac
//! already offers authenticated encryption for exactly this, so the export takes
//! a 32-byte pickle key and the app layer's job shrinks to storing that one key
//! properly. Losing the pickle key is equivalent to losing the sessions: every
//! peer must be re-established, which is recoverable and loud rather than
//! silent.
//!
//! ## What is deliberately not persisted
//!
//! The identity key. It is the app layer's to generate and store, it is the
//! thing a family vouched for, and a store that carried it would turn one leaked
//! blob into a stolen identity rather than stolen sessions. [`import`] takes the
//! identity key as an argument and refuses a store that was written under a
//! different one.

use serde::{Deserialize, Serialize};
use vodozemac::Curve25519PublicKey;
use vodozemac::olm::{Account, AccountPickle, Session, SessionPickle};

use crate::bundle::PeerKeys;
use crate::identity::{IdentityKey, IdentityPublicKey};
use crate::session::SessionManager;

/// The store format version.
pub const STORE_VERSION: u8 = 1;

/// Why a store could not be written or read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// A store version this build does not speak.
    UnsupportedVersion {
        /// The version found in the store.
        found: u8,
    },
    /// The store belongs to a different device.
    WrongDevice {
        /// The device id the caller is restoring as.
        expected: String,
        /// The device id the store was written by.
        found: String,
    },
    /// The store was written under a different identity key.
    ///
    /// Refused rather than repaired: sessions are bound to an identity the
    /// family vouched for, and silently adopting them under a new one would
    /// make the vouch meaningless.
    WrongIdentity {
        /// The identity key the caller supplied, base64.
        expected: String,
        /// The identity key the store was written under, base64.
        found: String,
    },
    /// A pickle would not decrypt — wrong pickle key, or a corrupted store.
    Undecryptable(String),
    /// A stored key was not valid base64 key material.
    BadKeyMaterial(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion { found } => write!(f, "unsupported store version {found}"),
            Self::WrongDevice { expected, found } => {
                write!(f, "store belongs to `{found}`, restoring as `{expected}`")
            }
            Self::WrongIdentity { expected, found } => write!(
                f,
                "store was written under identity `{found}`, restoring with `{expected}`"
            ),
            Self::Undecryptable(detail) => write!(f, "could not decrypt store: {detail}"),
            Self::BadKeyMaterial(detail) => write!(f, "bad stored key material: {detail}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// One peer's verified keys, and its session if there was one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPeer {
    /// The peer's transport-layer device id.
    pub device_id: String,
    /// The peer's vouched identity key, base64.
    pub identity_pk: String,
    /// The peer's Olm Curve25519 identity key, base64.
    pub curve25519: String,
    /// The peer's signed fallback key, base64.
    pub fallback_key: String,
    /// The fallback key's Olm key id.
    pub fallback_key_id: String,
    /// The encrypted session pickle, absent if no session was open.
    pub session: Option<String>,
}

/// Everything the session layer needs to come back after process death.
///
/// Serialisable, opaque, and safe to hand to platform storage as long as the
/// pickle key is stored properly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionStore {
    /// Store format version.
    pub v: u8,
    /// The device this store belongs to.
    pub device_id: String,
    /// The identity key it was written under, base64. Checked on import, never
    /// used as a source of trust.
    pub identity_pk: String,
    /// The encrypted Olm account pickle.
    pub account: String,
    /// Peers, in device-id order.
    pub peers: Vec<StoredPeer>,
}

/// Export a manager's state.
///
/// `pickle_key` encrypts the account and every session. The same key must be
/// supplied to [`import`].
#[must_use]
pub fn export(manager: &SessionManager, pickle_key: &[u8; 32]) -> SessionStore {
    let peers = manager
        .peer_states()
        .map(|(device_id, keys, session)| StoredPeer {
            device_id: device_id.to_owned(),
            identity_pk: keys.identity.to_base64(),
            curve25519: keys.curve25519.to_base64(),
            fallback_key: keys.fallback_key.to_base64(),
            fallback_key_id: keys.fallback_key_id.clone(),
            session: session.map(|session| session.pickle().encrypt(pickle_key)),
        })
        .collect();

    SessionStore {
        v: STORE_VERSION,
        device_id: manager.device_id().to_owned(),
        identity_pk: manager.identity_public_key().to_base64(),
        account: manager.account().pickle().encrypt(pickle_key),
        peers,
    }
}

/// Restore a manager from an exported store.
///
/// # Errors
///
/// Returns [`StoreError::UnsupportedVersion`] for a future store,
/// [`StoreError::WrongDevice`] or [`StoreError::WrongIdentity`] if the store
/// belongs to another device or identity, [`StoreError::Undecryptable`] on a
/// wrong pickle key, and [`StoreError::BadKeyMaterial`] if stored key material
/// does not parse.
pub fn import(
    store: &SessionStore,
    device_id: &str,
    identity: IdentityKey,
    pickle_key: &[u8; 32],
) -> Result<SessionManager, StoreError> {
    if store.v != STORE_VERSION {
        return Err(StoreError::UnsupportedVersion { found: store.v });
    }
    if store.device_id != device_id {
        return Err(StoreError::WrongDevice {
            expected: device_id.to_owned(),
            found: store.device_id.clone(),
        });
    }
    let identity_pk = identity.public_key().to_base64();
    if store.identity_pk != identity_pk {
        return Err(StoreError::WrongIdentity {
            expected: identity_pk,
            found: store.identity_pk.clone(),
        });
    }

    let account = AccountPickle::from_encrypted(&store.account, pickle_key)
        .map_err(|error| StoreError::Undecryptable(error.to_string()))?;
    let mut manager = SessionManager::from_account(device_id, identity, Account::from(account));

    for peer in &store.peers {
        let keys = PeerKeys {
            device_id: peer.device_id.clone(),
            identity: IdentityPublicKey::from_base64(&peer.identity_pk).map_err(|error| {
                StoreError::BadKeyMaterial(format!("`{}` identity_pk: {error}", peer.device_id))
            })?,
            curve25519: curve(&peer.curve25519, &peer.device_id, "curve25519")?,
            fallback_key: curve(&peer.fallback_key, &peer.device_id, "fallback_key")?,
            fallback_key_id: peer.fallback_key_id.clone(),
        };
        let session = match &peer.session {
            Some(pickle) => Some(Session::from_pickle(
                SessionPickle::from_encrypted(pickle, pickle_key)
                    .map_err(|error| StoreError::Undecryptable(error.to_string()))?,
            )),
            None => None,
        };
        manager.restore_peer(keys, session);
    }

    Ok(manager)
}

fn curve(encoded: &str, device_id: &str, field: &str) -> Result<Curve25519PublicKey, StoreError> {
    Curve25519PublicKey::from_base64(encoded)
        .map_err(|error| StoreError::BadKeyMaterial(format!("`{device_id}` {field}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionError;

    const PICKLE_KEY: [u8; 32] = [42u8; 32];

    fn identity(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    /// Two managers that have verified each other and exchanged one message, so
    /// there is a live ratchet to persist rather than a fresh one.
    fn conversing() -> (SessionManager, SessionManager) {
        let mut a = SessionManager::create("dev_A", identity(1));
        let mut b = SessionManager::create("dev_B", identity(2));

        let a_bundle = a.publish_bundle("2026-07-26T10:00:00Z").expect("bundle");
        let b_bundle = b.publish_bundle("2026-07-26T10:00:00Z").expect("bundle");
        a.learn_peer(
            b_bundle
                .verify("dev_B", b.identity_public_key())
                .expect("verifies"),
        );
        b.learn_peer(
            a_bundle
                .verify("dev_A", a.identity_public_key())
                .expect("verifies"),
        );

        let frame = a.encrypt("dev_B", b"first").expect("encrypts");
        b.decrypt("dev_A", &frame).expect("decrypts");
        (a, b)
    }

    #[test]
    fn a_restored_session_continues_the_same_ratchet() {
        let (mut a, b) = conversing();

        let store = export(&b, &PICKLE_KEY);
        let json = serde_json::to_vec(&store).expect("serialises");
        let read_back: SessionStore = serde_json::from_slice(&json).expect("deserialises");
        let mut restored = import(&read_back, "dev_B", identity(2), &PICKLE_KEY).expect("imports");

        // A knows nothing of B's restart, which is the point.
        let next = a.encrypt("dev_B", b"after the restart").expect("encrypts");
        let got = restored.decrypt("dev_A", &next).expect("decrypts");
        assert_eq!(got.plaintext, b"after the restart");
        assert!(!got.new_session, "the same session, not a fresh one");
    }

    #[test]
    fn a_restored_manager_can_still_send() {
        let (mut a, b) = conversing();
        let store = export(&b, &PICKLE_KEY);
        let mut restored = import(&store, "dev_B", identity(2), &PICKLE_KEY).expect("imports");

        let reply = restored
            .encrypt("dev_A", b"reply after restart")
            .expect("encrypts");
        assert_eq!(
            a.decrypt("dev_B", &reply).expect("decrypts").plaintext,
            b"reply after restart"
        );
    }

    #[test]
    fn verified_peer_keys_survive_the_round_trip() {
        let (a, _b) = conversing();
        let store = export(&a, &PICKLE_KEY);
        let restored = import(&store, "dev_A", identity(1), &PICKLE_KEY).expect("imports");

        assert_eq!(restored.known_peers(), vec!["dev_B"]);
        assert!(restored.has_session("dev_B"));
        assert_eq!(
            restored.identity_public_key(),
            a.identity_public_key(),
            "the identity comes from the argument, not the store"
        );
    }

    #[test]
    fn a_peer_with_no_session_round_trips_as_such() {
        let mut a = SessionManager::create("dev_A", identity(1));
        let mut b = SessionManager::create("dev_B", identity(2));
        let a_bundle = a.publish_bundle("2026-07-26T10:00:00Z").expect("bundle");
        let b_bundle = b.publish_bundle("2026-07-26T10:00:00Z").expect("bundle");
        a.learn_peer(
            b_bundle
                .verify("dev_B", b.identity_public_key())
                .expect("verifies"),
        );
        // B has to know A to attribute anything to it, even though no session
        // exists in either direction yet.
        b.learn_peer(
            a_bundle
                .verify("dev_A", a.identity_public_key())
                .expect("verifies"),
        );

        let store = export(&a, &PICKLE_KEY);
        assert_eq!(store.peers.len(), 1);
        assert!(store.peers[0].session.is_none());

        let mut restored = import(&store, "dev_A", identity(1), &PICKLE_KEY).expect("imports");
        assert!(!restored.has_session("dev_B"));
        // Still enough to open one, which is what a channel established at join
        // with consent still closed looks like.
        let frame = restored
            .encrypt("dev_B", b"first contact")
            .expect("encrypts");
        assert_eq!(
            b.decrypt("dev_A", &frame).expect("decrypts").plaintext,
            b"first contact"
        );
    }

    #[test]
    fn the_wrong_pickle_key_is_refused_not_silently_empty() {
        let (a, _b) = conversing();
        let store = export(&a, &PICKLE_KEY);
        assert!(matches!(
            import(&store, "dev_A", identity(1), &[0u8; 32]),
            Err(StoreError::Undecryptable(_))
        ));
    }

    #[test]
    fn another_devices_store_is_refused() {
        let (a, _b) = conversing();
        let store = export(&a, &PICKLE_KEY);
        assert_eq!(
            import(&store, "dev_B", identity(1), &PICKLE_KEY).err(),
            Some(StoreError::WrongDevice {
                expected: "dev_B".to_owned(),
                found: "dev_A".to_owned(),
            })
        );
    }

    #[test]
    fn a_store_written_under_another_identity_is_refused() {
        // The case that matters: restoring someone else's sessions under your
        // own vouched identity would let a stolen blob speak as you.
        let (a, _b) = conversing();
        let store = export(&a, &PICKLE_KEY);
        assert!(matches!(
            import(&store, "dev_A", identity(99), &PICKLE_KEY),
            Err(StoreError::WrongIdentity { .. })
        ));
    }

    #[test]
    fn a_future_store_version_is_refused() {
        let (a, _b) = conversing();
        let mut store = export(&a, &PICKLE_KEY);
        store.v = STORE_VERSION + 1;
        assert_eq!(
            import(&store, "dev_A", identity(1), &PICKLE_KEY).err(),
            Some(StoreError::UnsupportedVersion {
                found: STORE_VERSION + 1
            })
        );
    }

    #[test]
    fn corrupt_stored_key_material_is_refused_and_named() {
        let (a, _b) = conversing();
        let mut store = export(&a, &PICKLE_KEY);
        store.peers[0].curve25519 = "not base64".to_owned();
        match import(&store, "dev_A", identity(1), &PICKLE_KEY) {
            Err(StoreError::BadKeyMaterial(detail)) => {
                assert!(detail.contains("dev_B"), "names the peer: {detail}");
                assert!(detail.contains("curve25519"), "names the field: {detail}");
            }
            other => panic!("expected BadKeyMaterial, got {other:?}"),
        }
    }

    #[test]
    fn the_store_carries_no_plaintext_key_material() {
        let (a, _b) = conversing();
        let store = export(&a, &PICKLE_KEY);
        let json = serde_json::to_string(&store).expect("serialises");

        // The account pickle is the sensitive part; assert it is not simply the
        // unencrypted pickle by checking the Curve25519 identity key — which is
        // public, but appears verbatim in an unencrypted pickle — is absent from
        // the account blob.
        let public = a.curve25519_key().to_base64();
        assert!(
            !store.account.contains(&public),
            "the account blob looks unencrypted"
        );
        assert!(json.contains("\"account\""));
    }

    #[test]
    fn export_is_stable_across_repeated_calls_for_the_same_state() {
        // Not byte-equal — the pickle encryption is randomised — but structurally
        // stable, so a caller diffing peers to decide whether to write does not
        // see phantom churn.
        let (a, _b) = conversing();
        let first = export(&a, &PICKLE_KEY);
        let second = export(&a, &PICKLE_KEY);
        assert_eq!(first.device_id, second.device_id);
        assert_eq!(first.identity_pk, second.identity_pk);
        assert_eq!(
            first.peers.iter().map(|p| &p.device_id).collect::<Vec<_>>(),
            second
                .peers
                .iter()
                .map(|p| &p.device_id)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn peers_are_exported_in_device_id_order() {
        let mut a = SessionManager::create("dev_A", identity(1));
        for (seed, id) in [(4u8, "dev_Z"), (5u8, "dev_B"), (6u8, "dev_M")] {
            let mut peer = SessionManager::create(id, identity(seed));
            let bundle = peer.publish_bundle("2026-07-26T10:00:00Z").expect("bundle");
            a.learn_peer(
                bundle
                    .verify(id, peer.identity_public_key())
                    .expect("verifies"),
            );
        }
        let store = export(&a, &PICKLE_KEY);
        let ids: Vec<&str> = store.peers.iter().map(|p| p.device_id.as_str()).collect();
        assert_eq!(ids, vec!["dev_B", "dev_M", "dev_Z"]);
    }

    #[test]
    fn a_restored_manager_reports_an_unknown_peer_as_unknown() {
        let (a, _b) = conversing();
        let store = export(&a, &PICKLE_KEY);
        let mut restored = import(&store, "dev_A", identity(1), &PICKLE_KEY).expect("imports");
        assert_eq!(
            restored.encrypt("dev_GONE", b"x"),
            Err(SessionError::UnknownPeer("dev_GONE".to_owned()))
        );
    }
}
