//! The two secrets a device holds, and the key derived from one of them.
//!
//! A device holds **two** Ed25519 keys, and the app layer must store both seeds
//! (`core/README.md`; `docs/FamilyBeacon-Sessions.md` → A separate protocol
//! identity key):
//!
//! - `sigauth::DeviceKey` signs HTTP requests to a server. The server knows this
//!   key; the host owns the device-list row that names it.
//! - `identity::IdentityKey` is the roster's `identity_pk` — it signs bundles,
//!   vouches and tombstones. No server ever sees the private half, and Try mode
//!   has no server key at all.
//!
//! Nothing cryptographically binds them. The vouch is the binding, which is the
//! roster's own position on who decides membership, and it is what sharpens the
//! dishonest host's limits: the host can add a row and can never forge a bundle.
//!
//! These live in the platform keystore, never in the state blob. The blob is
//! opened *with* them ([`crate::Client::open`]), which is also what makes a blob
//! restored onto a device without the seeds inert.

use sha2::{Digest, Sha256};
use sund_client::identity::IdentityKey;
use sund_client::sigauth::DeviceKey;

use crate::error::ClientError;

/// The length of each seed.
pub const SEED_BYTES: usize = 32;

/// Domain separator for the session pickle key.
///
/// The same `family-beacon/<purpose>/v1\0` shape the signing domains use
/// (`sund_client::identity::SignaturePurpose`), for the same reason: a
/// derivation whose input could be mistaken for another's is a derivation
/// waiting to collide. It is not a *signing* domain and is never signed over —
/// the input here is a private seed, not a canonical payload — so the two
/// families of string cannot be confused by construction.
const PICKLE_DOMAIN: &[u8] = b"family-beacon/session-pickle/v1\0";

/// A device's two Ed25519 seeds.
///
/// Generated once at first run and stored by the app layer in the platform
/// keystore. Losing them is losing the device's identity: there is no recovery
/// path, and the device has to be re-admitted with a fresh vouch.
#[derive(Clone, PartialEq, Eq)]
pub struct Seeds {
    device: [u8; SEED_BYTES],
    identity: [u8; SEED_BYTES],
}

impl std::fmt::Debug for Seeds {
    /// Opaque on purpose. A seed that reaches a log is a seed that has left the
    /// keystore.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Seeds").finish_non_exhaustive()
    }
}

impl Seeds {
    /// Draw two fresh seeds from the platform RNG.
    ///
    /// The only entropy this crate takes. Everything else random in the stack is
    /// either passed in by the caller (queue seeds) or produced by vodozemac.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Rng`] if the platform RNG is unavailable, which is
    /// fatal rather than recoverable: there is no weaker source to fall back to
    /// and no honest way to continue without one.
    pub fn generate() -> Result<Self, ClientError> {
        let mut device = [0u8; SEED_BYTES];
        let mut identity = [0u8; SEED_BYTES];
        getrandom::fill(&mut device).map_err(|error| ClientError::Rng {
            detail: error.to_string(),
        })?;
        getrandom::fill(&mut identity).map_err(|error| ClientError::Rng {
            detail: error.to_string(),
        })?;
        Ok(Self { device, identity })
    }

    /// Rebuild from seeds the app layer read back out of the keystore.
    #[must_use]
    pub fn from_parts(device: [u8; SEED_BYTES], identity: [u8; SEED_BYTES]) -> Self {
        Self { device, identity }
    }

    /// The request-signing seed, to be written to the keystore.
    #[must_use]
    pub fn device_seed(&self) -> &[u8; SEED_BYTES] {
        &self.device
    }

    /// The protocol-identity seed, to be written to the keystore.
    #[must_use]
    pub fn identity_seed(&self) -> &[u8; SEED_BYTES] {
        &self.identity
    }

    pub(crate) fn device_key(&self) -> DeviceKey {
        DeviceKey::from_seed(&self.device)
    }

    pub(crate) fn identity_key(&self) -> IdentityKey {
        IdentityKey::from_seed(&self.identity)
    }

    /// The key the session layer's account and session pickles are encrypted
    /// under.
    ///
    /// Derived rather than stored, for two reasons. It keeps the app layer down
    /// to the two secrets `core/README.md` already asks it to hold, instead of a
    /// third whose loss would be silently unrecoverable. And it means the
    /// pickles in the state blob stay encrypted under a key that lives in the
    /// keystore — so a blob that leaks past the platform's at-rest encryption
    /// still yields no session state.
    pub(crate) fn pickle_key(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PICKLE_DOMAIN);
        hasher.update(self.identity);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds() -> Seeds {
        Seeds::from_parts([1u8; SEED_BYTES], [2u8; SEED_BYTES])
    }

    #[test]
    fn generated_seeds_differ_from_each_other() {
        // One RNG call filling both would be a plausible-looking bug that makes
        // the request key and the identity key the same key.
        let seeds = Seeds::generate().expect("the platform RNG is available");
        assert_ne!(seeds.device_seed(), seeds.identity_seed());
        assert_ne!(seeds.device_seed(), &[0u8; SEED_BYTES]);
    }

    #[test]
    fn the_pickle_key_is_derived_from_the_identity_seed_alone() {
        let a = Seeds::from_parts([9u8; SEED_BYTES], [2u8; SEED_BYTES]);
        assert_eq!(
            seeds().pickle_key(),
            a.pickle_key(),
            "the request-signing seed must not enter the derivation: it is \
             replaceable, and the session store is not"
        );

        let b = Seeds::from_parts([1u8; SEED_BYTES], [3u8; SEED_BYTES]);
        assert_ne!(seeds().pickle_key(), b.pickle_key());
    }

    #[test]
    fn the_pickle_key_is_not_the_seed() {
        assert_ne!(
            seeds().pickle_key(),
            *seeds().identity_seed(),
            "a derivation that returned its input would put the signing seed \
             into every pickle"
        );
    }

    #[test]
    fn debug_does_not_print_seed_material() {
        let rendered = format!("{:?}", seeds());
        assert!(!rendered.contains('1'), "{rendered}");
        assert!(rendered.contains("Seeds"), "{rendered}");
    }
}
