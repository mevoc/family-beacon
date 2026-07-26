//! The key bundle: how a peer learns enough to start talking to an offline
//! device.
//!
//! Sund stores a bundle as an opaque, size-capped blob and never interprets it
//! (`../sund/docs/Sund-PRD.md` → Key bundles), so the format is entirely ours to
//! define. Two decisions shape it, both from CLAUDE.md decision #6 and
//! `docs/FamilyBeacon-Sessions.md`:
//!
//! **Grant-only reachability.** The bundle carries key material and *no
//! initiation address*. Knowing a device exists does not make it reachable:
//! sending needs a queue sender id, which the recipient mints and hands out
//! deliberately. A new device is therefore confined to its inviter until the
//! roster layer relays addresses on its behalf, and no member can be spammed by
//! a device nobody introduced. The alternative — a published-bundle mesh —
//! would have made every member reachable by every other, including by a device
//! a dishonest host injected into the device list before any vouch check
//! rejects it.
//!
//! **Fallback-key mode, not one-time prekeys.** Sund returns the same bytes to
//! every fetch and pops nothing, because popping would mean interpreting the
//! blob. Two peers fetching concurrently would therefore reuse a one-time key,
//! so the bundle publishes Olm's *signed fallback key* instead and accepts
//! signed-prekey-grade forward secrecy for the initial message only — until the
//! first ratchet step, after which the ratchet's own guarantees take over.
//!
//! ## Verifying against the right authority
//!
//! A bundle is self-authenticating: signed by the publishing device's
//! [`IdentityKey`](crate::identity::IdentityKey) and verified by the fetcher.
//! *What* the fetcher verifies against matters, and this crate takes the
//! roster's answer over Sund's. `../sund/docs/Sund-PRD.md` says a fetcher
//! verifies "against the device list"; `docs/FamilyBeacon-Roster.md` says to
//! verify "against the roster's `identity_pk`" — the key a family member
//! physically vouched for. The roster's rule is strictly stronger, because the
//! device list is writable by whoever hosts the server, and it is the one this
//! crate implements: [`SignedBundle::verify`] takes the expected
//! [`IdentityPublicKey`] as an argument and has no way to discover one on its
//! own. A caller holding only the server's list can still pass that, and will
//! be less safe for it; the type cannot stop them, so the roster layer is where
//! that choice is made and ledgered.

use serde::{Deserialize, Serialize};
use vodozemac::Curve25519PublicKey;

use crate::canonical::{CanonicalError, to_canonical_json};
use crate::identity::{IdentityPublicKey, SignaturePurpose, VerifyError};

/// Sund's cap on a published bundle, in bytes.
///
/// Ours is a couple of hundred bytes, so the cap is not a design constraint —
/// it is here so an over-long `device_id` or a future field fails on this
/// device with a clear error instead of as a 413 from the server.
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024;

/// The bundle format version.
pub const BUNDLE_VERSION: u8 = 1;

/// What a device publishes so peers can open a session with it while it is
/// offline.
///
/// This is the signed payload. Field names are the wire names, and the encoding
/// that gets signed is [`crate::canonical`], not this struct's declaration
/// order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    /// Bundle format version.
    pub v: u8,
    /// The publishing device's transport-layer id — its Sund device id, or in
    /// Try mode the id minted at join.
    ///
    /// Inside the signature so a bundle cannot be lifted from one device's slot
    /// and served as another's. Sund would happily do that; the signature makes
    /// it detectable.
    pub device_id: String,
    /// The publisher's protocol identity key, base64. The roster's
    /// `identity_pk`, and the key this bundle's own signature verifies against.
    pub identity_pk: String,
    /// The publisher's Olm Curve25519 identity key, base64.
    pub curve25519: String,
    /// The signed fallback key, base64.
    pub fallback_key: String,
    /// The fallback key's Olm key id, so a rotation is visible as a change of
    /// id rather than only as a change of bytes.
    pub fallback_key_id: String,
    /// When this bundle was published, RFC 3339 UTC.
    ///
    /// Advisory: it lets a fetcher notice a bundle that has not rotated in far
    /// too long. It is not a freshness *guarantee*, because the publisher writes
    /// it — and it is inside the signature only so the host cannot rewrite it.
    pub published_at: String,
}

/// A [`Bundle`] with the signature that makes it self-authenticating.
///
/// This is what crosses the wire, and what [`crate::client::DeviceClient::publish_bundle`]
/// takes as opaque bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBundle {
    /// The signed payload.
    pub bundle: Bundle,
    /// Base64 Ed25519 signature by `bundle.identity_pk` over
    /// `family-beacon/bundle/v1\0 || canonical_json(bundle)`.
    pub sig: String,
}

/// Why a bundle was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleError {
    /// The bytes were not a `SignedBundle` at all.
    Malformed(String),
    /// A version this build does not speak.
    UnsupportedVersion {
        /// The version found on the wire.
        found: u8,
    },
    /// The bundle is signed by a key other than the one expected — the
    /// injected-device and stale-key signal both land here.
    WrongIdentity {
        /// The `identity_pk` the caller expected, base64.
        expected: String,
        /// The `identity_pk` the bundle carries, base64.
        found: String,
    },
    /// The signature did not verify.
    BadSignature(VerifyError),
    /// A key inside the bundle was not a valid Curve25519 point, or a field was
    /// empty.
    BadKeyMaterial(String),
    /// Over [`MAX_BUNDLE_BYTES`].
    TooLarge {
        /// The encoded size.
        bytes: usize,
    },
    /// The payload could not be canonically encoded.
    Canonical(CanonicalError),
}

impl From<CanonicalError> for BundleError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "malformed bundle: {detail}"),
            Self::UnsupportedVersion { found } => write!(f, "unsupported bundle version {found}"),
            Self::WrongIdentity { expected, found } => write!(
                f,
                "bundle is signed by `{found}`, expected the vouched `{expected}`"
            ),
            Self::BadSignature(error) => write!(f, "bundle signature: {error}"),
            Self::BadKeyMaterial(detail) => write!(f, "bad key material: {detail}"),
            Self::TooLarge { bytes } => {
                write!(
                    f,
                    "bundle is {bytes} bytes, over the {MAX_BUNDLE_BYTES} cap"
                )
            }
            Self::Canonical(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for BundleError {}

impl SignedBundle {
    /// Parse published bytes without verifying anything.
    ///
    /// Deliberately not enough to use: everything that matters comes from
    /// [`Self::verify`], and the two are separate only so a caller can read
    /// `bundle.identity_pk` in order to *look up* what to expect. Reading it and
    /// then verifying against it would be circular, and is exactly the mistake
    /// [`Self::verify`]'s signature makes awkward.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::Malformed`], [`BundleError::TooLarge`] or
    /// [`BundleError::UnsupportedVersion`].
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleError> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(BundleError::TooLarge { bytes: bytes.len() });
        }
        let signed: Self = serde_json::from_slice(bytes)
            .map_err(|error| BundleError::Malformed(error.to_string()))?;
        if signed.bundle.v != BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion {
                found: signed.bundle.v,
            });
        }
        Ok(signed)
    }

    /// Encode for publication.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::Malformed`] if the value cannot be serialised, or
    /// [`BundleError::TooLarge`] over the cap.
    pub fn encode(&self) -> Result<Vec<u8>, BundleError> {
        let bytes =
            serde_json::to_vec(self).map_err(|error| BundleError::Malformed(error.to_string()))?;
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(BundleError::TooLarge { bytes: bytes.len() });
        }
        Ok(bytes)
    }

    /// Verify the signature against the identity key the family vouched for,
    /// and return the key material it carries.
    ///
    /// `expected_identity` must come from the roster — the `identity_pk` in the
    /// vouch that admitted this device — and never from the bundle itself or
    /// from Sund's device list. The `device_id` check is part of the same
    /// argument: the caller says who it thinks it is talking to, and a bundle
    /// served from the wrong slot fails here.
    ///
    /// # Errors
    ///
    /// Returns [`BundleError::WrongIdentity`] if the bundle names a different
    /// identity key, [`BundleError::BadSignature`] if it does not verify,
    /// [`BundleError::Malformed`] on a device-id mismatch, and
    /// [`BundleError::BadKeyMaterial`] if the Curve25519 keys do not parse.
    pub fn verify(
        &self,
        expected_device_id: &str,
        expected_identity: IdentityPublicKey,
    ) -> Result<PeerKeys, BundleError> {
        let expected_b64 = expected_identity.to_base64();
        if self.bundle.identity_pk != expected_b64 {
            return Err(BundleError::WrongIdentity {
                expected: expected_b64,
                found: self.bundle.identity_pk.clone(),
            });
        }
        if self.bundle.device_id != expected_device_id {
            return Err(BundleError::Malformed(format!(
                "bundle is for device `{}`, expected `{expected_device_id}`",
                self.bundle.device_id
            )));
        }

        let canonical = to_canonical_json(&self.bundle)?;
        expected_identity
            .verify_canonical(SignaturePurpose::Bundle, &canonical, &self.sig)
            .map_err(BundleError::BadSignature)?;

        Ok(PeerKeys {
            device_id: self.bundle.device_id.clone(),
            identity: expected_identity,
            curve25519: parse_curve25519(&self.bundle.curve25519, "curve25519")?,
            fallback_key: parse_curve25519(&self.bundle.fallback_key, "fallback_key")?,
            fallback_key_id: self.bundle.fallback_key_id.clone(),
        })
    }
}

fn parse_curve25519(encoded: &str, field: &str) -> Result<Curve25519PublicKey, BundleError> {
    if encoded.is_empty() {
        return Err(BundleError::BadKeyMaterial(format!("`{field}` is empty")));
    }
    Curve25519PublicKey::from_base64(encoded)
        .map_err(|error| BundleError::BadKeyMaterial(format!("`{field}`: {error}")))
}

/// Everything a verified bundle yields: the keys needed to open a session, and
/// the identity they are bound to.
///
/// Only obtainable from [`SignedBundle::verify`], so there is no path from
/// unverified bytes to usable key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerKeys {
    /// The peer's transport-layer device id.
    pub device_id: String,
    /// The peer's vouched protocol identity key.
    pub identity: IdentityPublicKey,
    /// The peer's Olm Curve25519 identity key.
    pub curve25519: Curve25519PublicKey,
    /// The peer's signed fallback key, used as the one-time key when opening an
    /// outbound session.
    pub fallback_key: Curve25519PublicKey,
    /// The fallback key's Olm key id.
    pub fallback_key_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKey;
    use vodozemac::olm::Account;

    struct Fixture {
        identity: IdentityKey,
        signed: SignedBundle,
    }

    fn fixture() -> Fixture {
        let identity = IdentityKey::from_seed(&[3u8; 32]);
        let mut account = Account::new();
        account.generate_fallback_key();
        let (key_id, fallback) = account
            .fallback_key()
            .into_iter()
            .next()
            .expect("a fallback key was just generated");

        let bundle = Bundle {
            v: BUNDLE_VERSION,
            device_id: "dev_A".to_owned(),
            identity_pk: identity.public_key().to_base64(),
            curve25519: account.curve25519_key().to_base64(),
            fallback_key: fallback.to_base64(),
            fallback_key_id: key_id.to_base64(),
            published_at: "2026-07-26T10:00:00Z".to_owned(),
        };
        let sig = identity
            .sign(SignaturePurpose::Bundle, &bundle)
            .expect("signs");
        Fixture {
            identity,
            signed: SignedBundle { bundle, sig },
        }
    }

    #[test]
    fn a_well_formed_bundle_round_trips_and_verifies() {
        let f = fixture();
        let bytes = f.signed.encode().expect("encodes");
        let decoded = SignedBundle::decode(&bytes).expect("decodes");
        assert_eq!(decoded, f.signed);

        let keys = decoded
            .verify("dev_A", f.identity.public_key())
            .expect("verifies");
        assert_eq!(keys.device_id, "dev_A");
        assert_eq!(keys.identity, f.identity.public_key());
    }

    #[test]
    fn a_bundle_signed_by_another_key_is_refused_before_any_crypto() {
        // The injected-device case: a host serves a bundle whose identity key it
        // controls. The vouched key does not match, so this fails on the field
        // comparison and never reaches signature verification.
        let f = fixture();
        let attacker = IdentityKey::from_seed(&[99u8; 32]);
        assert!(matches!(
            f.signed.verify("dev_A", attacker.public_key()),
            Err(BundleError::WrongIdentity { .. })
        ));
    }

    #[test]
    fn a_tampered_bundle_fails_the_signature() {
        let f = fixture();
        let mut tampered = f.signed.clone();
        // Swap in key material the attacker holds, keeping the claimed identity.
        let mut theirs = Account::new();
        theirs.generate_fallback_key();
        tampered.bundle.curve25519 = theirs.curve25519_key().to_base64();

        assert!(matches!(
            tampered.verify("dev_A", f.identity.public_key()),
            Err(BundleError::BadSignature(VerifyError::Mismatch))
        ));
    }

    #[test]
    fn a_bundle_served_from_the_wrong_slot_is_refused() {
        // Sund would serve dev_A's bytes from dev_B's endpoint without noticing;
        // device_id is inside the signature so the client does.
        let f = fixture();
        assert!(matches!(
            f.signed.verify("dev_B", f.identity.public_key()),
            Err(BundleError::Malformed(_))
        ));
    }

    #[test]
    fn an_unknown_version_is_refused_at_decode() {
        let f = fixture();
        let mut future = f.signed.clone();
        future.bundle.v = 2;
        let bytes = serde_json::to_vec(&future).expect("encodes");
        assert_eq!(
            SignedBundle::decode(&bytes),
            Err(BundleError::UnsupportedVersion { found: 2 })
        );
    }

    #[test]
    fn empty_or_invalid_key_material_is_refused_and_named() {
        let f = fixture();
        let identity = IdentityKey::from_seed(&[3u8; 32]);
        let mut bundle = f.signed.bundle.clone();
        bundle.fallback_key = String::new();
        let sig = identity
            .sign(SignaturePurpose::Bundle, &bundle)
            .expect("signs");
        let signed = SignedBundle { bundle, sig };

        match signed.verify("dev_A", identity.public_key()) {
            Err(BundleError::BadKeyMaterial(detail)) => {
                assert!(detail.contains("fallback_key"), "names the field: {detail}");
            }
            other => panic!("expected BadKeyMaterial, got {other:?}"),
        }
    }

    #[test]
    fn a_bundle_carries_no_initiation_address() {
        // Grant-only reachability, asserted rather than merely documented: if a
        // field like `sender_id` is ever added, this fails and whoever added it
        // has to revisit the decision in the module docs.
        let f = fixture();
        let value: serde_json::Value =
            serde_json::from_slice(&f.signed.encode().expect("encodes")).expect("parses");
        let fields: Vec<&str> = value["bundle"]
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fields,
            vec![
                "curve25519",
                "device_id",
                "fallback_key",
                "fallback_key_id",
                "identity_pk",
                "published_at",
                "v",
            ]
        );
    }

    #[test]
    fn a_real_bundle_is_far_inside_sunds_cap() {
        let f = fixture();
        let bytes = f.signed.encode().expect("encodes");
        assert!(
            bytes.len() < MAX_BUNDLE_BYTES / 4,
            "bundle is {} bytes; the cap is not supposed to be near",
            bytes.len()
        );
    }

    #[test]
    fn oversized_bytes_are_refused_at_decode() {
        let bytes = vec![b'x'; MAX_BUNDLE_BYTES + 1];
        assert_eq!(
            SignedBundle::decode(&bytes),
            Err(BundleError::TooLarge {
                bytes: MAX_BUNDLE_BYTES + 1
            })
        );
    }
}
