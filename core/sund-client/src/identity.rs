//! The protocol identity key: the thing a family vouches for.
//!
//! Deliberately **not** [`crate::sigauth::DeviceKey`]. Both are Ed25519 and it
//! would have been cheaper to use one key for both jobs, but they answer to
//! different layers and the split is the point:
//!
//! | | [`sigauth::DeviceKey`](crate::sigauth::DeviceKey) | [`IdentityKey`] |
//! | --- | --- | --- |
//! | Authenticates | HTTP requests to one Sund | the device, to the family |
//! | Known to | the server, in its device list | every peer, via a vouch |
//! | Exists in Try mode | no — there is no server | yes, unchanged |
//! | Signs | request tuples | bundles, vouches, tombstones |
//!
//! Three consequences worth stating, because each one is a reason the cheaper
//! option was rejected:
//!
//! 1. **Try mode needs an identity and has no Sund key.** Reusing the transport
//!    key would have left `docs/FamilyBeacon-TryMode.md` with a different answer
//!    to the same question, and the roster sits *above* the transport port
//!    precisely so it does not have two.
//! 2. **A dishonest host cannot forge a bundle.** The host can write any public
//!    key into Sund's `devices` row and can serve any bytes from the bundle
//!    store, but it holds no identity key, so the signature fails against the
//!    `identity_pk` the family vouched for. This is `docs/FamilyBeacon-Roster.md`
//!    → "the server's device list is not the authority on membership", enforced
//!    with arithmetic instead of policy.
//! 3. **The binding between the two keys is the vouch, and nothing else.** A
//!    device record ties one `device_id` to one `identity_pk`; the server ties
//!    the same `device_id` to a transport key. When they disagree, the roster
//!    wins, and the disagreement is exactly the injected-device signal the
//!    roster doc asks clients to surface.
//!
//! ## Domain separation
//!
//! One key signs three different kinds of statement, so each signature commits
//! to which kind it is:
//!
//! ```text
//! "family-beacon/" purpose "/v1" 0x00  ||  canonical_json(payload)
//! ```
//!
//! The trailing NUL is what makes the prefix unambiguous: without it a purpose
//! named `vouch` and one named `vouchx` would share a prefix, and a signature
//! over one could be replayed as the other given a cooperative payload.
//! [`SignaturePurpose`] is an enum rather than a `&str` argument for the same
//! reason — a typo would otherwise mint a new, silently incompatible domain.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::Serialize;

use crate::canonical::{CanonicalError, to_canonical_json};

/// The version component of every signing domain.
///
/// Bumping this invalidates every signature made under the old domain, which is
/// the intended blast radius: it is the lever for a breaking change to *what* is
/// signed, and a family mid-upgrade must not accept both.
pub const DOMAIN_VERSION: &str = "v1";

/// What a signature is a statement about.
///
/// The registry is one list on purpose. Bundles are made by this crate; vouches
/// and tombstones are made by the roster layer above it
/// (`docs/FamilyBeacon-Roster.md` → Wire types) and are named here so that no
/// two layers can invent overlapping domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignaturePurpose {
    /// A published key bundle ([`crate::bundle`]).
    Bundle,
    /// A `roster_introduce` vouch: "I authenticated this device in person."
    Vouch,
    /// A `roster_remove` tombstone.
    Removal,
}

impl SignaturePurpose {
    /// The purpose's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bundle => "bundle",
            Self::Vouch => "vouch",
            Self::Removal => "removal",
        }
    }

    /// The full domain prefix, NUL terminator included.
    #[must_use]
    pub fn domain(self) -> Vec<u8> {
        let mut domain = format!("family-beacon/{}/{DOMAIN_VERSION}", self.as_str()).into_bytes();
        domain.push(0);
        domain
    }

    /// The exact bytes signed for this purpose over an already-canonical
    /// payload.
    #[must_use]
    pub fn signing_bytes(self, canonical_payload: &[u8]) -> Vec<u8> {
        let mut bytes = self.domain();
        bytes.extend_from_slice(canonical_payload);
        bytes
    }
}

/// Why a signature did not verify.
///
/// The three cases are kept apart because the transparency ledger tells the user
/// different things about each: a malformed signature is a bug or a truncated
/// message, a mismatch is an attack or a stale key, and a canonicalisation
/// failure never leaves the device that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The payload could not be encoded canonically, so there was nothing to
    /// verify against.
    Canonical(CanonicalError),
    /// The signature was not 64 bytes of base64.
    Malformed,
    /// The signature is well-formed and does not match this key over this
    /// payload.
    Mismatch,
}

impl From<CanonicalError> for VerifyError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonical(error) => write!(f, "{error}"),
            Self::Malformed => write!(f, "malformed signature"),
            Self::Mismatch => write!(f, "signature does not match"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// A device's protocol identity key pair.
///
/// Like [`crate::sigauth::DeviceKey`], it is built from a seed the app layer
/// generates and stores, because key storage is where the platforms genuinely
/// differ — Keystore, Secure Enclave, browser storage. This crate never
/// generates one.
#[derive(Debug, Clone)]
pub struct IdentityKey {
    signing: SigningKey,
}

impl IdentityKey {
    /// Build from a 32-byte seed.
    ///
    /// The seed must be distinct from the device's [`crate::sigauth::DeviceKey`]
    /// seed. Nothing here can check that — the two keys never meet — so it is
    /// stated as a contract and enforced by the app layer generating two.
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The public half: the roster's `identity_pk`.
    #[must_use]
    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey(self.signing.verifying_key())
    }

    /// Sign a structure for one purpose, returning the base64 signature.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalError`] if the payload contains a float or cannot be
    /// serialised.
    pub fn sign<T: Serialize + ?Sized>(
        &self,
        purpose: SignaturePurpose,
        payload: &T,
    ) -> Result<String, CanonicalError> {
        let canonical = to_canonical_json(payload)?;
        Ok(self.sign_canonical(purpose, &canonical))
    }

    /// Sign an already-canonical payload.
    ///
    /// For callers that hold the canonical bytes for another reason — a digest
    /// to compare, a vector to publish — and must not risk re-encoding them
    /// differently.
    #[must_use]
    pub fn sign_canonical(&self, purpose: SignaturePurpose, canonical_payload: &[u8]) -> String {
        let bytes = purpose.signing_bytes(canonical_payload);
        BASE64.encode(self.signing.sign(&bytes).to_bytes())
    }
}

/// The public half of an [`IdentityKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityPublicKey(VerifyingKey);

impl IdentityPublicKey {
    /// Read from 32 raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Malformed`] if the bytes are not a valid Ed25519
    /// public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, VerifyError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| VerifyError::Malformed)
    }

    /// Read from the base64 form used on the wire and in the roster.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Malformed`] if the string is not base64 of a valid
    /// 32-byte Ed25519 public key.
    pub fn from_base64(encoded: &str) -> Result<Self, VerifyError> {
        let bytes = BASE64.decode(encoded).map_err(|_| VerifyError::Malformed)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| VerifyError::Malformed)?;
        Self::from_bytes(&bytes)
    }

    /// The raw 32 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The base64 form used on the wire and in the roster.
    #[must_use]
    pub fn to_base64(self) -> String {
        BASE64.encode(self.0.to_bytes())
    }

    /// Verify a signature over a structure for one purpose.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError`] distinguishing an unencodable payload, a
    /// malformed signature and a mismatch.
    pub fn verify<T: Serialize + ?Sized>(
        &self,
        purpose: SignaturePurpose,
        payload: &T,
        signature_b64: &str,
    ) -> Result<(), VerifyError> {
        let canonical = to_canonical_json(payload)?;
        self.verify_canonical(purpose, &canonical, signature_b64)
    }

    /// Verify a signature over an already-canonical payload.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Malformed`] or [`VerifyError::Mismatch`].
    pub fn verify_canonical(
        &self,
        purpose: SignaturePurpose,
        canonical_payload: &[u8],
        signature_b64: &str,
    ) -> Result<(), VerifyError> {
        let raw = BASE64
            .decode(signature_b64)
            .map_err(|_| VerifyError::Malformed)?;
        let raw: [u8; 64] = raw.try_into().map_err(|_| VerifyError::Malformed)?;
        let signature = Signature::from_bytes(&raw);
        let bytes = purpose.signing_bytes(canonical_payload);
        self.0
            .verify(&bytes, &signature)
            .map_err(|_| VerifyError::Mismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    #[derive(Serialize)]
    struct Payload {
        subject: &'static str,
        epoch: u32,
    }

    fn payload() -> Payload {
        Payload {
            subject: "dev_B",
            epoch: 3,
        }
    }

    #[test]
    fn a_signature_verifies_against_its_own_key_and_purpose() {
        let signer = key(1);
        let signature = signer
            .sign(SignaturePurpose::Vouch, &payload())
            .expect("signs");
        assert_eq!(
            signer
                .public_key()
                .verify(SignaturePurpose::Vouch, &payload(), &signature),
            Ok(())
        );
    }

    #[test]
    fn a_signature_does_not_verify_under_another_purpose() {
        // The whole point of the domain prefix: a tombstone signature must not
        // be replayable as a vouch, whatever the payload looks like.
        let signer = key(1);
        let signature = signer
            .sign(SignaturePurpose::Removal, &payload())
            .expect("signs");
        assert_eq!(
            signer
                .public_key()
                .verify(SignaturePurpose::Vouch, &payload(), &signature),
            Err(VerifyError::Mismatch)
        );
    }

    #[test]
    fn a_signature_does_not_verify_under_another_key() {
        let signature = key(1)
            .sign(SignaturePurpose::Vouch, &payload())
            .expect("signs");
        assert_eq!(
            key(2)
                .public_key()
                .verify(SignaturePurpose::Vouch, &payload(), &signature),
            Err(VerifyError::Mismatch)
        );
    }

    #[test]
    fn a_changed_payload_does_not_verify() {
        let signer = key(1);
        let signature = signer
            .sign(SignaturePurpose::Vouch, &payload())
            .expect("signs");
        let tampered = Payload {
            subject: "dev_B",
            epoch: 4,
        };
        assert_eq!(
            signer
                .public_key()
                .verify(SignaturePurpose::Vouch, &tampered, &signature),
            Err(VerifyError::Mismatch)
        );
    }

    #[test]
    fn field_order_does_not_change_the_signature() {
        // Canonicalisation means a peer that serialises its struct in a
        // different declaration order still produces the same bytes.
        #[derive(Serialize)]
        struct Reordered {
            epoch: u32,
            subject: &'static str,
        }

        let signer = key(1);
        let a = signer
            .sign(SignaturePurpose::Vouch, &payload())
            .expect("signs");
        let b = signer
            .sign(
                SignaturePurpose::Vouch,
                &Reordered {
                    epoch: 3,
                    subject: "dev_B",
                },
            )
            .expect("signs");
        assert_eq!(a, b);
    }

    #[test]
    fn a_malformed_signature_is_distinguished_from_a_mismatch() {
        let verifier = key(1).public_key();
        assert_eq!(
            verifier.verify(SignaturePurpose::Vouch, &payload(), "not base64!"),
            Err(VerifyError::Malformed)
        );
        assert_eq!(
            verifier.verify(
                SignaturePurpose::Vouch,
                &payload(),
                &BASE64.encode([0u8; 8])
            ),
            Err(VerifyError::Malformed),
            "right alphabet, wrong length"
        );
    }

    #[test]
    fn a_float_in_the_payload_is_refused_rather_than_signed() {
        #[derive(Serialize)]
        struct Floaty {
            accuracy: f64,
        }

        assert!(matches!(
            key(1).sign(SignaturePurpose::Vouch, &Floaty { accuracy: 1.5 }),
            Err(CanonicalError::FloatingPoint { .. })
        ));
    }

    #[test]
    fn the_public_key_round_trips_through_base64() {
        let public = key(7).public_key();
        assert_eq!(
            IdentityPublicKey::from_base64(&public.to_base64()),
            Ok(public)
        );
    }

    #[test]
    fn the_domain_is_nul_terminated_so_no_purpose_prefixes_another() {
        let domain = SignaturePurpose::Vouch.domain();
        assert_eq!(domain, b"family-beacon/vouch/v1\0");
        assert_eq!(*domain.last().expect("non-empty"), 0);
    }

    #[test]
    fn the_identity_key_is_not_the_device_key_even_from_the_same_seed() {
        // Same primitive, same seed, different *domain* — so a caller who
        // wrongly reuses one seed still cannot get a Sund request signature to
        // verify as a vouch. The contract is one seed each; this is the
        // backstop.
        let seed = [9u8; 32];
        let identity = IdentityKey::from_seed(&seed);
        let device = crate::sigauth::DeviceKey::from_seed(&seed);
        assert_eq!(
            identity.public_key().to_bytes(),
            device.public_key(),
            "same seed does yield the same public key"
        );

        let request = crate::sigauth::RequestToSign {
            method: "GET",
            path: "/v1/me/bundle",
            timestamp: "2026-07-26T10:00:00Z",
            nonce: "n1",
            body: b"",
        };
        let request_signature = device.sign(&request);
        let canonical = to_canonical_json(&payload()).expect("encodes");
        assert_eq!(
            identity.public_key().verify_canonical(
                SignaturePurpose::Vouch,
                &canonical,
                &request_signature
            ),
            Err(VerifyError::Mismatch),
            "a request signature must never verify as a vouch"
        );
    }
}
