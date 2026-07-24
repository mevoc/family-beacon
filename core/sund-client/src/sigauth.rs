//! The canonical form of a signed Sund management-plane request.
//!
//! This is the one contract the server and every client must reproduce
//! byte-for-byte. Sund's own `internal/sigauth` package says so and keeps its
//! Go implementation dependency-free for the same reason; this is the Rust
//! side of the same agreement, and the tests below are deliberately the same
//! assertions as Sund's, so drift shows up as a failure rather than as a 401
//! nobody can explain.
//!
//! A device signs, with its Ed25519 identity key, the newline-joined tuple:
//!
//! ```text
//! METHOD \n PATH \n TIMESTAMP \n NONCE \n hex(sha256(BODY))
//! ```
//!
//! where PATH carries no query string, TIMESTAMP is the RFC 3339 UTC string
//! also sent in the header, NONCE is per-request, and BODY is the raw request
//! body (empty for GET). The server rejects a timestamp more than five minutes
//! from its own clock and remembers nonces for that window to refuse replays.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};

/// Header carrying the device id.
pub const HEADER_DEVICE_ID: &str = "Sund-Device-Id";
/// Header carrying the signed timestamp.
pub const HEADER_TIMESTAMP: &str = "Sund-Timestamp";
/// Header carrying the per-request nonce.
pub const HEADER_NONCE: &str = "Sund-Nonce";
/// Header carrying the base64 signature.
pub const HEADER_SIGNATURE: &str = "Sund-Signature";
/// Header carrying a per-queue sender key on the first send to an open queue,
/// after which the server has bound it and it is absent.
pub const HEADER_SENDER_KEY: &str = "Sund-Sender-Key";

/// A request about to be signed.
///
/// The timestamp and nonce are arguments rather than something this module
/// generates. The core does not own a clock or a random source: the app layer
/// does, it is the layer that must stay inside the server's skew window, and
/// tests get determinism for free.
#[derive(Debug, Clone, Copy)]
pub struct RequestToSign<'a> {
    /// HTTP method, uppercase.
    pub method: &'a str,
    /// URL path, without query string. Any proxy that rewrites this breaks
    /// every signature — see the reverse-proxy warning in
    /// `docker/caddy/Caddyfile`.
    pub path: &'a str,
    /// RFC 3339 UTC timestamp, also sent in [`HEADER_TIMESTAMP`].
    pub timestamp: &'a str,
    /// Per-request nonce, also sent in [`HEADER_NONCE`].
    pub nonce: &'a str,
    /// Raw request body; empty for GET.
    pub body: &'a [u8],
}

/// Build the exact byte sequence a client signs and the server verifies.
#[must_use]
pub fn signing_string(request: &RequestToSign<'_>) -> Vec<u8> {
    let digest = Sha256::digest(request.body);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        // Writing to a String cannot fail; the Result is discarded rather than
        // unwrapped so no panic path exists here at all.
        let _ = write!(hex, "{byte:02x}");
    }
    [
        request.method,
        request.path,
        request.timestamp,
        request.nonce,
        &hex,
    ]
    .join("\n")
    .into_bytes()
}

/// A device's Ed25519 identity key.
#[derive(Debug, Clone)]
pub struct DeviceKey {
    signing: SigningKey,
}

/// A per-queue key, which signs on the transport plane.
///
/// Same primitive and same signing string as [`DeviceKey`], different key and
/// different principal: a transport-plane request is authenticated by the queue
/// key alone and carries no device id, which is what stops the server from
/// linking a message to the device that sent it. Sund binds a queue's sender
/// key on the first valid send and never rebinds it.
///
/// The alias exists so that call sites say which of the two they mean; nothing
/// stops a caller passing an identity key here, and nothing should — the server
/// only ever compares against the key the queue was created or bound with.
pub type QueueKey = DeviceKey;

impl DeviceKey {
    /// Build from a 32-byte seed. Generating and storing that seed is the app
    /// layer's job, because key storage is where the platforms genuinely differ
    /// (Keystore, Secure Enclave, browser storage).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// The public key, as Sund stores it.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign a request, returning the base64 signature for
    /// [`HEADER_SIGNATURE`].
    #[must_use]
    pub fn sign(&self, request: &RequestToSign<'_>) -> String {
        BASE64.encode(self.signing.sign(&signing_string(request)).to_bytes())
    }

    /// The full header set for a request, ready to attach.
    #[must_use]
    pub fn headers(
        &self,
        device_id: &str,
        request: &RequestToSign<'_>,
    ) -> Vec<(&'static str, String)> {
        vec![
            (HEADER_DEVICE_ID, device_id.to_owned()),
            (HEADER_TIMESTAMP, request.timestamp.to_owned()),
            (HEADER_NONCE, request.nonce.to_owned()),
            (HEADER_SIGNATURE, self.sign(request)),
        ]
    }
}

/// Verify a base64 signature against a raw public key.
///
/// The client needs this to check what a peer signed, and the tests need it to
/// prove the two halves agree.
#[must_use]
pub fn verify(public_key: &[u8; 32], request: &RequestToSign<'_>, signature_b64: &str) -> bool {
    let Ok(bytes) = BASE64.decode(signature_b64) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&bytes) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    key.verify(&signing_string(request), &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request<'a>(method: &'a str, path: &'a str, body: &'a [u8]) -> RequestToSign<'a> {
        RequestToSign {
            method,
            path,
            timestamp: "2026-07-20T10:04:12Z",
            nonce: "n1",
            body,
        }
    }

    #[test]
    fn the_signing_string_is_the_documented_tuple() {
        // Byte-for-byte, including the hash of the empty body. This constant is
        // the cross-implementation anchor: if Sund, beaconsim or this crate
        // ever disagree about the canonical form, one of them fails here rather
        // than emitting 401s in the field.
        let got = signing_string(&request("GET", "/v1/devices", b""));
        assert_eq!(
            String::from_utf8(got).expect("utf8"),
            "GET\n/v1/devices\n2026-07-20T10:04:12Z\nn1\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn every_field_changes_the_signing_string() {
        let base = signing_string(&request("GET", "/v1/devices", b""));
        let variants = [
            signing_string(&request("POST", "/v1/devices", b"")),
            signing_string(&request("GET", "/v1/other", b"")),
            signing_string(&request("GET", "/v1/devices", b"x")),
            signing_string(&RequestToSign {
                timestamp: "2026-07-20T10:09:12Z",
                ..request("GET", "/v1/devices", b"")
            }),
            signing_string(&RequestToSign {
                nonce: "n2",
                ..request("GET", "/v1/devices", b"")
            }),
        ];
        for variant in variants {
            assert_ne!(base, variant);
        }
    }

    #[test]
    fn signatures_round_trip_and_do_not_transfer() {
        let key = DeviceKey::from_seed(&[7u8; 32]);
        let req = request("POST", "/v1/devices/register", br#"{"x":1}"#);
        let signature = key.sign(&req);
        assert!(verify(&key.public_key(), &req, &signature));

        // The same signature over a different path must not verify: this is
        // exactly what a path-rewriting proxy would produce.
        let rewritten = request("POST", "/register", br#"{"x":1}"#);
        assert!(!verify(&key.public_key(), &rewritten, &signature));

        // Nor should another device's key accept it.
        let other = DeviceKey::from_seed(&[8u8; 32]);
        assert!(!verify(&other.public_key(), &req, &signature));
    }

    #[test]
    fn a_mangled_signature_is_refused_rather_than_panicking() {
        let key = DeviceKey::from_seed(&[7u8; 32]);
        let req = request("GET", "/v1/devices", b"");
        assert!(!verify(&key.public_key(), &req, "not base64!"));
        assert!(!verify(&key.public_key(), &req, "c2hvcnQ="));
    }

    #[test]
    fn headers_carry_what_the_server_reads() {
        let key = DeviceKey::from_seed(&[7u8; 32]);
        let req = request("GET", "/v1/devices", b"");
        let headers = key.headers("dev_A", &req);
        let names: Vec<&str> = headers.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec![
                HEADER_DEVICE_ID,
                HEADER_TIMESTAMP,
                HEADER_NONCE,
                HEADER_SIGNATURE
            ]
        );
        let signature = &headers[3].1;
        assert!(verify(&key.public_key(), &req, signature));
    }
}
