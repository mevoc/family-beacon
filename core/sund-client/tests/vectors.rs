//! Conformance against the shared bundle and canonical-JSON vectors.
//!
//! Same discipline as `beacon-protocol`'s vector suite and for the same reason:
//! three implementations exist (this crate, Sund's Go side, beaconsim in
//! Python), and three implementations drift unless they are tested against one
//! source of truth. The corpus lives at `shared/protocol/testvectors/` and is
//! consumed by checkout at a pinned ref, never vendored.
//!
//! What these vectors gate is narrower and harder than the envelope corpus: the
//! *exact bytes* a signature is computed over. Ed25519 is deterministic (RFC
//! 8032), so `sig_b64` is reproducible by every implementation, and a
//! disagreement about key ordering or the domain prefix shows up here as a
//! failed byte comparison rather than as a rejected vouch nobody can explain.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sund_client::bundle::{Bundle, BundleError, SignedBundle};
use sund_client::canonical::{CanonicalError, to_canonical_json};
use sund_client::identity::{IdentityKey, IdentityPublicKey, SignaturePurpose, VerifyError};

const VECTORS: &str = include_str!("../../../shared/protocol/testvectors/bundles.json");

fn corpus() -> serde_json::Value {
    serde_json::from_str(VECTORS).expect("vector file parses")
}

fn seed_from(encoded: &str) -> [u8; 32] {
    BASE64
        .decode(encoded)
        .expect("seed is base64")
        .try_into()
        .expect("seed is 32 bytes")
}

fn signed_bundle_from(case: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "bundle": case["bundle"].clone(),
        "sig": case["sig_b64"].clone(),
    })
}

#[test]
fn the_signing_domains_are_the_bytes_the_corpus_declares() {
    let corpus = corpus();
    let hex = &corpus["signing"]["domain_hex"];
    for (purpose, name) in [
        (SignaturePurpose::Bundle, "bundle"),
        (SignaturePurpose::Vouch, "vouch"),
        (SignaturePurpose::Removal, "removal"),
    ] {
        let expected = hex[name].as_str().expect("domain hex");
        let actual: String = purpose
            .domain()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(actual, expected, "domain for `{name}`");
        assert!(
            actual.ends_with("00"),
            "the domain for `{name}` must be NUL-terminated"
        );
    }
}

#[test]
fn every_canonical_json_case_encodes_as_the_corpus_says() {
    let corpus = corpus();
    let cases = corpus["canonical_json_cases"]
        .as_array()
        .expect("canonical_json_cases array");
    assert!(!cases.is_empty(), "corpus must not be empty");

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let input = &case["input"];
        let expect = case["expect"].as_str().expect("expect");

        match expect {
            "encode" => {
                let expected = case["canonical_json"].as_str().expect("canonical_json");
                let actual = to_canonical_json(input)
                    .unwrap_or_else(|error| panic!("case `{name}`: {error}"));
                assert_eq!(
                    String::from_utf8(actual).expect("utf-8"),
                    expected,
                    "case `{name}`"
                );
            }
            "refuse" => {
                let reason = case["reason"].as_str().expect("reason");
                assert_eq!(reason, "floating_point", "case `{name}`: unknown reason");
                let path = case["float_path"].as_str().expect("float_path");
                assert_eq!(
                    to_canonical_json(input),
                    Err(CanonicalError::FloatingPoint {
                        path: path.to_owned()
                    }),
                    "case `{name}`"
                );
            }
            other => panic!("case `{name}`: unknown expectation `{other}`"),
        }
    }
}

#[test]
fn every_bundle_case_behaves_as_the_corpus_says() {
    let corpus = corpus();
    let cases = corpus["bundle_cases"]
        .as_array()
        .expect("bundle_cases array");
    assert!(!cases.is_empty(), "corpus must not be empty");

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let expect = case["expect"].as_str().expect("expect");

        match expect {
            // The load-bearing case: canonical bytes, a deterministic signature,
            // and a successful verification, all pinned together.
            "verify" => {
                let seed = seed_from(case["identity_seed_b64"].as_str().expect("seed"));
                let identity = IdentityKey::from_seed(&seed);
                assert_eq!(
                    identity.public_key().to_base64(),
                    case["identity_pk_b64"].as_str().expect("identity_pk_b64"),
                    "case `{name}`: seed does not derive the declared public key"
                );

                let bundle: Bundle =
                    serde_json::from_value(case["bundle"].clone()).expect("bundle parses");
                let canonical = to_canonical_json(&bundle).expect("encodes");
                assert_eq!(
                    String::from_utf8(canonical.clone()).expect("utf-8"),
                    case["canonical_json"].as_str().expect("canonical_json"),
                    "case `{name}`: canonical encoding"
                );

                let signature = identity.sign_canonical(SignaturePurpose::Bundle, &canonical);
                assert_eq!(
                    signature,
                    case["sig_b64"].as_str().expect("sig_b64"),
                    "case `{name}`: Ed25519 is deterministic, so this must match exactly"
                );

                let signed: SignedBundle =
                    serde_json::from_value(signed_bundle_from(case)).expect("signed bundle parses");
                let device_id = case["expected_device_id"].as_str().expect("device id");
                let keys = signed
                    .verify(device_id, identity.public_key())
                    .unwrap_or_else(|error| panic!("case `{name}`: {error}"));
                assert_eq!(keys.device_id, device_id);
            }

            // Grant-only reachability, asserted against the shipping struct
            // rather than only against the corpus.
            "field_set" => {
                let expected: Vec<&str> = case["fields"]
                    .as_array()
                    .expect("fields array")
                    .iter()
                    .map(|field| field.as_str().expect("field name"))
                    .collect();

                let reference = cases
                    .iter()
                    .find(|other| other["expect"] == "verify")
                    .expect("corpus needs a verify case to take a bundle shape from");
                let bundle: Bundle =
                    serde_json::from_value(reference["bundle"].clone()).expect("bundle parses");
                let encoded = to_canonical_json(&bundle).expect("encodes");
                let value: serde_json::Value = serde_json::from_slice(&encoded).expect("re-parses");
                let actual: Vec<&str> = value
                    .as_object()
                    .expect("object")
                    .keys()
                    .map(String::as_str)
                    .collect();
                assert_eq!(actual, expected, "case `{name}`");
            }

            "wrong_identity" | "bad_signature" | "wrong_device" => {
                let expected_identity = IdentityPublicKey::from_base64(
                    case["expected_identity_pk_b64"]
                        .as_str()
                        .expect("expected_identity_pk_b64"),
                )
                .expect("valid public key");
                let signed: SignedBundle =
                    serde_json::from_value(signed_bundle_from(case)).expect("signed bundle parses");
                let device_id = case["expected_device_id"].as_str().expect("device id");
                let outcome = signed.verify(device_id, expected_identity);

                match (expect, &outcome) {
                    ("wrong_identity", Err(BundleError::WrongIdentity { .. })) => {}
                    ("bad_signature", Err(BundleError::BadSignature(VerifyError::Mismatch))) => {}
                    ("wrong_device", Err(BundleError::Malformed(_))) => {}
                    _ => panic!("case `{name}`: expected `{expect}`, got {outcome:?}"),
                }
            }

            "unsupported_version" => {
                let found = u8::try_from(
                    case["found_version"]
                        .as_u64()
                        .expect("found_version is a number"),
                )
                .expect("version fits a u8");
                let bytes = serde_json::to_vec(&signed_bundle_from(case)).expect("serialises");
                assert_eq!(
                    SignedBundle::decode(&bytes),
                    Err(BundleError::UnsupportedVersion { found }),
                    "case `{name}`"
                );
            }

            other => panic!("case `{name}`: unknown expectation `{other}`"),
        }
    }
}

#[test]
fn the_corpus_covers_every_signature_purpose() {
    // A purpose nobody wrote a domain vector for is a purpose nothing gates —
    // the same argument the envelope corpus makes about message types.
    let corpus = corpus();
    let declared = corpus["signing"]["domains"]
        .as_object()
        .expect("domains object");
    for purpose in [
        SignaturePurpose::Bundle,
        SignaturePurpose::Vouch,
        SignaturePurpose::Removal,
    ] {
        assert!(
            declared.contains_key(purpose.as_str()),
            "no vector for signature purpose `{}`",
            purpose.as_str()
        );
    }
    assert_eq!(
        declared.len(),
        3,
        "a purpose was added or removed without updating the corpus"
    );
}

#[test]
fn the_corpus_exercises_each_bundle_failure_mode() {
    let corpus = corpus();
    let seen: Vec<&str> = corpus["bundle_cases"]
        .as_array()
        .expect("bundle_cases array")
        .iter()
        .map(|case| case["expect"].as_str().expect("expect"))
        .collect();
    for required in [
        "verify",
        "field_set",
        "wrong_identity",
        "bad_signature",
        "wrong_device",
        "unsupported_version",
    ] {
        assert!(
            seen.contains(&required),
            "corpus has no `{required}` case; every refusal path must be pinned"
        );
    }
}
