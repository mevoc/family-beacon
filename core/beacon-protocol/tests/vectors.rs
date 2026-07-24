//! Conformance against the shared test vectors.
//!
//! `docs/FamilyBeacon-Protocol.md` → Versioning mandates these vectors and
//! `docs/FamilyBeacon-Testing.md` fixes where they live: canonical in this
//! repo under `shared/protocol/testvectors/`, consumed by every implementation
//! — this crate, and Sund's beaconsim by checkout at a pinned ref. They are the
//! gate on all three implementations rather than per-implementation assertions,
//! because three implementations drift unless they are tested against one
//! source of truth.

use beacon_protocol::envelope::RejectReason;
use beacon_protocol::{Outcome, receive};

const VECTORS: &str = include_str!("../../../shared/protocol/testvectors/envelopes.json");

/// The stable tag each rejection is labelled with in the corpus. Keeping the
/// mapping explicit is the point: a reason renamed in Rust must be renamed in
/// the corpus too, which is what makes the corpus a contract rather than a
/// mirror of this crate.
fn reason_tag(reason: &RejectReason) -> &'static str {
    match reason {
        RejectReason::Malformed(_) => "malformed",
        RejectReason::UnsupportedVersion { .. } => "unsupported_version",
        RejectReason::EmptyField(_) => "empty_field",
        RejectReason::BodyNotObject => "body_not_object",
        RejectReason::BadTimestamp(_) => "bad_timestamp",
        RejectReason::SenderMismatch { .. } => "sender_mismatch",
    }
}

#[test]
fn every_vector_behaves_as_the_corpus_says() {
    let corpus: serde_json::Value = serde_json::from_str(VECTORS).expect("vector file parses");
    let cases = corpus["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty(), "corpus must not be empty");

    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let sender = case["authenticated_sender"]
            .as_str()
            .expect("authenticated_sender");

        // A case carries either a well-formed envelope object or a raw string,
        // the latter for input no object could express.
        let plaintext = match (case.get("raw"), case.get("envelope")) {
            (Some(raw), _) => raw.as_str().expect("raw is a string").as_bytes().to_vec(),
            (None, Some(envelope)) => serde_json::to_vec(envelope).expect("re-encode envelope"),
            (None, None) => panic!("case `{name}` has neither `raw` nor `envelope`"),
        };

        let reception = receive(&plaintext, sender);
        let expect = case["expect"].as_str().expect("expect");

        match (expect, &reception.outcome) {
            ("accept", Outcome::Accepted(envelope)) => {
                assert!(
                    envelope.message_type.is_known(),
                    "case `{name}`: accepted an unknown type"
                );
            }
            ("unknown_type", Outcome::UnknownType(envelope)) => {
                assert!(
                    !envelope.message_type.is_known(),
                    "case `{name}`: known type reported as unknown"
                );
                assert_eq!(
                    envelope.body,
                    serde_json::json!({}),
                    "case `{name}`: an unknown type's body must be dropped"
                );
            }
            ("reject", Outcome::Rejected(reason)) => {
                let want = case["reason"].as_str().expect("reason tag");
                assert_eq!(
                    reason_tag(reason),
                    want,
                    "case `{name}`: rejected for the wrong reason ({reason})"
                );
            }
            (want, got) => panic!("case `{name}`: expected {want}, got {got:?}"),
        }
    }
}

#[test]
fn every_vector_produces_a_ledger_entry() {
    // The ledger rule has no exemptions — not for unknown types, not for
    // garbage that never parsed. Asserting it across the whole corpus is
    // cheaper than remembering to assert it per case.
    let corpus: serde_json::Value = serde_json::from_str(VECTORS).expect("vector file parses");
    for case in corpus["cases"].as_array().expect("cases array") {
        let name = case["name"].as_str().expect("case name");
        let sender = case["authenticated_sender"]
            .as_str()
            .expect("authenticated_sender");
        let plaintext = match (case.get("raw"), case.get("envelope")) {
            (Some(raw), _) => raw.as_str().expect("raw is a string").as_bytes().to_vec(),
            (None, Some(envelope)) => serde_json::to_vec(envelope).expect("re-encode envelope"),
            (None, None) => panic!("case `{name}` has neither `raw` nor `envelope`"),
        };

        let reception = receive(&plaintext, sender);
        assert_eq!(
            reception.ledger.peer, sender,
            "case `{name}`: ledgered against the wrong peer"
        );
    }
}

#[test]
fn the_corpus_covers_every_v1_type() {
    // A type added to the registry without a vector is a type nothing gates.
    let corpus: serde_json::Value = serde_json::from_str(VECTORS).expect("vector file parses");
    let covered: Vec<String> = corpus["cases"]
        .as_array()
        .expect("cases array")
        .iter()
        .filter_map(|c| c["envelope"]["type"].as_str().map(str::to_owned))
        .collect();

    for required in [
        "location",
        "battery",
        "sos",
        "sos_clear",
        "attention",
        "geofence_event",
        "consent_update",
        "config_update",
        "member_info",
        "roster_introduce",
        "roster_remove",
        "roster_sync",
        "receipt",
    ] {
        assert!(
            covered.iter().any(|t| t == required),
            "no vector covers the `{required}` message type"
        );
    }
}
