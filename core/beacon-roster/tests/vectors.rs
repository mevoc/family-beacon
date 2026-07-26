//! Conformance against the shared roster vectors.
//!
//! `docs/FamilyBeacon-Roster.md` requires them in one line — "its test vectors
//! must cover the vouch and removal signatures" — and the reason is the same one
//! that made the bundle corpus matter more than the envelope corpus: what is
//! pinned here is the *exact bytes* a signature covers. An implementation that
//! orders object keys differently produces vouches that verify nowhere, and no
//! amount of outcome-level testing finds that.
//!
//! The corpus also pins the two abuse constants. A family whose devices disagree
//! about the size cap would admit devices some members refuse, which is a split
//! nobody chose.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use beacon_protocol::roster::{RosterIntroduce, RosterRemove, RosterSync};
use beacon_roster::churn::{CHURN_WINDOW, MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY};
use beacon_roster::roster::MAX_ACTIVE_DEVICES;
use sha2::{Digest as _, Sha256};
use sund_client::canonical::to_canonical_json;
use sund_client::identity::{IdentityKey, IdentityPublicKey, SignaturePurpose};

const VECTORS: &str = include_str!("../../../shared/protocol/testvectors/roster.json");

fn corpus() -> serde_json::Value {
    serde_json::from_str(VECTORS).expect("vector file parses")
}

fn seed_from(encoded: &str) -> [u8; 32] {
    BASE64
        .decode(encoded)
        .expect("base64")
        .try_into()
        .expect("32 bytes")
}

fn key(corpus: &serde_json::Value, which: &str) -> IdentityKey {
    let field = format!("{which}_seed_b64");
    IdentityKey::from_seed(&seed_from(
        corpus["keys"][field.as_str()].as_str().expect("seed"),
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn the_declared_public_keys_derive_from_the_declared_seeds() {
    let corpus = corpus();
    for which in ["introducer", "subject"] {
        let field = format!("{which}_pk_b64");
        assert_eq!(
            key(&corpus, which).public_key().to_base64(),
            corpus["keys"][field.as_str()].as_str().expect("pk"),
            "{which}"
        );
    }
}

#[test]
fn the_canonical_vouch_verifies_and_its_signature_is_reproducible() {
    let corpus = corpus();
    let case = corpus["vouch_cases"]
        .as_array()
        .expect("vouch_cases")
        .iter()
        .find(|case| case["expect"] == "verify")
        .expect("a verify case");

    let message: RosterIntroduce =
        serde_json::from_value(case["message"].clone()).expect("message parses");
    let canonical = to_canonical_json(&message.payload()).expect("encodes");
    assert_eq!(
        String::from_utf8(canonical.clone()).expect("utf-8"),
        case["canonical_json"].as_str().expect("canonical_json"),
        "the bytes a vouch covers"
    );

    let introducer = key(&corpus, "introducer");
    assert_eq!(
        introducer.sign_canonical(SignaturePurpose::Vouch, &canonical),
        message.vouch,
        "Ed25519 is deterministic, so this must match exactly"
    );
    assert_eq!(
        introducer
            .public_key()
            .verify(SignaturePurpose::Vouch, &message.payload(), &message.vouch),
        Ok(())
    );
}

#[test]
fn the_canonical_removal_verifies_and_its_signature_is_reproducible() {
    let corpus = corpus();
    let case = corpus["removal_cases"]
        .as_array()
        .expect("removal_cases")
        .iter()
        .find(|case| case["expect"] == "verify")
        .expect("a verify case");

    let message: RosterRemove =
        serde_json::from_value(case["message"].clone()).expect("message parses");
    let canonical = to_canonical_json(&message.payload()).expect("encodes");
    assert_eq!(
        String::from_utf8(canonical.clone()).expect("utf-8"),
        case["canonical_json"].as_str().expect("canonical_json"),
        "the bytes a removal covers"
    );

    let remover = key(&corpus, "introducer");
    assert_eq!(
        remover.sign_canonical(SignaturePurpose::Removal, &canonical),
        message.sig
    );
    assert_eq!(
        remover
            .public_key()
            .verify(SignaturePurpose::Removal, &message.payload(), &message.sig),
        Ok(())
    );
}

#[test]
fn a_vouch_and_a_removal_signature_do_not_transfer_between_purposes() {
    // The domain prefix, exercised against real corpus material rather than
    // synthetic payloads: a removal signature must not verify as a vouch even
    // though both are Ed25519 by the same key.
    let corpus = corpus();
    let vouch: RosterIntroduce = serde_json::from_value(
        corpus["vouch_cases"].as_array().expect("cases")[0]["message"].clone(),
    )
    .expect("parses");
    let removal: RosterRemove = serde_json::from_value(
        corpus["removal_cases"].as_array().expect("cases")[0]["message"].clone(),
    )
    .expect("parses");
    let public = key(&corpus, "introducer").public_key();

    assert!(
        public
            .verify(SignaturePurpose::Removal, &vouch.payload(), &vouch.vouch)
            .is_err(),
        "a vouch must not verify as a removal"
    );
    assert!(
        public
            .verify(SignaturePurpose::Vouch, &removal.payload(), &removal.sig)
            .is_err(),
        "a removal must not verify as a vouch"
    );
}

#[test]
fn every_tampered_case_fails_verification() {
    let corpus = corpus();
    let public = key(&corpus, "introducer").public_key();

    for (list, purpose) in [
        ("vouch_cases", SignaturePurpose::Vouch),
        ("removal_cases", SignaturePurpose::Removal),
    ] {
        let cases = corpus[list].as_array().expect("cases");
        let genuine = cases
            .iter()
            .find(|case| case["expect"] == "verify")
            .expect("a verify case");

        for case in cases.iter().filter(|case| case.get("tamper").is_some()) {
            let name = case["name"].as_str().expect("name");
            let tamper = &case["tamper"];
            let field = tamper["field"].as_str().expect("field");
            let to = tamper["to"].as_str().expect("to");

            let mut message = genuine["message"].clone();
            apply_tamper(&mut message, field, to);

            let verified = if purpose == SignaturePurpose::Vouch {
                let parsed: RosterIntroduce =
                    serde_json::from_value(message).expect("still parses");
                public.verify(purpose, &parsed.payload(), &parsed.vouch)
            } else {
                let parsed: RosterRemove = serde_json::from_value(message).expect("still parses");
                public.verify(purpose, &parsed.payload(), &parsed.sig)
            };
            assert!(
                verified.is_err(),
                "case `{name}`: tampering must not verify"
            );
            assert_eq!(
                case["reason"].as_str().expect("reason"),
                "bad_signature",
                "case `{name}`"
            );
        }
    }
}

fn apply_tamper(message: &mut serde_json::Value, field: &str, to: &str) {
    let mut target = message;
    let mut parts = field.split('.').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            target[part] = serde_json::json!(to);
            return;
        }
        target = target
            .get_mut(part)
            .unwrap_or_else(|| panic!("no field `{part}`"));
    }
}

#[test]
fn the_structural_refusal_case_carries_a_valid_signature() {
    // `self_vouch` is refused for what it *is*, not for being forged. Pinning
    // that distinction stops an implementation from "passing" the case by
    // failing verification for the wrong reason.
    let corpus = corpus();
    let case = corpus["vouch_cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["reason"] == "self_vouch")
        .expect("a self_vouch case");
    assert_eq!(case["signed_by"], "subject");
    assert_eq!(case["introducer_is_subject"], true);

    // The subject really can produce a signature that verifies against its own
    // key; the state machine refuses it anyway.
    let genuine: RosterIntroduce = serde_json::from_value(
        corpus["vouch_cases"].as_array().expect("cases")[0]["message"].clone(),
    )
    .expect("parses");
    let subject_key = key(&corpus, "subject");
    let self_signed = subject_key
        .sign(SignaturePurpose::Vouch, &genuine.payload())
        .expect("signs");
    assert_eq!(
        subject_key
            .public_key()
            .verify(SignaturePurpose::Vouch, &genuine.payload(), &self_signed),
        Ok(()),
        "cryptographically fine, structurally refused"
    );
}

#[test]
fn the_sync_digest_is_reproducible_and_covers_a_sorted_list() {
    let corpus = corpus();
    let case = &corpus["sync_cases"].as_array().expect("sync_cases")[0];
    let message: RosterSync =
        serde_json::from_value(case["message"].clone()).expect("message parses");

    let canonical = to_canonical_json(&message.payload()).expect("encodes");
    assert_eq!(
        String::from_utf8(canonical.clone()).expect("utf-8"),
        case["canonical_json"].as_str().expect("canonical_json")
    );
    assert_eq!(hex(&Sha256::digest(&canonical)), message.digest);

    let ids: Vec<&str> = message
        .devices
        .iter()
        .map(|device| device.device_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "the format requires device_id order");
}

#[test]
fn a_reordered_sync_list_changes_the_digest() {
    // Which is why the ordering is part of the format rather than a convention:
    // two senders with the same knowledge must produce the same bytes.
    let corpus = corpus();
    let case = &corpus["sync_cases"].as_array().expect("sync_cases")[0];
    let message: RosterSync = serde_json::from_value(case["message"].clone()).expect("parses");

    let mut reversed = message.clone();
    reversed.devices.reverse();
    let canonical = to_canonical_json(&reversed.payload()).expect("encodes");
    assert_ne!(hex(&Sha256::digest(&canonical)), message.digest);
}

#[test]
fn the_abuse_constants_match_the_corpus() {
    // Build-time constants, and every implementation must agree: a family whose
    // devices disagree about the cap would admit devices some members refuse.
    let corpus = corpus();
    let constants = &corpus["constants"];
    assert_eq!(
        constants["max_active_devices"].as_u64(),
        Some(MAX_ACTIVE_DEVICES as u64)
    );
    assert_eq!(
        constants["max_membership_events_per_device_per_day"].as_u64(),
        Some(MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY as u64)
    );
    assert_eq!(
        constants["churn_window_seconds"].as_u64(),
        Some(CHURN_WINDOW.as_secs())
    );
}

#[test]
fn the_corpus_pins_every_message_type_and_refusal_it_should() {
    let corpus = corpus();
    for list in ["vouch_cases", "removal_cases", "sync_cases"] {
        assert!(
            !corpus[list].as_array().expect("array").is_empty(),
            "`{list}` must not be empty"
        );
    }
    let vouch_reasons: Vec<&str> = corpus["vouch_cases"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|case| case["reason"].as_str())
        .collect();
    assert!(
        vouch_reasons.contains(&"self_vouch"),
        "the structural refusal must be pinned, not only the forged one"
    );
    assert!(vouch_reasons.contains(&"bad_signature"));
}

#[test]
fn the_declared_identity_keys_are_usable() {
    let corpus = corpus();
    for which in ["introducer_pk_b64", "subject_pk_b64"] {
        assert!(
            IdentityPublicKey::from_base64(corpus["keys"][which].as_str().expect("pk")).is_ok(),
            "{which}"
        );
    }
}
