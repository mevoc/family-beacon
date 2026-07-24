//! The transport-trust layer, against a server that really terminates TLS.
//!
//! `../../sund/docs/Sund-Pinning-Contract.md` exists so that three independent
//! client implementations agree exactly. A unit test can assert that this one
//! is self-consistent; only a live handshake against Sund's own `internal/tlsid`
//! proves the two computed the same fingerprint over the same bytes.
//!
//! The interesting assertions here are the refusals. A pinning implementation
//! that accepts the right certificate but also accepts the wrong one is worse
//! than none, because it looks like it works.

use contract_tests::relays;
use std::sync::Arc;
use sund_client::address::{ServerAddress, TrustMode};
use sund_client::agent::{HttpAgent, SystemStamps};
use sund_client::client::{SundClient, SundError};
use sund_client::http::HttpError;

/// The pinned leg, or `None` when it is not configured.
fn pinned() -> Option<&'static contract_tests::Relay> {
    relays().iter().find(|relay| relay.name == "pinned")
}

/// The same address with one byte of the pin flipped — a certificate that is
/// otherwise entirely valid, which is exactly the man-in-the-middle case.
fn with_a_broken_pin(address: &ServerAddress) -> ServerAddress {
    let TrustMode::Pinned { fingerprint } = address.mode() else {
        panic!("the pinned leg must carry a pinned address");
    };
    let mut wrong = *fingerprint;
    wrong[0] ^= 0x01;
    let hex: String = wrong.iter().map(|byte| format!("{byte:02x}")).collect();
    ServerAddress::parse(&format!(
        "sund://{}:{}#{hex}",
        address.host(),
        address.port()
    ))
    .expect("still a well-formed address")
}

fn probe(address: &ServerAddress) -> Result<(), SundError> {
    let agent = HttpAgent::new(address).expect("build an agent");
    SundClient::new(Arc::new(agent), Arc::new(SystemStamps))
        .health()
        .map(|_| ())
}

#[test]
fn the_pinned_certificate_is_accepted() {
    let Some(relay) = pinned() else {
        eprintln!("contract: pinned leg not configured — skipped");
        return;
    };
    probe(&relay.address).expect("the server's own fingerprint must verify");
}

#[test]
fn a_wrong_pin_is_refused_and_not_retried() {
    let Some(relay) = pinned() else {
        eprintln!("contract: pinned leg not configured — skipped");
        return;
    };

    let error = probe(&with_a_broken_pin(&relay.address))
        .expect_err("a mismatched pin must fail the connection");
    assert!(
        matches!(error, SundError::Http(HttpError::Tls(_))),
        "a pin mismatch must surface as an identity failure, not as a network \
         error — an intercepting network has to be distinguishable from an \
         absent one; got {error:?}"
    );
}

#[test]
fn identity_does_not_depend_on_the_hostname() {
    let Some(relay) = pinned() else {
        eprintln!("contract: pinned leg not configured — skipped");
        return;
    };

    // The same server, reached by another name, is the same server: the pin is
    // the identity and hostname verification is off. This is what lets a family
    // keep working when the home server's address changes — and it is also the
    // property that makes a pinned deployment survive without DNS at all.
    let other_name = match relay.address.host() {
        "127.0.0.1" => "localhost",
        _ => "127.0.0.1",
    };
    let TrustMode::Pinned { fingerprint } = relay.address.mode() else {
        panic!("pinned address");
    };
    let hex: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
    let renamed = ServerAddress::parse(&format!(
        "sund://{other_name}:{}#{hex}",
        relay.address.port()
    ))
    .expect("well-formed");

    probe(&renamed).expect("the pin travels with the server, not with the name");
}

#[test]
fn a_pinned_client_will_not_talk_to_a_webpki_server() {
    let (Some(pinned_relay), Some(webpki_relay)) = (
        pinned(),
        relays().iter().find(|relay| relay.name == "webpki"),
    ) else {
        eprintln!("contract: both legs are needed for the no-fallback assertion — skipped");
        return;
    };

    // A pinned address pointed at the WebPKI deployment: the proxy's publicly
    // trusted certificate has nothing to do with the pin, so this must fail —
    // and must not quietly succeed by falling back to platform trust (§6).
    let TrustMode::Pinned { fingerprint } = pinned_relay.address.mode() else {
        panic!("pinned address");
    };
    let hex: String = fingerprint.iter().map(|b| format!("{b:02x}")).collect();
    let crossed = ServerAddress::parse(&format!(
        "sund://{}:{}#{hex}",
        webpki_relay.address.host(),
        webpki_relay.address.port()
    ))
    .expect("well-formed");

    let error = probe(&crossed).expect_err("no fallback between modes");
    assert!(
        matches!(error, SundError::Http(HttpError::Tls(_))),
        "expected an identity failure, got {error:?}"
    );
}
