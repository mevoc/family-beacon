//! The signing scheme, verified against the implementation that has to agree
//! with it — Sund's own `internal/sigauth`.
//!
//! `sund-client`'s unit tests pin the canonical signing string against a
//! constant. That catches this crate drifting from itself; only a live server
//! catches the two repositories drifting from each other, which is what these
//! assertions are for.

use contract_tests::{FixedStamp, PathRewritingHttp, for_each_relay, seed};
use std::sync::Arc;
use sund_client::agent::SystemStamps;
use sund_client::client::SundError;
use sund_client::http::{Stamp, StampSource};
use sund_client::sigauth::DeviceKey;

#[test]
fn a_signature_from_the_wrong_key_is_refused() {
    for_each_relay(|relay| {
        let device = relay.enroll();
        let impostor = relay.impersonate(device.device_id(), DeviceKey::from_seed(&seed()));
        assert_eq!(
            impostor.list_devices().err(),
            Some(SundError::Unauthorized),
            "{}: the device id is a claim, the signature is the proof",
            relay.name
        );
    });
}

#[test]
fn a_replayed_request_is_refused_the_second_time() {
    for_each_relay(|relay| {
        let device = relay.enroll();
        // Same timestamp, same nonce, same body: byte for byte the request the
        // server already answered.
        let frozen = relay.resign(
            &device,
            Arc::new(FixedStamp(Stamp {
                timestamp: SystemStamps.stamp().timestamp,
                nonce: format!("replay-{}", device.device_id()),
            })),
        );

        frozen.list_devices().expect("the first one is fine");
        assert_eq!(
            frozen.list_devices().err(),
            Some(SundError::Unauthorized),
            "{}: a nonce may be used once inside the skew window",
            relay.name
        );
    });
}

#[test]
fn a_timestamp_far_outside_the_skew_window_is_refused() {
    for_each_relay(|relay| {
        let device = relay.enroll();

        // Well-formed, correctly signed, and years stale. The server's window
        // is five minutes; what this asserts across the repo boundary is that
        // the timestamp is *checked* and that the format both sides use is the
        // one being compared.
        let stale = relay.resign(
            &device,
            Arc::new(FixedStamp(Stamp {
                timestamp: "2020-01-01T00:00:00Z".to_owned(),
                nonce: format!("stale-{}", device.device_id()),
            })),
        );
        assert_eq!(
            stale.list_devices().err(),
            Some(SundError::Unauthorized),
            "{}: a stale timestamp must not verify",
            relay.name
        );

        // The same device with an ordinary stamp still works, so the assertion
        // above is about the timestamp and not about a broken fixture.
        device.list_devices().expect("a fresh stamp verifies");
    });
}

#[test]
fn a_proxy_that_rewrites_the_path_breaks_every_signature() {
    for_each_relay(|relay| {
        let device = relay.enroll();

        // The failure `docker/caddy/Caddyfile` warns about, made to happen: the
        // client signs GET /v1/devices and something in front of the server
        // delivers GET /v1/invitations. Both routes exist and both are signed,
        // so this reaches Sund's verifier rather than its router — and the
        // verifier hashes the path it was *given*. It is also why the topology
        // job asserts a 401 for an unauthenticated /v1/devices: a 404 there
        // would mean the proxy rewrote the path.
        let rewriting = Arc::new(PathRewritingHttp::new(
            relay.http(),
            "/v1/devices",
            "/v1/invitations",
        ));
        assert_eq!(
            relay.through(&device, rewriting).list_devices().err(),
            Some(SundError::Unauthorized),
            "{}: a rewritten path must not verify",
            relay.name
        );

        device.list_devices().expect("unrewritten still verifies");
    });
}
