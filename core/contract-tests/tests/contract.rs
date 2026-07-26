//! The contract suite, as one binary.
//!
//! One binary on purpose: each relay is bootstrapped from a single-use
//! invitation, so the founding device can be enrolled exactly once per process.
//! Adding a second `tests/*.rs` would start a second process against an
//! already-spent token. Add a module here instead.

// `#[path]` because everything directly under `tests/` becomes a test binary of
// its own, which is precisely what must not happen here; a subdirectory does
// not.
#[path = "contract/enrollment.rs"]
mod enrollment;
#[path = "contract/membership.rs"]
mod membership;
#[path = "contract/pinning.rs"]
mod pinning;
#[path = "contract/port.rs"]
mod port;
#[path = "contract/queues.rs"]
mod queues;
#[path = "contract/sessions.rs"]
mod sessions;
#[path = "contract/signing.rs"]
mod signing;

use contract_tests::{for_each_relay, relays, wait_until_ready};
use std::time::Duration;

#[test]
fn the_relay_answers_and_says_what_it_is() {
    for_each_relay(|relay| {
        let version = wait_until_ready(relay, Duration::from_secs(20))
            .unwrap_or_else(|e| panic!("{}: relay never became healthy: {e}", relay.name));
        // Reported rather than asserted: a failure elsewhere in this suite
        // should name the Sund build it happened against.
        eprintln!("contract: {} is running Sund {version}", relay.name);
    });
}

#[test]
fn the_suite_knows_which_legs_it_covered() {
    let configured: Vec<&str> = relays().iter().map(|relay| relay.name).collect();
    eprintln!("contract: legs under test: {configured:?}");
}
