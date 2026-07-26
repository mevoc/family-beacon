//! The churn budget: rate limiting membership events.
//!
//! `docs/FamilyBeacon-Roster.md` → Churn budget. The size cap bounds how many
//! devices exist at once and does nothing about *churn*: a hostile member can
//! introduce and remove devices indefinitely, and each cycle costs every other
//! member channel setup, key-bundle fetches, roster syncs, ledger entries,
//! notifications — and quota, which Sund charges to the recipient. Tombstones do
//! not count toward the size cap, so the cap alone leaves this unbounded.
//!
//! Four things about the design are load-bearing, and three are not the obvious
//! choice. All four are implemented here rather than described elsewhere:
//!
//! 1. **Enforced at the verifier, never at the introducer.** The introducer is
//!    the attacker; a budget it applies to itself is decoration. So this type
//!    lives in each device's own roster and counts what *it* has seen. No
//!    coordination, no shared counter, and it works identically in Try mode.
//! 2. **The window is wall-clock, not epoch.** Per-epoch is exactly backwards:
//!    every removal bumps the epoch, so an introduce/remove attacker would reset
//!    their own allowance with each cycle — the attack would pay for its own
//!    budget. A rolling 24 hours instead, measured against the event's *signed*
//!    timestamp.
//! 3. **Removals count but are never refused.** Both message types consume
//!    budget, because churn is the two of them in a loop and budgeting only
//!    admissions would miss half the cycle. An over-budget removal still applies
//!    immediately — see [`Ledger`](beacon_protocol::ledger) and the roster's
//!    apply path. Removal takes capability away and is fail-safe; admission
//!    grants it and is fail-dangerous.
//! 4. **Over budget means held, not rejected.** That decision lives in the state
//!    machine; this module only counts.
//!
//! Two things are never counted at all: a device removing itself (leaving is not
//! churn inflicted on the family) and the founder's self-vouch.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// How many membership events one device may sign inside the window before its
/// admissions are held for human approval.
///
/// A build-time constant, not a configuration key. Five is a setup-day number,
/// not a Tuesday number. If honest families are landing in quarantine, raise it —
/// but never weaken the quarantine into an auto-admit.
pub const MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY: usize = 5;

/// The rolling window the budget is measured over.
pub const CHURN_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);

/// Per-introducer counts of the membership events this device has witnessed.
///
/// Serialisable, because a budget that resets on app restart is not a budget.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChurnLog {
    /// Unix-second timestamps of counted events, per signing device.
    ///
    /// Unix seconds rather than `SystemTime` so the persisted form is a plain
    /// number in every language that has to read it.
    events: BTreeMap<String, Vec<i64>>,
}

impl ChurnLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one membership event signed by `signer`.
    ///
    /// `signed_at` is the event's own timestamp and `now` is this device's clock.
    /// The timestamp is **clamped to `now` if it is in the future**, which is the
    /// same guard the protocol's staleness rule applies to `sent`: without it, an
    /// attacker would future-date events so they never fall inside anyone's
    /// window and the budget would never bite.
    pub fn record(&mut self, signer: &str, signed_at: SystemTime, now: SystemTime) {
        let at = unix_seconds(clamp_to_now(signed_at, now));
        let entry = self.events.entry(signer.to_owned()).or_default();
        entry.push(at);
        // Keep the vector from growing without bound on a long-lived install.
        // Anything outside the window can never be counted again.
        let cutoff = unix_seconds(now) - window_seconds();
        entry.retain(|&at| at >= cutoff);
    }

    /// How many events `signer` has inside the window ending at `now`.
    #[must_use]
    pub fn count_in_window(&self, signer: &str, now: SystemTime) -> usize {
        let cutoff = unix_seconds(now) - window_seconds();
        self.events.get(signer).map_or(0, |events| {
            events.iter().filter(|&&at| at >= cutoff).count()
        })
    }

    /// Whether one more event from `signer` would exceed the budget.
    ///
    /// Evaluated *before* recording, so the Nth event is allowed and the
    /// (N+1)th is over.
    #[must_use]
    pub fn would_exceed(&self, signer: &str, now: SystemTime) -> bool {
        self.count_in_window(signer, now) >= MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY
    }

    /// Drop every record for a device, used when it leaves the family.
    pub fn forget(&mut self, signer: &str) {
        self.events.remove(signer);
    }
}

fn window_seconds() -> i64 {
    // The constant is well inside i64; the cast cannot lose information.
    i64::try_from(CHURN_WINDOW.as_secs()).unwrap_or(i64::MAX)
}

fn clamp_to_now(signed_at: SystemTime, now: SystemTime) -> SystemTime {
    if signed_at > now { now } else { signed_at }
}

fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
        // Before 1970: only reachable from a badly wrong device clock, and
        // treated as "very old" rather than panicking.
        Err(_) => i64::MIN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(unix: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(unix)
    }

    const NOON: u64 = 1_784_000_000;

    #[test]
    fn an_empty_log_counts_nothing_and_permits() {
        let log = ChurnLog::new();
        assert_eq!(log.count_in_window("dev_A", at(NOON)), 0);
        assert!(!log.would_exceed("dev_A", at(NOON)));
    }

    #[test]
    fn the_budget_permits_exactly_the_constant_and_then_holds() {
        let mut log = ChurnLog::new();
        for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
            assert!(
                !log.would_exceed("dev_A", at(NOON)),
                "event {n} must be inside the budget"
            );
            log.record("dev_A", at(NOON), at(NOON));
        }
        assert!(
            log.would_exceed("dev_A", at(NOON)),
            "the event after the budget must be over"
        );
        assert_eq!(
            log.count_in_window("dev_A", at(NOON)),
            MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY
        );
    }

    #[test]
    fn the_window_rolls_off() {
        let mut log = ChurnLog::new();
        for _ in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
            log.record("dev_A", at(NOON), at(NOON));
        }
        assert!(log.would_exceed("dev_A", at(NOON)));

        // A day and a second later, none of it counts.
        let later = at(NOON + 24 * 60 * 60 + 1);
        assert_eq!(log.count_in_window("dev_A", later), 0);
        assert!(!log.would_exceed("dev_A", later));
    }

    #[test]
    fn the_window_boundary_is_inclusive() {
        let mut log = ChurnLog::new();
        log.record("dev_A", at(NOON), at(NOON));
        let exactly_a_day_later = at(NOON + 24 * 60 * 60);
        assert_eq!(
            log.count_in_window("dev_A", exactly_a_day_later),
            1,
            "an event exactly at the cutoff still counts"
        );
    }

    #[test]
    fn budgets_are_per_device() {
        let mut log = ChurnLog::new();
        for _ in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
            log.record("dev_A", at(NOON), at(NOON));
        }
        assert!(log.would_exceed("dev_A", at(NOON)));
        assert!(
            !log.would_exceed("dev_B", at(NOON)),
            "one device's churn must not spend another's budget"
        );
    }

    #[test]
    fn a_future_dated_event_is_clamped_into_the_window() {
        // Without the clamp, an attacker dates events years ahead so they never
        // fall inside anyone's rolling window and the budget never bites.
        let mut log = ChurnLog::new();
        let far_future = at(NOON + 365 * 24 * 60 * 60);
        for _ in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
            log.record("dev_A", far_future, at(NOON));
        }
        assert!(
            log.would_exceed("dev_A", at(NOON)),
            "future-dated events must still spend the budget"
        );
    }

    #[test]
    fn a_backdated_event_falls_outside_the_window_on_its_own_merits() {
        // Backdating is the mirror image and needs no clamp: an event dated
        // yesterday simply does not count today, which costs the attacker
        // nothing but also buys them nothing — the events they need to be
        // *recent* are the ones the budget is counting.
        let mut log = ChurnLog::new();
        let yesterday = at(NOON - 24 * 60 * 60 - 10);
        log.record("dev_A", yesterday, at(NOON));
        assert_eq!(log.count_in_window("dev_A", at(NOON)), 0);
    }

    #[test]
    fn the_log_does_not_grow_without_bound() {
        let mut log = ChurnLog::new();
        // Two years of daily churn, recorded as it would arrive.
        for day in 0..730u64 {
            let when = at(NOON + day * 24 * 60 * 60);
            log.record("dev_A", when, when);
        }
        let last = at(NOON + 729 * 24 * 60 * 60);
        assert!(
            log.count_in_window("dev_A", last) <= 2,
            "pruning keeps only what could still be counted"
        );
    }

    #[test]
    fn forgetting_a_device_clears_its_history() {
        let mut log = ChurnLog::new();
        for _ in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
            log.record("dev_A", at(NOON), at(NOON));
        }
        log.forget("dev_A");
        assert_eq!(log.count_in_window("dev_A", at(NOON)), 0);
    }

    #[test]
    fn the_log_survives_serialisation() {
        let mut log = ChurnLog::new();
        log.record("dev_A", at(NOON), at(NOON));
        let json = serde_json::to_string(&log).expect("serialises");
        let back: ChurnLog = serde_json::from_str(&json).expect("deserialises");
        assert_eq!(back, log);
        assert_eq!(back.count_in_window("dev_A", at(NOON)), 1);
    }
}
