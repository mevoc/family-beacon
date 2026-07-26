//! The membership state machine against every rule
//! `docs/FamilyBeacon-Roster.md` states.
//!
//! Organised by the spec's own sections rather than by method, because the rules
//! are what must not regress — several of them are deliberately counter-intuitive
//! (removals apply while over budget, a sync never admits, a revoked device is not
//! tombstoned) and a test named after a method would not say why.

use std::time::{Duration, SystemTime};

use beacon_protocol::ledger::{Direction, LedgerEvent};
use beacon_protocol::roster::{DeviceState, RemovalReason, RosterSync, SyncDevice};
use beacon_roster::churn::MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY;
use beacon_roster::records::{DeviceRecord, SelfDescription};
use beacon_roster::roster::{
    Admission, MAX_ACTIVE_DEVICES, Removal, RemovalRefusal, Roster, RosterSnapshot, ServerDevice,
    ServerFinding, SnapshotError, Sync, VouchRefusal,
};
use sund_client::identity::IdentityKey;

const NOON: u64 = 1_784_000_000;
const JOINED: &str = "2026-07-26T10:00:00Z";

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(NOON)
}

fn later(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(NOON + seconds)
}

/// A device with an identity key and a self-description.
struct Device {
    id: String,
    identity: IdentityKey,
}

fn device(id: &str, seed: u8) -> Device {
    Device {
        id: id.to_owned(),
        identity: IdentityKey::from_seed(&[seed; 32]),
    }
}

impl Device {
    fn description(&self) -> SelfDescription {
        SelfDescription {
            device_id: self.id.clone(),
            display_name: format!("{}'s phone", self.id),
            member_group: self.id.clone(),
            role: "adult".to_owned(),
            joined_at: JOINED.to_owned(),
        }
    }

    fn subject(&self) -> beacon_protocol::roster::VouchedSubject {
        self.description()
            .subject(self.identity.public_key().to_base64())
    }

    fn record(&self, introduced_by: &str) -> DeviceRecord {
        DeviceRecord::from_vouch(&self.subject(), introduced_by)
    }
}

/// A founded family with one device.
fn founded(founder: &Device) -> Roster {
    Roster::found(&founder.description(), &founder.identity).outcome
}

/// Admit `joiner` into `roster` on `introducer`'s vouch.
fn admit(roster: &mut Roster, introducer: &Device, joiner: &Device) -> Admission {
    let vouch = roster
        .vouch_for(&joiner.subject(), &introducer.identity)
        .expect("vouch");
    roster
        .receive_introduce(&vouch, &introducer.id, now())
        .outcome
}

// ---------------------------------------------------------------- founding

#[test]
fn the_founding_device_self_vouches_at_epoch_zero() {
    let alice = device("dev_A", 1);
    let applied = Roster::found(&alice.description(), &alice.identity);
    let roster = &applied.outcome;

    assert_eq!(roster.epoch(), 0);
    assert_eq!(roster.active_count(), 1);
    assert!(roster.is_active("dev_A"));
    let record = roster.record("dev_A").expect("own record");
    assert_eq!(
        record.introduced_by, "dev_A",
        "the founder is its own introducer"
    );
    assert_eq!(
        record.identity_pk,
        alice.identity.public_key().to_base64(),
        "the founder's key is the family's first root of trust"
    );
    assert_eq!(
        applied.ledger.len(),
        1,
        "founding is a membership event and is ledgered"
    );
    assert_eq!(
        applied.ledger[0].event,
        LedgerEvent::DeviceJoined {
            vouched_by: "dev_A".to_owned()
        }
    );
}

#[test]
fn the_founders_self_vouch_does_not_spend_its_own_churn_budget() {
    // Otherwise a family of six set up in one afternoon would quarantine its own
    // sixth device because founding used a slot.
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);
    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_{n}"), 100 + u8::try_from(n).expect("small"));
        assert_eq!(
            admit(&mut roster, &alice, &joiner),
            Admission::Admitted,
            "device {n} should not be held"
        );
    }
}

// --------------------------------------------------------------- admission

#[test]
fn a_valid_vouch_admits_the_device_and_names_its_introducer() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);

    let vouch = roster
        .vouch_for(&bob.subject(), &alice.identity)
        .expect("vouch");
    let applied = roster.receive_introduce(&vouch, &alice.id, now());

    assert_eq!(applied.outcome, Admission::Admitted);
    assert!(roster.is_active("dev_B"));
    assert_eq!(
        roster.record("dev_B").expect("record").introduced_by,
        "dev_A"
    );
    assert_eq!(
        applied.ledger[0].event,
        LedgerEvent::DeviceJoined {
            vouched_by: "dev_A".to_owned()
        }
    );
    assert_eq!(applied.ledger[0].direction, Direction::Inbound);
}

#[test]
fn a_vouch_from_a_device_that_is_not_an_active_member_is_refused() {
    // A vouch from a removed device carries no authority — the rule that stops a
    // just-evicted member from re-populating the family behind everyone's back.
    let alice = device("dev_A", 1);
    let stranger = device("dev_X", 9);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);

    let vouch = roster
        .vouch_for(&bob.subject(), &stranger.identity)
        .expect("a stranger can still compose one");
    let applied = roster.receive_introduce(&vouch, &stranger.id, now());

    assert_eq!(
        applied.outcome,
        Admission::Refused(VouchRefusal::IntroducerNotActive {
            introducer: "dev_X".to_owned()
        })
    );
    assert!(!roster.is_active("dev_B"));
    assert!(matches!(
        applied.ledger[0].event,
        LedgerEvent::VouchRejected { .. }
    ));
}

#[test]
fn a_vouch_for_a_tombstoned_device_is_refused() {
    // The rule that stops a removed device being quietly reintroduced by a member
    // who missed the removal.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    roster
        .remove(
            "dev_B",
            RemovalReason::Removed,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");

    let vouch = roster
        .vouch_for(&bob.subject(), &alice.identity)
        .expect_err("the introducer's own side refuses first");
    assert_eq!(
        vouch,
        VouchRefusal::SubjectTombstoned {
            subject: "dev_B".to_owned()
        }
    );
}

#[test]
fn a_reintroduction_of_a_tombstoned_device_is_refused_at_the_verifier_too() {
    // The introducer-side check above is a courtesy; this is the one that matters,
    // because the attacker is the introducer.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let carol = device("dev_C", 3);

    // Carol's roster still has Bob when Alice's does not.
    let mut alice_roster = founded(&alice);
    admit(&mut alice_roster, &alice, &bob);
    let vouch_before_removal = alice_roster
        .vouch_for(&bob.subject(), &alice.identity)
        .expect("vouch");

    let mut carol_roster = founded(&carol);
    let alice_vouch = carol_roster
        .vouch_for(&alice.subject(), &carol.identity)
        .expect("vouch");
    carol_roster.receive_introduce(&alice_vouch, &carol.id, now());
    carol_roster
        .remove(
            "dev_B",
            RemovalReason::Lost,
            "2026-07-26T11:00:00Z",
            &carol.identity,
            now(),
        )
        .expect("removal");

    let applied = carol_roster.receive_introduce(&vouch_before_removal, &alice.id, now());
    assert_eq!(
        applied.outcome,
        Admission::Refused(VouchRefusal::SubjectTombstoned {
            subject: "dev_B".to_owned()
        })
    );
}

#[test]
fn a_device_may_not_vouch_for_itself() {
    // Only the founding device self-vouches, and only when founding. Otherwise
    // any device that got hold of a channel could admit itself.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    let self_vouch = roster
        .vouch_for(&bob.subject(), &bob.identity)
        .expect("composable");
    let applied = roster.receive_introduce(&self_vouch, &bob.id, now());
    assert_eq!(
        applied.outcome,
        Admission::Refused(VouchRefusal::SelfVouch {
            subject: "dev_B".to_owned()
        })
    );
}

#[test]
fn a_forged_vouch_signature_is_refused() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let impostor = device("dev_A", 99); // same id, different key
    let mut roster = founded(&alice);

    let vouch = roster
        .vouch_for(&bob.subject(), &impostor.identity)
        .expect("composable");
    let applied = roster.receive_introduce(&vouch, "dev_A", now());
    assert_eq!(
        applied.outcome,
        Admission::Refused(VouchRefusal::BadSignature)
    );
    assert!(!roster.is_active("dev_B"));
}

#[test]
fn a_tampered_vouch_subject_is_refused() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let attacker = device("dev_EVIL", 66);
    let mut roster = founded(&alice);

    let mut vouch = roster
        .vouch_for(&bob.subject(), &alice.identity)
        .expect("vouch");
    // Swap in the attacker's key while keeping Alice's signature.
    vouch.subject.identity_pk = attacker.identity.public_key().to_base64();

    let applied = roster.receive_introduce(&vouch, &alice.id, now());
    assert_eq!(
        applied.outcome,
        Admission::Refused(VouchRefusal::BadSignature)
    );
}

#[test]
fn a_vouch_that_would_change_a_known_devices_identity_key_is_refused() {
    // identity_pk is the security-bearing field. A peer that re-keys has to
    // re-join with a fresh device id, not be silently updated.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let rekeyed = device("dev_B", 22);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    let vouch = roster
        .vouch_for(&rekeyed.subject(), &alice.identity)
        .expect("vouch");
    let applied = roster.receive_introduce(&vouch, &alice.id, now());
    assert_eq!(
        applied.outcome,
        Admission::Refused(VouchRefusal::IdentityChanged {
            subject: "dev_B".to_owned()
        })
    );
    assert_eq!(
        roster.record("dev_B").expect("record").identity_pk,
        bob.identity.public_key().to_base64(),
        "the original key stands"
    );
}

#[test]
fn a_rebroadcast_vouch_is_idempotent_and_costs_the_introducer_nothing() {
    // Step 3 of admission broadcasts to every member, and syncs re-assert; a
    // second copy must be ordinary rather than an error or a budget charge.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);

    let vouch = roster
        .vouch_for(&bob.subject(), &alice.identity)
        .expect("vouch");
    assert_eq!(
        roster.receive_introduce(&vouch, &alice.id, now()).outcome,
        Admission::Admitted
    );
    let again = roster.receive_introduce(&vouch, &alice.id, now());
    assert_eq!(again.outcome, Admission::AlreadyKnown);
    assert!(
        again.ledger.is_empty(),
        "nothing changed, so nothing to ledger"
    );

    // Budget charged exactly once for the two copies: Bob's admission spent one
    // slot, so the rest of the allowance is still available.
    for n in 1..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_x{n}"), 150 + u8::try_from(n).expect("small"));
        assert_eq!(
            admit(&mut roster, &alice, &joiner),
            Admission::Admitted,
            "the re-broadcast must not have spent a slot"
        );
    }
}

// ----------------------------------------------------------- the size cap

#[test]
fn the_family_is_capped_at_twenty_active_devices() {
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);

    // Fill to the cap. Each newly admitted device introduces the next, so no
    // introducer signs more than one event and the churn budget never enters into
    // what this test is about.
    let mut introducers = vec![alice];
    while roster.active_count() < MAX_ACTIVE_DEVICES {
        let n = roster.active_count();
        let joiner = device(&format!("dev_{n:02}"), u8::try_from(n + 10).expect("small"));
        let introducer = introducers.last().expect("at least the founder");
        let vouch = roster
            .vouch_for(&joiner.subject(), &introducer.identity)
            .expect("vouch");
        assert_eq!(
            roster
                .receive_introduce(&vouch, &introducer.id, later(u64::try_from(n).unwrap_or(0)))
                .outcome,
            Admission::Admitted,
            "filling to the cap at {n}"
        );
        introducers.push(joiner);
    }
    assert_eq!(roster.active_count(), MAX_ACTIVE_DEVICES);

    let one_too_many = device("dev_LAST", 200);
    let introducer = &introducers[0];

    // Refused on the introducer's side, so its screen can say why…
    assert_eq!(
        roster
            .vouch_for(&one_too_many.subject(), &introducer.identity)
            .expect_err("over the cap"),
        VouchRefusal::SizeCapReached {
            active: MAX_ACTIVE_DEVICES
        }
    );

    // …and at the verifier, which is the check that actually binds.
    let smaller = founded(&device("dev_A", 1));
    let vouch = smaller
        .vouch_for(&one_too_many.subject(), &introducer.identity)
        .expect("composable in a small family");
    let applied = roster.receive_introduce(&vouch, &introducer.id, now());
    assert_eq!(
        applied.outcome,
        Admission::Refused(VouchRefusal::SizeCapReached {
            active: MAX_ACTIVE_DEVICES
        })
    );
}

#[test]
fn tombstoned_devices_do_not_count_toward_the_cap() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    assert_eq!(roster.active_count(), 2);

    roster
        .remove(
            "dev_B",
            RemovalReason::Left,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");
    assert_eq!(roster.active_count(), 1, "only active records count");
    assert!(roster.record("dev_B").is_some(), "the record is kept");
}

// -------------------------------------------------------- the churn budget

#[test]
fn the_sixth_admission_in_a_day_is_held_for_approval_not_rejected() {
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);

    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_{n}"), 100 + u8::try_from(n).expect("small"));
        assert_eq!(admit(&mut roster, &alice, &joiner), Admission::Admitted);
    }

    let held_one = device("dev_HELD", 60);
    let applied = {
        let vouch = roster
            .vouch_for(&held_one.subject(), &alice.identity)
            .expect("vouch");
        roster.receive_introduce(&vouch, &alice.id, now())
    };
    assert_eq!(
        applied.outcome,
        Admission::Held {
            events_in_window: MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY
        }
    );
    assert!(!roster.is_active("dev_HELD"), "held is not admitted");
    assert_eq!(
        applied.ledger[0].event,
        LedgerEvent::AdmissionHeld {
            events_in_window: MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY
        },
        "the count that triggered it is what the sentence needs"
    );
    assert_eq!(roster.held_admissions().len(), 1);
    assert_eq!(roster.held_admissions()[0].introducer, "dev_A");
}

#[test]
fn approving_a_held_admission_admits_it() {
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);
    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_{n}"), 100 + u8::try_from(n).expect("small"));
        admit(&mut roster, &alice, &joiner);
    }
    let held_one = device("dev_HELD", 60);
    admit(&mut roster, &alice, &held_one);

    let applied = roster.approve_held("dev_HELD");
    assert_eq!(applied.outcome, Some(Admission::Admitted));
    assert!(roster.is_active("dev_HELD"));
    assert_eq!(
        roster.record("dev_HELD").expect("record").introduced_by,
        "dev_A",
        "the approved record still names who vouched"
    );
    assert!(
        applied
            .ledger
            .iter()
            .any(|entry| entry.event == LedgerEvent::AdmissionResolved { admitted: true })
    );
    assert!(roster.held_admissions().is_empty());
}

#[test]
fn denying_a_held_admission_discards_it() {
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);
    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_{n}"), 100 + u8::try_from(n).expect("small"));
        admit(&mut roster, &alice, &joiner);
    }
    admit(&mut roster, &alice, &device("dev_HELD", 60));

    let applied = roster.deny_held("dev_HELD");
    assert!(applied.outcome);
    assert!(!roster.is_active("dev_HELD"));
    assert!(roster.held_admissions().is_empty());
    assert_eq!(
        applied.ledger[0].event,
        LedgerEvent::AdmissionResolved { admitted: false }
    );

    assert!(
        !roster.deny_held("dev_HELD").outcome,
        "denying twice is a no-op"
    );
}

#[test]
fn approving_a_vouch_whose_introducer_was_since_removed_is_refused() {
    // Quarantine is not a bypass: the refusal rules are re-checked at approval,
    // because the introducer can lose its standing while the vouch waits.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    // Spend Bob's budget, then have Bob vouch once more so it is held.
    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_b{n}"), 120 + u8::try_from(n).expect("small"));
        let vouch = roster
            .vouch_for(&joiner.subject(), &bob.identity)
            .expect("vouch");
        roster.receive_introduce(&vouch, &bob.id, now());
    }
    let held_one = device("dev_HELD", 60);
    let vouch = roster
        .vouch_for(&held_one.subject(), &bob.identity)
        .expect("vouch");
    assert!(matches!(
        roster.receive_introduce(&vouch, &bob.id, now()).outcome,
        Admission::Held { .. }
    ));

    // Bob is removed while its vouch sits in quarantine.
    roster
        .remove(
            "dev_B",
            RemovalReason::Removed,
            "2026-07-26T12:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");

    let applied = roster.approve_held("dev_HELD");
    assert_eq!(
        applied.outcome,
        Some(Admission::Refused(VouchRefusal::IntroducerNotActive {
            introducer: "dev_B".to_owned()
        }))
    );
    assert!(!roster.is_active("dev_HELD"));
}

#[test]
fn the_budget_recovers_after_the_window() {
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);
    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_{n}"), 100 + u8::try_from(n).expect("small"));
        admit(&mut roster, &alice, &joiner);
    }

    let tomorrow = later(24 * 60 * 60 + 1);
    let joiner = device("dev_TOMORROW", 70);
    let vouch = roster
        .vouch_for(&joiner.subject(), &alice.identity)
        .expect("vouch");
    assert_eq!(
        roster
            .receive_introduce(&vouch, &alice.id, tomorrow)
            .outcome,
        Admission::Admitted,
        "a rolling window means tomorrow is a fresh allowance"
    );
}

#[test]
fn budgets_are_per_introducer_not_family_wide() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    // Alice spends the rest of her allowance.
    for n in 1..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_a{n}"), 130 + u8::try_from(n).expect("small"));
        assert_eq!(admit(&mut roster, &alice, &joiner), Admission::Admitted);
    }
    let over = device("dev_OVER", 80);
    assert!(matches!(
        admit(&mut roster, &alice, &over),
        Admission::Held { .. }
    ));

    // Bob's is untouched.
    let bobs_pick = device("dev_BOBS", 81);
    assert_eq!(
        admit(&mut roster, &bob, &bobs_pick),
        Admission::Admitted,
        "one member's churn must not spend another's budget"
    );
}

// ----------------------------------------------------------------- removal

#[test]
fn removing_a_device_tombstones_it_bumps_the_epoch_and_ledgers_both() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    assert_eq!(roster.epoch(), 0);

    let applied = roster
        .remove(
            "dev_B",
            RemovalReason::Lost,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");

    assert_eq!(applied.outcome.subject, "dev_B");
    assert_eq!(applied.outcome.reason, RemovalReason::Lost);
    assert_eq!(applied.outcome.epoch, 1);
    assert_eq!(roster.epoch(), 1, "every removal bumps the epoch");
    assert!(!roster.is_active("dev_B"));
    let tombstone = roster.tombstone("dev_B").expect("tombstone");
    assert_eq!(tombstone.removed_by, "dev_A");
    assert_eq!(tombstone.reason, RemovalReason::Lost);
    assert_eq!(
        roster.record("dev_B").expect("record").state,
        DeviceState::Removed,
        "the record is kept so the family's history stays readable"
    );

    assert!(applied.ledger.iter().any(|entry| entry.event
        == LedgerEvent::DeviceRemoved {
            removed_by: "dev_A".to_owned(),
            reason: RemovalReason::Lost
        }));
    assert!(
        applied
            .ledger
            .iter()
            .any(|entry| entry.event == LedgerEvent::EpochBumped { epoch: 1 })
    );
}

#[test]
fn any_active_device_may_remove_any_other_including_the_founder() {
    // There is no admin. A device admitted five minutes ago may evict the device
    // that founded the family — chosen deliberately against the abusive-member
    // case, where concentrating removal would hand the wrong person a lock.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut bobs_roster = founded(&bob);
    let vouch = bobs_roster
        .vouch_for(&alice.subject(), &bob.identity)
        .expect("vouch");
    bobs_roster.receive_introduce(&vouch, &bob.id, now());

    let removal = bobs_roster
        .remove(
            "dev_A",
            RemovalReason::Removed,
            "2026-07-26T11:00:00Z",
            &bob.identity,
            now(),
        )
        .expect("the founder is not privileged");
    assert_eq!(removal.outcome.subject, "dev_A");
    assert!(!bobs_roster.is_active("dev_A"));
}

#[test]
fn a_device_may_always_remove_itself_and_it_is_not_charged_as_churn() {
    // The roster-layer form of "the app can be disabled or uninstalled at any
    // time". Leaving is not churn inflicted on the family.
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);
    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_{n}"), 100 + u8::try_from(n).expect("small"));
        admit(&mut roster, &alice, &joiner);
    }

    // Over budget already, and leaving still works.
    let applied = roster
        .remove(
            "dev_A",
            RemovalReason::Left,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("a device may always leave");
    assert_eq!(applied.outcome.reason, RemovalReason::Left);
    assert!(roster.tombstone("dev_A").is_some());
}

#[test]
fn an_over_budget_removal_still_applies_immediately() {
    // The asymmetry the whole document runs on: removal takes capability away and
    // is fail-safe, admission grants it and is fail-dangerous. A stolen-phone
    // removal must never be delayed by a rate limiter.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let victim = device("dev_V", 30);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    admit(&mut roster, &alice, &victim);

    // Burn Bob's whole budget on removals.
    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_t{n}"), 160 + u8::try_from(n).expect("small"));
        admit(&mut roster, &bob, &joiner);
    }
    assert!(
        matches!(
            admit(&mut roster, &bob, &device("dev_NOPE", 90)),
            Admission::Held { .. }
        ),
        "precondition: Bob is over budget"
    );

    // Bob's removal of the victim applies anyway.
    let mut bobs_own = founded(&bob);
    let alice_vouch = bobs_own
        .vouch_for(&victim.subject(), &bob.identity)
        .expect("vouch");
    bobs_own.receive_introduce(&alice_vouch, &bob.id, now());
    let removal = bobs_own
        .remove(
            "dev_V",
            RemovalReason::Lost,
            "2026-07-26T12:00:00Z",
            &bob.identity,
            now(),
        )
        .expect("removal");

    let applied = roster.receive_remove(&removal.outcome, &bob.id, now());
    assert_eq!(
        applied.outcome,
        Removal::Applied,
        "an over-budget removal is counted, never refused"
    );
    assert!(!roster.is_active("dev_V"));
}

#[test]
fn a_removal_from_a_non_member_is_refused() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let stranger = device("dev_X", 9);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    let mut strangers_roster = founded(&stranger);
    let vouch = strangers_roster
        .vouch_for(&bob.subject(), &stranger.identity)
        .expect("vouch");
    strangers_roster.receive_introduce(&vouch, &stranger.id, now());
    let removal = strangers_roster
        .remove(
            "dev_B",
            RemovalReason::Removed,
            "2026-07-26T11:00:00Z",
            &stranger.identity,
            now(),
        )
        .expect("composable");

    let applied = roster.receive_remove(&removal.outcome, &stranger.id, now());
    assert_eq!(
        applied.outcome,
        Removal::Refused(RemovalRefusal::RemoverNotActive {
            remover: "dev_X".to_owned()
        })
    );
    assert!(roster.is_active("dev_B"), "nothing was removed");
}

#[test]
fn a_forged_removal_signature_is_refused() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    let mut removal = roster
        .remove(
            "dev_B",
            RemovalReason::Removed,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal")
        .outcome;
    // A fresh roster where Bob is still active, and a tampered subject.
    let mut fresh = founded(&alice);
    admit(&mut fresh, &alice, &bob);
    let carol = device("dev_C", 3);
    admit(&mut fresh, &alice, &carol);
    removal.subject = "dev_C".to_owned();

    let applied = fresh.receive_remove(&removal, &alice.id, now());
    assert_eq!(
        applied.outcome,
        Removal::Refused(RemovalRefusal::BadSignature)
    );
    assert!(fresh.is_active("dev_C"));
}

#[test]
fn removal_is_monotonic() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let carol = device("dev_C", 3);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    admit(&mut roster, &alice, &carol);

    let first = roster
        .remove(
            "dev_C",
            RemovalReason::Removed,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");
    let applied = roster.receive_remove(&first.outcome, &alice.id, now());
    assert_eq!(
        applied.outcome,
        Removal::AlreadyRemoved,
        "there is no un-remove, and a re-broadcast is not a second event"
    );
    assert!(applied.ledger.is_empty());
}

#[test]
fn being_removed_is_recorded_and_surfaced_without_self_tombstoning() {
    // "The removed device is told, when it is reachable. It must never simply
    // discover it has gone quiet." A device that erased its own record could not
    // show its user what happened.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);

    let mut bobs_roster = founded(&bob);
    let vouch = bobs_roster
        .vouch_for(&alice.subject(), &bob.identity)
        .expect("vouch");
    bobs_roster.receive_introduce(&vouch, &bob.id, now());

    let mut alices_roster = founded(&alice);
    let bob_vouch = alices_roster
        .vouch_for(&bob.subject(), &alice.identity)
        .expect("vouch");
    alices_roster.receive_introduce(&bob_vouch, &alice.id, now());
    let removal = alices_roster
        .remove(
            "dev_B",
            RemovalReason::Removed,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");

    let applied = bobs_roster.receive_remove(&removal.outcome, &alice.id, now());
    assert_eq!(applied.outcome, Removal::AboutSelf);
    assert!(
        bobs_roster.tombstone("dev_B").is_none(),
        "a device does not tombstone itself on someone else's word"
    );
    assert!(bobs_roster.is_active("dev_B"));
    assert_eq!(bobs_roster.removed_me_by(), vec!["dev_A"]);
    assert!(applied.ledger.iter().any(|entry| entry.event
        == LedgerEvent::DeviceRemoved {
            removed_by: "dev_A".to_owned(),
            reason: RemovalReason::Removed
        }));
}

#[test]
fn a_device_deactivated_by_the_server_can_no_longer_remove_others() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    roster.reconcile_server_list(&[
        ServerDevice {
            device_id: "dev_A".to_owned(),
            revoked: true,
        },
        ServerDevice {
            device_id: "dev_B".to_owned(),
            revoked: false,
        },
    ]);

    assert_eq!(
        roster
            .remove(
                "dev_B",
                RemovalReason::Removed,
                "2026-07-26T11:00:00Z",
                &alice.identity,
                now(),
            )
            .expect_err("a removed device's removals carry no authority"),
        RemovalRefusal::RemoverNotActive {
            remover: "dev_A".to_owned()
        }
    );
}

#[test]
fn a_removed_devices_churn_history_is_forgotten() {
    // Otherwise a re-admitted device id would inherit a stranger's spent budget.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_b{n}"), 170 + u8::try_from(n).expect("small"));
        admit(&mut roster, &bob, &joiner);
    }

    let snapshot_before = roster.export();
    roster
        .remove(
            "dev_B",
            RemovalReason::Removed,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");
    let snapshot_after = roster.export();

    assert_ne!(
        snapshot_before.churn, snapshot_after.churn,
        "the removed device's history is dropped"
    );
    assert_eq!(snapshot_after.churn.count_in_window("dev_B", now()), 0);
}

// ---------------------------------------------------------------- adoption

#[test]
fn a_joining_device_adopts_its_introducers_roster() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let carol = device("dev_C", 3);

    let mut alices = founded(&alice);
    admit(&mut alices, &alice, &carol);
    let vouch_for_bob = alices
        .vouch_for(&bob.subject(), &alice.identity)
        .expect("vouch");

    let applied = Roster::adopt(
        "dev_B",
        &alice.record("dev_A"),
        alices.active().into_iter().cloned().collect(),
        alices.tombstones().into_iter().cloned().collect(),
        alices.epoch(),
        &vouch_for_bob,
    )
    .expect("adopt");

    let bobs = applied.outcome;
    assert!(bobs.is_active("dev_A"));
    assert!(bobs.is_active("dev_B"));
    assert!(bobs.is_active("dev_C"), "the whole roster is adopted");
    assert_eq!(
        bobs.record("dev_B").expect("own record").introduced_by,
        "dev_A"
    );
    assert_eq!(bobs.self_id(), "dev_B");
    assert!(
        applied
            .ledger
            .iter()
            .any(|entry| matches!(entry.event, LedgerEvent::DeviceJoined { .. })),
        "adopting a roster is a pile of membership events, each ledgered"
    );
}

#[test]
fn a_joining_device_adopts_tombstones_too() {
    // A roster that forgets a removal re-admits the removed device on the next
    // reconciliation, which is precisely the failure a lost-phone removal must
    // not have — including for a device that joined afterwards.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let gone = device("dev_GONE", 40);

    let mut alices = founded(&alice);
    admit(&mut alices, &alice, &gone);
    alices
        .remove(
            "dev_GONE",
            RemovalReason::Lost,
            "2026-07-26T10:30:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");
    let vouch_for_bob = alices
        .vouch_for(&bob.subject(), &alice.identity)
        .expect("vouch");

    let bobs = Roster::adopt(
        "dev_B",
        &alice.record("dev_A"),
        alices.active().into_iter().cloned().collect(),
        alices.tombstones().into_iter().cloned().collect(),
        alices.epoch(),
        &vouch_for_bob,
    )
    .expect("adopt")
    .outcome;

    assert!(bobs.tombstone("dev_GONE").is_some());
    assert_eq!(bobs.epoch(), 1, "the epoch comes with the roster");
}

#[test]
fn a_joiner_refuses_a_vouch_that_is_not_for_it() {
    let alice = device("dev_A", 1);
    let carol = device("dev_C", 3);
    let alices = founded(&alice);
    let vouch_for_carol = alices
        .vouch_for(&carol.subject(), &alice.identity)
        .expect("vouch");

    assert!(matches!(
        Roster::adopt(
            "dev_B",
            &alice.record("dev_A"),
            Vec::new(),
            Vec::new(),
            0,
            &vouch_for_carol,
        ),
        Err(VouchRefusal::SelfVouch { .. })
    ));
}

#[test]
fn a_joiner_refuses_a_vouch_not_signed_by_the_co_present_introducer() {
    // The QR establishes which key the introducer holds; a vouch signed by
    // anything else means the ceremony was subverted.
    let alice = device("dev_A", 1);
    let impostor = device("dev_A", 77);
    let bob = device("dev_B", 2);
    let alices = founded(&alice);
    let forged = alices
        .vouch_for(&bob.subject(), &impostor.identity)
        .expect("composable");

    assert_eq!(
        Roster::adopt(
            "dev_B",
            &alice.record("dev_A"),
            Vec::new(),
            Vec::new(),
            0,
            &forged,
        )
        .expect_err("must not adopt"),
        VouchRefusal::BadSignature
    );
}

// ------------------------------------------------------------------- sync

#[test]
fn a_matching_sync_is_a_no_op() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    let message = roster.sync();
    let applied = roster.receive_sync(&message, &bob.id);
    assert_eq!(applied.outcome, Sync::InSync);
    assert!(applied.ledger.is_empty(), "the common case costs nothing");
}

#[test]
fn a_sync_with_a_wrong_digest_is_refused() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    let mut message = roster.sync();
    message.digest = "0".repeat(64);
    assert_eq!(
        roster.receive_sync(&message, &bob.id).outcome,
        Sync::BadDigest
    );
}

#[test]
fn a_sync_from_a_non_member_is_refused_before_anything_merges() {
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);
    let message = roster.sync();
    assert_eq!(
        roster.receive_sync(&message, "dev_STRANGER").outcome,
        Sync::Refused {
            sender: "dev_STRANGER".to_owned()
        }
    );
}

#[test]
fn a_sync_revealing_an_unknown_device_is_an_anomaly_not_an_admission() {
    // Rule 5, and the counterpart of the admission rule: sync spreads knowledge
    // of removals quickly and knowledge of additions only as confirmation of a
    // vouch that can be verified.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let ghost = device("dev_GHOST", 50);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    let message = RosterSync {
        epoch: 0,
        devices: {
            let mut devices = vec![
                SyncDevice {
                    device_id: "dev_A".to_owned(),
                    identity_pk: alice.identity.public_key().to_base64(),
                    state: DeviceState::Active,
                },
                SyncDevice {
                    device_id: "dev_B".to_owned(),
                    identity_pk: bob.identity.public_key().to_base64(),
                    state: DeviceState::Active,
                },
                SyncDevice {
                    device_id: "dev_GHOST".to_owned(),
                    identity_pk: ghost.identity.public_key().to_base64(),
                    state: DeviceState::Active,
                },
            ];
            devices.sort_by(|a, b| a.device_id.cmp(&b.device_id));
            devices
        },
        digest: String::new(),
    };
    // Recompute the digest the way a sender would.
    let message = RosterSync {
        digest: digest_for(&message),
        ..message
    };

    let applied = roster.receive_sync(&message, &bob.id);
    match &applied.outcome {
        Sync::Merged { anomalies, .. } => assert_eq!(anomalies, &vec!["dev_GHOST".to_owned()]),
        other => panic!("expected Merged, got {other:?}"),
    }
    assert!(
        !roster.is_active("dev_GHOST"),
        "a sync must never admit anything"
    );
    assert!(
        applied
            .ledger
            .iter()
            .any(|entry| matches!(entry.event, LedgerEvent::VouchRejected { .. })),
        "the anomaly is ledgered and shown while waiting for a vouch"
    );
}

#[test]
fn a_sync_reporting_a_removal_applies_it() {
    // Tombstones win, always. Accepting this from a sync grants the sender no
    // power it did not already have — any active device may remove any other — and
    // it is what makes a lost-phone removal reliable in a family whose devices are
    // rarely all online at once.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let carol = device("dev_C", 3);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    admit(&mut roster, &alice, &carol);

    let mut bobs = founded(&bob);
    let v1 = bobs
        .vouch_for(&alice.subject(), &bob.identity)
        .expect("vouch");
    bobs.receive_introduce(&v1, &bob.id, now());
    let v2 = bobs
        .vouch_for(&carol.subject(), &bob.identity)
        .expect("vouch");
    bobs.receive_introduce(&v2, &bob.id, now());
    bobs.remove(
        "dev_C",
        RemovalReason::Lost,
        "2026-07-26T11:00:00Z",
        &bob.identity,
        now(),
    )
    .expect("removal");

    let applied = roster.receive_sync(&bobs.sync(), &bob.id);
    match &applied.outcome {
        Sync::Merged {
            removals_applied, ..
        } => assert_eq!(*removals_applied, 1),
        other => panic!("expected Merged, got {other:?}"),
    }
    assert!(!roster.is_active("dev_C"));
    assert!(roster.tombstone("dev_C").is_some());
    assert_eq!(roster.epoch(), 1, "epoch is max(local, received)");
}

#[test]
fn the_epoch_only_moves_forward() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let carol = device("dev_C", 3);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    admit(&mut roster, &alice, &carol);
    roster
        .remove(
            "dev_C",
            RemovalReason::Removed,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");
    assert_eq!(roster.epoch(), 1);

    // A peer that is behind must not drag the epoch back.
    let mut behind = founded(&bob);
    let vouch = behind
        .vouch_for(&alice.subject(), &bob.identity)
        .expect("vouch");
    behind.receive_introduce(&vouch, &bob.id, now());
    roster.receive_sync(&behind.sync(), &bob.id);
    assert_eq!(roster.epoch(), 1, "max(local, received)");
}

// ------------------------------------------------------ mutual eviction

#[test]
fn mutual_eviction_is_surfaced_and_never_resolved() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);

    let mut alices = founded(&alice);
    let vouch = alices
        .vouch_for(&bob.subject(), &alice.identity)
        .expect("vouch");
    alices.receive_introduce(&vouch, &alice.id, now());

    let mut bobs = founded(&bob);
    let vouch = bobs
        .vouch_for(&alice.subject(), &bob.identity)
        .expect("vouch");
    bobs.receive_introduce(&vouch, &bob.id, now());

    // Each removes the other, in ignorance.
    let alice_removes_bob = alices
        .remove(
            "dev_B",
            RemovalReason::Removed,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");
    let bob_removes_alice = bobs
        .remove(
            "dev_A",
            RemovalReason::Removed,
            "2026-07-26T11:00:05Z",
            &bob.identity,
            now(),
        )
        .expect("removal");

    // Alice learns Bob removed her. Both tombstones stand.
    let applied = alices.receive_remove(&bob_removes_alice.outcome, &bob.id, now());
    assert_eq!(applied.outcome, Removal::AboutSelf);
    assert_eq!(alices.splits(), vec!["dev_B"]);
    assert!(
        applied.ledger.iter().any(|entry| entry.event
            == LedgerEvent::FamilySplit {
                counterpart: "dev_B".to_owned()
            }),
        "the split gets its own ledger entry naming both sides"
    );
    assert!(
        alices.tombstone("dev_B").is_some(),
        "both removals remain valid; nothing is auto-resolved"
    );
    // And the message Alice sent stands on Bob's side too.
    assert_eq!(bob_removes_alice.outcome.subject, "dev_A");
    assert_eq!(alice_removes_bob.outcome.subject, "dev_B");
}

// ------------------------------------------- reconciling the server list

#[test]
fn the_server_list_produces_the_four_documented_findings() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let carol = device("dev_C", 3);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    admit(&mut roster, &alice, &carol);

    let applied = roster.reconcile_server_list(&[
        ServerDevice {
            device_id: "dev_A".to_owned(),
            revoked: false,
        },
        ServerDevice {
            device_id: "dev_B".to_owned(),
            revoked: true,
        },
        ServerDevice {
            device_id: "dev_INJECTED".to_owned(),
            revoked: false,
        },
        // dev_C is absent from the list entirely.
    ]);

    assert!(applied.outcome.contains(&ServerFinding::Normal {
        device_id: "dev_A".to_owned()
    }));
    assert!(applied.outcome.contains(&ServerFinding::RevokedByServer {
        device_id: "dev_B".to_owned()
    }));
    assert!(applied.outcome.contains(&ServerFinding::Unvouched {
        device_id: "dev_INJECTED".to_owned()
    }));
    assert!(applied.outcome.contains(&ServerFinding::Unreachable {
        device_id: "dev_C".to_owned()
    }));
}

#[test]
fn an_injected_device_is_ledgered_and_never_admitted() {
    // The one place a dishonest host becomes visible to the family.
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);

    let applied = roster.reconcile_server_list(&[
        ServerDevice {
            device_id: "dev_A".to_owned(),
            revoked: false,
        },
        ServerDevice {
            device_id: "dev_INJECTED".to_owned(),
            revoked: false,
        },
    ]);

    assert!(!roster.is_active("dev_INJECTED"));
    assert!(roster.record("dev_INJECTED").is_none());
    assert!(
        applied
            .ledger
            .iter()
            .any(|entry| entry.event == LedgerEvent::UnvouchedDeviceListed)
    );
    assert!(
        roster.identity_of("dev_INJECTED").is_none(),
        "no key material is handed out for a device nobody vouched for"
    );
}

#[test]
fn a_server_revocation_deactivates_but_does_not_tombstone() {
    // Deliberate, and a narrowing of the spec's "treat as removed": a permanent
    // tombstone would let a host that revokes everyone destroy a family's roster
    // irreversibly, since re-admission needs a fresh device id. Deactivating keeps
    // the honest case identical and leaves the dishonest one recoverable.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    roster.reconcile_server_list(&[
        ServerDevice {
            device_id: "dev_A".to_owned(),
            revoked: false,
        },
        ServerDevice {
            device_id: "dev_B".to_owned(),
            revoked: true,
        },
    ]);

    assert!(!roster.is_active("dev_B"), "capability is taken away");
    assert!(
        roster.tombstone("dev_B").is_none(),
        "but not irreversibly, because the evidence is the host's"
    );

    // A fresh vouch can bring it back, which a tombstone would have forbidden.
    let vouch = roster
        .vouch_for(&bob.subject(), &alice.identity)
        .expect("no tombstone stands in the way");
    assert_eq!(
        roster.receive_introduce(&vouch, &alice.id, now()).outcome,
        Admission::Admitted
    );
}

#[test]
fn an_absent_device_is_marked_unreachable_and_not_removed() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    roster.reconcile_server_list(&[ServerDevice {
        device_id: "dev_A".to_owned(),
        revoked: false,
    }]);
    assert!(
        roster.is_active("dev_B"),
        "never tombstoned on this evidence alone"
    );
}

// ----------------------------------------------------------------- labels

#[test]
fn a_device_may_change_its_own_labels_and_each_change_is_ledgered() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    let applied = roster.update_labels("dev_B", Some("Emma's phone"), Some("Emma"), Some("child"));
    assert!(applied.outcome);
    assert_eq!(applied.ledger.len(), 3);
    assert_eq!(
        roster.record("dev_B").expect("record").display_name,
        "Emma's phone"
    );
    assert!(applied.ledger.iter().any(|entry| entry.event
        == LedgerEvent::LabelsChanged {
            field: "display_name",
            value: "Emma's phone".to_owned()
        }));
}

#[test]
fn an_unchanged_label_is_not_a_ledger_event() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    let current = roster.record("dev_B").expect("record").display_name.clone();

    let applied = roster.update_labels("dev_B", Some(&current), None, None);
    assert!(!applied.outcome);
    assert!(applied.ledger.is_empty(), "the ledger is not a heartbeat");
}

#[test]
fn labels_from_a_device_with_no_record_are_dropped() {
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);
    let applied = roster.update_labels("dev_STRANGER", Some("Trust me"), None, None);
    assert!(!applied.outcome);
    assert!(roster.record("dev_STRANGER").is_none());
}

#[test]
fn a_label_confers_nothing() {
    // A device that renames itself gains no authority: the assertion is that the
    // security-bearing field is untouched by a label update.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    let key_before = roster.record("dev_B").expect("record").identity_pk.clone();

    roster.update_labels("dev_B", Some("Mum's phone"), Some("Mum"), Some("parent"));
    assert_eq!(
        roster.record("dev_B").expect("record").identity_pk,
        key_before
    );
    assert!(
        roster
            .remove(
                "dev_A",
                RemovalReason::Removed,
                "2026-07-26T11:00:00Z",
                &alice.identity,
                now()
            )
            .is_ok(),
        "a `parent` role does not stop anyone removing anyone"
    );
}

// ------------------------------------------------------------ persistence

#[test]
fn a_roster_survives_a_restart_with_every_kind_of_state() {
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let gone = device("dev_GONE", 40);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);
    admit(&mut roster, &alice, &gone);
    roster
        .remove(
            "dev_GONE",
            RemovalReason::Lost,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");
    // Push Bob over budget so a held vouch exists to persist.
    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_b{n}"), 180 + u8::try_from(n).expect("small"));
        admit(&mut roster, &bob, &joiner);
    }
    admit(&mut roster, &bob, &device("dev_HELD", 61));
    assert_eq!(roster.held_admissions().len(), 1);

    let snapshot = roster.export();
    let json = serde_json::to_vec(&snapshot).expect("serialises");
    let read_back: RosterSnapshot = serde_json::from_slice(&json).expect("deserialises");
    let restored = Roster::import(&read_back, "dev_A").expect("imports");

    assert_eq!(restored, roster);
    assert_eq!(restored.epoch(), roster.epoch());
    assert!(restored.tombstone("dev_GONE").is_some());
    assert_eq!(restored.held_admissions().len(), 1);
    assert_eq!(restored.held_admissions()[0].introducer, "dev_B");
}

#[test]
fn a_restored_roster_keeps_the_churn_budget_spent() {
    // A budget that resets on app restart is not a budget.
    let alice = device("dev_A", 1);
    let mut roster = founded(&alice);
    for n in 0..MAX_MEMBERSHIP_EVENTS_PER_DEVICE_PER_DAY {
        let joiner = device(&format!("dev_{n}"), 100 + u8::try_from(n).expect("small"));
        admit(&mut roster, &alice, &joiner);
    }

    let mut restored = Roster::import(&roster.export(), "dev_A").expect("imports");
    let joiner = device("dev_AFTER", 62);
    let vouch = restored
        .vouch_for(&joiner.subject(), &alice.identity)
        .expect("vouch");
    assert!(
        matches!(
            restored.receive_introduce(&vouch, &alice.id, now()).outcome,
            Admission::Held { .. }
        ),
        "restarting the app must not refill the attacker's allowance"
    );
}

#[test]
fn another_devices_roster_is_refused() {
    let alice = device("dev_A", 1);
    let roster = founded(&alice);
    assert_eq!(
        Roster::import(&roster.export(), "dev_B").expect_err("wrong device"),
        SnapshotError::WrongDevice {
            expected: "dev_B".to_owned(),
            found: "dev_A".to_owned(),
        }
    );
}

#[test]
fn a_future_snapshot_version_is_refused() {
    let alice = device("dev_A", 1);
    let mut snapshot = founded(&alice).export();
    snapshot.v += 1;
    assert!(matches!(
        Roster::import(&snapshot, "dev_A"),
        Err(SnapshotError::UnsupportedVersion { .. })
    ));
}

// ---------------------------------------------------- the session handoff

#[test]
fn the_roster_is_the_only_source_of_a_peers_identity_key() {
    // What the session layer must check a fetched bundle against. A device that
    // is not an active member yields nothing, which is what stops a server list
    // from becoming a key source.
    let alice = device("dev_A", 1);
    let bob = device("dev_B", 2);
    let mut roster = founded(&alice);
    admit(&mut roster, &alice, &bob);

    assert_eq!(
        roster.identity_of("dev_B").expect("key"),
        bob.identity.public_key()
    );
    assert!(roster.identity_of("dev_NOBODY").is_none());

    roster
        .remove(
            "dev_B",
            RemovalReason::Removed,
            "2026-07-26T11:00:00Z",
            &alice.identity,
            now(),
        )
        .expect("removal");
    assert!(
        roster.identity_of("dev_B").is_none(),
        "a removed device's key is not handed out"
    );
}

/// Recompute a sync digest the way a sender would, for corpus-free tests.
fn digest_for(message: &RosterSync) -> String {
    // Build a roster whose sync would carry these devices is impractical here, so
    // reuse the library's own producer via a round trip: a sync built by `sync()`
    // is digest-correct, and this helper only needs to agree with it.
    use sha2::{Digest as _, Sha256};
    let payload = beacon_protocol::roster::SyncPayload {
        epoch: message.epoch,
        devices: &message.devices,
    };
    let canonical = sund_client::canonical::to_canonical_json(&payload).expect("encodes");
    let digest = Sha256::digest(&canonical);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
