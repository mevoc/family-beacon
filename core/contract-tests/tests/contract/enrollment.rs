//! Enrollment, invitations, the device list, bundles, push endpoints and
//! revocation — the management plane, against a real server.

use contract_tests::for_each_relay;
use sund_client::client::SundError;

#[test]
fn an_invitation_enrolls_exactly_one_device() {
    for_each_relay(|relay| {
        let invitation = relay
            .founder()
            .create_invitation()
            .expect("mint an invitation");

        let device = relay
            .try_enroll_with(&invitation.token)
            .expect("the first use of a token enrolls");
        assert!(!device.device_id().is_empty());

        // Single-use: the server cannot tell a replayed token from a forged
        // one, and answers the same way for both.
        assert_eq!(
            relay
                .try_enroll_with(&invitation.token)
                .expect_err("a spent token is refused"),
            SundError::Unauthorized,
            "{}: a token must enroll exactly one device",
            relay.name
        );
    });
}

#[test]
fn an_enrolled_device_appears_in_the_family_with_the_key_it_enrolled_with() {
    for_each_relay(|relay| {
        let device = relay.enroll();

        let listed = relay.founder().list_devices().expect("list devices");
        let record = listed
            .iter()
            .find(|record| record.id == device.device_id())
            .unwrap_or_else(|| panic!("{}: the new device is not listed", relay.name));

        // The key in the list is what a peer verifies a newly paired device
        // against, so it has to survive the round trip byte for byte.
        assert_eq!(record.public_key, device.key.public_key());
        assert!(!record.revoked);
        assert_eq!(record.capabilities, "contract-tests");

        // Membership is symmetric on the server: the new device sees the family
        // too, which is what the transparency rule requires — no silent
        // membership, in either direction.
        let from_the_new_device = device.list_devices().expect("list from the new device");
        assert!(
            from_the_new_device
                .iter()
                .any(|record| record.id == relay.founder().device_id())
        );
    });
}

#[test]
fn an_invitation_can_be_revoked_before_anyone_uses_it() {
    for_each_relay(|relay| {
        let invitation = relay.founder().create_invitation().expect("mint");

        let outstanding = relay.founder().list_invitations().expect("list");
        assert!(
            outstanding.iter().any(|record| record.id == invitation.id),
            "{}: a fresh invitation should be listed",
            relay.name
        );
        assert!(
            outstanding
                .iter()
                .all(|record| record.id != invitation.token),
            "a listing must never carry the token itself"
        );

        relay
            .founder()
            .revoke_invitation(&invitation.id)
            .expect("revoke");
        assert_eq!(
            relay.try_enroll_with(&invitation.token).err(),
            Some(SundError::Unauthorized),
            "{}: a revoked invitation must not enroll",
            relay.name
        );

        // And revoking it twice is not a way to learn whether it existed.
        assert_eq!(
            relay.founder().revoke_invitation(&invitation.id).err(),
            Some(SundError::NotFound)
        );
    });
}

#[test]
fn a_consumed_invitation_leaves_the_outstanding_list() {
    for_each_relay(|relay| {
        let invitation = relay.founder().create_invitation().expect("mint");
        relay
            .try_enroll_with(&invitation.token)
            .expect("enroll with it");

        let outstanding = relay.founder().list_invitations().expect("list");
        assert!(
            outstanding.iter().all(|record| record.id != invitation.id),
            "{}: a consumed invitation is no longer outstanding",
            relay.name
        );
    });
}

#[test]
fn a_key_bundle_comes_back_exactly_as_it_was_published() {
    for_each_relay(|relay| {
        let device = relay.enroll();
        // Opaque to the server by design — it stores bytes it must not
        // interpret, which is also why one-time prekeys cannot be popped
        // server-side and the session layer runs in fallback-key mode.
        let bundle: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
        device.publish_bundle(&bundle).expect("publish");

        let fetched = relay
            .founder()
            .fetch_bundle(device.device_id())
            .expect("fetch a peer's bundle");
        assert_eq!(fetched.bundle, bundle, "{}: bundle round trip", relay.name);
        assert!(fetched.updated.is_some());
    });
}

#[test]
fn an_oversized_bundle_is_refused_rather_than_truncated() {
    for_each_relay(|relay| {
        let device = relay.enroll();
        assert_eq!(
            device.publish_bundle(&vec![7u8; (8 << 10) + 1]).err(),
            Some(SundError::TooLarge),
            "{}: the 8 KiB bundle cap",
            relay.name
        );
        assert!(matches!(
            device.publish_bundle(b"").err(),
            Some(SundError::Rejected(_))
        ));
    });
}

#[test]
fn a_push_endpoint_can_be_set_and_cleared() {
    for_each_relay(|relay| {
        let device = relay.enroll();
        device
            .set_push_endpoint("https://ntfy.example.org/upABCDEF")
            .expect("set");

        let record = relay
            .founder()
            .list_devices()
            .expect("list")
            .into_iter()
            .find(|record| record.id == device.device_id())
            .expect("listed");
        assert_eq!(record.push_endpoint, "https://ntfy.example.org/upABCDEF");

        device.set_push_endpoint("").expect("clear");
        assert!(matches!(
            device.set_push_endpoint(&"x".repeat(2049)).err(),
            Some(SundError::Rejected(_)),
        ));
    });
}

#[test]
fn revocation_takes_effect_immediately_and_is_visible_to_the_family() {
    for_each_relay(|relay| {
        let device = relay.enroll();
        assert!(device.list_devices().is_ok(), "live before revocation");

        relay
            .founder()
            .revoke_device(device.device_id())
            .expect("revoke");

        // The revoked device's identity key is dead: not "eventually", not
        // "after a token expires".
        assert_eq!(
            device.list_devices().err(),
            Some(SundError::Unauthorized),
            "{}: a revoked device must be refused at once",
            relay.name
        );

        // And the family can see that it was removed, rather than it merely
        // going quiet.
        let record = relay
            .founder()
            .list_devices()
            .expect("list")
            .into_iter()
            .find(|record| record.id == device.device_id())
            .expect("a revoked device stays listed");
        assert!(record.revoked);

        // A revoked device is also no longer a source of key material.
        assert_eq!(
            relay.founder().fetch_bundle(device.device_id()).err(),
            Some(SundError::NotFound)
        );
    });
}

#[test]
fn a_device_in_another_account_is_indistinguishable_from_one_that_never_existed() {
    for_each_relay(|relay| {
        assert_eq!(
            relay.founder().revoke_device("dev_definitelynotreal").err(),
            Some(SundError::NotFound),
            "{}: unknown devices 404 without confirming anything",
            relay.name
        );
        assert_eq!(
            relay.founder().fetch_bundle("dev_definitelynotreal").err(),
            Some(SundError::NotFound)
        );
    });
}
