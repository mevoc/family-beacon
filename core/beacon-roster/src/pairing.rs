//! The initiation-address relay: how a joining device becomes reachable.
//!
//! `docs/FamilyBeacon-Roster.md` → Admission, steps 5a–5c. Grant-only bundles
//! carry key material and no address, so after a join every pair knows how to
//! *encrypt* to each other and not where to *send*. Sending needs a queue sender
//! id, and only the recipient can mint one. The introducer — the single device
//! that already has channels to everybody — carries the first one across.
//!
//! ## The shape, and why it is one hop and not two
//!
//! The spec describes the introducer relaying in both directions. It only has to
//! relay one:
//!
//! ```text
//!   J mints a queue per member, seals each address to its member
//!   J ──offer(of=J, for=P)──▶ M ──offer(of=J, for=P)──▶ P     relayed
//!   P can now send to J
//!   P ──offer(of=P, for=J)─────────────────────────────▶ J     direct
//!   both directions live
//! ```
//!
//! Once P holds J's address, P can reach J on its own, so it returns its own
//! offer over the channel that now exists. Halving the relay halves what the
//! introducer touches, which is the point of the next section.
//!
//! ## The relayer is a courier, not a party
//!
//! A sender id is a capability: whoever holds it may write to that queue, and
//! Sund binds a queue's sender key to whoever writes *first*. A relayer that
//! could read the address could therefore bind the queue itself and permanently
//! break the pair it was introducing — a silent, persistent denial of service by
//! the one device the joiner had no choice but to trust.
//!
//! So the address is **sealed to its recipient**: `ChannelOffer::sealed` is a
//! session frame from `of` to `for`, and the relayer forwards bytes it cannot
//! read. Both devices already hold each other's verified key material by this
//! point — the vouch put them in each other's rosters and their bundles are
//! fetchable — so the sealing costs one nested encryption and no extra round
//! trip.
//!
//! What a relayer *can* still do is drop an offer, or replay an old one. Dropping
//! is a visible failure (the join does not complete, and the joiner can ask
//! again); replaying re-attaches a stale address, which surfaces as
//! [`TransportError::Retired`](sund_client::transport::TransportError::Retired)
//! on the next send and is repaired by a fresh exchange.
//! [`ChannelAddress::minted_at`](beacon_protocol::roster::ChannelAddress::minted_at)
//! is carried so a receiver could order offers and refuse an older one without a
//! format change; nothing does that yet, because the failure is already loud and
//! recoverable and the attacker is a device that could equally just remove the
//! victim from the family.
//!
//! ## What this module is and is not
//!
//! Policy, like the rest of the crate: it decides who needs an offer and whether
//! an arriving one may be acted on. It mints no queues, seals nothing and sends
//! nothing — the caller owns the transport and the session layer, and
//! [`AcceptedOffer`] tells it exactly what to do next.

use beacon_protocol::ledger::{LedgerEntry, LedgerEvent};
use beacon_protocol::roster::ChannelOffer;

use crate::roster::{Applied, Roster};

/// Why a channel offer was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferRefusal {
    /// The offer is addressed to another device. Anyone else must drop it —
    /// including the relayer, which handles it without reading it.
    NotForMe {
        /// The device the offer names.
        intended: String,
    },
    /// The device whose inbox this addresses is not an active member.
    ///
    /// The same rule as everywhere else in this crate: the roster decides who is
    /// in the family, so an address for a stranger — or for a device that has
    /// been removed since the offer was made — is not acted on.
    OwnerNotActive {
        /// The device the offer claims to be from.
        owner: String,
    },
    /// The device that carried the offer is not an active member.
    RelayerNotActive {
        /// The device that sent it.
        relayer: String,
    },
    /// The offer claims to be from this device.
    ///
    /// Nothing legitimate produces one, and acting on it would have this device
    /// send to its own inbox.
    OwnerIsSelf,
}

impl std::fmt::Display for OfferRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotForMe { intended } => write!(f, "the offer is addressed to `{intended}`"),
            Self::OwnerNotActive { owner } => write!(f, "`{owner}` is not an active member"),
            Self::RelayerNotActive { relayer } => {
                write!(f, "`{relayer}` is not an active member")
            }
            Self::OwnerIsSelf => write!(f, "the offer claims to come from this device"),
        }
    }
}

/// An offer that may be acted on.
///
/// Obtainable only from [`accept_offer`], so there is no path from unvalidated
/// bytes to an attached address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedOffer {
    /// The device whose inbox this addresses.
    ///
    /// Unseal `sealed` with the session for **this** device — not for whoever
    /// relayed it. The session layer's own check is what turns the offer's claim
    /// into a fact: a frame that decrypts under this peer's session was sealed by
    /// this peer.
    pub owner: String,
    /// Whether the offer arrived directly from its owner rather than through a
    /// relayer.
    ///
    /// Not a security distinction — both are validated identically — but the
    /// ledger can say "Emma's phone sent you its address" rather than "Dad's
    /// phone passed on Emma's address", and those are different sentences to a
    /// person.
    pub direct: bool,
}

/// Active members this device has no way to reach yet.
///
/// `already_addressed` is what the caller's transport says it can already send
/// to; this crate deliberately does not track it, because the transport already
/// does and two sources of truth about the same fact is how they drift.
///
/// Self is never included, and neither is any device that is not an active
/// member — a removed device is not owed an address.
#[must_use]
pub fn peers_needing_offers(roster: &Roster, already_addressed: &[&str]) -> Vec<String> {
    roster
        .active()
        .into_iter()
        .map(|record| record.device_id.clone())
        .filter(|device_id| {
            device_id != roster.self_id() && !already_addressed.contains(&device_id.as_str())
        })
        .collect()
}

/// Validate an arriving offer.
///
/// `relayed_by` is the device the *session* authenticated as having sent the
/// carrying envelope — the introducer for a relayed offer, or the owner itself
/// for the direct reply. It is never read from the message.
///
/// The address inside is not touched here: unsealing needs the session layer,
/// which the caller owns. Validate first, unseal second, attach third.
pub fn accept_offer(
    roster: &Roster,
    offer: &ChannelOffer,
    relayed_by: &str,
) -> Applied<Result<AcceptedOffer, OfferRefusal>> {
    let refuse = |refusal: OfferRefusal| Applied {
        ledger: vec![LedgerEntry::inbound(
            relayed_by,
            None,
            LedgerEvent::ChannelOfferRefused {
                reason: refusal.to_string(),
            },
        )],
        outcome: Err(refusal),
    };

    if offer.for_device != roster.self_id() {
        return refuse(OfferRefusal::NotForMe {
            intended: offer.for_device.clone(),
        });
    }
    if offer.of == roster.self_id() {
        return refuse(OfferRefusal::OwnerIsSelf);
    }
    if !roster.is_active(relayed_by) {
        return refuse(OfferRefusal::RelayerNotActive {
            relayer: relayed_by.to_owned(),
        });
    }
    if !roster.is_active(&offer.of) {
        return refuse(OfferRefusal::OwnerNotActive {
            owner: offer.of.clone(),
        });
    }

    Applied {
        outcome: Ok(AcceptedOffer {
            owner: offer.of.clone(),
            direct: offer.of == relayed_by,
        }),
        ledger: vec![LedgerEntry::inbound(
            &offer.of,
            None,
            LedgerEvent::ChannelEstablished { outbound: true },
        )],
    }
}

/// Why an offer will not be relayed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayRefusal {
    /// The offer is for this device: accept it, do not relay it.
    ForMe,
    /// The offer was not handed over by the device that owns it.
    ///
    /// **This is the rule that keeps the relay from becoming a general-purpose
    /// forwarding primitive.** Without it, any member could push arbitrary sealed
    /// payloads at any other member through a third one — spam and traffic
    /// laundering with someone else's device as the courier. A relayer carries
    /// exactly one thing: an address its owner personally handed it.
    NotFromItsOwner {
        /// The device that offered it.
        from: String,
        /// The device the offer says owns it.
        owner: String,
    },
    /// One of the two ends is not an active member.
    NotAFamilyMatter {
        /// The end that is not a member.
        stranger: String,
    },
}

impl std::fmt::Display for RelayRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForMe => write!(f, "the offer is addressed to this device"),
            Self::NotFromItsOwner { from, owner } => write!(
                f,
                "`{from}` offered an address belonging to `{owner}`; only its owner may hand it over"
            ),
            Self::NotAFamilyMatter { stranger } => {
                write!(f, "`{stranger}` is not an active member")
            }
        }
    }
}

/// Where to forward an offer this device is only carrying, if anywhere.
///
/// The introducer's side of the relay. `from` is the authenticated sender of the
/// carrying envelope.
///
/// # Errors
///
/// Returns [`RelayRefusal`] when the offer is for this device, was handed over by
/// someone other than its owner, or names a device outside the family.
pub fn relay_target(
    roster: &Roster,
    offer: &ChannelOffer,
    from: &str,
) -> Result<String, RelayRefusal> {
    if offer.for_device == roster.self_id() {
        return Err(RelayRefusal::ForMe);
    }
    if offer.of != from {
        return Err(RelayRefusal::NotFromItsOwner {
            from: from.to_owned(),
            owner: offer.of.clone(),
        });
    }
    for end in [&offer.of, &offer.for_device] {
        if !roster.is_active(end) {
            return Err(RelayRefusal::NotAFamilyMatter {
                stranger: end.clone(),
            });
        }
    }
    Ok(offer.for_device.clone())
}

/// The ledger entry for having made this device reachable by a peer.
///
/// The other half of [`accept_offer`]'s entry, and the reason both exist: a
/// channel is two one-way facts, and "Emma's phone can now reach you" is a
/// different sentence from "you can now reach Emma's phone".
#[must_use]
pub fn offered(peer: &str) -> LedgerEntry {
    LedgerEntry::outbound(
        peer,
        None,
        LedgerEvent::ChannelEstablished { outbound: false },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::SelfDescription;
    use beacon_protocol::roster::RemovalReason;
    use std::time::{Duration, SystemTime};
    use sund_client::identity::IdentityKey;

    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_784_000_000)
    }

    fn identity(seed: u8) -> IdentityKey {
        IdentityKey::from_seed(&[seed; 32])
    }

    fn description(id: &str) -> SelfDescription {
        SelfDescription {
            device_id: id.to_owned(),
            display_name: id.to_owned(),
            member_group: id.to_owned(),
            role: "adult".to_owned(),
            joined_at: "2026-07-26T10:00:00Z".to_owned(),
        }
    }

    /// A roster owned by `dev_A` with `dev_B` and `dev_C` admitted.
    fn family() -> Roster {
        let alice = identity(1);
        let mut roster = Roster::found(&description("dev_A"), &alice).outcome;
        for (id, seed) in [("dev_B", 2u8), ("dev_C", 3)] {
            let subject = description(id).subject(identity(seed).public_key().to_base64());
            let vouch = roster.vouch_for(&subject, &alice).expect("vouch");
            roster.receive_introduce(&vouch, "dev_A", now());
        }
        roster
    }

    fn offer(of: &str, for_device: &str) -> ChannelOffer {
        ChannelOffer {
            of: of.to_owned(),
            for_device: for_device.to_owned(),
            sealed: "c2VhbGVk".to_owned(),
        }
    }

    #[test]
    fn every_active_member_but_self_needs_an_offer_at_first() {
        let roster = family();
        assert_eq!(peers_needing_offers(&roster, &[]), vec!["dev_B", "dev_C"]);
    }

    #[test]
    fn peers_the_transport_can_already_reach_are_not_offered_again() {
        let roster = family();
        assert_eq!(peers_needing_offers(&roster, &["dev_B"]), vec!["dev_C"]);
        assert!(peers_needing_offers(&roster, &["dev_B", "dev_C"]).is_empty());
    }

    #[test]
    fn a_removed_member_is_not_owed_an_address() {
        let mut roster = family();
        roster
            .remove(
                "dev_C",
                RemovalReason::Removed,
                "2026-07-26T11:00:00Z",
                &identity(1),
                now(),
            )
            .expect("removal");
        assert_eq!(peers_needing_offers(&roster, &[]), vec!["dev_B"]);
    }

    #[test]
    fn a_relayed_offer_is_accepted_and_names_whose_session_to_unseal_with() {
        let roster = family();
        // dev_C's address, carried by dev_B.
        let applied = accept_offer(&roster, &offer("dev_C", "dev_A"), "dev_B");
        assert_eq!(
            applied.outcome,
            Ok(AcceptedOffer {
                owner: "dev_C".to_owned(),
                direct: false,
            }),
            "the owner is the session to unseal with, not the relayer"
        );
        assert_eq!(
            applied.ledger[0].event,
            LedgerEvent::ChannelEstablished { outbound: true }
        );
        assert_eq!(
            applied.ledger[0].peer, "dev_C",
            "ledgered against the peer it makes reachable, not the courier"
        );
    }

    #[test]
    fn a_direct_offer_is_accepted_and_marked_as_such() {
        let roster = family();
        let applied = accept_offer(&roster, &offer("dev_B", "dev_A"), "dev_B");
        assert_eq!(
            applied.outcome,
            Ok(AcceptedOffer {
                owner: "dev_B".to_owned(),
                direct: true,
            })
        );
    }

    #[test]
    fn an_offer_for_someone_else_is_dropped() {
        let roster = family();
        let applied = accept_offer(&roster, &offer("dev_C", "dev_B"), "dev_B");
        assert_eq!(
            applied.outcome,
            Err(OfferRefusal::NotForMe {
                intended: "dev_B".to_owned()
            })
        );
        assert!(matches!(
            applied.ledger[0].event,
            LedgerEvent::ChannelOfferRefused { .. }
        ));
    }

    #[test]
    fn an_offer_from_a_stranger_is_refused_even_when_relayed_by_a_member() {
        // The rule that keeps the roster the authority: a member can carry an
        // address, but it cannot introduce a device by carrying one.
        let roster = family();
        let applied = accept_offer(&roster, &offer("dev_STRANGER", "dev_A"), "dev_B");
        assert_eq!(
            applied.outcome,
            Err(OfferRefusal::OwnerNotActive {
                owner: "dev_STRANGER".to_owned()
            })
        );
    }

    #[test]
    fn an_offer_relayed_by_a_stranger_is_refused() {
        let roster = family();
        let applied = accept_offer(&roster, &offer("dev_B", "dev_A"), "dev_STRANGER");
        assert_eq!(
            applied.outcome,
            Err(OfferRefusal::RelayerNotActive {
                relayer: "dev_STRANGER".to_owned()
            })
        );
    }

    #[test]
    fn an_offer_claiming_to_be_from_this_device_is_refused() {
        let roster = family();
        let applied = accept_offer(&roster, &offer("dev_A", "dev_A"), "dev_B");
        assert_eq!(applied.outcome, Err(OfferRefusal::OwnerIsSelf));
    }

    #[test]
    fn an_offer_whose_owner_was_removed_since_is_refused() {
        // The offer was legitimate when it was made; by the time it arrives the
        // family has evicted its owner. Removal is fail-safe, so the late offer
        // loses.
        let mut roster = family();
        roster
            .remove(
                "dev_C",
                RemovalReason::Lost,
                "2026-07-26T11:00:00Z",
                &identity(1),
                now(),
            )
            .expect("removal");
        let applied = accept_offer(&roster, &offer("dev_C", "dev_A"), "dev_B");
        assert_eq!(
            applied.outcome,
            Err(OfferRefusal::OwnerNotActive {
                owner: "dev_C".to_owned()
            })
        );
    }

    #[test]
    fn an_offer_from_its_owner_is_relayed_to_its_recipient() {
        let roster = family();
        assert_eq!(
            relay_target(&roster, &offer("dev_B", "dev_C"), "dev_B"),
            Ok("dev_C".to_owned())
        );
    }

    #[test]
    fn an_offer_for_this_device_is_accepted_rather_than_relayed() {
        let roster = family();
        assert_eq!(
            relay_target(&roster, &offer("dev_B", "dev_A"), "dev_B"),
            Err(RelayRefusal::ForMe)
        );
    }

    #[test]
    fn a_relay_carries_only_an_address_its_owner_handed_over() {
        // The rule that stops the relay becoming a general forwarding primitive:
        // without it, any member could push arbitrary sealed payloads at any
        // other member using a third one as the courier.
        let roster = family();
        assert_eq!(
            relay_target(&roster, &offer("dev_C", "dev_B"), "dev_B"),
            Err(RelayRefusal::NotFromItsOwner {
                from: "dev_B".to_owned(),
                owner: "dev_C".to_owned(),
            }),
            "dev_B may not hand over an address that belongs to dev_C"
        );
    }

    #[test]
    fn a_relay_never_involves_a_non_member_at_either_end() {
        let roster = family();
        assert_eq!(
            relay_target(&roster, &offer("dev_B", "dev_STRANGER"), "dev_B"),
            Err(RelayRefusal::NotAFamilyMatter {
                stranger: "dev_STRANGER".to_owned()
            })
        );
        assert_eq!(
            relay_target(&roster, &offer("dev_STRANGER", "dev_C"), "dev_STRANGER"),
            Err(RelayRefusal::NotAFamilyMatter {
                stranger: "dev_STRANGER".to_owned()
            })
        );
    }

    #[test]
    fn making_this_device_reachable_is_its_own_ledger_entry() {
        let entry = offered("dev_B");
        assert_eq!(
            entry.event,
            LedgerEvent::ChannelEstablished { outbound: false },
            "the two directions are different sentences to a person"
        );
        assert_eq!(entry.peer, "dev_B");
    }
}
