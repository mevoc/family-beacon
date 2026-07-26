//! The session layer: a double ratchet over vodozemac.
//!
//! Specified in `docs/FamilyBeacon-Sessions.md`. This is the piece that makes
//! [`crate::transport`]'s "ciphertext" field true rather than aspirational —
//! everything below the port carried opaque bytes by convention until now.
//!
//! ## Why a ratchet and not a handshake
//!
//! CLAUDE.md decision #6 rejected Noise here, and the reason is a property of
//! this transport rather than a preference: delivery is at-least-once,
//! per-channel ordered, and *deliberately lossy*. Location messages carry short
//! TTLs because a stale position is worse than none, Sund deletes expired
//! messages unread, and Try mode's cache window drops them permanently. Skipped
//! message keys are therefore the normal case, not the exception, and Noise's
//! transport phase assumes a reliable ordered stream. The ratchet also gives
//! post-compromise recovery, which the stolen-device and hostile-member
//! scenarios in ETHICS.md need.
//!
//! ## The two bounds that fall out of vodozemac
//!
//! Both are worth knowing because they are the *only* places a lossy transport
//! can make a session unusable:
//!
//! - **40 skipped keys per receiver chain** (five chains, so ~200 in flight).
//!   Ample: it bounds out-of-order *arrival*, and messages older than that have
//!   expired at the relay anyway.
//! - **A hard gap ceiling of 2000 messages.** A receiver that jumps forward more
//!   than 2000 messages cannot decrypt at all. Sund holds a message for at most
//!   7 days, so this needs a sender emitting >2000 messages to a peer that is
//!   away the whole time — roughly one a minute for 33 hours. It is reachable,
//!   not hypothetical, so it is a named outcome ([`SessionError::SessionLost`])
//!   whose documented remedy is to re-establish, never to retry.
//!
//! ## What authenticates a sender
//!
//! [`Decrypted::authenticated_sender`] is the device the *channel* belongs to,
//! cross-checked against the Curve25519 key from a roster-verified bundle. It
//! never comes from the message. That is what makes
//! `beacon_protocol::receive`'s sender comparison meaningful: the envelope's own
//! `sender` field is attribution after decryption, and this is the thing it is
//! compared against.

use std::collections::BTreeMap;
use std::time::Duration;

use vodozemac::olm::{Account, OlmMessage, Session, SessionConfig};

use crate::bundle::{BUNDLE_VERSION, Bundle, BundleError, PeerKeys, SignedBundle};
use crate::canonical::CanonicalError;
use crate::identity::{IdentityKey, IdentityPublicKey, SignaturePurpose};

/// Version byte on every session frame.
///
/// The frame is the only thing this layer puts on the wire that is not Olm's
/// own encoding, so it is the hook for a future compact envelope format — the
/// same reason `docs/FamilyBeacon-Protocol.md` keeps `v` on the envelope.
pub const FRAME_VERSION: u8 = 1;

/// How long a published fallback key stays usable before rotation.
///
/// Seven days, and the number is derived rather than chosen. Sund clamps a
/// queued message's TTL to seven days, so the oldest pre-key message that can
/// ever arrive is seven days old. vodozemac keeps exactly two fallback private
/// keys — current and previous — so rotating on this period means the key a peer
/// fetched just before a rotation stays decryptable for precisely as long as a
/// message encrypted to it can survive, and no longer. Rotating faster would
/// silently drop initial messages; rotating slower would widen the
/// signed-prekey-grade window this mode already accepts.
pub const FALLBACK_KEY_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// What can go wrong in the session layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// No verified key material is held for this peer, so nothing can be sent
    /// to it or attributed to it.
    ///
    /// The remedy is above this layer: fetch the peer's bundle, verify it
    /// against the roster's `identity_pk`, and hand the result to
    /// [`SessionManager::learn_peer`]. A message arriving from a device with no
    /// roster record is *supposed* to reach this error and be dropped.
    UnknownPeer(String),
    /// A frame this build cannot parse.
    Frame(String),
    /// A frame version this build does not speak.
    UnsupportedFrameVersion(u8),
    /// The session with this peer can no longer decrypt what is arriving, and
    /// retrying will not help.
    ///
    /// Two causes, both benign-looking and both terminal for the session: the
    /// message gap exceeded vodozemac's ceiling, or the message key was already
    /// used or discarded. The remedy is to re-establish — fetch the peer's
    /// bundle again and open a fresh outbound session — and to ledger it, since
    /// a peer whose sessions keep dying is something the user should be able to
    /// see.
    SessionLost {
        /// The peer whose session must be re-established.
        peer: String,
        /// Vodozemac's account of what happened.
        detail: String,
    },
    /// A normal (non-pre-key) message arrived before any session existed.
    ///
    /// Ordinary after a reinstall or a cache-window loss: the peer is ratcheting
    /// a session this device no longer has. Re-establishment has to be driven by
    /// whichever side can — see the spec's Recovery section.
    NoSession(String),
    /// Olm refused the operation.
    Olm(String),
    /// The peer's bundle could not be built or verified.
    Bundle(BundleError),
    /// The bundle payload could not be canonically encoded for signing.
    Canonical(CanonicalError),
}

impl From<BundleError> for SessionError {
    fn from(error: BundleError) -> Self {
        Self::Bundle(error)
    }
}

impl From<CanonicalError> for SessionError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPeer(peer) => write!(f, "no verified key material for `{peer}`"),
            Self::Frame(detail) => write!(f, "malformed session frame: {detail}"),
            Self::UnsupportedFrameVersion(found) => {
                write!(f, "unsupported session frame version {found}")
            }
            Self::SessionLost { peer, detail } => {
                write!(f, "session with `{peer}` must be re-established: {detail}")
            }
            Self::NoSession(peer) => write!(f, "no session with `{peer}` to decrypt with"),
            Self::Olm(detail) => write!(f, "olm: {detail}"),
            Self::Bundle(error) => write!(f, "{error}"),
            Self::Canonical(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SessionError {}

/// One decrypted message, with the sender the session layer vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    /// The device this plaintext genuinely came from.
    ///
    /// Pass straight to `beacon_protocol::receive` as its
    /// `authenticated_sender`. It is derived from the channel and the verified
    /// Curve25519 identity key, never from the message body.
    pub authenticated_sender: String,
    /// The envelope bytes.
    pub plaintext: Vec<u8>,
    /// Whether this message established or re-established the session.
    ///
    /// Worth surfacing: a re-established session is the observable half of a
    /// peer reinstalling, restoring a backup, or recovering from
    /// [`SessionError::SessionLost`], and the transparency ledger should be able
    /// to say so rather than leaving the user to guess.
    pub new_session: bool,
}

/// A peer this device can talk to: its verified keys, and the session if one is
/// open.
#[derive(Debug)]
struct PeerState {
    keys: PeerKeys,
    session: Option<Session>,
}

/// Everything a device needs to hold sessions with its family.
///
/// Owns the Olm account and one session per peer. It does **not** own a clock,
/// a random source for anything it can avoid, or a loop — timestamps are
/// arguments and the caller drives, exactly as with [`crate::sigauth`] and
/// [`crate::transport`]. The one unavoidable exception is Olm key generation,
/// which draws from the system RNG inside vodozemac; it happens on
/// [`SessionManager::create`] and on fallback rotation, and never on the
/// receive path.
pub struct SessionManager {
    device_id: String,
    identity: IdentityKey,
    account: Account,
    peers: BTreeMap<String, PeerState>,
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Hand-written so no derive can ever start printing the account, which
        // holds private keys.
        f.debug_struct("SessionManager")
            .field("device_id", &self.device_id)
            .field("identity_pk", &self.identity.public_key().to_base64())
            .field("peers", &self.peers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl SessionManager {
    /// Create a fresh account for a device that has never had one.
    ///
    /// Generates Olm keys, so it draws from the system RNG. Call once per
    /// device install and persist the result with
    /// [`crate::session_store`] — calling it again mints a new Curve25519
    /// identity and orphans every session the device had.
    #[must_use]
    pub fn create(device_id: impl Into<String>, identity: IdentityKey) -> Self {
        Self {
            device_id: device_id.into(),
            identity,
            account: Account::new(),
            peers: BTreeMap::new(),
        }
    }

    /// Rebuild from a restored account. See [`crate::session_store`].
    #[must_use]
    pub fn from_account(
        device_id: impl Into<String>,
        identity: IdentityKey,
        account: Account,
    ) -> Self {
        Self {
            device_id: device_id.into(),
            identity,
            account,
            peers: BTreeMap::new(),
        }
    }

    /// This device's transport-layer id.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// This device's protocol identity key — the roster's `identity_pk`.
    #[must_use]
    pub fn identity_public_key(&self) -> IdentityPublicKey {
        self.identity.public_key()
    }

    /// The Olm Curve25519 identity key this device publishes.
    #[must_use]
    pub fn curve25519_key(&self) -> vodozemac::Curve25519PublicKey {
        self.account.curve25519_key()
    }

    /// Peers with verified key material, in id order.
    #[must_use]
    pub fn known_peers(&self) -> Vec<&str> {
        self.peers.keys().map(String::as_str).collect()
    }

    /// Whether an open session exists with this peer.
    #[must_use]
    pub fn has_session(&self, peer: &str) -> bool {
        self.peers
            .get(peer)
            .is_some_and(|state| state.session.is_some())
    }

    /// Build and sign this device's own bundle for publication.
    ///
    /// Generates a fallback key if the account has no unpublished one, then
    /// marks the account's keys published. `published_at` is an RFC 3339 UTC
    /// string from the app layer's clock.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::Olm`] if no fallback key could be produced, or
    /// [`SessionError::Canonical`] if the payload cannot be signed.
    pub fn publish_bundle(&mut self, published_at: &str) -> Result<SignedBundle, SessionError> {
        if self.account.fallback_key().is_empty() {
            self.account.generate_fallback_key();
        }
        let (key_id, fallback) = self
            .account
            .fallback_key()
            .into_iter()
            .next()
            .ok_or_else(|| SessionError::Olm("no fallback key available".to_owned()))?;

        let bundle = Bundle {
            v: BUNDLE_VERSION,
            device_id: self.device_id.clone(),
            identity_pk: self.identity.public_key().to_base64(),
            curve25519: self.account.curve25519_key().to_base64(),
            fallback_key: fallback.to_base64(),
            fallback_key_id: key_id.to_base64(),
            published_at: published_at.to_owned(),
        };
        let sig = self.identity.sign(SignaturePurpose::Bundle, &bundle)?;

        // Only after signing succeeds, so a failure here does not leave the
        // account believing it published something it did not.
        self.account.mark_keys_as_published();
        Ok(SignedBundle { bundle, sig })
    }

    /// Rotate the fallback key and return the bundle to publish.
    ///
    /// Call every [`FALLBACK_KEY_LIFETIME`]. The key being replaced stays
    /// decryptable until the *next* rotation, which is what gives initial
    /// messages the overlap they need; see that constant for why the period and
    /// the overlap are the same number.
    ///
    /// # Errors
    ///
    /// As [`Self::publish_bundle`].
    pub fn rotate_fallback_key(
        &mut self,
        published_at: &str,
    ) -> Result<SignedBundle, SessionError> {
        self.account.generate_fallback_key();
        self.publish_bundle(published_at)
    }

    /// Forget the previous fallback key ahead of schedule.
    ///
    /// Normal operation never needs this — the overlap expires on its own. It
    /// exists for the case where a device believes its published key material is
    /// compromised and wants the window shut now, accepting that initial
    /// messages already in flight to the old key will be lost.
    ///
    /// Returns whether there was a previous key to forget.
    pub fn forget_previous_fallback_key(&mut self) -> bool {
        self.account.forget_fallback_key()
    }

    /// Record verified key material for a peer.
    ///
    /// [`PeerKeys`] is only obtainable from [`SignedBundle::verify`], so there
    /// is no way to reach this with unverified keys. Re-learning a peer whose
    /// Curve25519 identity changed drops the existing session: that is a peer
    /// that reinstalled, and keeping the old session would only produce
    /// undecryptable traffic.
    pub fn learn_peer(&mut self, keys: PeerKeys) {
        match self.peers.get_mut(&keys.device_id) {
            Some(state) if state.keys.curve25519 == keys.curve25519 => {
                // Same device, refreshed bundle (a fallback rotation). The
                // session is unaffected.
                state.keys = keys;
            }
            Some(state) => {
                state.keys = keys;
                state.session = None;
            }
            None => {
                let device_id = keys.device_id.clone();
                self.peers.insert(
                    device_id,
                    PeerState {
                        keys,
                        session: None,
                    },
                );
            }
        }
    }

    /// Forget a peer entirely: its keys and its session.
    ///
    /// The session-layer half of a roster removal. Returns whether the peer was
    /// known.
    pub fn forget_peer(&mut self, peer: &str) -> bool {
        self.peers.remove(peer).is_some()
    }

    /// Open an outbound session with a peer, replacing any existing one.
    ///
    /// Uses the peer's signed fallback key as the one-time key, which is the
    /// whole of fallback-key mode.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::UnknownPeer`] if no verified keys are held, or
    /// [`SessionError::Olm`] if Olm refuses the key material.
    pub fn establish_outbound(&mut self, peer: &str) -> Result<(), SessionError> {
        let state = self
            .peers
            .get_mut(peer)
            .ok_or_else(|| SessionError::UnknownPeer(peer.to_owned()))?;
        let session = self
            .account
            .create_outbound_session(
                SessionConfig::default(),
                state.keys.curve25519,
                state.keys.fallback_key,
            )
            .map_err(|error| SessionError::Olm(error.to_string()))?;
        state.session = Some(session);
        Ok(())
    }

    /// Encrypt an envelope for a peer, returning a frame for
    /// [`crate::transport::Outbound`].
    ///
    /// Establishes the session first if there is none, because a caller that
    /// holds verified keys and wants to send has already expressed the intent.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::UnknownPeer`] if no verified keys are held, or
    /// [`SessionError::Olm`] if encryption fails.
    pub fn encrypt(&mut self, peer: &str, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if !self.has_session(peer) {
            self.establish_outbound(peer)?;
        }
        let state = self
            .peers
            .get_mut(peer)
            .ok_or_else(|| SessionError::UnknownPeer(peer.to_owned()))?;
        let session = state
            .session
            .as_mut()
            .ok_or_else(|| SessionError::NoSession(peer.to_owned()))?;
        let message = session
            .encrypt(plaintext)
            .map_err(|error| SessionError::Olm(error.to_string()))?;
        Ok(encode_frame(&message))
    }

    /// Decrypt a frame that arrived on the channel belonging to `peer`.
    ///
    /// `peer` is the channel's owner, and it — not anything in the message — is
    /// what ends up in [`Decrypted::authenticated_sender`]. A pre-key message is
    /// additionally checked against the peer's verified Curve25519 identity key,
    /// so a frame that decrypts is a frame from that device.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::UnknownPeer`] for a peer with no verified keys,
    /// [`SessionError::Frame`] or [`SessionError::UnsupportedFrameVersion`] for
    /// a frame this build cannot read, [`SessionError::NoSession`] for a normal
    /// message with no session to read it with, and
    /// [`SessionError::SessionLost`] when the session can no longer decrypt what
    /// is arriving.
    pub fn decrypt(&mut self, peer: &str, frame: &[u8]) -> Result<Decrypted, SessionError> {
        // The peer check comes first deliberately. A frame from a device this
        // layer holds no verified keys for is refused without parsing a byte of
        // it: the bytes are attacker-controlled, the answer cannot change, and
        // "unknown peer" is what the ledger should say rather than whatever the
        // frame happened to malform into.
        if !self.peers.contains_key(peer) {
            return Err(SessionError::UnknownPeer(peer.to_owned()));
        }
        let message = decode_frame(frame)?;
        let state = self
            .peers
            .get_mut(peer)
            .ok_or_else(|| SessionError::UnknownPeer(peer.to_owned()))?;

        match message {
            OlmMessage::PreKey(pre_key) => {
                // A pre-key message for the session we already hold is just an
                // ordinary message the peer sent before its first ratchet step.
                let matches_current = state
                    .session
                    .as_ref()
                    .is_some_and(|session| session.session_id() == pre_key.session_id());

                if matches_current {
                    let session = state
                        .session
                        .as_mut()
                        .ok_or_else(|| SessionError::NoSession(peer.to_owned()))?;
                    let plaintext = session
                        .decrypt(&OlmMessage::PreKey(pre_key))
                        .map_err(|error| lost(peer, &error))?;
                    return Ok(Decrypted {
                        authenticated_sender: peer.to_owned(),
                        plaintext,
                        new_session: false,
                    });
                }

                // A different session: the peer opened a new one. Passing the
                // *verified* identity key means vodozemac rejects a message
                // whose embedded key disagrees with what the family vouched
                // for, rather than trusting the message's own claim.
                let result = self
                    .account
                    .create_inbound_session(
                        SessionConfig::default(),
                        state.keys.curve25519,
                        &pre_key,
                    )
                    .map_err(|error| SessionError::Olm(error.to_string()))?;
                state.session = Some(result.session);
                Ok(Decrypted {
                    authenticated_sender: peer.to_owned(),
                    plaintext: result.plaintext,
                    new_session: true,
                })
            }
            OlmMessage::Normal(normal) => {
                let session = state
                    .session
                    .as_mut()
                    .ok_or_else(|| SessionError::NoSession(peer.to_owned()))?;
                let plaintext = session
                    .decrypt(&OlmMessage::Normal(normal))
                    .map_err(|error| lost(peer, &error))?;
                Ok(Decrypted {
                    authenticated_sender: peer.to_owned(),
                    plaintext,
                    new_session: false,
                })
            }
        }
    }

    /// The account, for [`crate::session_store`] to pickle.
    pub(crate) fn account(&self) -> &Account {
        &self.account
    }

    /// The sessions and verified keys, for [`crate::session_store`] to pickle.
    pub(crate) fn peer_states(&self) -> impl Iterator<Item = (&str, &PeerKeys, Option<&Session>)> {
        self.peers
            .iter()
            .map(|(id, state)| (id.as_str(), &state.keys, state.session.as_ref()))
    }

    /// Restore one peer's keys and session together.
    pub(crate) fn restore_peer(&mut self, keys: PeerKeys, session: Option<Session>) {
        let device_id = keys.device_id.clone();
        self.peers.insert(device_id, PeerState { keys, session });
    }
}

/// Map a decryption failure onto the one thing the caller can act on.
///
/// `MissingMessageKey` and `TooBigMessageGap` are the two the lossy transport
/// produces, and both mean the same thing to a caller: this session is finished,
/// open a new one. Everything else — a bad MAC, bad padding — is a corrupt or
/// forged frame, and is reported as such rather than being dressed up as loss.
fn lost(peer: &str, error: &vodozemac::olm::DecryptionError) -> SessionError {
    match error {
        vodozemac::olm::DecryptionError::MissingMessageKey(_)
        | vodozemac::olm::DecryptionError::TooBigMessageGap(_, _) => SessionError::SessionLost {
            peer: peer.to_owned(),
            detail: error.to_string(),
        },
        other => SessionError::Olm(other.to_string()),
    }
}

/// Wrap an Olm message as a frame: version, message type, then Olm's bytes.
fn encode_frame(message: &OlmMessage) -> Vec<u8> {
    let (message_type, ciphertext) = message.to_parts();
    let mut frame = Vec::with_capacity(ciphertext.len() + 2);
    frame.push(FRAME_VERSION);
    // Olm's type is 0 or 1 and nothing else exists to widen it to.
    frame.push(u8::try_from(message_type).unwrap_or(u8::MAX));
    frame.extend_from_slice(&ciphertext);
    frame
}

fn decode_frame(frame: &[u8]) -> Result<OlmMessage, SessionError> {
    let (&version, rest) = frame
        .split_first()
        .ok_or_else(|| SessionError::Frame("empty frame".to_owned()))?;
    if version != FRAME_VERSION {
        return Err(SessionError::UnsupportedFrameVersion(version));
    }
    let (&message_type, ciphertext) = rest
        .split_first()
        .ok_or_else(|| SessionError::Frame("frame has no message type".to_owned()))?;
    OlmMessage::from_parts(usize::from(message_type), ciphertext)
        .map_err(|error| SessionError::Frame(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityKey;

    /// Two devices that have verified each other's bundles, which is the state
    /// the roster layer hands this layer.
    struct Pair {
        a: SessionManager,
        b: SessionManager,
    }

    fn pair() -> Pair {
        let mut a = SessionManager::create("dev_A", IdentityKey::from_seed(&[1u8; 32]));
        let mut b = SessionManager::create("dev_B", IdentityKey::from_seed(&[2u8; 32]));

        let a_bundle = a.publish_bundle("2026-07-26T10:00:00Z").expect("bundle");
        let b_bundle = b.publish_bundle("2026-07-26T10:00:00Z").expect("bundle");

        let a_keys = a_bundle
            .verify("dev_A", a.identity_public_key())
            .expect("verifies");
        let b_keys = b_bundle
            .verify("dev_B", b.identity_public_key())
            .expect("verifies");

        a.learn_peer(b_keys);
        b.learn_peer(a_keys);
        Pair { a, b }
    }

    #[test]
    fn a_message_round_trips_and_names_its_sender() {
        let mut p = pair();
        let frame = p.a.encrypt("dev_B", b"envelope-1").expect("encrypts");
        let got = p.b.decrypt("dev_A", &frame).expect("decrypts");

        assert_eq!(got.plaintext, b"envelope-1");
        assert_eq!(
            got.authenticated_sender, "dev_A",
            "the channel's owner, not anything in the message"
        );
        assert!(got.new_session, "the first message establishes the session");
    }

    #[test]
    fn the_session_survives_into_a_two_way_conversation() {
        let mut p = pair();
        let frame = p.a.encrypt("dev_B", b"hello").expect("encrypts");
        p.b.decrypt("dev_A", &frame).expect("decrypts");

        // B can now reply on the session it just learned, and A ratchets on.
        let reply = p.b.encrypt("dev_A", b"hello back").expect("encrypts");
        let got = p.a.decrypt("dev_B", &reply).expect("decrypts");
        assert_eq!(got.plaintext, b"hello back");
        assert!(!got.new_session);

        let third = p.a.encrypt("dev_B", b"still here").expect("encrypts");
        assert_eq!(
            p.b.decrypt("dev_A", &third).expect("decrypts").plaintext,
            b"still here"
        );
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let mut p = pair();
        let frame = p.a.encrypt("dev_B", b"57.7089,11.9746").expect("encrypts");
        let haystack = String::from_utf8_lossy(&frame);
        assert!(!haystack.contains("57.7089"));
    }

    #[test]
    fn out_of_order_delivery_still_decrypts() {
        // The property Noise could not give us. Per-channel order holds at the
        // relay, but redelivery and the outbox make local reordering real.
        let mut p = pair();
        let first = p.a.encrypt("dev_B", b"one").expect("encrypts");
        let second = p.a.encrypt("dev_B", b"two").expect("encrypts");
        let third = p.a.encrypt("dev_B", b"three").expect("encrypts");

        assert_eq!(
            p.b.decrypt("dev_A", &third).expect("decrypts").plaintext,
            b"three"
        );
        assert_eq!(
            p.b.decrypt("dev_A", &first).expect("decrypts").plaintext,
            b"one"
        );
        assert_eq!(
            p.b.decrypt("dev_A", &second).expect("decrypts").plaintext,
            b"two"
        );
    }

    #[test]
    fn a_dropped_message_does_not_break_the_ones_after_it() {
        // Short TTLs mean expiry is routine; the receiver must not care.
        let mut p = pair();
        let _expired = p.a.encrypt("dev_B", b"stale location").expect("encrypts");
        let arrives = p.a.encrypt("dev_B", b"fresh location").expect("encrypts");

        assert_eq!(
            p.b.decrypt("dev_A", &arrives).expect("decrypts").plaintext,
            b"fresh location"
        );
    }

    #[test]
    fn many_dropped_messages_do_not_break_the_next_one() {
        // Well past the 40-key skip window and well inside the 2000 ceiling.
        let mut p = pair();
        for _ in 0..500 {
            let _dropped = p.a.encrypt("dev_B", b"dropped").expect("encrypts");
        }
        let arrives = p.a.encrypt("dev_B", b"arrives").expect("encrypts");
        assert_eq!(
            p.b.decrypt("dev_A", &arrives).expect("decrypts").plaintext,
            b"arrives"
        );
    }

    #[test]
    fn a_gap_over_vodozemacs_ceiling_reports_a_lost_session() {
        // The one bound that is reachable in production: >2000 messages while
        // the peer is away. It must be a named, actionable outcome rather than
        // an opaque failure.
        let mut p = pair();
        let opener =
            p.a.encrypt("dev_B", b"opens the session")
                .expect("encrypts");
        p.b.decrypt("dev_A", &opener).expect("decrypts");

        for _ in 0..2100 {
            let _dropped = p.a.encrypt("dev_B", b"dropped").expect("encrypts");
        }
        let arrives = p.a.encrypt("dev_B", b"too far ahead").expect("encrypts");

        match p.b.decrypt("dev_A", &arrives) {
            Err(SessionError::SessionLost { peer, .. }) => assert_eq!(peer, "dev_A"),
            other => panic!("expected SessionLost, got {other:?}"),
        }
    }

    #[test]
    fn a_replayed_message_is_refused() {
        let mut p = pair();
        let opener = p.a.encrypt("dev_B", b"opens").expect("encrypts");
        p.b.decrypt("dev_A", &opener).expect("decrypts");

        let once = p.a.encrypt("dev_B", b"only once").expect("encrypts");
        assert_eq!(
            p.b.decrypt("dev_A", &once).expect("decrypts").plaintext,
            b"only once"
        );
        assert!(
            p.b.decrypt("dev_A", &once).is_err(),
            "the message key is consumed; a replay must not decrypt again"
        );
    }

    #[test]
    fn a_frame_from_a_third_party_does_not_decrypt() {
        let mut p = pair();
        let mut outsider = SessionManager::create("dev_X", IdentityKey::from_seed(&[9u8; 32]));
        let b_bundle = p.b.publish_bundle("2026-07-26T10:00:00Z").expect("bundle");
        let b_keys = b_bundle
            .verify("dev_B", p.b.identity_public_key())
            .expect("verifies");
        outsider.learn_peer(b_keys);

        // The outsider can encrypt to B — B publishes a bundle — but B attributes
        // channels to peers, and the outsider has no channel. Replayed onto A's
        // channel, the frame is from the wrong Curve25519 identity and Olm
        // refuses it.
        let frame = outsider.encrypt("dev_B", b"not from A").expect("encrypts");
        assert!(
            p.b.decrypt("dev_A", &frame).is_err(),
            "a frame injected onto another peer's channel must not decrypt"
        );
    }

    #[test]
    fn an_unknown_peer_cannot_be_addressed_or_attributed() {
        let mut p = pair();
        assert_eq!(
            p.a.encrypt("dev_NOBODY", b"x"),
            Err(SessionError::UnknownPeer("dev_NOBODY".to_owned()))
        );
        assert_eq!(
            p.a.decrypt("dev_NOBODY", &[FRAME_VERSION, 1, 0, 0]),
            Err(SessionError::UnknownPeer("dev_NOBODY".to_owned()))
        );
    }

    #[test]
    fn a_normal_message_with_no_session_is_distinguishable_from_corruption() {
        // What a reinstall looks like from the other side: the peer is
        // ratcheting a session we no longer hold.
        //
        // Getting a *normal* message out of A takes a full round trip — Olm
        // keeps repeating the pre-key message until it has heard back, which is
        // what makes an initial message survive a lost first attempt.
        let mut p = pair();
        let opener = p.a.encrypt("dev_B", b"opens").expect("encrypts");
        p.b.decrypt("dev_A", &opener).expect("decrypts");
        let reply = p.b.encrypt("dev_A", b"heard you").expect("encrypts");
        p.a.decrypt("dev_B", &reply).expect("decrypts");

        let normal = p.a.encrypt("dev_B", b"ordinary").expect("encrypts");
        assert_eq!(normal[1], 1, "precondition: a normal, non-pre-key message");

        // B reinstalls: new account, but it re-verifies A's bundle.
        let mut fresh = SessionManager::create("dev_B", IdentityKey::from_seed(&[2u8; 32]));
        let a_bundle = p.a.publish_bundle("2026-07-26T11:00:00Z").expect("bundle");
        let a_keys = a_bundle
            .verify("dev_A", p.a.identity_public_key())
            .expect("verifies");
        fresh.learn_peer(a_keys);

        assert_eq!(
            fresh.decrypt("dev_A", &normal),
            Err(SessionError::NoSession("dev_A".to_owned()))
        );
    }

    #[test]
    fn a_peer_that_reinstalls_can_re_establish_over_the_top() {
        let mut p = pair();
        let opener = p.a.encrypt("dev_B", b"before").expect("encrypts");
        p.b.decrypt("dev_A", &opener).expect("decrypts");

        // A reinstalls, keeping its identity key (the roster still vouches for
        // it) but with a fresh Olm account.
        let mut a2 = SessionManager::create("dev_A", IdentityKey::from_seed(&[1u8; 32]));
        let b_bundle = p.b.publish_bundle("2026-07-26T11:00:00Z").expect("bundle");
        let b_keys = b_bundle
            .verify("dev_B", p.b.identity_public_key())
            .expect("verifies");
        a2.learn_peer(b_keys);

        // B must re-learn A's new key material; until it does, the new pre-key
        // message is from an identity key B does not expect.
        let a2_bundle = a2.publish_bundle("2026-07-26T11:00:00Z").expect("bundle");
        let a2_keys = a2_bundle
            .verify("dev_A", a2.identity_public_key())
            .expect("verifies");
        p.b.learn_peer(a2_keys);

        let after = a2.encrypt("dev_B", b"after").expect("encrypts");
        let got = p.b.decrypt("dev_A", &after).expect("decrypts");
        assert_eq!(got.plaintext, b"after");
        assert!(got.new_session, "a reinstall is a visible new session");
    }

    #[test]
    fn re_learning_a_peer_with_new_key_material_drops_the_session() {
        let mut p = pair();
        let opener = p.a.encrypt("dev_B", b"opens").expect("encrypts");
        p.b.decrypt("dev_A", &opener).expect("decrypts");
        assert!(p.b.has_session("dev_A"));

        let mut reinstalled = SessionManager::create("dev_A", IdentityKey::from_seed(&[1u8; 32]));
        let bundle = reinstalled
            .publish_bundle("2026-07-26T11:00:00Z")
            .expect("bundle");
        let keys = bundle
            .verify("dev_A", reinstalled.identity_public_key())
            .expect("verifies");
        p.b.learn_peer(keys);
        assert!(
            !p.b.has_session("dev_A"),
            "a changed Curve25519 identity invalidates the session"
        );
    }

    #[test]
    fn a_refreshed_bundle_from_the_same_device_keeps_the_session() {
        // A fallback rotation must not cost every peer a re-pair.
        let mut p = pair();
        let opener = p.a.encrypt("dev_B", b"opens").expect("encrypts");
        p.b.decrypt("dev_A", &opener).expect("decrypts");

        let rotated =
            p.a.rotate_fallback_key("2026-08-02T10:00:00Z")
                .expect("rotates");
        let keys = rotated
            .verify("dev_A", p.a.identity_public_key())
            .expect("verifies");
        p.b.learn_peer(keys);

        assert!(p.b.has_session("dev_A"));
        let next = p.a.encrypt("dev_B", b"after rotation").expect("encrypts");
        assert_eq!(
            p.b.decrypt("dev_A", &next).expect("decrypts").plaintext,
            b"after rotation"
        );
    }

    #[test]
    fn an_initial_message_to_the_previous_fallback_key_still_decrypts() {
        // The overlap FALLBACK_KEY_LIFETIME exists for: a peer fetched the old
        // bundle just before rotation and sends afterwards.
        let mut p = pair();
        let stale =
            p.a.encrypt("dev_B", b"encrypted to the old key")
                .expect("encrypts");

        p.b.rotate_fallback_key("2026-08-02T10:00:00Z")
            .expect("rotates");

        assert_eq!(
            p.b.decrypt("dev_A", &stale).expect("decrypts").plaintext,
            b"encrypted to the old key"
        );
    }

    #[test]
    fn forgetting_the_previous_fallback_key_closes_the_window() {
        let mut p = pair();
        let stale = p.a.encrypt("dev_B", b"to the old key").expect("encrypts");

        p.b.rotate_fallback_key("2026-08-02T10:00:00Z")
            .expect("rotates");
        assert!(p.b.forget_previous_fallback_key());

        assert!(
            p.b.decrypt("dev_A", &stale).is_err(),
            "the old key is gone, so the initial message is lost — the documented cost"
        );
    }

    #[test]
    fn forgetting_a_peer_removes_keys_and_session() {
        let mut p = pair();
        let opener = p.a.encrypt("dev_B", b"opens").expect("encrypts");
        p.b.decrypt("dev_A", &opener).expect("decrypts");

        assert!(p.b.forget_peer("dev_A"));
        assert!(!p.b.has_session("dev_A"));
        assert_eq!(p.b.known_peers(), Vec::<&str>::new());
        assert!(!p.b.forget_peer("dev_A"), "idempotent");
    }

    #[test]
    fn the_frame_carries_its_version_and_olm_type() {
        let mut p = pair();
        let frame = p.a.encrypt("dev_B", b"x").expect("encrypts");
        assert_eq!(frame[0], FRAME_VERSION);
        assert_eq!(frame[1], 0, "the first message is a pre-key message");

        p.b.decrypt("dev_A", &frame).expect("decrypts");
        let reply = p.b.encrypt("dev_A", b"y").expect("encrypts");
        assert_eq!(reply[1], 1, "an established session sends normal messages");
    }

    #[test]
    fn a_frame_from_the_future_is_refused_by_version_not_misread() {
        let mut p = pair();
        let mut frame = p.a.encrypt("dev_B", b"x").expect("encrypts");
        frame[0] = FRAME_VERSION + 1;
        assert_eq!(
            p.b.decrypt("dev_A", &frame),
            Err(SessionError::UnsupportedFrameVersion(FRAME_VERSION + 1))
        );
    }

    #[test]
    fn truncated_frames_are_refused_cleanly() {
        let mut p = pair();
        assert!(matches!(
            p.b.decrypt("dev_A", &[]),
            Err(SessionError::Frame(_))
        ));
        assert!(matches!(
            p.b.decrypt("dev_A", &[FRAME_VERSION]),
            Err(SessionError::Frame(_))
        ));
        assert!(
            matches!(
                p.b.decrypt("dev_A", &[FRAME_VERSION, 7, 1, 2, 3]),
                Err(SessionError::Frame(_))
            ),
            "7 is not an Olm message type"
        );
    }

    #[test]
    fn a_corrupted_ciphertext_is_not_reported_as_loss() {
        // A bad MAC is a forged or damaged frame, not a session that needs
        // re-establishing. Conflating them would send clients into a
        // re-pair loop on a flipped bit.
        let mut p = pair();
        let mut frame = p.a.encrypt("dev_B", b"tampered").expect("encrypts");
        let last = frame.len() - 1;
        frame[last] ^= 0xff;

        match p.b.decrypt("dev_A", &frame) {
            Err(SessionError::Olm(_)) | Err(SessionError::Frame(_)) => {}
            other => panic!("expected a plain Olm/Frame error, got {other:?}"),
        }
    }

    #[test]
    fn the_debug_impl_does_not_print_key_material() {
        let p = pair();
        let rendered = format!("{:?}", p.a);
        assert!(rendered.contains("dev_A"));
        assert!(rendered.contains("dev_B"), "peers are listed by id");
        assert!(
            !rendered.to_lowercase().contains("secret"),
            "no private key material: {rendered}"
        );
    }

    #[test]
    fn the_fallback_lifetime_matches_sunds_maximum_ttl() {
        // If Sund ever changes its clamp, this is the assertion that says the
        // rotation period has to move with it.
        assert_eq!(FALLBACK_KEY_LIFETIME, Duration::from_secs(7 * 24 * 60 * 60));
    }
}
