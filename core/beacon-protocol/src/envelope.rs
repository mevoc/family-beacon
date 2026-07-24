//! The envelope: the unit handed to the session layer for encryption.
//!
//! Specified in `docs/FamilyBeacon-Protocol.md` → Envelope. JSON in v1; a
//! compact binary encoding can come later behind the same field names, which is
//! a decision for this library rather than for any app.

use serde::{Deserialize, Serialize};

/// The envelope version this library speaks.
///
/// `v` bumps only on breaking *envelope* changes. Type-level evolution happens
/// in bodies, additively — unknown body fields are ignored, never errors.
pub const ENVELOPE_VERSION: u8 = 1;

/// A message type from the v1 registry, plus the catch-all that keeps mixed
/// version families working.
///
/// A family is a permanently mixed-version deployment: phones update at
/// different times, so an unrecognised type is an ordinary event, not a fault.
/// It decodes to [`MessageType::Unknown`], which the receive path ledgers and
/// drops rather than rejecting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Position report. Requires an active location grant to the recipient.
    Location,
    /// Battery level and charging state. Requires the battery grant.
    Battery,
    /// Broadcast about the sender's own situation. Reception is mandatory.
    Sos,
    /// Stands down a previous [`MessageType::Sos`] on every device.
    SosClear,
    /// Directed "contact me urgently" nudge. Gated by an inbound allow the
    /// *recipient* holds — see [`crate::consent`].
    Attention,
    /// Geofence crossing, evaluated on the device the fence concerns.
    GeofenceEvent,
    /// Advertises a grant or revocation to the peer whose UI reflects it.
    ConsentUpdate,
    /// Shared configuration under the v1 single-owner conflict model.
    ConfigUpdate,
    /// Self-asserted display labels. Confers no authority.
    MemberInfo,
    /// Signed vouch admitting a device (`FamilyBeacon-Roster.md`).
    RosterIntroduce,
    /// Signed tombstone removing a device.
    RosterRemove,
    /// Periodic full-roster digest for reconciliation.
    RosterSync,
    /// Delivery/seen (and, for attention, suppression and reply) reporting.
    Receipt,
    /// A type this build does not know. Carries the wire string so the ledger
    /// can name it to the user.
    Unknown(String),
}

impl MessageType {
    /// The wire string for this type.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Location => "location",
            Self::Battery => "battery",
            Self::Sos => "sos",
            Self::SosClear => "sos_clear",
            Self::Attention => "attention",
            Self::GeofenceEvent => "geofence_event",
            Self::ConsentUpdate => "consent_update",
            Self::ConfigUpdate => "config_update",
            Self::MemberInfo => "member_info",
            Self::RosterIntroduce => "roster_introduce",
            Self::RosterRemove => "roster_remove",
            Self::RosterSync => "roster_sync",
            Self::Receipt => "receipt",
            Self::Unknown(s) => s,
        }
    }

    /// Whether this build understands the type.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl From<&str> for MessageType {
    fn from(s: &str) -> Self {
        match s {
            "location" => Self::Location,
            "battery" => Self::Battery,
            "sos" => Self::Sos,
            "sos_clear" => Self::SosClear,
            "attention" => Self::Attention,
            "geofence_event" => Self::GeofenceEvent,
            "consent_update" => Self::ConsentUpdate,
            "config_update" => Self::ConfigUpdate,
            "member_info" => Self::MemberInfo,
            "roster_introduce" => Self::RosterIntroduce,
            "roster_remove" => Self::RosterRemove,
            "roster_sync" => Self::RosterSync,
            "receipt" => Self::Receipt,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

impl Serialize for MessageType {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MessageType {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self::from(String::deserialize(d)?.as_str()))
    }
}

/// A decoded envelope.
///
/// The field names are the wire names; `type` is a Rust keyword, hence the
/// rename on [`Envelope::message_type`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Envelope version. See [`ENVELOPE_VERSION`].
    pub v: u8,
    /// Unique per message; the dedupe key under at-least-once delivery.
    pub id: String,
    /// Per-sender, per-pair monotonic counter. Gaps after dedupe mean loss or
    /// expiry, which a receiver may surface as staleness and must never
    /// silently interpolate over.
    pub seq: u64,
    /// The message type.
    #[serde(rename = "type")]
    pub message_type: MessageType,
    /// RFC 3339 instant at which the sender emitted the message.
    pub sent: String,
    /// The sender's Sund device id. Attribution after decryption — never the
    /// source of trust; see [`Envelope::check_sender`].
    pub sender: String,
    /// Type-specific body. Always a JSON object.
    pub body: serde_json::Value,
}

/// Why an envelope was refused.
///
/// Rejection is never silent: every variant reaches the transparency ledger
/// through [`crate::Reception`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// Not parseable as an envelope at all.
    Malformed(String),
    /// A breaking envelope version this build cannot read.
    UnsupportedVersion {
        /// The version found on the wire.
        found: u8,
    },
    /// A required string field was present but empty.
    EmptyField(&'static str),
    /// `body` was not a JSON object.
    BodyNotObject,
    /// `sent` was not a well-formed RFC 3339 instant.
    BadTimestamp(String),
    /// The claimed sender is not the device the session authenticated.
    SenderMismatch {
        /// The `sender` field's claim.
        claimed: String,
        /// The device the session layer actually authenticated.
        authenticated: String,
    },
}

impl std::fmt::Display for RejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "malformed envelope: {detail}"),
            Self::UnsupportedVersion { found } => {
                write!(f, "unsupported envelope version {found}")
            }
            Self::EmptyField(field) => write!(f, "empty required field `{field}`"),
            Self::BodyNotObject => write!(f, "body is not a JSON object"),
            Self::BadTimestamp(value) => write!(f, "`sent` is not RFC 3339: {value}"),
            Self::SenderMismatch {
                claimed,
                authenticated,
            } => write!(
                f,
                "sender `{claimed}` does not match authenticated device `{authenticated}`"
            ),
        }
    }
}

impl std::error::Error for RejectReason {}

impl Envelope {
    /// Encode to the v1 wire form.
    ///
    /// # Errors
    ///
    /// Only if the body contains something `serde_json` cannot serialise, such
    /// as a map with non-string keys.
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Decode and validate, without checking the sender against a session.
    ///
    /// Prefer [`crate::receive`], which pairs every outcome with its ledger
    /// entry. This is the codec half on its own, for callers that already have
    /// the plaintext and their own ledgering.
    ///
    /// # Errors
    ///
    /// Returns the [`RejectReason`] the receiver should ledger.
    pub fn decode(bytes: &[u8]) -> Result<Self, RejectReason> {
        let envelope: Self =
            serde_json::from_slice(bytes).map_err(|e| RejectReason::Malformed(e.to_string()))?;
        envelope.validate()?;
        Ok(envelope)
    }

    /// Check the structural rules that hold for every type.
    ///
    /// # Errors
    ///
    /// Returns the first rule violated.
    pub fn validate(&self) -> Result<(), RejectReason> {
        if self.v != ENVELOPE_VERSION {
            return Err(RejectReason::UnsupportedVersion { found: self.v });
        }
        if self.id.is_empty() {
            return Err(RejectReason::EmptyField("id"));
        }
        if self.sender.is_empty() {
            return Err(RejectReason::EmptyField("sender"));
        }
        if self.message_type.as_str().is_empty() {
            return Err(RejectReason::EmptyField("type"));
        }
        if !is_rfc3339(&self.sent) {
            return Err(RejectReason::BadTimestamp(self.sent.clone()));
        }
        if !self.body.is_object() {
            return Err(RejectReason::BodyNotObject);
        }
        Ok(())
    }

    /// Confirm the claimed sender is the device the session authenticated.
    ///
    /// The `sender` field exists for attribution after decryption, not as the
    /// source of trust: on mismatch the message is rejected and the rejection
    /// is ledgered.
    ///
    /// # Errors
    ///
    /// Returns [`RejectReason::SenderMismatch`] when the two disagree.
    pub fn check_sender(&self, authenticated: &str) -> Result<(), RejectReason> {
        if self.sender == authenticated {
            Ok(())
        } else {
            Err(RejectReason::SenderMismatch {
                claimed: self.sender.clone(),
                authenticated: authenticated.to_owned(),
            })
        }
    }

    /// The same envelope with its body dropped.
    ///
    /// Used for unknown types: the ledger names what arrived, but a body this
    /// build cannot interpret is not retained.
    #[must_use]
    pub fn without_body(mut self) -> Self {
        self.body = serde_json::Value::Object(serde_json::Map::new());
        self
    }
}

/// Shape-check an RFC 3339 instant.
///
/// Deliberately not a full date-time parser: this library holds `sent` as the
/// string it received and never does arithmetic on it. Ordering within a pair
/// comes from `seq`, and clocks belong to the app layer, which owns the
/// platform's time source. What matters here is that a malformed timestamp is
/// caught at the boundary rather than propagating into the ledger and the UI.
fn is_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let digits = |from: usize, len: usize| b[from..from + len].iter().all(u8::is_ascii_digit);
    let num = |from: usize, len: usize| -> u32 { s[from..from + len].parse().unwrap_or(u32::MAX) };

    if !(digits(0, 4) && b[4] == b'-' && digits(5, 2) && b[7] == b'-' && digits(8, 2)) {
        return false;
    }
    if b[10] != b'T' {
        return false;
    }
    if !(digits(11, 2) && b[13] == b':' && digits(14, 2) && b[16] == b':' && digits(17, 2)) {
        return false;
    }
    if !(1..=12).contains(&num(5, 2))
        || !(1..=31).contains(&num(8, 2))
        || num(11, 2) > 23
        || num(14, 2) > 59
        // 60 is a leap second, which RFC 3339 permits.
        || num(17, 2) > 60
    {
        return false;
    }

    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match b.get(i) {
        // Uppercase Z only: the protocol's canonical form, and lowercase would
        // give two encodings of one instant for no benefit.
        Some(b'Z') => i + 1 == b.len(),
        Some(b'+' | b'-') => {
            b.len() == i + 6 && digits(i + 1, 2) && b[i + 3] == b':' && digits(i + 4, 2)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(message_type: MessageType) -> Envelope {
        Envelope {
            v: 1,
            id: "b9f1c2".into(),
            seq: 412,
            message_type,
            sent: "2026-07-19T10:04:12Z".into(),
            sender: "dev_A".into(),
            body: serde_json::json!({ "lat": 56.05, "lon": 12.7 }),
        }
    }

    #[test]
    fn round_trips_through_the_wire_form() {
        let original = envelope(MessageType::Location);
        let bytes = original.encode().expect("encode");
        assert_eq!(Envelope::decode(&bytes).expect("decode"), original);
    }

    #[test]
    fn wire_names_are_stable() {
        let bytes = envelope(MessageType::GeofenceEvent)
            .encode()
            .expect("encode");
        let raw: serde_json::Value = serde_json::from_slice(&bytes).expect("parse");
        assert_eq!(raw["type"], "geofence_event");
        assert_eq!(raw["v"], 1);
        assert_eq!(raw["seq"], 412);
    }

    #[test]
    fn unknown_type_decodes_rather_than_failing() {
        let mut e = envelope(MessageType::Unknown("presence".into()));
        e.body = serde_json::json!({ "state": "home" });
        let decoded = Envelope::decode(&e.encode().expect("encode")).expect("decode");
        assert_eq!(
            decoded.message_type,
            MessageType::Unknown("presence".into())
        );
        assert!(!decoded.message_type.is_known());
    }

    #[test]
    fn unknown_body_fields_are_ignored_not_errors() {
        // Type-level evolution is additive: a v0.2 sender adding a field to a
        // body must not break a v0.1 receiver.
        let raw = br#"{"v":1,"id":"x","seq":1,"type":"battery","sent":"2026-07-19T10:04:12Z",
                       "sender":"dev_A","body":{"level_pct":40,"charging":false,"cycles":88}}"#;
        let decoded = Envelope::decode(raw).expect("decode");
        assert_eq!(decoded.body["cycles"], 88);
    }

    #[test]
    fn future_envelope_version_is_refused() {
        let mut e = envelope(MessageType::Location);
        e.v = 2;
        assert_eq!(
            e.validate(),
            Err(RejectReason::UnsupportedVersion { found: 2 })
        );
    }

    #[test]
    fn sender_must_match_the_authenticated_device() {
        let e = envelope(MessageType::Location);
        assert!(e.check_sender("dev_A").is_ok());
        assert_eq!(
            e.check_sender("dev_B"),
            Err(RejectReason::SenderMismatch {
                claimed: "dev_A".into(),
                authenticated: "dev_B".into(),
            })
        );
    }

    #[test]
    fn body_must_be_an_object() {
        let mut e = envelope(MessageType::Location);
        e.body = serde_json::json!("not an object");
        assert_eq!(e.validate(), Err(RejectReason::BodyNotObject));
    }

    #[test]
    fn timestamps_are_shape_checked() {
        assert!(is_rfc3339("2026-07-19T10:04:12Z"));
        assert!(is_rfc3339("2026-07-19T10:04:12.5Z"));
        assert!(is_rfc3339("2026-07-19T10:04:60Z")); // leap second
        assert!(is_rfc3339("2026-07-19T10:04:12+02:00"));
        assert!(!is_rfc3339("2026-07-19 10:04:12Z"));
        assert!(!is_rfc3339("2026-13-19T10:04:12Z"));
        assert!(!is_rfc3339("2026-07-19T25:04:12Z"));
        assert!(!is_rfc3339("2026-07-19T10:04:12z"));
        assert!(!is_rfc3339("2026-07-19T10:04:12"));
        assert!(!is_rfc3339("2026-07-19T10:04:12.Z"));
        assert!(!is_rfc3339(""));
    }

    #[test]
    fn dropping_the_body_keeps_the_attribution() {
        let stripped = envelope(MessageType::Location).without_body();
        assert_eq!(stripped.sender, "dev_A");
        assert_eq!(stripped.body, serde_json::json!({}));
    }
}
