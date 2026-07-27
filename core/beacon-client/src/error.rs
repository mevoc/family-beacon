//! One error enum the app can switch on.
//!
//! Each layer below has its own error vocabulary — `SundError`, `HttpError`,
//! `AddressError`, `StoreError`, `SnapshotError`, `SessionError`,
//! `TransportError` — and an app that had to know all seven would end up
//! matching on strings. Mapping them into one enum is the third of the three
//! jobs `docs/FamilyBeacon-AndroidPlan.md` gives this crate.
//!
//! The mapping flattens, but it does not flatten the one distinction that
//! carries a security property. See [`ClientError::ServerIdentity`].

use sund_client::address::AddressError;
use sund_client::client::SundError;
use sund_client::http::HttpError;
use sund_client::session::SessionError;
use sund_client::session_store::StoreError;
use sund_client::transport::TransportError;

/// What a call on [`crate::Client`] can fail with.
///
/// Variants carry named fields rather than positional ones so that adding
/// context later is not a breaking change for the bindings above.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// **The server's identity could not be verified.** A pin mismatch, an
    /// untrusted or expired chain, or a hostname that does not match.
    ///
    /// Never a connectivity failure, never retried, never downgraded, and never
    /// presented as something the user can click past. The UI must say "this is
    /// not the server you paired with"; rendering it as "no connection" makes an
    /// intercepting network indistinguishable from an absent one, which the
    /// pinning contract (§8.3) forbids. It is the only error in the app whose
    /// wording is a security property.
    ServerIdentity {
        /// What the TLS layer reported.
        detail: String,
    },
    /// The server could not be reached, or the connection failed mid-request.
    Network {
        /// What the transport reported.
        detail: String,
    },
    /// The server refused this device: an unknown or revoked device, a stale
    /// timestamp, a bad signature, a replayed nonce, or a spent invitation.
    ///
    /// Sund answers all of these with one status by design, so a prober learns
    /// nothing from which — and neither does this enum.
    Unauthorized,
    /// The device, invitation, bundle or queue is gone, or was never visible to
    /// this caller. The server does not distinguish the two.
    NotFound,
    /// The server took the request and declined it: a rejected body, an
    /// over-size payload, a quota, or any other status.
    ServerRefused {
        /// The server's own message.
        detail: String,
    },
    /// The two repos have drifted: a response that was not what the API
    /// promises. What the tier-2 contract suite exists to catch before a user
    /// does.
    Protocol {
        /// What did not parse.
        detail: String,
    },
    /// The address string is not a Sund address.
    ///
    /// A hard rejection with nothing to act on: the contract has no repairable
    /// address and no "trust anyway" affordance.
    Address {
        /// Why it was refused.
        detail: String,
    },
    /// The state blob could not be read: an unknown version, a truncated blob,
    /// or state belonging to another device.
    State {
        /// What was wrong with it.
        detail: String,
    },
    /// The session layer refused: undecryptable state, a wrong pickle key, key
    /// material that does not parse.
    Session {
        /// What the session layer reported.
        detail: String,
    },
    /// The membership layer refused.
    Roster {
        /// Why, in terms that can be shown.
        detail: String,
    },
    /// The transport port refused: an unknown or retired channel.
    Transport {
        /// What the port reported.
        detail: String,
    },
    /// The platform RNG was unavailable.
    ///
    /// Fatal rather than recoverable: there is no weaker source to fall back to,
    /// and no honest way to continue without one.
    Rng {
        /// What the platform reported.
        detail: String,
    },
}

impl ClientError {
    /// Whether this is a failure to verify the server's identity.
    ///
    /// Exists so the check that decides the wording cannot be written as a
    /// string match on a message that someone later rephrases.
    #[must_use]
    pub fn is_server_identity(&self) -> bool {
        matches!(self, Self::ServerIdentity { .. })
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServerIdentity { detail } => {
                write!(f, "this is not the server you paired with: {detail}")
            }
            Self::Network { detail } => write!(f, "the server could not be reached: {detail}"),
            Self::Unauthorized => f.write_str("the server did not accept this device"),
            Self::NotFound => f.write_str("not found"),
            Self::ServerRefused { detail } => write!(f, "the server refused: {detail}"),
            Self::Protocol { detail } => write!(f, "unexpected response from the server: {detail}"),
            Self::Address { detail } => write!(f, "not a Sund address: {detail}"),
            Self::State { detail } => write!(f, "stored state could not be read: {detail}"),
            Self::Session { detail } => write!(f, "session state: {detail}"),
            Self::Roster { detail } => write!(f, "family membership: {detail}"),
            Self::Transport { detail } => write!(f, "transport: {detail}"),
            Self::Rng { detail } => write!(f, "no secure random source: {detail}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<HttpError> for ClientError {
    fn from(error: HttpError) -> Self {
        match error {
            // The distinction the whole enum exists to preserve.
            HttpError::Tls(detail) => Self::ServerIdentity { detail },
            HttpError::Network(detail) => Self::Network { detail },
            HttpError::Protocol(detail) => Self::Protocol { detail },
        }
    }
}

impl From<SundError> for ClientError {
    fn from(error: SundError) -> Self {
        match error {
            SundError::Http(http) => http.into(),
            SundError::Unauthorized => Self::Unauthorized,
            SundError::NotFound => Self::NotFound,
            SundError::Rejected(detail) => Self::ServerRefused { detail },
            SundError::TooLarge => Self::ServerRefused {
                detail: "the message is over the server's size cap".to_owned(),
            },
            SundError::QuotaExceeded => Self::ServerRefused {
                detail: "the recipient's account is over its storage quota".to_owned(),
            },
            SundError::Status { status, message } => Self::ServerRefused {
                detail: format!("HTTP {status}: {message}"),
            },
            SundError::Malformed(detail) => Self::Protocol { detail },
        }
    }
}

impl From<AddressError> for ClientError {
    fn from(error: AddressError) -> Self {
        Self::Address {
            detail: error.to_string(),
        }
    }
}

impl From<StoreError> for ClientError {
    fn from(error: StoreError) -> Self {
        Self::Session {
            detail: error.to_string(),
        }
    }
}

impl From<SessionError> for ClientError {
    fn from(error: SessionError) -> Self {
        Self::Session {
            detail: error.to_string(),
        }
    }
}

impl From<TransportError> for ClientError {
    fn from(error: TransportError) -> Self {
        Self::Transport {
            detail: error.to_string(),
        }
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(error: serde_json::Error) -> Self {
        Self::State {
            detail: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pin_mismatch_never_becomes_a_connectivity_failure() {
        // The contract requirement of docs/FamilyBeacon-AndroidPlan.md → The API
        // surface, asserted at the one place the mapping happens. If this test
        // ever has to be changed, the pinning contract's §8.3 is what is being
        // changed with it.
        let mapped = ClientError::from(SundError::Http(HttpError::Tls(
            "certificate verification failed".to_owned(),
        )));

        assert!(mapped.is_server_identity(), "{mapped:?}");
        assert!(
            !matches!(mapped, ClientError::Network { .. }),
            "an intercepting network must stay distinguishable from an absent one"
        );
    }

    #[test]
    fn an_unreachable_server_is_a_network_failure_and_nothing_more() {
        let mapped = ClientError::from(SundError::Http(HttpError::Network(
            "connection refused".to_owned(),
        )));

        assert!(matches!(mapped, ClientError::Network { .. }), "{mapped:?}");
        assert!(!mapped.is_server_identity());
    }

    #[test]
    fn the_identity_failure_reads_as_an_identity_failure() {
        // The wording is the security property, so it is asserted rather than
        // left to whoever writes the string next.
        let rendered = ClientError::ServerIdentity {
            detail: "pin mismatch".to_owned(),
        }
        .to_string();

        assert!(
            rendered.contains("not the server you paired with"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("could not be reached"),
            "{rendered}: that sentence belongs to Network"
        );
    }

    #[test]
    fn every_sund_refusal_maps_to_something_a_person_can_be_shown() {
        for error in [
            SundError::Unauthorized,
            SundError::NotFound,
            SundError::TooLarge,
            SundError::QuotaExceeded,
            SundError::Rejected("bad body".to_owned()),
            SundError::Status {
                status: 503,
                message: "unavailable".to_owned(),
            },
            SundError::Malformed("no device_id".to_owned()),
        ] {
            let mapped = ClientError::from(error.clone());
            assert!(
                !mapped.to_string().is_empty(),
                "{error:?} rendered as nothing"
            );
            assert!(
                !mapped.is_server_identity(),
                "{error:?} is not an identity failure"
            );
        }
    }
}
