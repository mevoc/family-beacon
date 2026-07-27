//! The error enum, as the app switches on it.

/// What a call on [`crate::BeaconClient`] can fail with.
///
/// A mirror of `beacon_client::ClientError`. The conversion below is a total
/// match, so a variant added there is a compile error here rather than a variant
/// the app silently never sees.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum ClientException {
    /// **The server's identity could not be verified.**
    ///
    /// The one error in the app whose wording is a security property. Render it
    /// as "this is not the server you paired with" — never as a connectivity
    /// problem, never with a retry button, and never with a way to continue
    /// anyway. Reporting a pin mismatch as a network blip makes an intercepting
    /// network indistinguishable from an absent one, which the pinning contract
    /// (§8.3) forbids.
    ///
    /// It is a distinct variant precisely so this check is `is ServerIdentity`
    /// in Kotlin rather than a match on a message somebody later rephrases.
    ServerIdentity {
        /// What the TLS layer reported.
        detail: String,
    },
    /// The server could not be reached. The ordinary offline case: retry.
    Network {
        /// What the transport reported.
        detail: String,
    },
    /// The server did not accept this device — including a spent, expired or
    /// revoked invitation. Sund answers all of these with one status by design.
    Unauthorized,
    /// The device, invitation, bundle or queue is gone, or was never visible to
    /// this caller.
    NotFound,
    /// The server took the request and declined it.
    ServerRefused {
        /// The server's own message.
        detail: String,
    },
    /// The server answered with something the client could not read. Means the
    /// app and the server have drifted, not that the user did anything.
    Protocol {
        /// What did not parse.
        detail: String,
    },
    /// The address is not a Sund address. A hard rejection with nothing to
    /// repair and no "trust anyway".
    Address {
        /// Why it was refused.
        detail: String,
    },
    /// Stored state could not be read: an unknown version, a truncated blob, or
    /// state belonging to another device.
    State {
        /// What was wrong with it.
        detail: String,
    },
    /// Session state could not be opened — typically the wrong seeds.
    Session {
        /// What the session layer reported.
        detail: String,
    },
    /// The membership layer refused.
    Roster {
        /// Why, in terms that can be shown.
        detail: String,
    },
    /// The transport refused: an unknown or retired channel.
    Transport {
        /// What the transport reported.
        detail: String,
    },
    /// No secure random source. Fatal: there is nothing weaker to fall back to.
    Rng {
        /// What the platform reported.
        detail: String,
    },
}

impl std::fmt::Display for ClientException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately delegated rather than rewritten: the sentences are
        // `beacon-client`'s, and two copies of the pin-mismatch wording is one
        // copy too many.
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

impl std::error::Error for ClientException {}

impl From<beacon_client::ClientError> for ClientException {
    fn from(error: beacon_client::ClientError) -> Self {
        use beacon_client::ClientError as E;
        match error {
            E::ServerIdentity { detail } => Self::ServerIdentity { detail },
            E::Network { detail } => Self::Network { detail },
            E::Unauthorized => Self::Unauthorized,
            E::NotFound => Self::NotFound,
            E::ServerRefused { detail } => Self::ServerRefused { detail },
            E::Protocol { detail } => Self::Protocol { detail },
            E::Address { detail } => Self::Address { detail },
            E::State { detail } => Self::State { detail },
            E::Session { detail } => Self::Session { detail },
            E::Roster { detail } => Self::Roster { detail },
            E::Transport { detail } => Self::Transport { detail },
            E::Rng { detail } => Self::Rng { detail },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use beacon_client::ClientError;

    #[test]
    fn a_pin_mismatch_stays_its_own_variant_across_the_boundary() {
        // The contract requirement, asserted at the last place it could be lost.
        // `beacon-client` keeps the distinction; this is where it would quietly
        // collapse into "network" if someone simplified the enum for the
        // bindings' sake.
        let crossed = ClientException::from(ClientError::ServerIdentity {
            detail: "pin mismatch".to_owned(),
        });

        assert!(
            matches!(crossed, ClientException::ServerIdentity { .. }),
            "{crossed:?}"
        );
        assert!(
            crossed
                .to_string()
                .contains("not the server you paired with"),
            "{crossed}"
        );
    }

    #[test]
    fn network_and_identity_failures_do_not_read_alike() {
        let network = ClientException::from(ClientError::Network {
            detail: "timeout".to_owned(),
        })
        .to_string();
        let identity = ClientException::from(ClientError::ServerIdentity {
            detail: "timeout".to_owned(),
        })
        .to_string();

        assert_ne!(network, identity);
        assert!(!identity.contains("could not be reached"), "{identity}");
    }
}
