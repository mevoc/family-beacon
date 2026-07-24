//! Server addresses, and the trust mode each one fixes.
//!
//! Normative source: `../../sund/docs/Sund-Pinning-Contract.md` §1 (pinned
//! mode) and §8.1 (WebPKI mode). Two forms exist and a client must implement
//! both:
//!
//! ```text
//! sund://<host>:<port>#<64 lowercase hex>     pinned    — identity is the key
//! sund+webpki://<host>[:<port>]               WebPKI    — identity is the name
//! ```
//!
//! Parsing here is deliberately unforgiving, because the contract's central
//! argument is that the mode must be *stated, never inferred* (§8.1): an
//! attacker who strips the fragment from a pinned address would otherwise
//! silently downgrade a family to "any public CA will do", a downgrade achieved
//! by deletion — the cheapest possible edit. So a `sund://` address without a
//! well-formed fragment is malformed rather than "probably WebPKI", and no
//! edit turns one scheme into the other.
//!
//! What this module does *not* do is decide when an address may replace
//! another. A pin change (§5) and a mode change (§8.5) are both re-pairing
//! events that need a human to re-verify, and that decision belongs to the
//! layer holding the account, not to a parser.

use std::fmt;
use std::net::IpAddr;

/// How a client verifies the server's identity, per the address it was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustMode {
    /// Pinned mode: verify the presented chain against a pinned CA public key,
    /// with no CA store and no hostname check. The 32 bytes are the SHA-256 of
    /// the offline CA's DER `SubjectPublicKeyInfo` (§2).
    Pinned {
        /// The pinned SPKI digest.
        fingerprint: [u8; 32],
    },
    /// WebPKI mode: the platform's ordinary TLS verification, unmodified, with
    /// the hostname as the identity (§8.2).
    WebPki,
}

/// A parsed, validated Sund server address.
///
/// Store the whole value durably against the account (§1, §8.1): the mode is
/// part of the server's identity, not a connection-time detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAddress {
    mode: TrustMode,
    host: String,
    port: u16,
}

/// Why an address string was refused.
///
/// Every variant is a hard rejection. The contract has no repairable-address
/// case and no "trust anyway" affordance (§6, §8.3), so there is deliberately
/// nothing here that a caller could act on except showing the user that the
/// address is not a Sund address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// Neither `sund://` nor `sund+webpki://`.
    UnknownScheme,
    /// The host part is empty, or contains something that cannot be a host.
    InvalidHost,
    /// The port is missing (pinned mode requires it) or is not a number.
    InvalidPort,
    /// A `sund://` address with no fragment, or one that is not 64 lowercase
    /// hex characters. Never treated as a WebPKI address — see §8.1.
    InvalidFingerprint,
    /// A `sund+webpki://` address carrying a fragment (§8.1).
    UnexpectedFingerprint,
    /// A `sund+webpki://` address whose host is an IP literal (§8.1): in this
    /// mode the name *is* the identity, and there is nothing to verify a
    /// certificate against.
    IpLiteralNotAllowed,
    /// Anything after the authority — a path, query or userinfo. A Sund address
    /// is an authority and nothing else.
    TrailingGarbage,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::UnknownScheme => "not a sund:// or sund+webpki:// address",
            Self::InvalidHost => "invalid host",
            Self::InvalidPort => "missing or invalid port",
            Self::InvalidFingerprint => {
                "a sund:// address needs a #fingerprint of 64 lowercase hex characters"
            }
            Self::UnexpectedFingerprint => "a sund+webpki:// address must not carry a fragment",
            Self::IpLiteralNotAllowed => "a sund+webpki:// address must name a host, not an IP",
            Self::TrailingGarbage => "a server address is a host and port, nothing more",
        };
        f.write_str(text)
    }
}

impl std::error::Error for AddressError {}

/// The default port for WebPKI mode (§8.1). Pinned mode has no default.
const WEBPKI_DEFAULT_PORT: u16 = 443;

const PINNED_SCHEME: &str = "sund://";
const WEBPKI_SCHEME: &str = "sund+webpki://";

impl ServerAddress {
    /// Parse an address in either form.
    ///
    /// # Errors
    ///
    /// Returns an [`AddressError`] for anything that is not exactly one of the
    /// two documented forms. There is no lenient path: see the module docs.
    pub fn parse(input: &str) -> Result<Self, AddressError> {
        let trimmed = input.trim();
        // Schemes are case-insensitive per RFC 3986; the fingerprint is not
        // (§1 requires lowercase hex), so only the scheme is folded.
        let lowered = trimmed.to_ascii_lowercase();

        if let Some(rest) = lowered.strip_prefix(WEBPKI_SCHEME) {
            let rest = &trimmed[trimmed.len() - rest.len()..];
            return Self::parse_webpki(rest);
        }
        if let Some(rest) = lowered.strip_prefix(PINNED_SCHEME) {
            let rest = &trimmed[trimmed.len() - rest.len()..];
            return Self::parse_pinned(rest);
        }
        Err(AddressError::UnknownScheme)
    }

    fn parse_pinned(rest: &str) -> Result<Self, AddressError> {
        let (authority, fragment) = match rest.split_once('#') {
            Some((authority, fragment)) => (authority, fragment),
            // Fails closed: no fragment is malformed, not "WebPKI by omission".
            None => return Err(AddressError::InvalidFingerprint),
        };
        let fingerprint = parse_fingerprint(fragment)?;
        let (host, port) = split_authority(authority)?;
        let port = port.ok_or(AddressError::InvalidPort)?;
        Ok(Self {
            mode: TrustMode::Pinned { fingerprint },
            host,
            port,
        })
    }

    fn parse_webpki(rest: &str) -> Result<Self, AddressError> {
        if rest.contains('#') {
            return Err(AddressError::UnexpectedFingerprint);
        }
        let (host, port) = split_authority(rest)?;
        if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
            return Err(AddressError::IpLiteralNotAllowed);
        }
        Ok(Self {
            mode: TrustMode::WebPki,
            host,
            port: port.unwrap_or(WEBPKI_DEFAULT_PORT),
        })
    }

    /// The trust mode this address fixes.
    #[must_use]
    pub fn mode(&self) -> &TrustMode {
        &self.mode
    }

    /// The host to connect to. In pinned mode it is only *where* the server is
    /// and carries no identity (§1); in WebPKI mode it is the identity (§8.1).
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The TCP port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `https://host:port`, the origin every request path is appended to.
    ///
    /// Always HTTPS: a client may not connect over plain HTTP in either mode,
    /// and may not fall back to it if TLS fails (§8.3).
    #[must_use]
    pub fn origin(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("https://{host}:{}", self.port)
    }
}

impl fmt::Display for ServerAddress {
    /// Renders the canonical form, which round-trips through [`ServerAddress::parse`].
    ///
    /// An explicit `:443` in WebPKI mode is not preserved — it is the default
    /// and means the same address.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match &self.mode {
            TrustMode::Pinned { fingerprint } => {
                write!(f, "{PINNED_SCHEME}{host}:{}#", self.port)?;
                for byte in fingerprint {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            TrustMode::WebPki if self.port == WEBPKI_DEFAULT_PORT => {
                write!(f, "{WEBPKI_SCHEME}{host}")
            }
            TrustMode::WebPki => write!(f, "{WEBPKI_SCHEME}{host}:{}", self.port),
        }
    }
}

/// Split `host:port`, `host`, `[v6]:port` or `[v6]` into an unbracketed host
/// and an optional port.
fn split_authority(authority: &str) -> Result<(String, Option<u16>), AddressError> {
    if authority.is_empty() {
        return Err(AddressError::InvalidHost);
    }
    if authority.contains('/') || authority.contains('?') || authority.contains('@') {
        return Err(AddressError::TrailingGarbage);
    }

    let (host, port_text) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or(AddressError::InvalidHost)?;
        if host.parse::<IpAddr>().is_err() {
            return Err(AddressError::InvalidHost);
        }
        match after {
            "" => (host.to_owned(), None),
            _ => (
                host.to_owned(),
                Some(after.strip_prefix(':').ok_or(AddressError::InvalidPort)?),
            ),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host.to_owned(), Some(port)),
            None => (authority.to_owned(), None),
        }
    };

    if host.is_empty() || host.contains(':') && host.parse::<IpAddr>().is_err() {
        return Err(AddressError::InvalidHost);
    }
    let port = match port_text {
        Some(text) => Some(text.parse::<u16>().map_err(|_| AddressError::InvalidPort)?),
        None => None,
    };
    if port == Some(0) {
        return Err(AddressError::InvalidPort);
    }
    Ok((host, port))
}

/// Parse the fragment of a `sund://` address: exactly 64 lowercase hex
/// characters (§1). Uppercase is refused rather than folded, so that two
/// clients cannot disagree about whether two addresses are the same one.
fn parse_fingerprint(fragment: &str) -> Result<[u8; 32], AddressError> {
    if fragment.len() != 64 {
        return Err(AddressError::InvalidFingerprint);
    }
    let mut out = [0u8; 32];
    let bytes = fragment.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_value(bytes[i * 2]).ok_or(AddressError::InvalidFingerprint)?;
        let lo = hex_value(bytes[i * 2 + 1]).ok_or(AddressError::InvalidFingerprint)?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "9d4f2a1b3c5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";

    fn pinned(text: &str) -> Result<ServerAddress, AddressError> {
        ServerAddress::parse(text)
    }

    #[test]
    fn a_pinned_address_parses_into_host_port_and_pin() {
        let addr = pinned(&format!("sund://beacon.lan:5870#{FP}")).expect("parse");
        assert_eq!(addr.host(), "beacon.lan");
        assert_eq!(addr.port(), 5870);
        assert_eq!(addr.origin(), "https://beacon.lan:5870");
        let TrustMode::Pinned { fingerprint } = addr.mode() else {
            panic!("expected pinned mode");
        };
        assert_eq!(fingerprint[0], 0x9d);
        assert_eq!(fingerprint[31], 0xf8);
    }

    #[test]
    fn a_pinned_address_without_a_fragment_is_malformed_not_webpki() {
        // The whole argument of §8.1: deleting the fragment must not downgrade
        // the trust model, it must produce a rejected address.
        assert_eq!(
            pinned("sund://beacon.lan:5870"),
            Err(AddressError::InvalidFingerprint)
        );
    }

    #[test]
    fn a_fingerprint_must_be_64_lowercase_hex_characters() {
        let cases = [
            format!("sund://h:1#{}", &FP[..63]),           // too short
            format!("sund://h:1#{FP}a"),                   // too long
            format!("sund://h:1#{}", FP.to_uppercase()),   // uppercase
            format!("sund://h:1#{}Z", &FP[..63]),          // non-hex
            format!("sund://h:1#{}", FP.replace('9', "")), // short again
        ];
        for case in cases {
            assert_eq!(
                ServerAddress::parse(&case),
                Err(AddressError::InvalidFingerprint),
                "{case} should be refused"
            );
        }
    }

    #[test]
    fn pinned_mode_requires_an_explicit_port() {
        assert_eq!(
            pinned(&format!("sund://beacon.lan#{FP}")),
            Err(AddressError::InvalidPort)
        );
    }

    #[test]
    fn a_webpki_address_defaults_to_443() {
        let addr = ServerAddress::parse("sund+webpki://beacon.example.org").expect("parse");
        assert_eq!(addr.mode(), &TrustMode::WebPki);
        assert_eq!(addr.port(), 443);
        assert_eq!(addr.origin(), "https://beacon.example.org:443");
    }

    #[test]
    fn a_webpki_address_may_not_carry_a_fragment_or_name_an_ip() {
        assert_eq!(
            ServerAddress::parse(&format!("sund+webpki://beacon.example.org#{FP}")),
            Err(AddressError::UnexpectedFingerprint)
        );
        assert_eq!(
            ServerAddress::parse("sund+webpki://192.168.1.10"),
            Err(AddressError::IpLiteralNotAllowed)
        );
        assert_eq!(
            ServerAddress::parse("sund+webpki://[2001:db8::1]:8443"),
            Err(AddressError::IpLiteralNotAllowed)
        );
    }

    #[test]
    fn pinned_mode_accepts_ip_literals_because_identity_is_the_key() {
        let v4 = pinned(&format!("sund://192.168.1.10:5870#{FP}")).expect("v4");
        assert_eq!(v4.host(), "192.168.1.10");
        let v6 = pinned(&format!("sund://[2001:db8::1]:5870#{FP}")).expect("v6");
        assert_eq!(v6.host(), "2001:db8::1");
        assert_eq!(v6.origin(), "https://[2001:db8::1]:5870");
    }

    #[test]
    fn addresses_round_trip_through_display() {
        for text in [
            format!("sund://beacon.lan:5870#{FP}"),
            format!("sund://[2001:db8::1]:5870#{FP}"),
            "sund+webpki://beacon.example.org".to_owned(),
            "sund+webpki://beacon.example.org:8443".to_owned(),
        ] {
            let addr = ServerAddress::parse(&text).expect("parse");
            assert_eq!(addr.to_string(), text);
            assert_eq!(ServerAddress::parse(&addr.to_string()), Ok(addr));
        }
    }

    #[test]
    fn the_two_modes_are_never_the_same_address() {
        // §8.5: a mode change is a re-pairing event, so the values must not
        // compare equal even when they point at the same box.
        let a = pinned(&format!("sund://beacon.example.org:443#{FP}")).expect("pinned");
        let b = ServerAddress::parse("sund+webpki://beacon.example.org").expect("webpki");
        assert_ne!(a, b);
    }

    #[test]
    fn junk_is_refused() {
        let cases = [
            ("https://beacon.example.org", AddressError::UnknownScheme),
            ("sund://", AddressError::InvalidFingerprint),
            ("sund+webpki://", AddressError::InvalidHost),
            (
                "sund+webpki://beacon.example.org/v1/devices",
                AddressError::TrailingGarbage,
            ),
            (
                "sund+webpki://user@beacon.example.org",
                AddressError::TrailingGarbage,
            ),
            (
                "sund+webpki://beacon.example.org:0",
                AddressError::InvalidPort,
            ),
            (
                "sund+webpki://beacon.example.org:99999",
                AddressError::InvalidPort,
            ),
        ];
        for (text, want) in cases {
            assert_eq!(ServerAddress::parse(text), Err(want), "{text}");
        }
    }

    #[test]
    fn the_scheme_is_case_insensitive_and_surrounding_space_is_ignored() {
        // A QR scanner or a hand-typed address may arrive shouted or padded;
        // neither changes which server or which mode is meant.
        let addr = ServerAddress::parse("  SUND+WEBPKI://Beacon.Example.org  ").expect("parse");
        assert_eq!(addr.mode(), &TrustMode::WebPki);
        assert_eq!(addr.host(), "Beacon.Example.org");
    }
}
