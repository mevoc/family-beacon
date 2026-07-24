//! The shipping HTTP client: blocking, rustls, both trust modes.
//!
//! This is where `../../sund/docs/Sund-Pinning-Contract.md` stops being a
//! document and becomes code. Two modes, selected by the stored address and
//! never negotiated:
//!
//! - **Pinned (§§1–7)** — [`PinnedVerifier`]. Platform trust is switched off
//!   entirely: no CA store, no hostname check. The presented chain must contain
//!   a certificate whose SPKI SHA-256 equals the pin, and the leaf must chain
//!   to *that* certificate as the sole trust root, within its validity window
//!   and asserting serverAuth.
//! - **WebPKI (§8)** — the platform's ordinary verification, unmodified. The
//!   contract is explicit that the correct implementation here is "the default
//!   TLS client with no options changed", so this mode adds no anchors of its
//!   own and disables nothing.
//!
//! There is no fallback between them, in either direction, and no way to accept
//! a certificate that failed (§6, §8.3). That is not an oversight to be fixed
//! later by a `trust_anyway` flag: certificate errors in WebPKI mode are common
//! enough operationally that any such affordance trains users to click through
//! the one that matters.
//!
//! **Why blocking, and why a custom connector.** The core is driven from
//! outside — WorkManager, BGTask — so it owns no runtime and an async client
//! would buy nothing. ureq supplies HTTP/1.1, connection pooling and timeouts;
//! it does not expose a hook for a custom certificate verifier, so TLS is set
//! up here, through ureq's connector seam, and the rest of HTTP is left to a
//! library that already gets chunked bodies and keep-alive right.

use crate::address::{ServerAddress, TrustMode};
use crate::http::{HttpClient, HttpError, HttpRequest, HttpResponse, Stamp, StampSource};
use crate::rfc3339;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, StreamOwned};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::io::{Read as _, Write as _};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use ureq::unversioned::resolver::DefaultResolver;
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, TcpConnector, Transport,
    TransportAdapter,
};

/// How long a single request may take, end to end.
///
/// Short on purpose: every call this client makes is small, and a client that
/// hangs on a dead server is a client that drains a battery and misses the next
/// scheduled drain.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A blocking HTTP client bound to one Sund server.
///
/// Bound to one address rather than taking one per call, so that the trust mode
/// cannot be forgotten on a single request. Cheap to clone.
#[derive(Clone)]
pub struct HttpAgent {
    agent: ureq::Agent,
    origin: String,
}

impl fmt::Debug for HttpAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpAgent")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl HttpAgent {
    /// Build a client for one server address, in the trust mode that address
    /// fixes.
    ///
    /// # Errors
    ///
    /// Returns [`HttpError::Tls`] if the platform's trust store cannot be read
    /// in WebPKI mode, or if rustls refuses the configuration.
    pub fn new(address: &ServerAddress) -> Result<Self, HttpError> {
        let tls = match address.mode() {
            TrustMode::Pinned { fingerprint } => pinned_config(*fingerprint)?,
            TrustMode::WebPki => webpki_config()?,
        };

        let config = ureq::Agent::config_builder()
            .timeout_global(Some(REQUEST_TIMEOUT))
            // A 4xx is an answer, not a failure to get one: Sund says what it
            // refused and why, and mapping statuses to meaning belongs to
            // `crate::client`, in one place, not to two error paths.
            .http_status_as_error(false)
            // Sund answers every request itself; a redirect means something is
            // in front of it that we did not agree to follow.
            .max_redirects(0)
            .max_redirects_will_error(true)
            // Belt and braces with `ServerAddress::origin`, which only ever
            // produces https: neither mode may fall back to plain HTTP (§8.3).
            .https_only(true)
            .user_agent(concat!("sund-client/", env!("CARGO_PKG_VERSION")))
            .build();

        let connector = TcpConnector::default().chain(RustlsPinnedConnector { config: tls });
        Ok(Self {
            agent: ureq::Agent::with_parts(config, connector, DefaultResolver::default()),
            origin: address.origin(),
        })
    }
}

impl HttpClient for HttpAgent {
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let url = format!("{}{}", self.origin, request.path);
        let mut builder = ureq::http::Request::builder()
            .method(request.method.as_str())
            .uri(&url);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let outgoing = builder
            .body(&request.body[..])
            .map_err(|e| HttpError::Protocol(e.to_string()))?;

        let response = self.agent.run(outgoing).map_err(classify)?;
        let status = response.status().as_u16();
        let body = response
            .into_body()
            .read_to_vec()
            .map_err(|e| HttpError::Protocol(e.to_string()))?;
        Ok(HttpResponse { status, body })
    }
}

/// Map ureq's errors onto the seam's three, keeping TLS failures distinct.
///
/// The pinning contract asks for exactly this distinction (§8.3): a client
/// should be able to say "cannot verify the server's identity", because an
/// intercepting network must not look like an absent one.
fn classify(error: ureq::Error) -> HttpError {
    match error {
        ureq::Error::Tls(detail) => HttpError::Tls(detail.to_owned()),
        ureq::Error::Rustls(detail) => HttpError::Tls(detail.to_string()),
        ureq::Error::Io(io) if is_tls_failure(&io) => HttpError::Tls(io.to_string()),
        error @ (ureq::Error::Timeout(_)
        | ureq::Error::Io(_)
        | ureq::Error::HostNotFound
        | ureq::Error::ConnectionFailed) => HttpError::Network(error.to_string()),
        other => HttpError::Protocol(other.to_string()),
    }
}

/// Recover "this was a certificate problem" from a nested I/O error.
///
/// rustls surfaces a verification failure through the stream as an
/// `io::Error` carrying the `rustls::Error` — and it carries it in
/// `get_ref()`, not in `source()`, which returns the *inner error's* source and
/// therefore skips exactly the value being looked for. A walk over `source()`
/// alone finds nothing and reports a pin mismatch as a network blip; the
/// contract suite asserts against precisely that.
fn is_tls_failure(error: &std::io::Error) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> =
        error.get_ref().map(|inner| inner as &dyn std::error::Error);
    // Bounded: a cyclic or absurdly deep chain is not worth spinning on.
    for _ in 0..8 {
        let Some(candidate) = current else {
            return false;
        };
        if candidate.is::<rustls::Error>() {
            return true;
        }
        current = match candidate.downcast_ref::<std::io::Error>() {
            Some(nested) => nested
                .get_ref()
                .map(|inner| inner as &dyn std::error::Error),
            None => candidate.source(),
        };
    }
    false
}

/// Pinned mode: no platform trust, no hostname verification, one pinned key.
fn pinned_config(fingerprint: [u8; 32]) -> Result<Arc<ClientConfig>, HttpError> {
    let provider = provider();
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| HttpError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
            fingerprint,
            provider,
        }))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// WebPKI mode: the platform's own verification, unmodified.
///
/// Roots come from the platform store, so an operator-installed CA works
/// exactly as it does for every other application on the device, and CI can
/// trust its own ephemeral authority by installing it rather than by weakening
/// the client. The compiled-in Mozilla set is a fallback for platforms whose
/// store cannot be read (some Android and container images), not a preference:
/// falling back the other way would ignore an enterprise root the user's
/// platform has already accepted.
fn webpki_config() -> Result<Arc<ClientConfig>, HttpError> {
    let mut roots = RootCertStore::empty();
    let loaded = rustls_native_certs::load_native_certs();
    for certificate in loaded.certs {
        // Ignore a root the platform holds but rustls will not parse; the
        // platform store is a mixed bag and one bad entry is not a reason to
        // refuse to connect at all.
        let _ = roots.add(certificate);
    }
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if roots.is_empty() {
        return Err(HttpError::Tls(
            "no trusted certificate authorities are available on this platform".to_owned(),
        ));
    }

    let config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| HttpError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The crypto provider, chosen explicitly rather than through rustls's process
/// default — a library that installs a process-wide default fights with
/// whatever else the app links.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The pinned-mode certificate verifier: §4 of the pinning contract, in order.
#[derive(Debug)]
pub struct PinnedVerifier {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedVerifier {
    /// A verifier for one pinned SPKI fingerprint.
    #[must_use]
    pub fn new(fingerprint: [u8; 32]) -> Self {
        Self {
            fingerprint,
            provider: provider(),
        }
    }
}

/// SHA-256 over a certificate's DER `SubjectPublicKeyInfo` — the pin (§2).
///
/// The public key info, not the whole certificate and not the leaf: pinning the
/// SPKI survives re-issuance with the same key, and pinning the CA lets the
/// server rotate its leaf without re-pairing every device.
///
/// `None` means the certificate could not be parsed at all, which is not the
/// same as "does not match" — the caller treats both as no match, but only one
/// of them is a certificate.
#[must_use]
pub fn spki_fingerprint(certificate: &CertificateDer<'_>) -> Option<[u8; 32]> {
    // Sund computes this over `RawSubjectPublicKeyInfo`, i.e. including the
    // outer SEQUENCE header, and so does this accessor. The two implementations
    // agreeing on that detail is what makes the fingerprint in a QR mean the
    // same thing on both sides; a contract test asserts it against a live
    // pinned server rather than against a constant.
    let parsed = ParsedCertificate::try_from(certificate).ok()?;
    Some(Sha256::digest(parsed.subject_public_key_info().as_ref()).into())
}

/// Whether two fingerprints match, without leaking where they diverge.
///
/// The pin is public — it travels in a QR — so this is hygiene rather than a
/// hard requirement (§6), and hygiene that costs nothing is worth keeping.
fn fingerprints_match(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Step 4: find the presented certificate whose SPKI matches the pin.
        // The server name is deliberately unused: identity is the pinned key,
        // not a CA chain and not a name (§4.2).
        let presented = std::iter::once(end_entity).chain(intermediates);
        let mut pinned = None;
        for certificate in presented {
            let Some(fingerprint) = spki_fingerprint(certificate) else {
                continue;
            };
            if fingerprints_match(&fingerprint, &self.fingerprint) {
                pinned = Some(certificate.clone());
                break;
            }
        }

        // Step 5: no match is the MITM case. Reject; never retry unpinned.
        let Some(pinned) = pinned else {
            return Err(rustls::Error::General(
                "server certificate does not match the pinned fingerprint".to_owned(),
            ));
        };

        // Step 6: the leaf must chain to the pinned certificate as the *sole*
        // trust root, be inside every validity window, and assert serverAuth.
        // rustls's helper enforces all three; the anchor set is exactly one
        // certificate, so nothing else can vouch for this leaf.
        let mut roots = RootCertStore::empty();
        roots
            .add(pinned)
            .map_err(|e| rustls::Error::General(format!("pinned certificate unusable: {e}")))?;
        let parsed = ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Verified for real. A verifier that asserts here would accept a
        // handshake signed by someone who merely replayed a valid chain.
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Timestamps and nonces from the platform.
///
/// The core deliberately owns neither ([`crate::sigauth`]); this is the
/// host-native implementation the apps and the test suites use, and an app with
/// its own secure clock or entropy source can supply that instead.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemStamps;

impl StampSource for SystemStamps {
    fn stamp(&self) -> Stamp {
        let mut bytes = [0u8; 16];
        // A failure here means the platform has no entropy at all, which is not
        // a recoverable state for a client that signs every request. Falling
        // back to the clock keeps the request *shaped* correctly so the server
        // refuses it as a replay rather than the client panicking in a
        // background job.
        let nonce = if getrandom::fill(&mut bytes).is_ok() {
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        } else {
            format!("no-entropy-{:?}", SystemTime::now())
        };
        Stamp {
            timestamp: rfc3339::format(SystemTime::now()),
            nonce,
        }
    }
}

/// A ureq connector that wraps a TCP transport in *our* rustls configuration.
///
/// ureq's own rustls connector builds its configuration from ureq's
/// `TlsConfig`, which has no room for a custom certificate verifier — so this
/// exists to put one there, and does nothing else.
#[derive(Debug)]
struct RustlsPinnedConnector {
    config: Arc<ClientConfig>,
}

impl<In: Transport> Connector<In> for RustlsPinnedConnector {
    type Out = RustlsTransport<In>;

    fn connect(
        &self,
        details: &ConnectionDetails,
        chained: Option<In>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        let Some(transport) = chained else {
            return Err(ureq::Error::Tls("no transport to wrap in TLS"));
        };
        if !details.needs_tls() {
            // A Sund address is always https; anything else means a caller
            // built a URL this client should not be making.
            return Err(ureq::Error::Tls("refusing to speak plain HTTP"));
        }

        // In pinned mode the name is not the identity, but rustls still needs
        // one for SNI, which the contract permits sending (§4.1). An address
        // whose host is unusable as a name (an IP literal is not) falls back to
        // a placeholder: the verifier ignores it either way.
        let host = details
            .uri
            .authority()
            .map_or("sund.invalid", |authority| authority.host());
        let name = ServerName::try_from(host)
            .unwrap_or(
                ServerName::try_from("sund.invalid")
                    .unwrap_or(ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into())),
            )
            .to_owned();

        let connection = ClientConnection::new(self.config.clone(), name)
            .map_err(|_| ureq::Error::Tls("could not start the TLS connection"))?;
        Ok(Some(RustlsTransport {
            buffers: LazyBuffers::new(
                details.config.input_buffer_size(),
                details.config.output_buffer_size(),
            ),
            stream: StreamOwned {
                conn: connection,
                sock: TransportAdapter::new(transport),
            },
        }))
    }
}

/// The TLS-wrapped transport ureq drives.
struct RustlsTransport<In: Transport> {
    buffers: LazyBuffers,
    stream: StreamOwned<ClientConnection, TransportAdapter<In>>,
}

impl<In: Transport> fmt::Debug for RustlsTransport<In> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RustlsTransport").finish_non_exhaustive()
    }
}

impl<In: Transport> Transport for RustlsTransport<In> {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let output = &self.buffers.output()[..amount];
        self.stream.write_all(output)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.stream.get_mut().set_timeout(timeout);
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        self.stream.get_mut().get_mut().is_open()
    }

    fn is_tls(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_are_rfc3339_and_do_not_repeat() {
        let first = SystemStamps.stamp();
        let second = SystemStamps.stamp();
        assert_ne!(first.nonce, second.nonce, "a repeated nonce is a replay");
        assert_eq!(first.timestamp.len(), 20, "{}", first.timestamp);
        assert!(first.timestamp.ends_with('Z'));
    }

    #[test]
    fn the_fingerprint_comparison_is_length_independent() {
        let a = [1u8; 32];
        let mut b = a;
        assert!(fingerprints_match(&a, &b));
        b[31] = 2;
        assert!(!fingerprints_match(&a, &b));
        b[31] = 1;
        b[0] = 2;
        assert!(!fingerprints_match(&a, &b));
    }

    #[test]
    fn an_agent_can_be_built_for_both_modes() {
        let pinned = ServerAddress::parse(&format!("sund://127.0.0.1:5870#{}", "ab".repeat(32)))
            .expect("pinned address");
        assert!(HttpAgent::new(&pinned).is_ok());

        let webpki = ServerAddress::parse("sund+webpki://beacon.example.org").expect("webpki");
        assert!(HttpAgent::new(&webpki).is_ok());
    }
}
