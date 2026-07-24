//! The HTTP seam: what a request is, and who performs it.
//!
//! Everything above this module builds Sund requests and reads Sund responses;
//! nothing above it opens a socket. The seam exists for three reasons, in
//! descending order of how much they cost to ignore:
//!
//! - **The web client cannot use the shipping implementation.** A browser has
//!   no socket and no pinning API — the pinning contract says so outright
//!   (§8.6) — so `apps/web` must supply an `HttpClient` over `fetch()`. If the
//!   request-building code called a concrete client, that client would have to
//!   be ported rather than replaced.
//! - **Tests.** The management-plane and queue logic is exercised against a
//!   scripted client with no server, the same way the layers above the
//!   transport port are exercised against [`crate::memory`].
//! - **Platform HTTP stacks.** An app that wants requests to go through
//!   Cronet, URLSession or a VPN-aware stack supplies its own here.
//!
//! What crosses the seam is deliberately narrow: a method, a path, headers, a
//! body, and back a status and a body. No streaming, no redirects, no cookies —
//! Sund's API needs none of it, and each one would be another thing three
//! implementations have to agree about.

use std::fmt;

/// The HTTP methods Sund's API uses.
///
/// An enum rather than a string because the method is signed
/// ([`crate::sigauth`]), and a signature over a typo is a 401 nobody can
/// explain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `PUT`
    Put,
}

impl Method {
    /// The uppercase wire form, which is also what gets signed.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One request, ready to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// The method.
    pub method: Method,
    /// The path, with no query string and no origin — `/v1/devices`.
    ///
    /// This is the exact byte sequence the signature covers, so an
    /// implementation of [`HttpClient`] must send it unmodified. Anything that
    /// normalises, rewrites or strips a prefix invalidates every signature; the
    /// same warning applies to reverse proxies (`docker/caddy/Caddyfile`).
    pub path: String,
    /// Headers to send, in order.
    pub headers: Vec<(String, String)>,
    /// The raw body. Empty for GET.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// A request with no headers and no body.
    #[must_use]
    pub fn new(method: Method, path: impl Into<String>) -> Self {
        Self {
            method,
            path: path.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Attach a body. The caller sets any content type it needs; Sund's API is
    /// JSON throughout, and [`crate::client`] sets it.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Attach one header.
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// One response, as far as this crate cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code. Sund's errors are statuses plus a JSON `{"error": …}`
    /// body, and the meaning of each one is mapped in [`crate::client`].
    pub status: u16,
    /// The response body.
    pub body: Vec<u8>,
}

/// What can go wrong below the application layer.
///
/// [`Self::Tls`] is kept distinct from [`Self::Network`] on purpose: the
/// pinning contract requires a client to surface a verification failure as its
/// own explicable state rather than as a generic network error (§8.3), because
/// an intercepting network must be distinguishable from an absent one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    /// The server could not be reached, or the connection failed mid-request.
    Network(String),
    /// The server's identity could not be verified: pin mismatch, an untrusted
    /// or expired chain, a hostname that does not match. Never retried, never
    /// downgraded, and never presented as something the user can click past.
    Tls(String),
    /// A response arrived but was not usable — a malformed status line, a body
    /// that could not be read.
    Protocol(String),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(detail) => write!(f, "network: {detail}"),
            Self::Tls(detail) => write!(f, "cannot verify the server's identity: {detail}"),
            Self::Protocol(detail) => write!(f, "bad response: {detail}"),
        }
    }
}

impl std::error::Error for HttpError {}

/// Performs requests against one server.
///
/// An implementation is bound to a single [`crate::address::ServerAddress`] —
/// which is what makes the trust mode a property of the client rather than of
/// each call, and therefore impossible to forget on one request out of forty.
pub trait HttpClient: Send + Sync {
    /// Perform the request and return the response.
    ///
    /// Any status is a success here, including 4xx and 5xx: mapping statuses to
    /// meaning is [`crate::client`]'s job. Only a failure to obtain a response
    /// at all is an error.
    ///
    /// # Errors
    ///
    /// Returns an [`HttpError`] if the server could not be reached, could not
    /// be verified, or answered with something unreadable.
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError>;
}

/// The timestamp and nonce a signed request carries.
///
/// See [`crate::sigauth`] for why these are supplied rather than generated: the
/// core owns neither a clock nor a random source, both of which the app layer
/// already has in a platform-appropriate form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp {
    /// RFC 3339 UTC timestamp. Sund rejects anything more than five minutes
    /// from its own clock, so this must be real time, not a counter.
    pub timestamp: String,
    /// A value not used before with this key. Sund remembers nonces for the
    /// skew window and refuses replays.
    pub nonce: String,
}

/// Supplies the timestamp and nonce for each signed request.
///
/// One call rather than two, because they are always needed together and each
/// crossing of the FFI boundary costs.
pub trait StampSource: Send + Sync {
    /// Produce a stamp for one request.
    fn stamp(&self) -> Stamp;
}

#[cfg(test)]
pub(crate) mod testing {
    //! A scripted [`HttpClient`] for this crate's own tests.

    use super::{HttpClient, HttpError, HttpRequest, HttpResponse, Stamp, StampSource};
    use std::sync::Mutex;

    /// Records every request and answers from a queue of canned responses.
    #[derive(Debug, Default)]
    pub(crate) struct ScriptedHttp {
        seen: Mutex<Vec<HttpRequest>>,
        replies: Mutex<Vec<Result<HttpResponse, HttpError>>>,
    }

    impl ScriptedHttp {
        pub(crate) fn new(replies: Vec<Result<HttpResponse, HttpError>>) -> Self {
            let mut replies = replies;
            replies.reverse();
            Self {
                seen: Mutex::new(Vec::new()),
                replies: Mutex::new(replies),
            }
        }

        /// Answer every request with one status and body.
        pub(crate) fn answering(status: u16, body: &str) -> Self {
            Self::new(vec![Ok(HttpResponse {
                status,
                body: body.as_bytes().to_vec(),
            })])
        }

        pub(crate) fn requests(&self) -> Vec<HttpRequest> {
            self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }

        pub(crate) fn last(&self) -> HttpRequest {
            self.requests().pop().expect("a request was performed")
        }
    }

    impl HttpClient for ScriptedHttp {
        fn execute(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
            self.seen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(request.clone());
            let mut replies = self.replies.lock().unwrap_or_else(|e| e.into_inner());
            if replies.len() > 1 {
                replies.pop().expect("checked")
            } else {
                replies.last().cloned().unwrap_or(Err(HttpError::Network(
                    "the script ran out of replies".to_owned(),
                )))
            }
        }
    }

    /// Fixed stamps, so a test can assert on an exact signing string.
    #[derive(Debug)]
    pub(crate) struct FixedStamps;

    impl StampSource for FixedStamps {
        fn stamp(&self) -> Stamp {
            Stamp {
                timestamp: "2026-07-24T09:00:00Z".to_owned(),
                nonce: "n1".to_owned(),
            }
        }
    }
}
