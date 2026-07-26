//! Tier 2 — the contract suite: real `sund-client`, real Sund, no app.
//!
//! `docs/FamilyBeacon-Testing.md` puts the highest value per minute of CI time
//! here, because this is the tier that catches drift between two repositories
//! that ship separately. Everything below the assertions is real: the shipping
//! HTTP client, the shipping signing code, a published Sund image, a family
//! provisioned the way an operator provisions one.
//!
//! # Running it
//!
//! The suite needs a relay, and it will not start one — CI stands the stack up
//! with compose and passes it in, and so can you:
//!
//! ```sh
//! export COMPOSE="--env-file docker/compose/.env.ci \
//!   -f docker/compose/compose.yaml -f docker/compose/compose.ci.yaml"
//! docker compose $COMPOSE up -d --wait
//!
//! # profile A — pinned TLS, no domain, nothing else needed
//! fp=$(docker compose $COMPOSE exec -T sund-pinned \
//!        /sund cert fingerprint --tls-dir /data/certs)
//! export SUND_PINNED_ADDRESS="sund://127.0.0.1:5871#$fp"
//! export SUND_PINNED_INVITATION=$(docker compose $COMPOSE exec -T sund-pinned \
//!        /sund admin account create --json | jq -r .invitation_token)
//!
//! cargo test -p contract-tests
//! ```
//!
//! The profile B (WebPKI) leg additionally needs the hostname to resolve and
//! the CI certificate authority to be trusted — both of which are things done
//! to the *environment*, never to the client:
//!
//! ```sh
//! docker compose $COMPOSE cp caddy:/data/caddy/pki/authorities/local/root.crt ci-root.crt
//! echo "127.0.0.1 beacon.test" | sudo tee -a /etc/hosts
//! export SSL_CERT_FILE=$PWD/ci-root.crt          # read by the platform store
//! export SUND_WEBPKI_ADDRESS="sund+webpki://beacon.test"
//! export SUND_WEBPKI_INVITATION=…
//! ```
//!
//! A leg with no address configured is skipped, loudly. `SUND_CONTRACT_REQUIRED=1`
//! turns "nothing was configured" into a failure, which is what stops CI from
//! reporting a green suite that tested nothing.
//!
//! # Why one test binary
//!
//! Every configured relay is bootstrapped from a **single-use** invitation, so
//! the founding device can only be enrolled once per run. One binary means one
//! process, one [`OnceLock`], one founder — and every later device is enrolled
//! through an invitation that founder mints. Adding a second `tests/*.rs` file
//! would silently break that: the second process would find its token already
//! consumed.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use sund_client::address::ServerAddress;
use sund_client::agent::{HttpAgent, SystemStamps};
use sund_client::client::{DeviceClient, Enrollment, SundClient, SundError};
use sund_client::http::{HttpClient, HttpError, HttpRequest, HttpResponse, Stamp, StampSource};
use sund_client::sigauth::DeviceKey;

/// A device enrolled by the suite, and the key it signs with.
///
/// The key is kept because several assertions need to re-sign the same
/// device's requests differently — with a stale stamp, through a rewriting
/// proxy — which is exactly what a real client never does and what the server
/// must therefore refuse.
pub struct TestDevice {
    /// The signed-half client for this device.
    pub device: DeviceClient,
    /// Its identity key.
    pub key: DeviceKey,
}

impl std::ops::Deref for TestDevice {
    type Target = DeviceClient;

    fn deref(&self) -> &Self::Target {
        &self.device
    }
}

impl std::fmt::Debug for TestDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestDevice")
            .field("device_id", &self.device.device_id())
            .finish_non_exhaustive()
    }
}

/// One relay under test, with a family already provisioned on it.
pub struct Relay {
    /// `pinned` or `webpki` — named in assertion messages so a failure says
    /// which trust mode it happened under.
    pub name: &'static str,
    /// The address the suite was given.
    pub address: ServerAddress,
    http: Arc<dyn HttpClient>,
    client: SundClient,
    bootstrap: Mutex<Option<String>>,
    founder: OnceLock<TestDevice>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relay")
            .field("name", &self.name)
            .field("address", &self.address.to_string())
            .finish_non_exhaustive()
    }
}

impl Relay {
    /// The unsigned half of the API: health, enrollment, the transport plane.
    #[must_use]
    pub fn client(&self) -> &SundClient {
        &self.client
    }

    /// The founding device, enrolled from the operator's one-time invitation
    /// exactly the way the first phone in a family is.
    ///
    /// # Panics
    ///
    /// Panics if the bootstrap invitation cannot be consumed — there is no
    /// useful test to run past that point.
    pub fn founder(&self) -> &TestDevice {
        self.founder.get_or_init(|| {
            let token = self
                .bootstrap
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .expect("the bootstrap invitation is consumed exactly once");
            self.enroll_with(&token)
        })
    }

    /// Enroll another device into the family, through an invitation the
    /// founder mints — which is how every device after the first joins.
    ///
    /// # Panics
    ///
    /// Panics if the invitation cannot be minted or consumed.
    pub fn enroll(&self) -> TestDevice {
        let invitation = self
            .founder()
            .create_invitation()
            .expect("mint an invitation");
        self.enroll_with(&invitation.token)
    }

    /// Enroll with a token this test already holds, returning whatever the
    /// server says — the failure paths are as interesting as the happy one.
    ///
    /// # Errors
    ///
    /// Returns the server's refusal, typically [`SundError::Unauthorized`] for
    /// a token that is spent, expired or revoked.
    pub fn try_enroll_with(&self, token: &str) -> Result<TestDevice, SundError> {
        let key = DeviceKey::from_seed(&seed());
        let enrolled = self.client.register(&Enrollment {
            token,
            public_key: key.public_key(),
            push_endpoint: "",
            capabilities: "contract-tests",
        })?;
        Ok(TestDevice {
            device: self.client.device(enrolled.device_id, key.clone()),
            key,
        })
    }

    fn enroll_with(&self, token: &str) -> TestDevice {
        self.try_enroll_with(token).expect("enroll a device")
    }

    /// A client that signs with `key` while claiming to be `device_id` — for
    /// asserting what the server does with a signature that does not match.
    #[must_use]
    pub fn impersonate(&self, device_id: &str, key: DeviceKey) -> DeviceClient {
        self.client.device(device_id, key)
    }

    /// The same device, but stamping every request from a source of the
    /// caller's choosing — a frozen clock, a repeated nonce.
    #[must_use]
    pub fn resign(&self, device: &TestDevice, stamps: Arc<dyn StampSource>) -> DeviceClient {
        SundClient::new(self.http.clone(), stamps).device(device.device_id(), device.key.clone())
    }

    /// The same device, but with something in the path between it and the
    /// server — used to prove that a rewriting proxy breaks every signature.
    #[must_use]
    pub fn through(&self, device: &TestDevice, http: Arc<dyn HttpClient>) -> DeviceClient {
        SundClient::new(http, Arc::new(SystemStamps)).device(device.device_id(), device.key.clone())
    }

    /// The HTTP client this relay talks through, for wrapping.
    #[must_use]
    pub fn http(&self) -> Arc<dyn HttpClient> {
        self.http.clone()
    }
}

/// A stamp source that never varies — a replay, by construction.
#[derive(Debug)]
pub struct FixedStamp(pub Stamp);

impl StampSource for FixedStamp {
    fn stamp(&self) -> Stamp {
        self.0.clone()
    }
}

/// Distinct key material per call. Nothing here needs unpredictability — these
/// keys live for one test run against a throwaway relay — but they do need to
/// differ, since two devices with one key would hide a signature bug.
pub fn seed() -> [u8; 32] {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&n.to_le_bytes());
    // Keep the tail non-zero so a truncated seed cannot silently collide.
    seed[8..].fill(0xA5);
    seed
}

/// A unique channel id, so repeated runs against a long-lived relay never
/// collide.
pub fn channel_id(label: &str) -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{label}-{since_epoch}-{n}")
}

/// Every relay the environment configured.
///
/// # Panics
///
/// Panics if `SUND_CONTRACT_REQUIRED=1` and nothing was configured: a suite
/// that quietly tests nothing is worse than one that fails.
pub fn relays() -> &'static [Relay] {
    static RELAYS: OnceLock<Vec<Relay>> = OnceLock::new();
    RELAYS.get_or_init(|| {
        let mut relays = Vec::new();
        for (name, address_var, invitation_var) in [
            ("pinned", "SUND_PINNED_ADDRESS", "SUND_PINNED_INVITATION"),
            ("webpki", "SUND_WEBPKI_ADDRESS", "SUND_WEBPKI_INVITATION"),
        ] {
            let Ok(address) = std::env::var(address_var) else {
                eprintln!("contract: {name} leg not configured ({address_var} unset) — skipped");
                continue;
            };
            let address = ServerAddress::parse(&address)
                .unwrap_or_else(|e| panic!("{address_var} is not a server address: {e}"));
            let invitation = std::env::var(invitation_var)
                .unwrap_or_else(|_| panic!("{address_var} is set but {invitation_var} is not"));
            let agent: Arc<dyn HttpClient> =
                Arc::new(HttpAgent::new(&address).unwrap_or_else(|e| panic!("{name}: {e}")));
            relays.push(Relay {
                name,
                address,
                http: agent.clone(),
                client: SundClient::new(agent, Arc::new(SystemStamps)),
                bootstrap: Mutex::new(Some(invitation)),
                founder: OnceLock::new(),
            });
        }

        assert!(
            !(relays.is_empty() && std::env::var("SUND_CONTRACT_REQUIRED").as_deref() == Ok("1")),
            "SUND_CONTRACT_REQUIRED=1 but no relay was configured"
        );
        relays
    })
}

/// Run a test body against every configured relay, naming the leg on failure.
///
/// # Panics
///
/// Panics if no relay is configured — after printing why, so a local run
/// without a stack is a legible skip rather than a mystery.
pub fn for_each_relay(body: impl Fn(&Relay)) {
    let relays = relays();
    if relays.is_empty() {
        eprintln!("contract: no relay configured — nothing asserted");
        return;
    }
    for relay in relays {
        eprintln!("contract: {} ({})", relay.name, relay.address);
        body(relay);
    }
}

/// Wait until the relay answers, so a suite started next to `compose up` does
/// not race the server's first second.
///
/// # Errors
///
/// Returns the last error if the relay never answered.
pub fn wait_until_ready(relay: &Relay, timeout: Duration) -> Result<String, SundError> {
    let deadline = Instant::now() + timeout;
    loop {
        match relay.client().health() {
            Ok(health) => return Ok(health.version),
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// An [`HttpClient`] that rewrites the path after the signature is computed —
/// a reverse proxy configured the way `docker/caddy/Caddyfile` warns against.
pub struct PathRewritingHttp {
    inner: Arc<dyn HttpClient>,
    from: String,
    to: String,
}

impl PathRewritingHttp {
    /// Wrap a client, replacing the first occurrence of `from` with `to`.
    #[must_use]
    pub fn new(inner: Arc<dyn HttpClient>, from: impl Into<String>, to: impl Into<String>) -> Self {
        Self {
            inner,
            from: from.into(),
            to: to.into(),
        }
    }
}

/// An [`HttpClient`] the test can take offline and bring back.
///
/// The outbox's whole reason for existing is what happens while the network is
/// gone, and there is no honest way to assert that against a relay that is always
/// up. Failing at this seam rather than by stopping the container keeps the test
/// fast and keeps the failure shaped like the one a phone actually sees: the
/// server is fine, this device cannot reach it.
pub struct SwitchableHttp {
    inner: Arc<dyn HttpClient>,
    reachable: AtomicBool,
}

impl SwitchableHttp {
    /// Wrap a client, initially reachable.
    #[must_use]
    pub fn new(inner: Arc<dyn HttpClient>) -> Self {
        Self {
            inner,
            reachable: AtomicBool::new(true),
        }
    }

    /// Fail every request from now on.
    pub fn go_offline(&self) {
        self.reachable.store(false, Ordering::Relaxed);
    }

    /// Let requests through again.
    pub fn come_online(&self) {
        self.reachable.store(true, Ordering::Relaxed);
    }
}

impl HttpClient for SwitchableHttp {
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        if self.reachable.load(Ordering::Relaxed) {
            self.inner.execute(request)
        } else {
            Err(HttpError::Network("the network is gone".to_owned()))
        }
    }
}

impl HttpClient for PathRewritingHttp {
    fn execute(&self, request: &HttpRequest) -> Result<HttpResponse, HttpError> {
        let mut rewritten = request.clone();
        rewritten.path = request.path.replacen(&self.from, &self.to, 1);
        self.inner.execute(&rewritten)
    }
}
