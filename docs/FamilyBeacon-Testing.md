Family Beacon — Testing and CI strategy

Status: v0.4 (Draft) — tiers 1 and 2 and the deployment-topology job are
implemented; tier 3 awaits session crypto and the roster

How Family Beacon is tested, and specifically how it is tested *together with*
Sund — which lives in another repo (`../sund`), ships as a container image, and
already has a system suite of its own. The short version: Sund publishes a
vouched-for image tagged by commit, so Family Beacon's CI can stand up a real
relay in seconds and drive real client libraries against it.

This document covers the client side. Sund's own testing philosophy and its
S1–S9 scenario suite are in `../../sund/docs/Sund-ImplementationGuide.md`
(Testing); do not duplicate them here — that suite owns the transport, this one
owns the application layer above it.

---

What Sund already provides

Worth knowing before designing anything, because it removes most of the work:

- **A published image.** `ghcr.io/mevoc/sund`, multi-arch, built by Sund's CI.
  It is gated on `needs: [go, system]` — an image exists only if both of Sund's
  suites passed — and it is smoke-tested against `/health` before publication.
- **Commit-pinned tags.** Sund's metadata step emits `type=sha,format=long`
  alongside `latest`, so Family Beacon can pin an exact Sund commit rather than
  chasing a moving tag.
- **A self-probing health check.** `sund health` exists specifically so the
  distroless image (no shell, no curl) can declare
  `["CMD", "/sund", "health"]` — see `sund/main.go`, `runHealth`. Compose uses
  the exec form and it works as-is.
- **Non-interactive provisioning.** `sund admin account create --json` returns
  `{account_id, invitation_token}`, which is exactly what a test needs to mint a
  family.
- **A reference client.** `beaconsim` (Python, in Sund's `tests/`) implements
  the client side with real crypto, and Sund's `conftest.py` shows the pattern:
  compile once per session, start per test on a random loopback port against a
  temp SQLite file. It also has a `tls_sund` fixture that yields a real
  `sund://host:port#fingerprint` address — a ready-made profile A conformance
  target.

The one prerequisite this strategy used to carry — a private GHCR package — is
**cleared (July 2026)**: the Sund repo went public and the package followed, so
`ghcr.io/mevoc/sund` pulls anonymously. No `docker login`, no read token, no
secret in this repo. Verified against the registry's tag list rather than
assumed.

One wrinkle survives it. Sund's CI cancels superseded runs on the same ref
(`concurrency: cancel-in-progress`), so a commit whose run was cancelled has no
`sha-` tag at all — not every Sund commit is pinnable. Check the tag exists
before bumping the pin.

---

The four tiers

Tier 1 — Unit. No Sund, no network.

`beacon-protocol` is pure logic: envelope codec, consent state machine, ledger
rules, version degradation. It is gated on the shared test vectors
(FamilyBeacon-Protocol.md → Versioning), not on hand-written per-implementation
assertions.

`sund-client` needs a transport, and this is the transport port's second job
(FamilyBeacon-TryMode.md → Where the seam goes): an **in-memory implementation
of the port** lets pairing, session lifecycle, outbox/retry, dedupe and rotation
be tested with no server at all. This is why the port is defined now even though
its second real implementation (ntfy-client) is deferred — it earns its keep as
the unit-test seam first.

Runs per-commit. Milliseconds.

Tier 2 — Contract. Real Sund binary, no app. **Implemented** (July 2026) in
`core/contract-tests`, run per-commit by the `contract` job.

Drives `sund-client` against a real relay and asserts the things only a real
server can falsify: enrollment and invitation consumption, the signing scheme,
queue lifecycle and rotation, revocation taking effect, the size caps, and both
address forms of the pinning contract
(`../../sund/docs/Sund-Pinning-Contract.md`) — `sund://…#fingerprint` against a
`--tls-dir` server, `sund+webpki://…` against a plain-HTTP server behind a proxy
with a trusted certificate.

This is the tier that catches drift between the two repos, and it is the highest
value per minute of CI time.

How it is arranged, and why:

- **Both relays, every assertion.** The CI stack runs two: `sund` behind Caddy
  (profile B, WebPKI mode) and `sund-pinned` terminating its own TLS (profile A).
  Each test body runs against every configured leg, because the claim being
  tested is that the trust mode is orthogonal to the API — a claim worth
  falsifying rather than assuming. A leg with no address in the environment is
  skipped, loudly; `SUND_CONTRACT_REQUIRED=1` (set in CI) turns "nothing was
  configured" into a failure, so a misconfigured job cannot report green having
  asserted nothing.
- **One test binary.** Each relay is bootstrapped from a single-use invitation,
  so the founding device can be enrolled exactly once per process and every
  later device joins through an invitation that founder mints — the real
  ceremony. A second `tests/*.rs` file would be a second process against an
  already-spent token, so the suite's modules live under `tests/contract/` and
  are pulled in with `#[path]`.
- **The port's own promises are asserted twice**, over the in-memory transport
  and over real Sund queues, from one function (`tests/contract/port.rs`). That
  is what stops the port from quietly coming to mean "whatever Sund does", and
  it is where `ntfy-client` joins when Try mode is built.
- **The environment is what gets adjusted for WebPKI mode, never the client.**
  The hostname has to resolve (a `/etc/hosts` line in CI; DNS in production) and
  the CI certificate authority has to be trusted (`SSL_CERT_FILE`, which the
  platform trust store already reads). The pinning contract calls WebPKI mode
  "the platform's default TLS client with no options changed" (§8.2), so a test
  that needed the client to relax something would be testing a client nobody
  ships.

Two things the first real run against a live relay corrected, both worth keeping
written down:

- A **pin mismatch surfaced as a network error**, not as an identity failure.
  rustls carries the verification error in `io::Error::get_ref()`, while
  `source()` returns the *inner* error's source and skips it — so the obvious
  walk finds nothing and an intercepting network becomes indistinguishable from
  an absent one, which is exactly what §8.3 says must not happen. `sund-client`'s
  `agent::is_tls_failure` handles it and `pinning.rs` asserts it.
- The pinned relay **crash-looped on a certificate directory it could not
  write.** Sund's image chowns only `/data` to the distroless nonroot uid, so a
  named volume mounted anywhere else arrives root-owned; the CI stack keeps the
  CA under `/data/certs`.

Runs per-commit.

Tier 3 — System. Real Sund + several headless clients.

Where the *application* is actually tested. The clients here must be built from
**the real shipping libraries**, run headlessly — not from a reimplementation. A
system test whose client is a mockup tests the mockup.

What belongs here is everything that only exists between devices:

- consent enforced at the producer: a revoked grant stops data leaving, and the
  observer's UI state follows
- revocation and departure: the removed device reads nothing further
- `sos` reaching every pair, `sos_clear` standing it down everywhere
- `attention` suppression by the recipient's interruption budget, reported
  honestly in the receipt (`suppressed`) rather than silently
- ledger entries on both sides for every message, including unknown types
- seq gaps and TTL expiry surfacing as staleness, never as interpolation
- mixed-version families: a v0.1 client meeting a v0.2 `presence` message

`beaconsim` keeps a distinct and valuable role at this tier: as the
**independent-implementation adversary**. Pairing a real Family Beacon client
against beaconsim — a different language, written from the spec — turns spec
drift into a test failure instead of a field bug. That is precisely the risk the
protocol spec's three-implementations note raises.

Runs per-commit.

Tier 4 — Device and deployment. Slow, narrow, scheduled.

Two things that genuinely cannot run per-commit:

*Platform behaviour.* Background location, geofence triggering, doze and battery
optimisation, the non-dismissable sharing indicator, notification presentation
and the ringer override, UnifiedPush wake-up end to end. Android instrumented
tests on an emulator cover all of it. iOS is weaker: `xcrun simctl push` fakes a
push, but real background wake behaviour needs a physical device, so the iOS
wake path is honestly *not* covered by CI and needs a manual or self-hosted-runner
stage. Say so rather than implying coverage.

*Deployment topology.* `docker compose up` on the real files, asserting the whole
stack comes up and routes correctly — see below.

Runs nightly, plus on changes to the relevant paths.

A note on the nightly tier. Sund's implementation guide takes the position that
there is no nightly tier — "a test that cannot run per-commit is a test that will
not run" — and it is right for Sund, which is one Go binary with no devices in
the loop. Family Beacon cannot hold that line: an Android emulator boot alone
costs more than Sund's entire suite, and the behaviour being tested (doze,
background location) is time-dependent by nature. The discipline that replaces it
is that tiers 1–3 must stay per-commit and must cover everything that *can* be
covered without a device — a nightly tier is permitted only for what is
structurally impossible below it, never as a dumping ground for slow tests.

---

Getting Sund into CI

Three mechanisms, in order of preference.

1. Compose (recommended default)

Mirrors the production topology, and uses the exec-form health check that
already works against the distroless image:

    services:
      sund:
        image: ghcr.io/mevoc/sund:sha-<pinned>
        healthcheck:
          test: ["CMD", "/sund", "health"]

Pin by commit SHA on pull requests, so a red build means *your* change broke,
not that Sund moved under you. The pin lives in one place,
`docker/compose/.env.ci` (`SUND_IMAGE=`); the canary overrides it with `:latest`
from the shell environment, which takes precedence over an `--env-file`.

2. GitHub Actions `services:` — avoid for this image

It looks simpler, but `--health-cmd` sets the health test to
`["CMD-SHELL", …]`, i.e. it runs through `/bin/sh` — which the distroless
runtime does not have. Sund's `health` subcommand solves the problem for
compose (exec form) but cannot be reached this way. Either poll `/health` from a
job step instead of declaring a service health check, or use compose.

*Worth fixing upstream:* adding `HEALTHCHECK ["CMD", "/sund", "health"]` to
Sund's Dockerfile would make the image self-describing, so any runner —
Actions services included — gets a working check with no configuration, and
compose files could drop their healthcheck blocks entirely. Small change,
removes this whole footnote.

3. Build from source

    - uses: actions/checkout@v7
      with:
        repository: mevoc/sund
        ref: <pinned sha or main>
        path: sund
    - run: cd sund && CGO_ENABLED=0 go build -o sund .

Needed only to test against unreleased Sund changes — which is exactly what the
canary below does.

The canary job

Alongside the pinned per-PR runs, a **scheduled job that runs tiers 2 and 3
against Sund `main`**, allowed to fail loudly without blocking anyone. This is
what tells you Sund has broken its first consumer *before* you upgrade, rather
than a week later. It is the cheapest cross-repo insurance available and it
costs one nightly workflow.

Implemented in `.github/workflows/ci.yml` as a matrix variant rather than a
second workflow: scheduled and manual runs add a `latest` leg alongside the
pinned one, with `continue-on-error`. One copy of the steps, and a canary
failure is legible next to a passing pinned run.

What CI runs today

`.github/workflows/ci.yml` has three jobs:

- **`core`** — tier 1. `cargo fmt --check`, `cargo clippy --all-targets -D
  warnings` and `cargo test` over the `core/` workspace: `beacon-protocol`'s
  envelope codec, consent state machine and ledger vocabulary, `sund-client`'s
  signed-request form, address parsing, transport port and Sund transport
  against a scripted HTTP client, the in-memory transport, and the shared
  vectors below. No server, no network, no device.
- **`contract`** — tier 2, against both relays of the CI stack, with the same
  pinned/canary matrix as `topology`.
- **`topology`** — tier 4's deployment half, described below.

Tier 3 is not there yet, because what it would drive does not exist: session
crypto and the roster state machine, i.e. clients that can hold a conversation
rather than a queue. The contract suite is already the portable crate the
reverse direction needs (see The reverse direction).

The invocation is exact and all three arguments are load-bearing:

    docker compose --env-file docker/compose/.env.ci \
      -f docker/compose/compose.yaml \
      -f docker/compose/compose.ci.yaml up -d --wait

`--wait` is doing real work: it blocks until every service reports healthy,
which is what makes Sund's `health` subcommand pay off. The `--env-file` is
doing more than it looks like — see the topology section below.

The shape of a server-backed job

The `contract` job is the worked example; tier 3 will be the same shape with a
longer test invocation:

    jobs:
      contract:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v7
          # no registry login: ghcr.io/mevoc/sund is public
          - name: Start Sund
            run: docker compose $COMPOSE up -d --wait
          - name: Provision a family
            run: |
              docker compose $COMPOSE exec -T sund \
                /sund admin account create --json > account.json
          - run: cargo test -p contract-tests -- --test-threads=1
          - if: failure()
            run: docker compose $COMPOSE logs

The provisioning step is not hypothetical — the topology job ran it before there
was a suite to use it, which is why the fixture worked the first time the suite
asked for one.

`--test-threads=1` is not superstition: the suite provisions devices and queues
on a shared relay, and a serial run keeps a failure's server-side logs readable.
The whole thing takes under a second against a local relay, so there is nothing
to buy back with parallelism.

---

Deployment topology tests

Profile A is easy: `sund --tls-dir` on a random port, no domain, no proxy. The
CI stack runs one as `sund-pinned`, and the client's job — verify against it,
and *refuse* correctly when the fingerprint does not match — is asserted by
tier 2's pinning module rather than here. What that module proves and a unit
test cannot: that this client and Sund's `internal/tlsid` compute the same
fingerprint over the same bytes, that a wrong pin fails as an identity error
rather than a network one, that the pin travels with the server and not with
its hostname, and that a pinned address pointed at the WebPKI deployment does
not quietly succeed through platform trust.

Profile B cannot do ACME in CI — no domain, no public reachability. But ACME is
the least interesting part of that stack. What is worth testing is the topology:
that Caddy routes both hostnames, that **paths pass through unrewritten** (a
correctness requirement, since devices sign the path — see the Caddyfile's
warning about `handle_path`), that an oversized body is refused, and above all
that the `ntfy` network alias resolves inside the compose network. That alias is
the least obvious line in `docker/compose/compose.yaml` and exactly the kind of
thing that breaks silently.

One correction the first real run produced, worth keeping written down: the
oversized-body case is refused by **Sund's** 1 MiB cap, not by Caddy's
`request_body max_size`. Because `reverse_proxy` streams, the upstream answers
before Caddy's read limit is reached — a 2 MiB POST returns Sund's 400 and Caddy
logs nothing (Caddy 2.11.4). The edge cap is a backstop for an upstream that
drains the body, and a test asserting 413 asserts a behaviour the stack does not
have.

`docker/compose/compose.ci.yaml` handles this by putting Caddy on its internal
CA (`tls internal`) instead of Let's Encrypt, so the *real* Caddyfile is
exercised rather than a CI-only copy that would drift from it. See that file's
header for how to run it and how to trust the local CA.

The settings come from `docker/compose/.env.ci`, not from `environment:`
overrides, and that distinction is the one genuine trap in this stack: compose
interpolates each file when it *loads* it, before merging, so an override block
sets the container's environment far too late to satisfy `compose.yaml`'s own
`${BEACON_DOMAIN:?…}`. The case that actually bites is the network alias,
`${NTFY_DOMAIN:-ntfy.invalid}` — with nothing in the environment it resolves to
`ntfy.invalid` while Caddy serves `ntfy.test`, so the alias assertion passes
over a stack where the alias points nowhere. An env-file fixes both, and keeps
one copy of the hostnames.

Concretely, the job asserts: TLS and routing for the Sund vhost verified
against the exported CI root; `GET /v1/devices` arriving at Sund unrewritten
(401, where a 404 would mean Caddy rewrote the signed path); the same request
straight to the published relay port agreeing, so a failure localises to one
layer; a 2 MiB body refused; both hostnames routed; the ntfy alias
resolving from inside the compose network; and `sund admin account create
--json` returning a usable family.

---

Shared test vectors — where they live

The vectors gate both `beacon-protocol` implementations *and* beaconsim, which
lives in the Sund repo. They therefore need a canonical home both CIs can
consume. Decision: **canonical in this repo, under `shared/protocol/testvectors/`**,
consumed by Sund's CI via a checkout at a pinned ref.

`envelopes.json` exists and is live: one case per v1 message type, plus the
mixed-version case (an unknown type from a newer peer, which must decode and be
ledgered rather than rejected) and the deliberately malformed ones. Each case
carries the expected outcome and, for rejections, a stable reason tag —
`beacon-protocol`'s vector suite maps its Rust reasons onto those tags
explicitly, so renaming one without the other fails the build. A test also
asserts the corpus covers every type in the registry, because a type nobody
wrote a vector for is a type nothing gates.

The alternative — vendoring a copy into Sund — was rejected: two copies of a
conformance corpus drift, and drift in the corpus is worse than drift in the
implementations, because it hides the latter.

---

The reverse direction

Sund's CI should run Family Beacon's contract tests, so that a Sund change which
breaks its first consumer fails **in Sund's repo**, at the moment it is made. The
loop is already half-intended — Sund's implementation guide requires beaconsim to
track this repo's test vectors — and closing it makes the dependency honest in
both directions.

Practically: a job in Sund's CI that checks out family-beacon at a pinned ref and
runs the tier-2 suite against the just-built binary. It is the same test code,
run from the other side. Noted in `../../sund/docs/Sund-ImplementationGuide.md`
(Testing → Consumer contract tests).

---

Open items

1. ~~Language/runtime for the headless system-test client.~~ **Resolved by
   decision #6 (July 2026): a Rust core**, so tiers 1–3 are `cargo test` against
   the real crates — the same artifacts the apps bind, which is what tier 3
   demands ("a system test whose client is a mockup tests the mockup"). No JVM or
   emulator is involved below tier 4, which makes the fast tiers genuinely fast.
2. ~~Where the contract suite physically lives.~~ **Resolved with #1: a crate in
   `core/`**, runnable by `cargo test -p <suite>` from either repo's CI with
   nothing but a Rust toolchain and the Sund image. This is the portability the
   item was asking for — Sund's CI checks out this repo at a pinned ref and runs
   it, per Consumer contract tests.
3. ~~GHCR package visibility.~~ **Resolved (July 2026): the package is public**
   and pulls anonymously — the Sund repo went public and the package followed.
   Nothing to configure in this repo. See What Sund already provides.
4. ~~`docker/compose/.env.example` does not exist.~~ Added (July 2026).
5. **Emulator matrix breadth** — how many API levels are worth the nightly
   minutes. iOS is out of scope for now under the Android-first sequencing
   (ARCHITECTURE.md → Client platforms and build order); revisit when iOS work
   starts.
6. **Cross-compilation in CI.** New with the Rust core: Android NDK targets,
   iOS xcframework and wasm builds all have to be wired up before tier 4 can run
   on a real device. Not blocking for tiers 1–3, which are host-native. Note
   that the wasm target additionally needs `sund-client` built with
   `--no-default-features` (no `agent`) and an `HttpClient` over `fetch()`.
7. **Two small things worth fixing upstream in Sund**, both found by standing
   the profile A relay up for tier 2 and neither blocking:
   - `sund health` always probes `http://`, so it cannot health-check a server
     started with `--tls-dir`. The CI stack therefore declares no healthcheck
     for `sund-pinned` and lets the suite wait by connecting.
   - The image chowns only `/data` to the distroless nonroot uid, so
     `SUND_TLS_DIR` pointed at any other volume crash-loops on a permission
     error. Chowning the certificate directory too, or documenting the
     constraint, would save the next person the log-reading.
   (The third — adding `HEALTHCHECK` to the Dockerfile — is noted above under
   Getting Sund into CI.)

---

Relationship to other documents

- `FamilyBeacon-Protocol.md` → Versioning — mandates the shared test vectors this
  strategy distributes; → Layering defines the transport port tier 1 fakes.
- `FamilyBeacon-TryMode.md` — the port's second implementation, deferred; when it
  lands, tiers 1–3 must run against both transports.
- `../ARCHITECTURE.md` → Deployment — the two profiles the tier-4 topology tests
  cover.
- `../../sund/docs/Sund-ImplementationGuide.md` → Testing — Sund's own suites
  (S1–S9) and beaconsim; the transport layer is tested there, not here.
- `../../sund/docs/Sund-Pinning-Contract.md` — the address forms tier 2 asserts.
