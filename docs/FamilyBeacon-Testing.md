Family Beacon — Testing and CI strategy

Status: v0.1 (Draft)

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

One prerequisite to clear: the GHCR package is private while the Sund repo is
(noted in `sund/compose.yaml`). Family Beacon's CI therefore needs either a
`docker login ghcr.io` with a read-packages token, or the package made public.
Decide this before writing the workflow — it is the only hard dependency.

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

Tier 2 — Contract. Real Sund binary, no app.

Drives `sund-client` against a real relay and asserts the things only a real
server can falsify: enrollment and invitation consumption, the signing scheme,
queue lifecycle and rotation, revocation taking effect, quota behaviour at the
cap, and both address forms of the pinning contract
(`../../sund/docs/Sund-Pinning-Contract.md`) — `sund://…#fingerprint` against a
`--tls-dir` server, `sund+webpki://…` against a plain-HTTP server behind a proxy
with a trusted certificate.

This is the tier that catches drift between the two repos, and it is the highest
value per minute of CI time.

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
not that Sund moved under you.

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

Reference workflow

Adopt when there is code to build; the shape is stable, the build steps are not:

    name: CI
    on: [push, pull_request]

    jobs:
      unit:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v7
          # in-memory transport; no services needed
          - run: ./gradlew :beacon-protocol:test :sund-client:test

      contract-and-system:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v7
          - uses: docker/login-action@v4      # while the GHCR package is private
            with:
              registry: ghcr.io
              username: ${{ github.actor }}
              password: ${{ secrets.GHCR_READ_TOKEN }}
          - name: Start Sund
            run: docker compose -f docker/compose/compose.ci.yaml up -d --wait
          - name: Provision a family
            run: |
              docker compose -f docker/compose/compose.ci.yaml exec -T sund \
                /sund admin account create --json > account.json
          - run: ./gradlew :contract-tests:test :system-tests:test
          - if: failure()
            run: docker compose -f docker/compose/compose.ci.yaml logs

`--wait` is doing real work in that step: it blocks until every service reports
healthy, which is what makes Sund's `health` subcommand pay off.

---

Deployment topology tests

Profile A is easy: `sund --tls-dir` on a random port, no domain, no proxy.
Sund's own `tls_sund` fixture already produces the pinned address; the client's
job is to verify against it and to *refuse* correctly when the fingerprint does
not match.

Profile B cannot do ACME in CI — no domain, no public reachability. But ACME is
the least interesting part of that stack. What is worth testing is the topology:
that Caddy routes both hostnames, that **paths pass through unrewritten** (a
correctness requirement, since devices sign the path — see the Caddyfile's
warning about `handle_path`), that the request-body cap applies, and above all
that the `ntfy` network alias resolves inside the compose network. That alias is
the least obvious line in `docker/compose/compose.yaml` and exactly the kind of
thing that breaks silently.

`docker/compose/compose.ci.yaml` handles this by overriding one variable to put
Caddy on its internal CA (`tls internal`) instead of Let's Encrypt, so the *real*
Caddyfile is exercised rather than a CI-only copy that would drift from it. See
that file's header for how to run it and how to trust the local CA.

---

Shared test vectors — where they live

The vectors gate both `beacon-protocol` implementations *and* beaconsim, which
lives in the Sund repo. They therefore need a canonical home both CIs can
consume. Decision: **canonical in this repo, under `shared/protocol/testvectors/`**
(the directory already exists in the repo structure), consumed by Sund's CI via a
checkout at a pinned ref.

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

1. **Language/runtime for the headless system-test client.** Falls out of open
   decision #6 (library packaging): with Kotlin Multiplatform the harness is a
   JVM test binary; with a Rust core it is whatever the bindings suit. Blocked on
   that decision, not on this document.
2. **Where the contract suite physically lives** so both repos can run it — a
   Gradle module here, or something more portable. Interacts with #1.
3. **GHCR package visibility** (public, or a read token in this repo's secrets).
   Blocking for any CI that pulls the image.
4. **`docker/compose/.env.example`** is referenced by the compose file's header
   but does not exist yet; the CI override sidesteps it by setting its variables
   inline.
5. **Emulator matrix breadth** — how many API levels are worth the nightly
   minutes, and whether iOS gets a physical-device stage at all before v1.

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
