Family Beacon – Architecture Vision

> Revision note (July 2026): two decisions reshaped this document since the
> original vision. (1) The backend stack is locked to Go + SQLite — one static
> binary, one database file. (2) Family Beacon formally adopted `../sund`, the
> blind E2E store-and-forward relay, as its backend (CLAUDE.md decisions 1 and 3,
> closed). The Backend, Core API, Database, Authentication, Push Notifications
> and Deployment sections below reflect this; the server's own spec is
> `../sund/docs/Sund-PRD.md`.

Background

Family Beacon started as a peer-to-peer application using SMS for communication between family members.

This had several advantages:

- No backend server required.
- Worked without mobile data.
- No recurring hosting costs.
- Excellent privacy.

Over time this approach has become increasingly difficult:

- Android now prefers RCS over traditional SMS.
- Apple has limited support for background SMS automation.
- SMS behavior differs between devices and carriers.
- Cross-platform support has become harder to maintain.

To provide a reliable experience on both Android and iOS, Family Beacon will evolve into a lightweight self-hosted client/server architecture.

---

Design Goals

- Self-hostable.
- Docker-based deployment.
- Simple architecture.
- Privacy first.
- No cloud vendor lock-in.
- Low resource usage.
- Easy to contribute to.

---

Repository Structure

family-beacon/

apps/
    android/
    ios/
    web/

shared/
    protocol/    (envelope + message types — the client-side application protocol)
    models/

docker/
    compose/
    caddy/      (domain profile only — see Deployment)

docs/

ARCHITECTURE.md
README.md

The server itself lives in ../sund (its own repo). This repo contains the
clients, the client-side protocol, and deployment configuration — there is no
server/ directory to write.

---

Backend

The backend should be intentionally small.

Stack (locked July 2026 — see ../sund/docs/Sund-PRD.md, decision 10):

- Go + SQLite: one static binary, one database file
- Docker Compose for packaging
- TLS terminated by Sund itself (pinned mode); a reverse proxy only in the
  domain profile — see Deployment

Notes on the change from the original sketch (Kotlin/Ktor + PostgreSQL + Redis):

- The server component is ../sund, the blind relay extracted from Skerry
  (CLAUDE.md decisions 1 and 3, closed July 2026). Should a thin
  Family-Beacon-specific service ever prove necessary alongside Sund, it
  follows the same rule — Go + SQLite, one binary.
- PostgreSQL and Redis are dropped. SQLite is the database; at family scale
  there is no load that justifies separate database and cache processes, and
  backup becomes copying one file.
- Kotlin is not gone — it remains the natural choice for the Android client
  and shared client code. Only the server-side Ktor preference is superseded.

---

Core API

The server API is Sund's, specified in ../sund (PRD 0.3 and its implementation
guide). It has two planes: a management plane (device registration, device
list, revocation, key bundles, push endpoints, invitations) and a transport
plane (create/send/receive/ack/retire on blind queues). Family Beacon adds no
server endpoints of its own.

What the original sketch listed as endpoints are now end-to-end-encrypted
message types exchanged between clients over per-pair queues — the application
protocol specified in docs/FamilyBeacon-Protocol.md (a versioned envelope
+ message types):

- location update         (was POST /location)
- battery status          (was POST /battery)
- SOS                     (was POST /panic — same envelope at high priority,
                           delivered with a wake-up ping; broadcast to all)
- attention               (directed "contact me urgently" nudge to one member;
                           high priority, short TTL, no data, revocable allow —
                           deliberately a separate type from SOS)
- geofence event          (arrival/departure; originates on the moving device)
- settings / consent sync (was GET /commands + POST /ack; consent state is
                           exchanged between clients, never seen by the server)

Family membership (was GET /family + POST /invite) maps onto Sund's account
device list and invitation flow — see the walkthroughs in
../sund/docs/Sund-ImplementationGuide.md.

Communication uses HTTPS with JSON against Sund; payloads are opaque
ciphertext.

---

Database

Server side: the schema is Sund's, in one SQLite file — accounts, devices,
bundles, invitations, queues, messages. Nothing in it is Family Beacon-specific
and nothing in it is readable: payloads are ciphertext, and the schema stores
no sender-to-recipient links (see Sund's threat model).

Client side: each device keeps its own local store (e.g. Room on Android),
encrypted at rest, holding what the original sketch put on the server:

- family members and their devices (mirrored from Sund's device list)
- others' last-known location only — a received location overwrites the previous
  one; the app deliberately does not accumulate a movement trail of a family
  member (see Long-Term Features → Location history, and PRIVACY.md). The user's
  own location history is a separate, opt-in, local-only choice.
- geofences, and their discrete enter/exit events (bounded, not a track log)
- the transparency event log (the ethical line's activity ledger)
- per-feature consent state and settings

Keep the client schema simple and extensible; it can evolve per platform
because it is never shared over the wire — only protocol messages are.

---

Authentication

Sund's model — keys, not sessions:

- Per-device Ed25519 identity keypair; the private key never leaves the device.
- Management-plane requests are signed (device id, timestamp, nonce). No JWT,
  no refresh tokens, no passwords.
- Enrollment via QR: server address with pinned certificate fingerprint plus a
  single-use, short-TTL invitation token. Physical co-presence is the trust
  ceremony.
- Family-based authorization = Sund account membership. Every device sees the
  full device list; revocation is first-class — a removed device's key and
  queues die immediately.
- Transport-plane traffic authenticates with per-queue keys, unlinked to
  device identity.
- TLS everywhere, with the server certificate pinned from first contact.

---

Push Notifications

Instead of SMS — and instead of the original FCM sketch:

Android:

- UnifiedPush, with self-hosted ntfy as the default distributor (runs in the
  same compose file). Fully self-hostable; no Google dependency.

iOS:

- APNS remains structurally unavoidable: delivery goes through a
  vendor-operated push gateway that holds the APNS key. The gateway and Apple
  see wake timing only — never content or queue IDs.

Pings are payload-free by design: no content, no queue IDs, only "check in".
The original principle survives and is now structural: push only wakes the
app; actual data is always drained from Sund queues over the API.

Still open (CLAUDE.md decisions 2 and 4): who operates the iOS gateway and
what availability it promises, and what the SOS path guarantees when wake-up
is slow or down.

Not open, whatever that decision lands on: Family Beacon promises **no
guaranteed SOS delivery** and is **not a route to emergency services**. The SOS
path notifies family devices best-effort over the family's own
single-point-of-failure server; it never contacts an operator, authority or
alarm company. This limit is normative — see ETHICS.md (Safety limitations) — and
the clients must surface both facts in the UI at the point of use (arming/
triggering SOS, and onboarding), not bury them. Do not design or document the SOS
path in a way that implies a stronger promise than best-effort.

---

Offline Philosophy

Family Beacon should continue working even without network access.

Clients should:

- Cache configuration locally.
- Store location updates while offline.
- Synchronize automatically when connectivity returns.

The goal is graceful degradation rather than failure.

---

Deployment

Target deployment:

docker compose up -d

Two profiles for running a server. B is the recommended one for every deployment
that can have a domain; A is the fallback for those that cannot. Below both,
Try mode runs the product with no server at all — a trial, not a third profile;
see the end of this section.

Profile B — domain deployment (recommended)

Containers: sund (plain HTTP internally, no --tls-dir), ntfy (optional:
self-hosted UnifiedPush distributor for Android wake-up), caddy. Caddy
terminates ordinary WebPKI TLS on 443. Reference config: docker/caddy/Caddyfile.

Why this is the recommendation, and not merely the option for web users:
port 5870 is blocked on a large share of hotel, school, guest, airport and
corporate networks, which are precisely the networks a family member is on when
away from home — the situation the product exists for. A safety app that works
at the kitchen table and fails on a school trip has failed at its one job. Port
443 is the port that is open everywhere. That reachability argument applies to
every deployment, including a mobile-only family with no interest in the web
client, and it outweighs profile A's smaller setup.

Two things additionally require B outright:

- The web client. A browser cannot implement the pinning contract — there is no
  API to pin, and a request to a self-signed origin simply fails. apps/web
  structurally needs a real domain and a publicly trusted certificate, plus
  something to serve its static files. Caddy is both.
- A self-hosted, internet-facing ntfy. The phone-side UnifiedPush distributor
  validates against the public trust store and has no notion of Sund's pin, so
  that leg needs a trusted certificate whatever Sund does. (A public distributor
  such as ntfy.sh removes this; Sund→ntfy stays on the compose network.)
  Caddy is also what multiplexes 443 by SNI when Sund and ntfy both want it.

What B costs, and must be documented honestly: a domain, DNS records and ports
80/443 — none of which compose can bring up, so "up -d and nothing more" covers
the software but not the prerequisites; the proxy terminates TLS, making it a
component that sees Sund's API metadata in clear and would log it by default, so
the reference Caddyfile disables access logging explicitly; and a publicly
trusted certificate puts the hostname in Certificate Transparency logs,
permanently and publicly (the Caddyfile documents the wildcard-certificate
mitigation). Payload confidentiality is unaffected — content is end-to-end
encrypted below the transport, so none of this is a confidentiality regression,
only a metadata one.

Profile A — no domain (fallback)

Containers: sund run with `--tls-dir`, terminating TLS itself with a
fingerprint-pinned self-signed certificate, plus optional ntfy. The pin travels
in the onboarding QR as part of the server address
(`sund://host:port#fingerprint`); clients verify against it per
../sund/docs/Sund-Pinning-Contract.md.

No domain, no DNS, no ACME, no proxy — the whole deployment really is one
command, and it works on a bare IP or purely on the LAN. Choose it when a domain
is genuinely unavailable, when the deployment is LAN-only by intent, or to get
running before setting up DNS. Accept the consequence: devices will be
unreachable on networks that block non-standard ports, and there is no web
client. Serving the pinned listener on :443 instead of :5870 recovers part of
the reachability without a domain, but not on networks that intercept 443 —
pinning correctly refuses those, so the connection fails rather than downgrades.

Migrating A → B later is a re-pairing event: the server address in every
device's QR changes form. Prefer starting on B.

Try mode — no server at all (trial only, not a profile)

Below both profiles sits a third option that is deliberately not a peer of them:
Try mode, in which there is no Sund server and the same end-to-end-encrypted
envelopes travel over an ntfy instance (public or self-hosted), joined by QR.
Nothing to provision — no box, no domain, no Docker, no operator. It exists to
remove the adoption cliff, because even profile A presupposes someone willing to
be the operator *before* the family has seen the product work.

It is a trial, not a tier. Two guarantees are honestly weaker — messages are lost
past the ntfy instance's cache window, and revocation is client-side epoch
rotation with no server-side key kill — it does not help iOS at all (no
third-party push distributor exists there), and graduating to Sund re-pairs every
device, exactly like an A→B switch. The mode is named in onboarding, its limits
are restated where they bite, and the transparency ledger records which transport
a message travelled under; the app never presents it as equivalent to a Sund
deployment. Full spec, including the transport port that makes both backends
possible without weakening Sund mode: docs/FamilyBeacon-TryMode.md (CLAUDE.md
decision #8).

The client-side address form for B is `sund+webpki://host[:port]`, specified in
../sund/docs/Sund-Pinning-Contract.md §8 (added v0.2, July 2026): standard
platform TLS verification, no fragment, no fallback between modes in either
direction. Clients MUST implement both modes; the scheme selects which, and it
is stored per account rather than negotiated. Switching a running deployment
between modes re-pairs every device (§8.5), which is the other half of why the
profile choice belongs before onboarding.

Backup is copying one database file, in both profiles.

---

Long-Term Features

- Live location (interval share + on-demand pull; a location fix doubles as a
  liveness heartbeat)
- Location history — decided: no movement trail of others is built. Received
  location is kept as last-known only; the safety case needs "where now" plus
  discrete safe-zone events, not a track log. A user's own history stays a separate
  opt-in, local-only choice. See PRIVACY.md and docs/FamilyBeacon-DesignGuide.md
  (Live location → Retention).
- Geofences
- Battery status
- Contact me urgently — directed at one member, overrides their silent mode to get
  their attention; carries no data and is a grant they can revoke
- SOS — broadcast to the whole family about the sender's own situation; mandatory
  to receive. Distinct from the above in kind, not in degree; see
  docs/FamilyBeacon-DesignGuide.md → Two urgent channels
- Arrival / departure notifications
- Secure family chat (text in v1; image/media sharing depends on blob storage — see below)
- Web interface
- Home Assistant integration
- Guest access
- Webhooks

Media dependency: any feature that moves bytes larger than a single message —
shared images, member avatars, media in family chat, large/stored shared
configs — depends on bulk blob storage that Sund does not provide. Blob/object
storage is an explicit Sund *Non-goal* in V1 (see ../sund/docs/Sund-PRD.md →
Non-goals), added only when a consumer demonstrates need, as a separate optional
module keeping the same blindness guarantee. Family Beacon is that forcing
consumer: these features are deferred to a future protocol version whose first
step is driving the Sund blob module into existence, after which the clients
exchange encrypted blob references (not bytes) over the same E2E payloads. Until
then the wire protocol stays media-free. See docs/FamilyBeacon-Protocol.md →
Future versions.

---

Project Vision

Family Beacon aims to become a privacy-focused, self-hosted family safety platform.

The project should remain:

- Open source
- Easy to self-host
- Simple to understand
- Secure by default
- Independent of commercial cloud services

The server exists only to coordinate trusted family devices—not to collect or monetize user data.