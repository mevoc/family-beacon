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
    caddy/

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
- Caddy (preferred) or Nginx in front for TLS

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
                           delivered with a wake-up ping)
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

Containers:

- sund (the server: one static binary; its SQLite file lives in a volume)
- ntfy (optional: self-hosted UnifiedPush distributor for Android wake-up)
- caddy

Nothing more should be required. Backup is copying one database file.

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
- Contact me urgently
- SOS / Panic button
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