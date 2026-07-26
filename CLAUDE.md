# Family Beacon — Self-Hosted Family Safety Platform

Privacy-focused, self-hosted family safety: live location, geofences, battery
status, SOS and arrival/departure notifications between trusted family devices,
coordinated by a small server the family runs themselves.

**Status: the Rust core has begun (July 2026); no app yet.** `core/` holds
`beacon-protocol` (envelope codec, message registry, consent state machine,
ledger vocabulary), `sund-client` (the signed-request form, server addresses and
both transport-trust modes, the HTTP client, the two-plane API, the transport
port with its Sund implementation and an in-memory one, the session layer —
protocol identity key, key bundles, canonical JSON, the vodozemac ratchet and its
persistence — and the offline outbox), `beacon-roster` (the membership state machine: vouch-based
admission, removal and tombstones, the churn budget, reconciliation and split
detection) and `contract-tests` (tier 2, driving the real libraries against a
real relay in both modes — including a leg where devices actually found a family,
join it, and are introduced to each other by a relayed sealed address). Tiers 1
and 2 run in CI. Not yet written: the UniFFI bindings, and every app. `ARCHITECTURE.md` (the
founding vision doc) defines the shape; `core/README.md` maps what exists
against what does not.
Successor to `../family-beacon-android`, the original SMS-based peer-to-peer
app, which is kept frozen as-is; port client code from it selectively (see
below), but its SMS command layer is dead by design.

---

## The ethical line — carried over, and extended

The predecessor's defining constraint applies unchanged: **Family Beacon is NOT for
covert monitoring.** Explicit opt-in per feature, no silent capability, a
transparent activity log, always disable/uninstallable. Any change that makes the
app harder for its own user to see, disable or uninstall is wrong — raise it, don't
implement it.

The client/server architecture adds a **new asymmetry the SMS model never had**: the
family member who hosts the server can potentially see everyone's data at the DB
level. The server-side analogue of the ethical line is therefore normative too:

- **No covert read access for the server admin.** Every query the server answers
  about a device must be visible in that device's activity log.
- The admin role is an operator role, not a surveillance role. Design against the
  abusive-host scenario explicitly.

With `../sund` adopted (decision #1), the server-side line holds structurally
rather than by policy: the server cannot read content at all. What remains to
police is honesty about residual metadata (Sund's threat model) — see #5.

---

## Architecture (from ARCHITECTURE.md)

- **Backend:** Go + SQLite — one static binary, one database file (locked July
  2026 per `../sund/docs/Sund-PRD.md` decision 10; supersedes the original
  Ktor + PostgreSQL sketch). Intended server: `../sund`, terminating pinned TLS
  itself (no reverse proxy by default — see Deployment). Intentionally small.
- **Client core:** `core/` — a Rust workspace (`beacon-protocol`, `sund-client`,
  UniFFI bindings) holding envelope, session crypto, consent, ledger and roster,
  bound into every app (decision #6). Kotlin is the Android *app* layer only.
- **Clients:** `apps/android`, `apps/ios`, `apps/web` — **Android first**, to a
  complete v1 safety core, before iOS or web start (decision #10). Push only *wakes* the app
  (payload-free pings; UnifiedPush/ntfy on Android, APNS via vendor gateway on
  iOS) — data is always drained from Sund queues, never carried in the push.
- **Offline philosophy:** graceful degradation. Clients cache config, queue location
  updates offline, sync on reconnect.
- **Deployment:** two profiles (ARCHITECTURE.md → Deployment).
  **B (domain) is recommended for all deployments:** `sund` (plain HTTP) +
  `ntfy` (optional) + `caddy` terminating WebPKI TLS on 443, reference config
  in `docker/caddy/Caddyfile`. The reason is reachability, not the web client —
  :5870 is blocked on hotel/school/corporate networks, i.e. exactly where a
  family member is when the app matters. It is *additionally* mandatory for the
  web client (browsers cannot implement the pinning contract) and for an
  internet-facing self-hosted ntfy. Costs: a domain + DNS + ports 80/443,
  proxy-visible API metadata (so access logging is off in the reference config),
  and a public Certificate Transparency entry for the hostname.
  **A (no domain) is the fallback:** `sund --tls-dir` (pinned TLS, nothing else)
  for LAN-only or domain-less setups; no web client, and unreachable on
  port-blocking networks. Compose must still bring up the whole software stack
  in one command in both profiles — that's a hard constraint, not a hope; a
  domain is an operator prerequisite of B, not an extra moving part.
  Client address forms: `sund://host:port#fingerprint` (A) and
  `sund+webpki://host[:port]` (B), both normative in
  `../sund/docs/Sund-Pinning-Contract.md` (§8 added v0.2, July 2026). Clients
  implement both; no fallback between modes, and a mode switch re-pairs every
  device — so pick the profile before onboarding a family.

## Design decisions — resolve open ones before building the affected part

1. **E2EE stance — CLOSED (July 2026): end-to-end, server as blind relay.**
   Resolved by adopting `../sund` as the backend: the server stores ciphertext
   and minimal routing metadata, structurally — it cannot see location plaintext,
   so the admin-asymmetry problem dissolves rather than being policed. Residual
   metadata (timing, sizes, queue ownership) is documented in Sund's threat model
   and must be stated honestly in PRIVACY.md (see #5). See
   `sund/docs/Sund-PRD.md`.
2. **Push without lock-in.** FCM requires a Firebase project per self-hoster (or a
   central one, which re-centralizes traffic). UnifiedPush/ntfy is the candidate for
   Android; iOS has no APNS alternative. Contradicts "no commercial cloud
   dependency" until resolved. Analysis now in `sund/docs/Sund-PRD.md` (Push
   architecture): Android fully self-hostable via UnifiedPush; iOS structurally
   requires a vendor-operated APNS gateway seeing wake timing only — "no lock-in"
   is unattainable there, only containment. Resolve together with #4 (SOS path
   when wake-up is slow or down).
   **Deferred, not answered (July 2026):** decision #10 sequences Android first,
   so the gateway question leaves the critical path. Resolve both before iOS work
   starts; neither blocks Android.
3. **Skerry coupling — CLOSED (July 2026): consume `../sund`.** Family Beacon
   depends on Sund — the Layer-1 kernel extracted from Skerry (`../skerry`) — and
   on nothing else of Skerry. The app exercises the kernel both projects share,
   so the reference-app loop holds without coupling Family Beacon to the full
   platform. Stack: Go + SQLite (locked); ARCHITECTURE.md rewritten accordingly.
4. **Safety availability.** SMS worked without mobile data; a self-hosted server is
   a single point of failure (home server + power outage). Decide what the panic
   path promises when the server is unreachable — possibly a degraded SMS fallback
   for SOS only. **Fixed regardless of how this resolves:** Family Beacon gives no
   guaranteed SOS delivery and is not a route to emergency services (never contacts
   police/ambulance/fire/alarm operators). This is normative in ETHICS.md (Safety
   limitations) and must be surfaced in the UI at the point of use; never design or
   document SOS to imply a stronger promise than best-effort.
5. **ETHICS.md / PRIVACY.md — CLOSED (July 2026): rewritten for this architecture**
   (repo root, normative). New over the predecessor: the server-side ethical line
   held structurally (blind relay, admin = operator role), honest residual-metadata
   statement (from Sund's threat model), the SOS consent exception, iOS push third
   parties, retention/deletion, children's transparency on their own device, and
   GDPR for self-hosting (household exemption; hosting beyond the household may
   create data-controller duties). The protocol spec's consent state machine and
   ledger rule are the protocol-level half of the same guarantees.
6. **Client library packaging — CLOSED (July 2026): a Rust core with UniFFI
   bindings, session crypto by vodozemac.** The client code splits into two
   reusable libraries — app-agnostic `sund-client` (identity, pairing, sessions,
   queues, push) and FB-specific `beacon-protocol` (envelope, types, consent,
   ledger); the boundary is fixed in `docs/FamilyBeacon-Protocol.md` (Layering)
   so sund-client can be reused by other projects. Resolved together with the
   session primitive, because the two were never separable — the audited
   double-ratchet implementations are Rust, so the crypto choice decided the
   language.
   - **Session primitive: a double ratchet, not Noise.** Delivery here is
     at-least-once and deliberately lossy (short TTLs; Try mode's cache window
     drops messages permanently), so skipped-message-key handling is required —
     Noise's transport phase assumes a reliable ordered stream, and adding
     out-of-order handling plus rekeying to it means *building* the ratchet the
     spec says to adopt. A ratchet also gives post-compromise recovery, which the
     stolen-device and hostile-member scenarios need.
   - **Implementation: vodozemac** (Matrix's Rust Olm — X3DH + double ratchet),
     Apache-2.0 and independently audited. Chosen over libsignal, which is the
     better-audited library but is **AGPL-3.0-only** and would force the clients
     off MIT. Revisit only if that licensing trade is deliberately accepted;
     libsignal additionally brings PQXDH, which vodozemac does not have.
   - **One-time prekeys: run in fallback-key mode.** Sund stores key bundles
     opaquely and does not pop one-time prekeys (Sund's Architecture Principle
     forbids interpreting them), so concurrent fetchers would reuse an OTK. Olm's
     signed fallback key is the built-in answer: use it with frequent rotation and
     accept signed-prekey-grade forward secrecy for the initial message only,
     until the first ratchet step. Do not ask Sund for a pop-prekey primitive.
     **Rotation period: 7 days**, derived from Sund's TTL clamp — see
     `docs/FamilyBeacon-Sessions.md`.
   - **Session layer built July 2026; two sub-decisions closed with it**, both
     specified in `docs/FamilyBeacon-Sessions.md` and both re-pairing migrations
     if reversed, so treat them as settled:
     - **A separate protocol identity key.** Every device holds two Ed25519 keys:
       `sigauth::DeviceKey` signs HTTP requests to a server, and
       `identity::IdentityKey` is the roster's `identity_pk` — it signs bundles,
       vouches and tombstones. Chosen because the roster sits above the transport
       port and Try mode has no server key, and because it sharpens the dishonest
       host's limits: the host owns the device-list row and can never forge a
       bundle. The binding between the two keys is the vouch and nothing else,
       which is the roster's own position. The app layer must generate and store
       **two** seeds.
     - **Grant-only key bundles.** A bundle carries key material and no
       initiation address, so a device is reachable only by peers that were handed
       a queue sender id deliberately. Rejected the published-bundle mesh: it
       makes every member spammable by every other, including by a
       host-injected device before the vouch check rejects it. The cost lands on
       the roster — the introducer relays initiation addresses at join
       (`docs/FamilyBeacon-Roster.md` → Admission, steps 5a–5c), still unbuilt.
     One cross-repo divergence, raised not resolved: Sund's PRD says a fetcher
     verifies a bundle "against the device list"; this implementation verifies
     against the roster's vouched `identity_pk`, which is strictly stronger. Sund's
     wording should be amended; the server behaves identically either way.
   - **The split:** Rust owns everything from `beacon-protocol` down through
     `sund-client` — envelope codec, session crypto, the roster state machine
     (#9), the consent state machine, offline outbox, transport port. Native owns
     the app layer: UI, location/geofence, push registration, background
     scheduling, biometrics, notifications, local storage. That is the layering
     doc's own seam, not a new one.
   - **Known costs, accepted:** NDK cross-compilation, xcframework packaging and
     wasm-pack in CI from day one; worse cross-FFI debugging. UniFFI friction
     concentrates on async and callbacks — and the transport port is
     `subscribe → stream`, so design that boundary deliberately rather than
     assuming the generator handles it. The core must be drivable from outside
     (WorkManager, BGTask) rather than owning its own loop.
   - Rejected: **Kotlin Multiplatform** — best on the platform shipping first, but
     no audited multiplatform double ratchet exists, so it either re-adds per-
     platform FFI or writes the ratchet by hand. **Per-platform native** — three
     or four implementations of the roster merge and consent state machines,
     forever; test vectors catch encoding drift well and state-machine drift
     poorly, which is exactly backwards for this codebase. **MLS/OpenMLS** — needs
     a totally-ordered group delivery service; Sund gives per-pair queues with
     undefined cross-queue order by design, and the protocol has no group
     semantics on the wire.
7. **Urgent contact vs. SOS — CLOSED (July 2026): two separate v1 features,
   different in kind.** "Contact me urgently" (`attention`) is directed at one
   member, overrides their ringer, carries no data, and is an inbound *allow*
   they grant, revoke and rate-limit at their own device. SOS is a broadcast
   about the sender's own situation, mandatory to receive, and overrides sharing
   for its own content. Neither auto-escalates into the other and no client may
   synthesize one from the other — a family with no directed channel will misuse
   the broadcast one, and an alarm that cries wolf is worse than none. Promoted
   into the v1 safety core; spec in `docs/FamilyBeacon-Protocol.md`, product/UX
   rules in the design guide ("Two urgent channels"), the interruption-budget
   rule normative in ETHICS.md.
8. **Try mode (serverless ntfy transport) — DECIDED IN SHAPE (July 2026);
   SEQUENCED AFTER SUND MODE.** To remove the adoption cliff (profile A still presupposes an
   operator, a machine that stays up, and Docker — asked *before* the family has
   seen the product work), Family Beacon gains a second transport: the same
   E2E-encrypted envelopes over an ntfy instance, joined by QR, no server to
   provision. Spec: `docs/FamilyBeacon-TryMode.md`. Fixed by that decision:
   - The seam is a **narrow transport port** (`send`/`subscribe`/`ack`/channel
     lifecycle) below `beacon-protocol`; `ntfy-client` is a sibling of
     `sund-client`, and nothing above the port changes. **Management-plane
     capability stays above the port** — membership, introductions and
     revocation become explicit client-side logic, and Sund mode uses its
     management plane as a *stronger implementation* of that logic, never as the
     only one. Widening the port to fit both backends would design Sund mode
     down to ntfy's level; don't.
   - Try mode is a trial, not a tier. It is honestly weaker on two things —
     messages are lost past the instance's cache window, and revocation is
     epoch rotation with no server-side kill — and graduating to Sund
     **re-pairs every device**, like an A→B switch.
   - **The abstraction must not hide the downgrade** (normative): the mode is
     named in onboarding, its limits restated where they bite (device removal,
     SOS arming), the transparency ledger records the transport mode, and the
     app never presents Try mode as equivalent to a Sund deployment.
   - It does **not** help iOS — no third-party push distributor exists there, so
     an iOS client still needs the vendor APNS gateway of decision #2.
   **Timing — decided July 2026: not before Sund mode works end to end.** Try
   mode is additive and touches no normative guarantee, so it costs nothing to
   defer and would cost a lot to build against an unproven transport layer:
   the port has no second implementation to keep honest until the first one
   ships. Build Sund mode, then add ntfy-client behind the same port. Define
   the port now regardless — it is also the seam that lets the libraries be
   unit-tested against an in-memory transport, so it earns its keep before Try
   mode exists.
   Still open: state reconciliation after cache-window loss, which is blocking
   for Try mode — without it `consent_update` / `config_update` are not merely
   weaker but incorrect. Remaining open items are listed in the spec.
9. **Family roster — CLOSED (July 2026): specified in
   `docs/FamilyBeacon-Roster.md`.** The membership layer decision #8 pushed above
   the transport port, previously named in the layering diagrams and specified
   nowhere. Fixed by that spec:
   - **The consent principal is a device, not a person.** Members are a display
     grouping over devices; grants, channels, ledger entries and revocation all
     name a device. A "share with all of Dad's devices" convenience expands into
     per-device grants and never becomes one grant a future device inherits.
   - **The server's device list is not the authority on membership.** Admission
     requires a signed vouch from an existing member, carried end-to-end. An
     abusive host can add a row to Sund's `devices` table; a client that admitted
     peers from that list would pair with an injected device. The list stays
     authoritative for revocation and for locating key material — a host can deny
     service, visibly, and cannot inject.
   - **No in-app admin.** Roles are labels that seed defaults and never confer
     authority over another device. Any active device may remove any other; a
     device may always remove itself and leave. Chosen against the abusive-member
     case: concentrating removal in an admin hands the wrong person a lock, and
     the permissive rule's failure mode (eviction, loud and ledgered) is
     recoverable while the restrictive one's is not.
   - Channels are established automatically on join, consent is not — the channel
     is the pipe and the valve ships closed, so a new member can raise an SOS
     before anyone has tapped Accept.
   - **Abuse is bounded by two constants, both build-time:** 20 active devices
     per family (enforced at admission, never by degrading sync), and 5 membership
     events per device per rolling day. The second is a *churn* budget — it counts
     removals as well as vouches, because the attack is the two in a loop — and it
     is enforced at the verifier, since the introducer is the attacker. Over
     budget holds an admission for human approval; an over-budget removal still
     applies immediately, because removal is fail-safe and admission is not.
   **Built July 2026** in `core/beacon-roster`, with the wire types in
   `beacon-protocol`'s `roster` module and vectors in
   `shared/protocol/testvectors/roster.json`. Two ambiguities in the spec were
   settled in the building and written back into it, both in the safer direction:
   - **A server revocation deactivates a record; it does not tombstone it.**
     "Treat as removed" did not say which, and tombstones are permanent — so
     tombstoning on the host's say-so would let a host that revokes everything
     destroy a family's roster irreversibly, since re-admission needs a fresh
     device id. Deactivating keeps the honest case identical and the dishonest
     one recoverable by a fresh vouch.
   - **A removal naming the receiver is accepted even from a device the receiver
     has already removed.** Otherwise mutual eviction is undetectable in exactly
     the ordering that produces it, and the removed device is never told — which
     the spec forbids. It grants the remover nothing: it records a fact about the
     receiver's own standing and still requires a valid signature.
   Remaining open item in the spec: the founding device self-vouches, so whether a
   second device should co-sign the founding record is undecided. Not blocking.
   **The initiation-address relay is built (July 2026)** — the piece grant-only
   bundles made necessary, wire type `channel_offer`, in `beacon-roster`'s
   `pairing` module. Three properties are load-bearing and were settled in the
   building: the address is **sealed to its recipient**, so the introducer is a
   courier who never holds the capability it is introducing (a relayer that could
   read it could bind the queue's sender key first and permanently break the pair
   it was introducing); only **one direction is relayed**, because once the peer
   holds an address it can reply directly; and a relayer forwards **only an
   address its owner personally handed it**, which is what stops the relay
   becoming a general-purpose forwarding primitive. A relayer can still drop or
   replay an offer — both loud and recoverable, documented in the spec.
10. **Client build order — CLOSED (July 2026): Android first**, to a complete v1
   safety core, before iOS or web start. Rationale in ARCHITECTURE.md (Client
   platforms and build order): Android is the only platform where the whole stack
   is self-hostable today, Sund's only push provider is UnifiedPush, and it is the
   platform with code to port from `../family-beacon-android`. Consequences:
   decisions #2 and #4 are deferred off the critical path (resolve before iOS
   starts); the client libraries must not become Android-shaped, which the shared
   test vectors and beaconsim (a third implementation, third language) are there
   to enforce; web is second and scoped as a companion first.

## Porting from family-beacon-android

Transport-agnostic client code worth porting: `GeofenceHelper`, `LocationFgService`,
consent flow, `AuthHelper` (biometric), the transparent event log (Room), UI
screens. **Do not port:** `SmsReceiver`, `SmsUtil`, whitelist/`ContactStore` — the
SMS command model is the thing being replaced.

---

## Conventions

- Code, comments and commits in English. UI localised Swedish + English (keep
  string files in sync, as in the predecessor).
- Product decisions go in `docs/` PRDs, not code comments.
- Repo: to be published as `github.com/mevoc/family-beacon` (public, MIT).

## Docs

- `ARCHITECTURE.md` — founding vision, revised July 2026 around Sund adoption and
  the Go + SQLite stack lock.
- `ETHICS.md`, `PRIVACY.md` — **normative, not marketing copy** (July 2026 rewrite
  for the Sund architecture; the predecessor's versions stay with the SMS product).
- `docs/FamilyBeacon-Protocol.md` — the client-side application protocol:
  versioned envelope, message types (location/battery/sos/attention/geofence/
  consent/config/member_info/receipt), consent state machine, ledger rule, library
  layering (sund-client / beacon-protocol), test-vector discipline.
- `docs/FamilyBeacon-Sessions.md` — session crypto (the below of the protocol
  spec's plaintext boundary): the protocol identity key and its signing domains,
  canonical JSON, the grant-only bundle format, fallback-key rotation, the
  vodozemac ratchet and its two loss bounds, persistence and recovery. Read it
  before touching anything that encrypts, signs or persists key material.
- `docs/FamilyBeacon-Roster.md` — the membership layer (decision #9): device-as-
  principal, the vouch-based admission protocol, removal and tombstones,
  reconciliation, and why the server's device list is not the authority on who is
  in the family. Read it before touching pairing, family management or
  revocation in any client.
- `docs/FamilyBeacon-DesignGuide.md` — the app/client design guide (living):
  product functionality, UX principles, core flows, per-platform strategy, and
  app-level design decisions. The middle layer between the normative docs and the
  clients; iterate on how the apps work and feel here.
- `docs/FamilyBeacon-TryMode.md` — the serverless ntfy transport (decision #8):
  the transport port and where the seam goes, topic derivation, the QR join
  ceremony, epoch rotation, and an explicit account of what degrades. Read it
  before touching the client's transport layer — the port boundary it fixes also
  constrains Sund mode.
- `docs/FamilyBeacon-HostingGuide.md` — practical + legal (GDPR/Sweden) guide for
  running a server, centered on the household-vs-hosting-for-others line. Not legal
  advice; complements PRIVACY.md's "Self-hosting and the GDPR" section.
- The predecessor's `docs/family-beacon-prd-0.2.md` covers the *old* SMS product
  only.
