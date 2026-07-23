# Family Beacon — Self-Hosted Family Safety Platform

Privacy-focused, self-hosted family safety: live location, geofences, battery
status, SOS and arrival/departure notifications between trusted family devices,
coordinated by a small server the family runs themselves.

**Status: greenfield — no code yet.** `ARCHITECTURE.md` (the founding vision doc)
defines the shape. Successor to `../family-beacon-android`, the original SMS-based
peer-to-peer app, which is kept frozen as-is; port client code from it selectively
(see below), but its SMS command layer is dead by design.

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
  itself (no reverse proxy by default — see Deployment). Intentionally small. Kotlin stays for the Android client / shared client code.
- **Clients:** `apps/android`, `apps/ios`, `apps/web`. Push only *wakes* the app
  (payload-free pings; UnifiedPush/ntfy on Android, APNS via vendor gateway on
  iOS) — data is always drained from Sund queues, never carried in the push.
- **Offline philosophy:** graceful degradation. Clients cache config, queue location
  updates offline, sync on reconnect.
- **Deployment:** two profiles (ARCHITECTURE.md → Deployment). **A (default):**
  `docker compose up -d` → `sund` (with `--tls-dir`: it terminates pinned TLS
  itself, no domain/DNS/ACME) + `ntfy` (optional). **B (domain):** adds `caddy`
  for WebPKI — required for the web client (browsers cannot pin), for an
  internet-facing self-hosted ntfy, and for port-443 reachability on hostile
  networks; costs a domain, proxy-visible API metadata, and a public
  Certificate Transparency entry for the household hostname. Profile A must
  stay at "nothing more required" — that's a hard constraint, not a hope.

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
6. **Client library packaging.** The client code splits into two reusable
   libraries — app-agnostic `sund-client` (identity, pairing, sessions, queues,
   push) and FB-specific `beacon-protocol` (envelope, types, consent, ledger);
   the boundary is fixed in `docs/FamilyBeacon-Protocol.md` (Layering) so
   sund-client can be reused by other projects. Open: implementation strategy —
   Kotlin Multiplatform, a Rust core with generated bindings, or per-platform
   native code disciplined by the spec's shared test vectors.
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
- `docs/FamilyBeacon-DesignGuide.md` — the app/client design guide (living):
  product functionality, UX principles, core flows, per-platform strategy, and
  app-level design decisions. The middle layer between the normative docs and the
  clients; iterate on how the apps work and feel here.
- `docs/FamilyBeacon-HostingGuide.md` — practical + legal (GDPR/Sweden) guide for
  running a server, centered on the household-vs-hosting-for-others line. Not legal
  advice; complements PRIVACY.md's "Self-hosting and the GDPR" section.
- The predecessor's `docs/family-beacon-prd-0.2.md` covers the *old* SMS product
  only.
