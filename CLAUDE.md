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

---

## Architecture (from ARCHITECTURE.md)

- **Backend:** Kotlin + Ktor (preferred; Go is the fallback), PostgreSQL, optional
  Redis, Caddy in front. Intentionally small.
- **Clients:** `apps/android`, `apps/ios`, `apps/web`. Push (FCM/APNS) only *wakes*
  the app — data is always fetched from the API, never carried in the push payload.
- **Offline philosophy:** graceful degradation. Clients cache config, queue location
  updates offline, sync on reconnect.
- **Deployment:** `docker compose up -d` → `api`, `postgres`, `redis` (optional),
  `caddy`. Nothing more may be required — that's a hard constraint, not a hope.

## Open decisions — resolve before building the affected part

1. **E2EE stance.** Current API sketch has the server seeing location plaintext.
   End-to-end encryption (server as dumb relay) would dissolve the admin-asymmetry
   problem but constrains schema, sync and invitations. **Decide before the schema
   exists — this cannot be retrofitted.**
2. **Push without lock-in.** FCM requires a Firebase project per self-hoster (or a
   central one, which re-centralizes traffic). UnifiedPush/ntfy is the candidate for
   Android; iOS has no APNS alternative. Contradicts "no commercial cloud
   dependency" until resolved.
3. **Micro Cloud coupling.** This is the intended reference app for `../micro-cloud`
   (its PRD names Family Beacon). Standalone-first (own auth/push per
   ARCHITECTURE.md) or Micro-Cloud-first (consume its Layer 1 auth/push/storage)?
   Building both means the reference app never exercises the platform.
4. **Safety availability.** SMS worked without mobile data; a self-hosted server is
   a single point of failure (home server + power outage). Decide what the panic
   path promises when the server is unreachable — possibly a degraded SMS fallback
   for SOS only.
5. **ETHICS.md / PRIVACY.md.** The predecessor's versions are normative but written
   for the SMS/no-server model. Rewrite for this architecture (incl. GDPR: the
   hosting family member is a data controller for location data, typically of
   minors) — don't copy them verbatim.

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

- `ARCHITECTURE.md` — founding vision: layers, stack, API sketch, long-term features.
- `docs/` — PRDs to come; the predecessor's `docs/family-beacon-prd-0.2.md` covers
  the *old* SMS product only.
