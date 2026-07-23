# Family Beacon

**Family Beacon** is a privacy-focused, self-hosted family safety platform: live
location, geofences, battery status and SOS between trusted family devices —
coordinated by a small server **you** run.

> Own your family's safety data. The server exists only to coordinate trusted
> family devices — never to collect or monetize user data.

**Status: pre-alpha — design & spec stage.** The clients are not built yet; the
architecture, protocol, and design docs are the current work. This monorepo is the
successor to
[`family-beacon-android`](https://github.com/mevoc/family-beacon-android), the
original SMS-based peer-to-peer app. The SMS approach hit platform dead ends (RCS,
Play Store SMS permission policy, no iOS path), so development continues here as a
lightweight client/server architecture. See `ARCHITECTURE.md` for the vision.

## Architecture at a glance

- **Clients** — Android, iOS, web (in `apps/`). Push only *wakes* the app; data is
  drained from the server's blind queues, never carried in the push payload.
- **Server** — **Sund** (a separate repository): a blind, end-to-end-encrypted
  store-and-forward relay — one Go binary and one SQLite file. It stores ciphertext
  and minimal routing metadata and **cannot read your family's data**. Family Beacon
  adds no server endpoints of its own.
- **End-to-end encrypted** — content is readable only on family devices; the host
  who runs the server is an operator, not a viewer.
- **Deploy** — `docker compose up -d` brings up Sund, ntfy (Android wake-up) and
  Caddy. Put it on a domain with real TLS on port 443: port 5870 is blocked on
  many hotel, school and corporate networks — exactly where a family member is
  when the app matters most. A domain-less mode exists (Sund terminates TLS itself
  with a pinned certificate, nothing else required) and is the right choice for
  LAN-only setups, but it costs you that reachability and the web client. Backup
  is copying one database file.

## Layout

| Path | Contents |
| --- | --- |
| `apps/android`, `apps/ios`, `apps/web` | Client applications |
| `shared/protocol`, `shared/models` | Client-side protocol library and shared models |
| `docker/compose`, `docker/caddy` | Self-hosting deployment (Sund + ntfy + Caddy) |
| `docs/` | Architecture, protocol, design, and hosting documentation |

The server is **not** in this repo — it is Sund (Go + SQLite), maintained
separately.

## Key principles

- ✅ Self-hostable: `docker compose up -d` and nothing more to install (bring your
  own domain for the recommended deployment; a domain-less LAN mode needs nothing)
- ✅ End-to-end encrypted; the server is a blind relay that can't read your data
- ✅ Explicit opt-in for every feature — designed for family safety, not surveillance
- ✅ Transparent activity log visible to every device user
- ✅ No commercial cloud dependency, no data collection
- ✅ Open source (MIT)

## Documentation

- `ARCHITECTURE.md` — system vision and shape
- `ETHICS.md`, `PRIVACY.md` — the normative privacy and anti-surveillance line
- `docs/FamilyBeacon-DesignGuide.md` — app/client design (functionality, UX)
- `docs/FamilyBeacon-Protocol.md` — the client-side application protocol
- `docs/FamilyBeacon-HostingGuide.md` — **thinking of hosting for others?** the
  practical and legal (GDPR) side of running a server

## License

MIT — see `LICENSE`.
