# Family Beacon

**Family Beacon** is a privacy-focused, self-hosted family safety platform: live
location, geofences, battery status and SOS between trusted family devices —
coordinated by a small server **you** run.

> Own your family's safety data. The server exists only to coordinate trusted
> family devices — never to collect or monetize user data.

**Status: pre-alpha.** This monorepo is the successor to
[`family-beacon-android`](https://github.com/mevoc/family-beacon-android), the
original SMS-based peer-to-peer app. The SMS approach hit platform dead ends
(RCS, Play Store SMS permission policy, no iOS path), so development continues
here as a lightweight client/server architecture. See `ARCHITECTURE.md` for the
vision.

## Layout

| Path | Contents |
| --- | --- |
| `apps/android`, `apps/ios`, `apps/web` | Client applications |
| `server/api`, `server/migrations` | Backend (Kotlin + Ktor, PostgreSQL) |
| `shared/api`, `shared/models` | Shared API contracts and models |
| `docker/compose`, `docker/caddy` | Self-hosting deployment |
| `docs/` | PRDs and design docs |

## Key principles

- ✅ Self-hostable: `docker compose up -d` and nothing more
- ✅ Explicit opt-in for every feature — designed for family safety, not surveillance
- ✅ Transparent activity log visible to every device user
- ✅ No commercial cloud dependency, no data collection
- ✅ Open source (MIT)

## License

MIT — see `LICENSE`.
