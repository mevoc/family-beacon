Family Beacon – Architecture Vision

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

server/
    api/
    migrations/

shared/
    api/
    models/

docker/
    compose/
    caddy/

docs/

ARCHITECTURE.md
README.md

---

Backend

The backend should be intentionally small.

Suggested stack:

- Kotlin + Ktor (preferred) or Go
- PostgreSQL
- Redis (optional)
- Docker Compose
- Caddy (preferred) or Nginx

---

Core API

Examples:

POST /register
POST /login

POST /location
POST /battery
POST /panic

GET /commands
POST /ack

GET /family
POST /invite

Communication uses HTTPS with JSON.

---

Database

Initial entities:

- User
- Family
- Device
- Invitation
- DeviceLocation
- Geofence
- Notification
- DeviceSettings

Keep the schema simple and extensible.

---

Authentication

- JWT access tokens
- Refresh tokens
- TLS everywhere
- Device registration
- Family-based authorization

---

Push Notifications

Instead of SMS:

Android:

- Firebase Cloud Messaging (FCM)

iOS:

- Apple Push Notification Service (APNS)

Push notifications only wake the app.

Actual data is always fetched from the API.

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

- api
- postgres
- redis (optional)
- caddy

Nothing more should be required.

---

Long-Term Features

- Live location
- Location history
- Geofences
- Battery status
- SOS / Panic button
- Arrival / departure notifications
- Secure family chat
- Web interface
- Home Assistant integration
- Guest access
- Webhooks

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