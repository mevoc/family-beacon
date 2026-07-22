Family Beacon — Client-Side Protocol

Status: v0.1 (Draft)

This is the application protocol ARCHITECTURE.md's Core API section calls for:
the versioned envelope and message types that Family Beacon clients exchange
over Sund's blind queues. Everything specified here travels as opaque
ciphertext from the server's point of view — Sund (`../../sund`) is the
transport and is specified separately; this document never adds server
behavior. If something in this spec seems to need the server to understand a
message, the spec is wrong (Sund's Architecture Principle).

---

Design constraints

- Server-blind. The envelope, types and semantics below exist only inside
  encrypted payloads. The server sees size and timing, nothing else.
- Versioned for mixed families. Phones update at different times; a family is
  a permanently mixed-version deployment. Unknown must be survivable.
- Small. Every message fits Sund's payload size cap (64 KiB per message). No
  media in v1: photos, avatars and other large or persisted objects wait for
  bulk blob storage, which Sund does not provide. Blob/object storage is an
  explicit Sund *Non-goal* in V1, added only "when a consumer demonstrates
  need" as a separate optional module keeping the same blindness guarantee —
  and Family Beacon is that forcing consumer. Shipping shared images, avatars
  and stored configs is therefore a future-version item for Family Beacon that
  must first drive the Sund blob module into existence; it is out of scope for
  this spec (see Future versions).
- Consent-first. Consent is not UI polish on top of the protocol; it is
  enforced at the sender, in the protocol layer. Data for a feature without a
  grant never leaves the device.
- Ledgered. Every message sent or received produces an entry in the device's
  transparency ledger (the ethical line's activity log). No message type is
  exempt — a type that "shouldn't be shown to the user" is a design smell.

---

Layering

    Family Beacon apps        UI, notifications, policy, SOS escalation
    ─────────────────────────────────────────────────────────────────
    beacon-protocol library   this spec: envelope codec, message types,
                              consent state machine, transparency ledger
    ─────────────────────────────────────────────────────────────────
    sund-client library       generic, app-agnostic: device identity and
                              request signing, enrollment (QR), pairing,
                              session crypto, queue lifecycle and rotation,
                              offline outbox/retry, push registration
    ─────────────────────────────────────────────────────────────────
    Sund server API           blind queues (see ../../sund)

The two libraries are deliberately separable. sund-client contains nothing
about families or locations — it is the client half of Sund itself, reusable
by any project that adopts Sund as a backend (several candidates exist in this
workspace). beacon-protocol is Family Beacon's own layer. The packaging and
language strategy for both is an open decision (see end of this document);
what is fixed is the boundary between them.

Note on implementations: the Sund system-test client (beaconsim, in Go) is a
third implementation of much of this logic. Three implementations drift unless
tested against one source of truth — this spec must ship machine-readable test
vectors (sample envelopes, canonical encodings, consent scenarios) that every
implementation verifies against.

---

Transport assumptions (provided by sund-client, not specified here)

- Each pair of devices in the family shares a duplex pair of blind queues
  (Sund implementation guide, Walkthrough 2) plus an established end-to-end
  session providing confidentiality, integrity, sender authentication and
  forward secrecy. The session primitive is an open decision (established
  double-ratchet implementation vs. a Noise-based channel — adopt, don't
  build); this spec is agnostic: it defines the plaintext handed to the
  session layer.
- Delivery is at-least-once (queue redelivery is possible) and per-queue
  ordered, but cross-queue order is undefined. Hence dedupe ids and sequence
  numbers below.
- Group semantics do not exist on the wire. "The family" is a client-side
  composition over per-pair channels: sending to the family means sending the
  same message over every pair the sender has.

---

Envelope

The unit handed to the session layer for encryption. JSON in v1 (a compact
binary encoding can come later behind the same field names; decide in the
library, not per app).

    {
      "v": 1,                      // envelope version
      "id": "uuid",                // unique per message; dedupe key
      "seq": 412,                  // per-sender, per-pair monotonic counter
      "type": "location",          // message type, see below
      "sent": "2026-07-19T10:04:12Z",
      "sender": "dev_A",           // sender's Sund device id
      "body": { ... }              // type-specific
    }

Rules:

- v bumps only on breaking envelope changes. Type-level evolution happens in
  bodies, additively: unknown body fields are ignored, never errors.
- An unknown type is not an error: ledger it ("message of unknown type from
  Emma's phone — app update needed?"), acknowledge nothing, drop the body.
- sender must match the device authenticated by the session; on mismatch the
  message is rejected and the rejection is ledgered. The field exists for
  attribution after decryption, not as the source of trust.
- seq gaps after dedupe indicate loss or expiry (Sund deletes expired
  messages unread); the receiver may surface staleness ("last update 2 h
  ago"), never silently interpolate.

---

Message types — v1

location
    lat, lon, accuracy_m, recorded_at; optional: speed, heading, altitude,
    battery (convenience copy). Sent on the app's cadence/significant-change
    policy (app concern, not protocol). Requires an active location grant to
    the recipient. Short Sund TTL: a stale location is worse than none.

battery
    level_pct, charging. Sent on threshold crossings (e.g. low battery).
    Requires the battery grant. Short TTL.

sos
    recorded_at, last_location (optional — sent even without a location
    grant: an explicit SOS overrides granted sharing for its own content,
    and this exception is stated in the consent UI, not buried here),
    note (optional, short). Sent to every pair at maximum Sund priority with
    maximum TTL, delivered with a wake-up ping. Requires receipt (below);
    the sender app escalates while unacknowledged (re-send, then the
    degraded path of CLAUDE.md decision #4 — outside this spec). Best-effort
    only: at-least-once delivery over a single-point-of-failure server means an
    SOS may be delayed or never arrive, and neither this protocol nor Sund
    guarantees delivery. Family Beacon SOS is not a call to emergency services
    or any authority (ETHICS.md → Safety limitations); clients must surface both
    limits in the UI at the point of use.

sos_clear
    references the sos id; stands the alert down on all devices. Same
    delivery treatment as sos.

geofence_event
    fence_id, transition (enter | exit), recorded_at. Emitted by the moving
    device — the fence is evaluated on the device it concerns, which
    therefore must hold the fence definition and have granted the geofence
    feature. There is no server-side or observer-side fence evaluation.

consent_update
    feature (location | battery | geofence | …), action (grant | revoke),
    optional scope (e.g. a fence id). Directional and pairwise: the data
    producer grants the observer. Enforcement lives at the producer — a
    revoke takes effect locally and immediately; the message informs the
    peer's UI, it does not implement the revocation. Requires receipt.

config_update
    key, value, owner_rev. Shared configuration: fence definitions,
    notification preferences a pair has agreed on. v1 conflict model is
    ownership: each config item is owned by the device that created it and
    only the owner updates it (owner_rev increments). No CRDTs until a real
    need appears.

member_info
    display_name; avatar deferred to a future version (needs Sund's blob
    module, a Non-goal until Family Beacon forces it — see Future versions).
    Sent on join and on change.

receipt
    of (message id), status (delivered | seen). Mandatory for sos, sos_clear
    and consent_update. For everything else, receipts are off by default —
    "seen" tracking of routine location updates is surveillance-adjacent and
    stays opt-in per pair, both directions aware (it is itself a feature
    requiring a grant).

---

Consent state machine (normative)

- State lives at the producer: a per-(feature, observer) grant set, changed
  only by the device's own user, persisted locally, every change ledgered.
- Default deny. A fresh pairing shares nothing but member_info and the
  ability to receive sos.
- Grants are advertised via consent_update so the observer's UI can reflect
  reality, but the advertisement is informational — enforcement is the
  producer refusing to emit.
- Revocation cannot be blocked, delayed, or made invisible by the observer.
  The predecessor's rule holds: anything that hides sharing state from the
  person being shared is wrong.

---

Versioning and compatibility

- A client states its protocol version in member_info (proto_v). Clients
  never refuse to talk to older versions; they degrade to the intersection
  of understood types and ledger what they had to ignore.
- Test vectors: canonical example envelopes for every type, both valid and
  deliberately malformed, live beside this spec and gate all
  implementations' CI (beacon-protocol libraries and beaconsim alike).

---

Open items

1. Session primitive: established double-ratchet implementation vs.
   Noise-based channel. Owned by sund-client's design; blocking for any
   client code, not for this spec.
2. Library implementation strategy: Kotlin Multiplatform (shared
   Android/iOS), a Rust core with generated bindings, or per-platform native
   implementations disciplined by the shared test vectors. beaconsim (Go)
   exists regardless — the test-vector discipline is needed in every variant,
   so it is decided (see Versioning); the packaging choice is not.
3. Receipt policy details: whether "delivered" receipts (not "seen") should
   be default-on for location to power staleness UI, or whether seq-gap
   detection suffices.
4. config_update ownership model: sufficient for fences and shared prefs, or
   does any config genuinely need multi-writer semantics?

---

Proposed for v0.2 — presence heartbeat (candidate, not yet specified)

Driven by the app design guide's family-state widget (FamilyBeacon-DesignGuide.md
→ Signal-to-state mapping): an observer cannot honestly judge whether a member is
offline without knowing that member's expected check-in cadence. Proposed, pending
a full spec and test vectors:

- presence (new message type) — a lightweight "I am alive" ping. Emitted only when
  the device would otherwise be silent within its declared interval; any other
  message already serves as a heartbeat, so an active location stream costs no
  extra presence traffic. Requires a presence grant — a new consent feature using
  the same directional, pairwise machinery as location and battery; default deny.
- Heartbeat interval — carried as a config_update value (owner_rev): one per
  producer, role-defaulted and user-overridable, broadcast to the producer's
  granted observers. Observers judge freshness against the received interval and
  fall back to a role default until they have it. Deliberately one interval per
  producer, not per observer.
- Consent additions — presence joins the consent feature set
  (location | battery | geofence | presence | …); ungranting an observer emits the
  usual consent_update revoke, and that observer drops to "not shared" for
  liveness. This resolves entirely within the existing consent state machine.

Note on Sund's last_seen: the management-plane device list carries a last_seen the
whole account can see. It is deliberately not the liveness signal here — it cannot
be scoped to a consenting observer, whereas a presence feature can. Battery
crossing thresholds likewise stay client-local (the producer decides at what level
to emit a battery message); only the per-observer selection is on the wire, via
consent.

This is a candidate, not a commitment: it adds one message type, one consent
feature, and a config convention, all inside the existing envelope and consent
rules — and it must ship with test vectors like every other type before it is
v0.2.

---

Future versions

Deferred to a later protocol version, not v1. Each of these is gated on bulk
blob storage in Sund, which is a Sund *Non-goal* in V1 (Sund-PRD.md → Non-goals)
and will only be built when a consumer forces it. Family Beacon is that
consumer: the work below therefore has two halves — driving the Sund blob module
into existence (same blindness guarantee, opaque size-capped objects, a separate
optional module) and then adding the FB-level message types that reference it.
Until that module exists, none of this can ship, and the v1 types above stay
media-free.

- Shared images. Photo sharing (e.g. attached to chat or a check-in). Needs the
  blob module for storage/transfer beyond the 64 KiB message cap; the protocol
  addition is a new message type carrying an encrypted blob reference plus a
  content key, not the bytes.
- Avatars. The member_info avatar deferred above — a small profile image, same
  blob-reference mechanism, still consent-neutral (a member's own presentation).
- Stored / large configs. config_update today assumes small values inline. Large
  or binary shared configuration (e.g. rich fence sets, shared map assets) would
  move the value into a blob and keep only a reference and owner_rev inline.

The design constraint holds across all of them: the blob module stores opaque
ciphertext, content keys travel only inside E2E payloads, and every transfer is
ledgered like any other message. Consent, versioning and ledger rules are
inherited unchanged — a future version adds types and a storage dependency, not
new server trust.

---

Relationship to other documents

- ../ARCHITECTURE.md — names this spec (Core API section).
- ../../sund/docs/Sund-PRD.md — the transport this rides on; normative
  for everything below the envelope.
- ../../sund/docs/Sund-ImplementationGuide.md — pairing walkthroughs that
  establish the channels this spec assumes; beaconsim, which must track this
  spec's test vectors.
- ETHICS.md / PRIVACY.md rewrite (CLAUDE.md decision #5) — the consent state
  machine and ledger rule here are the protocol-level half of that work.
