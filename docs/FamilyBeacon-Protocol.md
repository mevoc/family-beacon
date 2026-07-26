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
    family roster             membership, introductions, revocation policy
    ─────────────────────────────────────────────────────────────────
    transport port            send / subscribe / ack / channel lifecycle
    ─────────────────────────────────────────────────────────────────
    sund-client library       generic, app-agnostic: device identity and
                              request signing, enrollment (QR), pairing,
                              session crypto, queue lifecycle and rotation,
                              offline outbox/retry, push registration
    ─────────────────────────────────────────────────────────────────
    Sund server API           blind queues (see ../../sund)

The libraries are deliberately separable. sund-client contains nothing
about families or locations — it is the client half of Sund itself, reusable
by any project that adopts Sund as a backend (several candidates exist in this
workspace). beacon-protocol is Family Beacon's own layer.

Both are **Rust crates behind UniFFI bindings** (decided July 2026, CLAUDE.md
decision #6). Everything in the stack above from `beacon-protocol` down through
`sund-client` is one Rust core; the "Family Beacon apps" row is native per
platform. Reusability was the point of the split and the core is its strongest
form — but the boundary between the two crates is what this spec fixes, and it
holds regardless of packaging.

The transport port and the second backend

The port is the interface this spec's Transport assumptions describe, stated as
an interface so that more than one thing can implement it:

    send(channel, ciphertext, priority, ttl) → message_id
    subscribe(channel) → stream of (message_id, ciphertext, received_at)
    ack(channel, message_id)
    open(channel) / retire(channel)

sund-client is one implementation. ntfy-client — the serverless Try mode of
CLAUDE.md decision #8, specified in FamilyBeacon-TryMode.md — is the other. The
port is narrow on purpose: everything in this document sits above it and is
identical in both modes, envelope and consent and ledger alike.

What the port deliberately does NOT carry is Sund's management plane — device
registry, key bundles, invitations, server-enforced revocation. Those become
explicit client-side logic in the family roster layer — specified in
FamilyBeacon-Roster.md, whose wire types are part of this document's registry
(see Message types → roster) — and Sund mode implements that logic *more
strongly* by also using its management plane (server-side key kill and queue
retirement) rather than only rotating client-side. Widening the
port until both backends fit would design Sund mode down to the weaker backend's
level; the difference between the modes is surfaced to the user instead of being
abstracted away (TryMode → Honesty rule).

Note on implementations: the Sund system-test client (beaconsim, in Python —
deliberately a different language from the Go server, so the wire format is
exercised by an independent implementation) is a third implementation of much
of this logic. Three implementations drift unless
tested against one source of truth — this spec must ship machine-readable test
vectors (sample envelopes, canonical encodings, consent scenarios) that every
implementation verifies against.

---

Transport assumptions (provided by sund-client, not specified here)

- Each pair of devices in the family shares a duplex pair of blind queues
  (Sund implementation guide, Walkthrough 2) plus an established end-to-end
  session providing confidentiality, integrity, sender authentication and
  forward secrecy. The session primitive is decided (July 2026): a double
  ratchet, implemented by vodozemac — Noise was rejected because its transport
  phase assumes a reliable ordered stream and this transport is deliberately
  lossy. See CLAUDE.md decision #6, and **`FamilyBeacon-Sessions.md` for the
  layer itself** (built July 2026): identity keys, key bundles, rotation and
  recovery. This spec stays agnostic regardless: it defines the plaintext handed
  to the session layer and nothing below it.
  One consequence of that layer is normative *here*: the `sender` comparison
  below is against the device the session authenticated, which is derived from
  the channel and verified key material and never from the message.
- Delivery is at-least-once (queue redelivery is possible) and per-queue
  ordered, but cross-queue order is undefined. Hence dedupe ids and sequence
  numbers below.
- Group semantics do not exist on the wire. "The family" is a client-side
  composition over per-pair channels: sending to the family means sending the
  same message over every pair the sender has. (Try mode has one narrow
  exception below the port — a family-wide channel carrying membership
  coordination only, never a message type from this spec. See
  FamilyBeacon-TryMode.md → Topics.)

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
    note (optional, short). A broadcast about the sender's own situation — the
    directed "I need you to answer me" case is a separate attention type (see
    Related v0.2 companions), never a downgraded sos. Sent to every pair at
    maximum Sund priority with
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

attention
    reason (optional, short, length-capped), recorded_at. The directed
    "contact me urgently" nudge: sent to one pair, it asks the recipient to
    override a silent or low ringer and get back to the sender. Deliberately
    not a weaker sos — the two differ in kind. attention is about the
    *recipient's availability* and addressed to one member; sos is about the
    *sender's situation* and broadcast to all. They therefore keep separate
    types, consent, content and delivery rules (design guide → Two urgent
    channels), and no client may synthesize one from the other or auto-escalate
    between them.
    - Carries no location, ever. The "where are you" case is location_request
      under the location grant, not this type.
    - High Sund priority with a wake-up ping, but a short TTL: an hour-old
      "call me now" is noise, not a nudge (sos takes the maximum TTL).
    - Requires an inbound allow grant held by the *recipient* (feature =
      attention in consent_update), revocable like any other — unlike sos
      reception, which is mandatory. This is the one type whose enforcement
      sits at the receiver rather than the producer: the sender cannot know the
      receiver's current interruption budget, so the receiving client decides
      whether an arrival is presented with the ringer override or as an
      ordinary notification. A revoked grant is still enforced at the producer
      in the usual way — the sender's app refuses to emit.
    - Rate-limited by the recipient (interruption budget; see the design guide
      for the anti-harassment rationale). Suppression is reported honestly via
      the receipt status below, never silently.
    - Requires receipt. status extends for this type to
      delivered | seen | suppressed (arrived without the override) and the
      one-tap replies calling | on_my_way | cannot_talk, so the sender always
      learns what actually happened.
    - Ledgered on both sides with sender name and reason. No anonymous nudge.

geofence_event
    fence_id, transition (enter | exit), recorded_at. Emitted by the moving
    device — the fence is evaluated on the device it concerns, which
    therefore must hold the fence definition and have granted the geofence
    feature. There is no server-side or observer-side fence evaluation.

consent_update
    feature (location | battery | geofence | attention | …), action
    (grant | revoke),
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
    display_name, member_group, role, proto_v; avatar deferred to a future
    version (needs Sund's blob module, a Non-goal until Family Beacon forces
    it — see Future versions). Sent on join and on change. All of these fields
    are self-asserted labels and confer no authority (FamilyBeacon-Roster.md →
    The model). Not an admission path: a member_info from a device with no
    roster record is ledgered as unknown-sender and dropped.

roster_introduce / roster_remove / roster_sync
    Membership: a signed vouch admitting a device, a signed tombstone removing
    one, and a periodic full-roster digest for reconciliation. Bodies,
    signature rules, the admission and removal state machine and the
    reconciliation merge rules are specified in FamilyBeacon-Roster.md; they
    are v1 types and are listed here because the registry is one list. Never
    consent-gated — membership is the precondition for features, not a feature.
    Always ledgered as discrete, readable events.

channel_offer
    of, for, sealed. Hands one device the queue address it needs to reach
    another. Grant-only key bundles carry no initiation address, so at join the
    introducer relays the first one (FamilyBeacon-Roster.md → Admission, step 5);
    `sealed` is a session frame from `of` to `for`, so the relayer carries a
    capability it cannot read. Plumbing rather than content, and like the roster
    types it is never consent-gated: the channel is the pipe and consent is the
    valve. Always ledgered — it changes who can reach you, which is the rule.

receipt
    of (message id), status (delivered | seen; plus suppressed and the reply
    values for attention, above). Mandatory for sos, sos_clear, attention and
    consent_update. For everything else, receipts are off by default —
    "seen" tracking of routine location updates is surveillance-adjacent and
    stays opt-in per pair, both directions aware (it is itself a feature
    requiring a grant).

---

Consent state machine (normative)

- State lives at the producer: a per-(feature, observer) grant set, changed
  only by the device's own user, persisted locally, every change ledgered.
- Inbound features invert the roles but not the rule. For attention (and
  location_request in v0.2) the grant is held by the party being reached: they
  are still the device's own user deciding what leaves or enters their device,
  the grant is still advertised by consent_update, and the peer still enforces
  it by refusing to emit. The difference is only that the receiver additionally
  enforces at delivery — it may present an allowed attention without the ringer
  override when its interruption budget is spent, and says so in the receipt.
  That is a policy the receiver owns, never something the sender can override.
- Default deny. A fresh pairing shares nothing but member_info and the
  ability to receive sos — which is mandatory precisely because it reports the
  sender's situation rather than demanding the recipient's attention. attention
  is not part of a fresh pairing: it must be granted like everything else.
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

1. ~~Session primitive.~~ **Decided July 2026: a double ratchet (vodozemac),
   and built.** Specified in `FamilyBeacon-Sessions.md`, implemented in
   `core/sund-client`, tiers 1 and 2 green. See Transport assumptions above and
   CLAUDE.md decision #6.
2. ~~Library implementation strategy.~~ **Decided July 2026: a Rust core with
   UniFFI bindings**, carrying everything from this spec down through
   sund-client; native code owns only the app layer. beaconsim (Python) remains
   the independent third implementation, so the test-vector discipline of
   Versioning is unaffected and still gates everything.
3. Receipt policy details: whether "delivered" receipts (not "seen") should
   be default-on for location to power staleness UI, or whether seq-gap
   detection suffices.
4. config_update ownership model: sufficient for fences and shared prefs, or
   does any config genuinely need multi-writer semantics?

---

Presence heartbeat — v0.2 specification

Defined for protocol v0.2. It is not one of the v1 wire types above and ships only
when its test vectors do; until then a v0.1 client treats a presence message as an
unknown type — ledger and ignore, per Versioning. Motivation: the family-state
widget (FamilyBeacon-DesignGuide.md → Signal-to-state mapping) needs an honest "is
this member reachable" signal, and an observer cannot judge silence without knowing
the producer's expected cadence. Presence supplies both, as a consent-gated feature
— unlike Sund's account-wide last_seen, which cannot be scoped to a single observer.

The message

    presence
        interval_s (required, integer > 0): the producer's current expected
        maximum gap, in seconds, between messages of any type to this observer.
        No location, no battery, no content — a pure liveness beat, meaning
        "sender was alive as of the envelope's sent time, and commits to being
        heard from again within interval_s." Requires a presence grant. Short TTL
        (recommended ~2x interval_s): only the most recent presence is meaningful,
        so a superseded beat is safe to expire unread. Normal priority — a
        heartbeat carries no wake-up urgency of its own.

Heartbeat contract (producer side)

- Any message of any type counts as a heartbeat. A producer already sending
  location or battery to an observer is proving liveness and MUST NOT also emit a
  redundant presence ping in the same window — presence pings exist only to fill
  silence. This piggyback rule is what makes presence near-free for members who
  already share location.
- To each observer holding a presence grant, the producer ensures at least one
  message arrives per interval_s (best-effort); if ordinary traffic will not, it
  sends a presence ping.
- The producer sends a presence ping immediately — not only on the idle timer —
  when it grants presence to an observer (this establishes interval_s for a fresh
  pair), when it changes interval_s, and when it returns from its own downtime.

Freshness evaluation (observer side)

- last_heard(producer) = the newest envelope sent value across all messages
  received from that producer on the pair, presence and content alike. A message
  whose sent is not newer than the current last_heard does not move it (this
  absorbs reordering and at-least-once redelivery).
- age = now - last_heard, clamped to >= 0 to guard against a future-dated sent
  (clock skew between devices).
- interval_s is taken from the most recently received presence ping; until one has
  arrived, the observer uses the role-based default (design guide). The widget's
  Signal-to-state mapping turns age and interval_s into state (fresh, aging,
  offline). This spec provides the inputs; the thresholds are the app's.

Consent

- presence joins the consent feature set alongside location, battery and geofence;
  consent_update carries it (feature = presence). Default deny, like every feature
  — a fresh pairing shares no presence.
- Directional and pairwise, enforced at the producer: revoking an observer's
  presence grant stops presence pings to them at once and emits the usual
  consent_update revoke. That observer's widget drops to "not shared" for liveness
  with no residual signal — the reason presence is preferred to last_seen.

Ledgering

- The presence grant and revoke are discrete, individually ledgered events, like
  any consent change.
- Individual heartbeats are telemetry: recorded as ongoing presence sharing and
  surfaced aggregated (an active-sharing indicator plus a last-beat time), not one
  ledger entry per beat. This is the same treatment high-frequency location updates
  require, and it keeps the ledger legible without exempting any type from
  transparency — the user always sees that presence is being shared and when it
  last beat. Formalizing telemetry aggregation in the ledger, once, for presence
  and location together is an open item.

Delivery cost (stated honestly)

- Every message arrival wakes the owning (observer) device through Sund's push-ping
  fan-in; Sund has no silent-delivery class today. So a presence ping in an
  otherwise idle pair costs one wake-up per observer per interval_s. Keep interval_s
  conservative for background liveness — role defaults on the order of minutes to
  tens of minutes, never seconds — and rely on the piggyback rule so active sharing
  adds no presence traffic at all. A future Sund low-priority / no-wake drain class
  could remove even the idle-pair wakes; it is out of scope here and not required
  for correctness.

Versioning and mixed families

- A v0.2 client advertises support in member_info (proto_v). A v0.1 observer that
  receives a presence message ledgers it as unknown and ignores it — it simply has
  no presence-based liveness for that member — and a v0.2 producer needs no
  knowledge of an observer's version to stay correct.

Test vectors (gating, like every type)

- A canonical valid presence envelope; a malformed one missing interval_s (and one
  with interval_s <= 0); an interval-change sequence; and consent_update grant/
  revoke for feature = presence — all added to the shared vectors that gate every
  implementation (beacon-protocol libraries and beaconsim).

Open sub-points

- Role-based default intervals and the exact freshness thresholds live in the
  design guide (open decisions 3 and 9); this spec is agnostic to their values.
- Telemetry ledger aggregation (above) should be formalized once, covering
  presence and location.

Related v0.2 companions (not yet specified)

Surfaced by the design guide's Feature & member controls, to be specified with the
same discipline as presence (bodies, consent, ledgering, test vectors):

- Live location, interval + pull. The interval-share half reuses the existing v1
  location type with a producer-declared max-gap interval (a location fix is itself
  a heartbeat — see the contract above). The on-demand half adds a location_request
  message; the reply is an ordinary location message, gated by the location grant
  and ledgered as a discrete event on both sides. Client-side retention is
  last-known-only by default (no movement trail) — a client policy, not a wire
  concern, stated in the design guide and PRIVACY.md.
- Pause — likely an "until"-carrying form of consent_update so a paused share
  renders as benign Paused at the observer rather than as staleness.

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
- FamilyBeacon-Roster.md — the membership layer this spec's Layering names:
  who is in the family, how a device is admitted and removed, and why the
  server's device list is not the authority on either.
- FamilyBeacon-TryMode.md — the second implementation of the transport port
  above: the serverless ntfy mode, what it gives up, and the honesty rule that
  keeps the swap visible to the user.
- ../../sund/docs/Sund-PRD.md — the transport this rides on; normative
  for everything below the envelope.
- ../../sund/docs/Sund-ImplementationGuide.md — pairing walkthroughs that
  establish the channels this spec assumes; beaconsim, which must track this
  spec's test vectors.
- ETHICS.md / PRIVACY.md rewrite (CLAUDE.md decision #5) — the consent state
  machine and ledger rule here are the protocol-level half of that work.
