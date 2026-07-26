Family Beacon — Session crypto

Status: v0.1 (Draft) — implemented July 2026 in `core/sund-client`
(`identity`, `bundle`, `canonical`, `session`, `session_store`), tiers 1 and 2
green.

The layer CLAUDE.md decision #6 decided and `FamilyBeacon-Protocol.md`
deliberately stops short of: **what happens between an envelope and the transport
port.** The protocol spec defines the plaintext handed to the session layer and
nothing below it; this document is the below.

Until this layer existed, `Outbound.ciphertext` was ciphertext by convention
only — the transport port had a field named for a guarantee nothing provided.
That is the gap this closes, and it is why this piece came before the roster, the
outbox and the bindings: everything above it either carries its output or is
meaningless without it.

---

Where it sits

    Family Beacon apps        UI, notifications, policy, SOS escalation
    ─────────────────────────────────────────────────────────────────
    beacon-protocol           envelope codec, message types, consent, ledger
    ─────────────────────────────────────────────────────────────────
    family roster             membership, introductions, revocation policy
    ─────────────────────────────────────────────────────────────────
    session crypto            THIS DOCUMENT — identity, bundles, the ratchet
    ─────────────────────────────────────────────────────────────────
    transport port            send / subscribe / ack / channel lifecycle
    ─────────────────────────────────────────────────────────────────
    sund-client  │  ntfy-client

The layer is **above** the transport port and knows nothing about Sund. A bundle
reaches a peer as opaque bytes, which is all Sund's dead drop promises and all
ntfy could ever offer; a frame reaches a peer as `Outbound.ciphertext`. The code
lives in the `sund-client` crate because `FamilyBeacon-Protocol.md` → Layering
put session crypto there, and it is written so Try mode's `ntfy-client` can
consume it unchanged. If that day comes and Try mode wants the crypto without the
Sund half, the extraction is a file move rather than a redesign.

---

Decision 1 — a separate protocol identity key

**Every device holds two Ed25519 keys, and they are not the same key.**

| | `sigauth::DeviceKey` | `identity::IdentityKey` |
| --- | --- | --- |
| Authenticates | HTTP requests to one Sund | the device, to the family |
| Known to | the server, in its device list | every peer, via a vouch |
| Exists in Try mode | no — there is no server | yes, unchanged |
| Signs | request tuples | bundles, vouches, tombstones |

Reusing the transport key for both would have been cheaper — one key to generate,
store and revoke. It was rejected for three reasons, in ascending order of
weight:

1. **Try mode has no Sund key.** The roster and the session layer sit above the
   transport port precisely so they have one answer, not one per backend. A
   transport-layer identity would have forced `FamilyBeacon-TryMode.md` to invent
   a second.
2. **One key signing in three protocols invites cross-protocol confusion.** The
   mitigation exists (domain separation, below) and is applied regardless, but
   not needing it is better than needing it.
3. **The separation makes a dishonest host's limits sharper.** The host controls
   the public key in Sund's `devices` row and the bytes the bundle store serves.
   It holds no identity key. So it can deny service, visibly, and it cannot forge
   a bundle — the signature fails against the `identity_pk` a family member
   physically vouched for.

The cost, stated plainly: **the binding between the two keys is the vouch and
nothing else.** A device record ties one `device_id` to one `identity_pk`; the
server ties the same `device_id` to a transport key. Nothing cryptographically
links them. That is not a gap — it is `FamilyBeacon-Roster.md`'s own position that
the server's device list is not the authority on membership. When the two
disagree, the roster wins, and the disagreement is the injected-device signal the
roster asks clients to surface.

The app layer must therefore generate and store **two** seeds. Nothing in the
core can check that they differ — the two keys never meet — so it is a contract,
with one backstop: a request signature can never verify as a vouch, because the
domains differ.

Domain separation

    "family-beacon/" purpose "/v1" 0x00  ||  canonical_json(payload)

Purposes are a closed enum (`bundle`, `vouch`, `removal`), not a string argument,
so a typo cannot mint a new silently-incompatible domain. The trailing NUL is
load-bearing: without it, purposes `vouch` and `vouchx` would share a prefix and a
signature over one could be replayed as the other given a cooperative payload.
Bumping the `v1` invalidates every signature made under the old domain, which is
the intended blast radius for a breaking change to *what* is signed.

Canonical JSON

Everything signed in this stack is signed over canonical JSON: object keys sorted
ascending by UTF-8 bytes, no insignificant whitespace, and **no floating-point
numbers**. The float rule refuses input rather than encoding it, because a float
has no single shortest representation every language agrees on — and
`FamilyBeacon-Roster.md` already states the principle: a signature scheme with two
encodings is a signature scheme with a forgery. Nothing signed here carries a
float; coordinates travel inside an encrypted envelope, which is sealed rather
than signed.

The corpus at `shared/protocol/testvectors/bundles.json` pins the encoding, the
three domains and a deterministic signature, because three implementations exist
(Rust, Sund's Go side, beaconsim in Python) and Ed25519 is deterministic — so a
disagreement shows up as a failed byte comparison rather than as a rejected vouch
nobody can explain.

---

Decision 2 — grant-only bundles

**A published bundle carries key material and no initiation address.**

    bundle
        v                 format version
        device_id         the publisher's transport-layer id
        identity_pk       the roster's vouched Ed25519 key, base64
        curve25519        the publisher's Olm identity key, base64
        fallback_key      the signed fallback key, base64
        fallback_key_id   Olm key id, so rotation is visible as an id change
        published_at      RFC3339 UTC, advisory
    sig                   Ed25519 by identity_pk over the bundle's canonical form

Sund lets the consumer choose its reachability topology, and the two options are
genuinely different products (`../sund/docs/Sund-PRD.md` → Key bundles →
Reachability). A *published-bundle mesh* — a bundle carrying a queue sender id —
makes any member able to initiate with any offline peer with no ceremony, which is
simpler: roster step 5 becomes "fetch bundle, send". **Grant-only** was chosen
instead: knowing a device exists does not make it reachable, so a device is
reachable only by peers that were handed a sender id deliberately.

The reason is the abuse case, not elegance. In a mesh, every member is reachable —
and spammable — by every other, *including* by a device a dishonest host injected
into the device list, in the window before the vouch check rejects it. Grant-only
is also how Sund's own PRD describes confining a newly invited device to its
inviter until further introductions are made, which is exactly the shape
`FamilyBeacon-Roster.md`'s admission protocol already has.

The cost is real and lands on the roster, not here: **the initiation addresses
have to be relayed by the introducer.** When M vouches for J, M already has
channels to every other member P, so M carries J's sender id to each P and each
P's sender id to J. J mints one queue per member up front, bounded by the 20-device
constant the roster already enforces. That sub-protocol is roster work and is not
specified here — this document only fixes that the bundle is not where an address
lives.

Two fields deserve a note on why they are inside the signature:

- `device_id`, because Sund serves bundle bytes from whichever slot the host puts
  them in without noticing. A bundle lifted from one device's slot and served as
  another's fails the client's check.
- `published_at`, not as a freshness guarantee — the publisher writes it — but so
  the host cannot rewrite it. It lets a fetcher notice a bundle that has not
  rotated in far too long.

Verifying against the right authority

`../sund/docs/Sund-PRD.md` says a fetcher verifies a bundle "against the device
list". `FamilyBeacon-Roster.md` says to verify against the roster's `identity_pk`.
**This implementation takes the roster's answer**, because the device list is
writable by whoever hosts the server and the vouched key is not. `verify` takes
the expected identity as an argument and has no way to discover one on its own, so
the weaker check is at least not the default. A caller holding only the server's
list can still pass that and will be less safe for it; the type cannot prevent it,
so the roster layer is where that choice is made and ledgered.

This is a documented divergence from Sund's PRD wording, in the safer direction.
Per the workspace convention on cross-repo spec conflicts it is raised rather than
silently resolved: **Sund's PRD should be amended to say "against the consumer's
own membership record, where it has one".** Not blocking — the server behaves
identically either way.

---

Decision 3 — fallback-key mode, and why rotation is weekly

Sund returns the same bundle bytes to every fetch and pops nothing, because
popping would mean interpreting the blob (its Architecture Principle forbids it,
and decision #6 says not to ask for a pop-prekey primitive). Two peers fetching
concurrently would therefore reuse a one-time key. Olm's signed fallback key is
the built-in answer: publish it, rotate it often, and accept
signed-prekey-grade forward secrecy **for the initial message only** — until the
first ratchet step, after which the ratchet's own guarantees take over.

The rotation period is derived, not chosen:

- Sund clamps a queued message's TTL to **7 days**, so the oldest pre-key message
  that can ever arrive is 7 days old.
- vodozemac retains exactly **two** fallback private keys, current and previous.
- Rotating every 7 days therefore keeps a fetched-just-before-rotation key
  decryptable for precisely as long as a message encrypted to it can survive, and
  no longer.

Rotating faster would silently drop initial messages. Rotating slower would widen
the window this mode already concedes. If Sund's clamp ever changes, the rotation
period moves with it — there is a unit test asserting the two numbers are the same
number.

`forget_previous_fallback_key` closes the overlap early. Normal operation never
calls it; it exists for a device that believes its published key material is
compromised and accepts losing initial messages already in flight.

---

The ratchet

**vodozemac 0.10**, Apache-2.0, independently audited, `rust-version 1.85` — an
exact match for the workspace. Olm session config **version 1** (the
non-experimental default): version 2's untruncated MAC is better, but it is behind
vodozemac's `experimental-session-config` feature and inbound v2 sessions are
gated with it, and beaconsim will need to interoperate using ordinary Olm
bindings. Revisit when v2 leaves experimental.

Why a ratchet rather than a handshake is CLAUDE.md decision #6's argument, and it
is a property of this transport rather than a preference: delivery is at-least-once,
per-channel ordered and *deliberately lossy*. Location carries short TTLs because a
stale position is worse than none, Sund deletes expired messages unread, and Try
mode's cache window drops them permanently. Skipped message keys are the normal
case here, and Noise's transport phase assumes a reliable ordered stream. The
ratchet also gives post-compromise recovery, which the stolen-device and
hostile-member scenarios in ETHICS.md need.

The two bounds that a lossy transport can actually hit

| Bound | Value | Consequence |
| --- | --- | --- |
| Skipped keys per receiver chain | 40 (5 chains, ~200 in flight) | Ample. It bounds out-of-order *arrival*, and anything older has expired at the relay. |
| Hard message-gap ceiling | 2000 | **Reachable.** A sender emitting >2000 messages to a peer that is away throughout — about one a minute for 33 hours, inside Sund's 7-day hold. |

The ceiling is a named outcome, not an opaque failure: `SessionError::SessionLost`,
whose documented remedy is to re-establish and never to retry. It is deliberately
kept distinct from a bad MAC, which means a forged or damaged frame — conflating
the two would send clients into a re-pair loop on a flipped bit.

What authenticates a sender

`Decrypted.authenticated_sender` is the device the **channel** belongs to,
cross-checked against the Curve25519 key from a roster-verified bundle. It never
comes from the message. That is what makes `beacon_protocol::receive`'s sender
comparison meaningful: the envelope's own `sender` field is attribution after
decryption, and this is the thing it is compared against. A peer with no verified
key material cannot be decrypted *or* attributed — a message from a device the
roster does not know reaches `SessionError::UnknownPeer` and is dropped, which is
the intended behaviour rather than a gap.

The frame

    [ frame version : u8 ] [ olm message type : u8 ] [ olm bytes … ]

Two bytes of overhead. The version byte is the hook for the compact binary
envelope encoding `FamilyBeacon-Protocol.md` reserves; the type byte is Olm's own
0 (pre-key) or 1 (normal). A frame from an unknown peer is refused *before* the
frame is parsed at all: the bytes are attacker-controlled, the answer cannot
change, and "unknown peer" is what the ledger should say rather than whatever the
frame happened to malform into.

---

Persistence

Two stores, written by two layers, restored independently — and neither is any use
without the other. The app layer persists both on every cold start:

- `session_store::{export, import}` — the Olm account and one session per peer.
- `sund_transport::{export, import}` — channel and queue state (already existed).

The session store is **encrypted here** rather than handed out in the clear. Key
*seeds* are given to the app layer raw, because that is a small one-time secret a
platform keystore holds well; Olm pickles are large, long-lived and change on
every message, so correct storage would become an app-layer problem on three
platforms. vodozemac already offers authenticated encryption for exactly this, so
the export takes a 32-byte pickle key and the app layer's job shrinks to storing
that one key properly. Losing the pickle key costs every session and no identity:
recoverable, and loud.

The identity key is **not** in the store. It is the app layer's to generate and
hold, it is the thing a family vouched for, and a store carrying it would turn one
leaked blob into a stolen identity rather than stolen sessions. `import` takes it
as an argument and refuses a store written under a different one — because
adopting someone else's sessions under your own vouched identity is precisely what
must not be possible.

---

Recovery — what re-establishment looks like

Four situations produce a session that cannot continue. All four are recoverable
and all four should be ledgered, because a peer whose sessions keep dying is
something the user should be able to see.

| Situation | Detected as | Remedy |
| --- | --- | --- |
| Gap over 2000 messages | `SessionLost` | Re-fetch the peer's bundle, open a fresh outbound session. |
| Peer reinstalled | a pre-key message with a new session id | Accepted automatically; `Decrypted.new_session` is true. |
| This device reinstalled or lost its store | `NoSession` on a normal message | The peer must re-establish; whichever side notices first drives it. |
| Peer's key material changed | `learn_peer` sees a new Curve25519 identity | The old session is dropped; keeping it would only produce undecryptable traffic. |

**Accepted limitation:** only the most recent session per peer is retained. If a
peer re-establishes while messages are still in flight on the old session, those
messages are lost. Olm implementations often keep old sessions for exactly this;
this one does not, because the transport is already lossy by design and the loss
surfaces as a `seq` gap, which the protocol layer already knows how to present as
staleness rather than as an error. Revisit if the ledger shows it happening in
practice.

---

Testing

- **Tier 1** — the ratchet's properties against an in-memory transport: round
  trips, out-of-order delivery, hundreds of dropped messages, the 2000-message
  ceiling, replay refusal, forged frames, rotation overlap, store round trips,
  and a Debug impl that cannot print key material.
- **Shared vectors** — `shared/protocol/testvectors/bundles.json`: canonical
  encoding cases, the three signing domains as hex, a deterministic signature, and
  one case per bundle refusal path. Tests assert the corpus covers every signature
  purpose and every failure mode, so an unpinned path fails the build.
- **Tier 2** — `core/contract-tests/tests/contract/sessions.rs`, against a real
  Sund in both trust modes. The dead-drop property (a bundle comes back
  byte-identical), a full envelope → session → real queue → session → envelope
  round trip, a forged `sender` rejected after decryption, session state surviving
  a restart alongside channel state, a session unaffected by the queue underneath
  it rotating, a rotated bundle republished, a revoked device's bundle no longer
  served, and an unpublished bundle indistinguishable from a nonexistent device.

**Tier 3 is now unblocked on this half.** `FamilyBeacon-Testing.md` names session
crypto and the roster state machine as the two reasons it does not exist — clients
that can hold a conversation rather than a queue. One of the two now exists.

---

Open items

1. **Olm session config v2.** Untruncated MAC, currently behind vodozemac's
   `experimental-session-config`. Revisit when it stabilises; it is a wire-format
   change and therefore a re-pair.
2. **Multiple retained sessions per peer.** The accepted limitation above. Ledger
   evidence should decide it, not speculation.
3. **The initiation-address relay.** Grant-only pushes it into the roster's
   admission protocol, where it is now specified (`FamilyBeacon-Roster.md` →
   Admission, steps 5a–5c) and not yet implemented. Blocking for a real join
   flow, and it belongs to the roster state machine rather than to this layer.
4. **Try mode's bundle distribution.** The format survives; the transport for it
   does not, because ntfy has no dead drop. A Try-mode open item, not a reason to
   reshape this — decision #8 sequences it after Sund mode works.
5. **PQXDH.** vodozemac does not have it; libsignal does and is AGPL. Unchanged
   from decision #6, noted here so the trade stays visible.

---

Related

- `FamilyBeacon-Protocol.md` — the envelope this layer seals, and the layering
  this document sits inside.
- `FamilyBeacon-Roster.md` — where `identity_pk` is vouched, and where the
  initiation-address relay has to live.
- `FamilyBeacon-TryMode.md` — the second transport this layer must survive.
- `FamilyBeacon-Testing.md` — the tiers, and the shared-vector discipline.
- `../sund/docs/Sund-PRD.md` — key bundles, reachability, and the TTL clamp the
  rotation period is derived from.
