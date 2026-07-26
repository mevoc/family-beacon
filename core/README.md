# core — the Rust client core

The shared client libraries of CLAUDE.md decision #6. Everything from
`beacon-protocol` down through `sund-client` lives here and is bound into every
app; UI, location and geofencing, push registration, background scheduling,
biometrics and local storage stay native per platform.

    Family Beacon apps        native per platform — not in this workspace
    ─────────────────────────────────────────────────────────────────
    beacon-protocol           envelope codec, message types, consent, ledger
    ─────────────────────────────────────────────────────────────────
    beacon-roster             membership, introductions, revocation policy
    ─────────────────────────────────────────────────────────────────
    session crypto            identity · bundle · session · session_store
    ─────────────────────────────────────────────────────────────────
    offline outbox            expire · supersede · retry · re-seal
    ─────────────────────────────────────────────────────────────────
    transport port            send / subscribe / ack / channel lifecycle
    ─────────────────────────────────────────────────────────────────
    sund-client  │  ntfy-client (Try mode, deferred)
      sund_transport            the port over Sund's queue pairs
      client                    the two planes: signed / queue-authenticated
      agent · address           HTTP, and the two transport-trust modes
    ─────────────────────────────────────────────────────────────────
    Sund server  │  ntfy instance

The seam between the two crates is fixed by `docs/FamilyBeacon-Protocol.md` →
Layering, and it is the reason the split exists: `sund-client` is the client
half of Sund itself, reusable by any project that adopts Sund as a backend, and
knows nothing about families, members or locations. If a type there mentions
one, it is in the wrong crate.

## What is here

| Crate | Contents |
| --- | --- |
| `beacon-protocol` | Envelope codec and the v1 message-type registry, the consent state machine, the transparency ledger's vocabulary, and the receive path that binds an outcome to its ledger entry. |
| `sund-client` | The canonical signed-request form (`sigauth`), server addresses and both transport-trust modes (`address`, `agent`), the two-plane API client (`client`), the transport port and its Sund implementation (`transport`, `sund_transport`), an in-memory implementation of the port for tests, the offline outbox (`outbox`), and the session layer: the protocol identity key and its signing domains (`identity`), canonical JSON (`canonical`), the grant-only key bundle (`bundle`), the vodozemac ratchet (`session`) and its persistence (`session_store`). |
| `beacon-roster` | The membership state machine of `docs/FamilyBeacon-Roster.md`: device records and tombstones, vouch-based admission, removal, the churn budget, `roster_sync` merging, server-list reconciliation, mutual-eviction detection, and the initiation-address relay that grant-only bundles require. Depends on `beacon-protocol` for the wire types and on `sund-client` for identity keys and canonical JSON — no HTTP client comes with it. |
| `contract-tests` | Tier 2 of `docs/FamilyBeacon-Testing.md`: the shipping libraries against a real relay in both trust modes. Needs a server; see below. |

Design points worth knowing before adding to any of them:

- **The receive path returns an outcome and a ledger entry together.** The
  ledger rule in `docs/FamilyBeacon-Protocol.md` has no exemptions, so there is
  deliberately no way to obtain one without the other.
- **The transport port is pulled, not pushed.** The core has to be drivable
  from outside — WorkManager, BGTask — and callback-shaped streams are the
  worst part of the UniFFI surface. The core never assumes it may run whenever
  it likes.
- **Trust is a property of the client, not of the call.** An `HttpClient` is
  built for one server address and carries that address's trust mode, so no
  request can be made in the wrong one. `HttpAgent` (feature `agent`, on by
  default) is the shipping implementation of both modes; the web client will
  supply its own over `fetch()`, because a browser can implement neither
  pinning nor sockets.
- **A duplex channel is two Sund queues, and they rotate separately.**
  `sund_transport` holds that asymmetry so nothing above the port sees it. The
  half we own is retired and recreated by us; the half the peer owns changes
  when they tell us, and each new peer queue binds a fresh sender key.

Three more, added with the session layer and the outbox:

- **A device holds two Ed25519 keys and the app layer must store both seeds.**
  `sigauth::DeviceKey` signs HTTP requests; `identity::IdentityKey` is the
  roster's `identity_pk` and signs bundles, vouches and tombstones. Nothing
  cryptographically binds them — the vouch is the binding, which is the roster's
  own position on who decides membership.
- **Everything signed is signed over canonical JSON with a domain prefix.**
  `family-beacon/<purpose>/v1\0 || canonical_json(payload)`, purposes being a
  closed enum. Floats are refused rather than encoded, because a float has no
  canonical form and a signature over an ambiguous encoding is a forgery waiting
  to happen.
- **The outbox queues plaintext and seals at drain.** Sealing at enqueue would
  bind every queued message to a session that may not survive the outage, and
  would advance the ratchet for messages that are then dropped for staleness. The
  cost is that the outbox snapshot holds message bodies in the clear — store it
  where the platform keeps sensitive state, not in a cache directory.

## What is not here yet

- **UniFFI bindings.** Deliberately absent until there is an app-facing API
  worth binding — they cost NDK cross-compilation, xcframework packaging and
  wasm-pack in CI, and none of that is needed for tiers 1–3, which are
  host-native. They arrive with the first Android integration.

## Building

    cargo test                              # unit suites + the shared vectors
    cargo clippy --all-targets -- -D warnings
    cargo fmt --check

Nothing in tier 1 needs a server, a network or a device; CI runs exactly these
three commands as the `core` job.

The contract suite is the exception, by design — it exists to talk to a real
Sund. It skips every leg the environment does not configure, so the commands
above stay offline. To run it, stand the stack up and hand it the two addresses
(`contract-tests/src/lib.rs` documents the whole invocation):

    docker compose --env-file docker/compose/.env.ci \
      -f docker/compose/compose.yaml -f docker/compose/compose.ci.yaml up -d --wait
    export SUND_PINNED_ADDRESS="sund://127.0.0.1:5871#$(…cert fingerprint…)"
    export SUND_PINNED_INVITATION=…
    cargo test -p contract-tests -- --test-threads=1
