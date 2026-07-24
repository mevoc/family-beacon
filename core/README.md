# core — the Rust client core

The shared client libraries of CLAUDE.md decision #6. Everything from
`beacon-protocol` down through `sund-client` lives here and is bound into every
app; UI, location and geofencing, push registration, background scheduling,
biometrics and local storage stay native per platform.

    Family Beacon apps        native per platform — not in this workspace
    ─────────────────────────────────────────────────────────────────
    beacon-protocol           envelope codec, message types, consent, ledger
    ─────────────────────────────────────────────────────────────────
    family roster             membership, introductions, revocation policy
    ─────────────────────────────────────────────────────────────────
    transport port            send / subscribe / ack / channel lifecycle
    ─────────────────────────────────────────────────────────────────
    sund-client  │  ntfy-client (Try mode, deferred)
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
| `sund-client` | The canonical signed-request form (`sigauth`), the transport port, and an in-memory implementation of the port for tests. |

Two design points worth knowing before adding to either:

- **The receive path returns an outcome and a ledger entry together.** The
  ledger rule in `docs/FamilyBeacon-Protocol.md` has no exemptions, so there is
  deliberately no way to obtain one without the other.
- **The transport port is pulled, not pushed.** The core has to be drivable
  from outside — WorkManager, BGTask — and callback-shaped streams are the
  worst part of the UniFFI surface. The core never assumes it may run whenever
  it likes.

## What is not here yet

- **The HTTP implementation of the port.** Enrollment, queue lifecycle and
  rotation against a real relay. This is what tier 2 of
  `docs/FamilyBeacon-Testing.md` needs, and it is the next piece.
- **Session crypto.** vodozemac, in fallback-key mode (decision #6). The
  protocol layer above it is deliberately agnostic: it defines the plaintext
  handed to the session layer and nothing below it.
- **The roster state machine.** Specified in `docs/FamilyBeacon-Roster.md`;
  its wire types are already in the registry here.
- **UniFFI bindings.** Deliberately absent until there is an app-facing API
  worth binding — they cost NDK cross-compilation, xcframework packaging and
  wasm-pack in CI, and none of that is needed for tiers 1–3, which are
  host-native. They arrive with the first Android integration.

## Building

    cargo test                              # unit suites + the shared vectors
    cargo clippy --all-targets -- -D warnings
    cargo fmt --check

Nothing here needs a server, a network or a device. CI runs exactly these three
commands as the `core` job.
