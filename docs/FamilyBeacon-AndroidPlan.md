Family Beacon — Android build plan

Status: v0.1 (Draft, living document) — slice 0 specified, later slices sketched

How the Android client gets built, in vertical slices. This is the working plan,
not a normative document: where it disagrees with ETHICS.md, PRIVACY.md, the
protocol spec or the roster spec, they win, and where it disagrees with
docs/FamilyBeacon-DesignGuide.md about how a screen should work, the guide wins.
What this document owns is *order and seams* — what gets built when, and what the
app layer is allowed to know about the core.

The method, in one paragraph: nothing in the design guide's Core flows is
demoable until two devices are paired and an envelope has made a round trip, so
the unit of work is a thin vertical slice — binding, app plumbing, one real
screen, running on real hardware — rather than a design phase followed by an
implementation phase. Screen specs are written at the head of the slice that
needs them, from the Core flows sketch, and land back in the design guide.

---

Slice order

| # | Slice | Ships | Why here |
|---|---|---|---|
| 0 | Walking skeleton | One device enrolls against a real Sund, founds a family, shows its ledger | Proves the stack vertically before any product surface exists |
| 1 | Pairing and roster | QR ceremony, vouch, device list, the relayed sealed address | Gate to everything; least reusable UI, so get it wrong early |
| 2 | Transparency surfaces | Ledger and the consent matrix | Built *before* the features that write to them, so the ledger rule holds by construction |
| 3 | Live location | Interval share, foreground indicator, freshness | The hardest platform work: background location, doze, OEM battery killers |
| 4 | Urgent channels | `attention` and `sos`, their notification tiers, receipts | They ship together (decision #7) and share the wake machinery |
| 5 | Places and battery | Geofences, battery thresholds | Ports most directly from ../family-beacon-android |
| 6 | Widget and presence | The family-state widget | Needs `presence`, specified for v0.2 but not in the core's registry |
| 7 | Hardening | Localization parity, accessibility, permissions, distribution | |

Slice 2 before slice 3 is the placement worth defending: a transparency log built
after the features it records acquires exemptions, and the ledger rule has none.

Spec work that runs alongside rather than blocking: decision #4 (what SOS
promises when the server is unreachable) is needed for slice 4's copy at the
latest; `location_request` (design-guide open decision 12) and pause semantics
(13) are needed before slice 3 is complete; the widget's thresholds (3 and 9)
before slice 6. None of it blocks slices 0–2.

---

Slice 0 — the walking skeleton

Goal: a debug APK on a phone that enrolls against a Sund running on the LAN,
founds a family, and shows a ledger with real entries in it. One device, no
pairing, no location, no push, no map.

That is a deliberately unglamorous target, because the risk in slice 0 is not
product risk. It is that the FFI boundary, the state model and the build get
designed by accident. All three are cheap now and expensive at slice 3.

Definition of done

- `./gradlew assembleDebug` produces an APK containing the core's shared
  library for arm64 and x86-64.
- The app generates and stores two Ed25519 seeds, enrolls against a
  `sund://host:port#fingerprint` address with an invitation token, and survives
  being force-stopped and reopened without re-enrolling.
- The founding device self-vouches, so the roster exists and the device list
  screen renders from it rather than from placeholder data.
- A pin mismatch is reported to the user as "this is not the server you paired
  with", distinguishable in the UI from "no connection". (See the error model
  below — this is a contract requirement, not polish.)
- Protocol state is at rest under the platform's encrypted storage, never in a
  cache directory.
- CI builds the Android artifacts on every commit.

---

The facade crate — the one architectural decision in slice 0

The core today has no orchestrator. `contract-tests/tests/contract/membership.rs`
defines a `Member` struct holding "everything a phone would hold" — a
`DeviceClient`, an `IdentityKey`, a `Roster`, a `SessionManager` and a
`SundTransport` — and the test wires them together: publish a bundle, fetch a
peer's, verify it against `Roster::identity_of`, learn the peer, open a channel,
seal, send. That wiring is the client. It currently exists only in test code.

If the UniFFI layer is placed directly over `beacon-protocol`, `beacon-roster`
and `sund-client`, that orchestration moves into Kotlin — and then into Swift,
and then into TypeScript. Three implementations of the sequence that decides
whether a bundle is trusted is precisely the failure mode CLAUDE.md decision #6
rejected per-platform native to avoid.

So slice 0 adds a crate to `core/`:

    beacon-client        the composition: identity + roster + sessions +
                         transport + outbox, driven as one object
    beacon-ffi           uniffi scaffolding over it; cdylib, no logic

Two crates rather than one, so that `beacon-client` stays pure Rust and can be
driven headlessly by tier 3 without going through a binding. `beacon-ffi` should
contain no decision a test could fail on.

(Name is a proposal. `beacon-client` reads as the Family Beacon client composed,
next to `sund-client` as the Sund client composed. Settle it before the first
commit — renaming a crate that a Gradle build and a CI job already reference is
tedious.)

What the facade owns:

- The composition above, behind one `Client` object.
- The state blob: opening from bytes, and producing bytes to persist.
- Mapping the layers' errors into one enum the app can switch on.

What it must not own: a thread, a clock it invented, a scheduler, or any policy
that belongs in `beacon-roster`. Every layer beneath it takes the time as an
argument, and the facade should keep doing that rather than reaching for
`SystemTime::now()` in the middle of a state machine.

---

State and persistence — snapshot in, snapshot out

No callback interfaces across the FFI. UniFFI's friction concentrates on async
and callbacks (decision #6, "Known costs, accepted"), and a storage trait
implemented in Kotlin and called back into from inside a ratchet step is the
worst version of that. The core is already snapshot-shaped —
`roster::RosterSnapshot`, the session store, the outbox snapshot — so the
boundary follows the shape it already has:

- **Protocol state is one opaque blob.** `Client::open(state, seeds)` and
  `client.snapshot() -> bytes`. The app writes the blob after any call that
  mutated it. At family scale (20 devices, a handful of sessions, a short outbox)
  this is kilobytes, and whole-blob rewrite is the right trade against a
  fine-grained persistence API that would have to be re-specified for every
  future message type.
- **The blob is versioned from the first byte.** A schema integer at the front,
  and an `open` that refuses a version it does not know rather than guessing.
  This is the field-upgrade path; adding it later means a migration for devices
  that already hold state.
- **Ledger entries come out as values.** The receive path returns an outcome and
  a ledger entry together, deliberately and with no way to get one without the
  other, so the facade hands entries to the app and the app appends them to Room.
  The ledger is the one piece of state that grows without bound, and it is also
  the one the UI needs to query, filter and page — which is Room's job, not a
  blob's.
- **Seeds live in the platform keystore, not in the blob.** Two of them
  (`sigauth::DeviceKey` and `identity::IdentityKey`), generated at first run,
  passed into `open`. The app layer storing both is stated in `core/README.md`
  as a requirement on the app; this is where it lands.
- **The blob is encrypted at rest.** Non-negotiable in slice 0 rather than later:
  the outbox holds message bodies in the clear by design (it seals at drain, not
  at enqueue), so the snapshot contains plaintext locations. `core/README.md`
  says to store it where the platform keeps sensitive state — that means an
  EncryptedFile or a keystore-wrapped key over app-private storage, and never
  `cacheDir`.

---

The API surface — what slice 0 actually binds

Blocking, not async. Every public entry point in `sund-client` is synchronous
today (`register`, `list_devices`, `fetch_bundle`, `send_to_queue`), and the
transport port is pulled rather than pushed precisely so the core can be driven
from WorkManager. That means UniFFI generates plain blocking Kotlin functions and
the async problem never arises. The rule that replaces it: **nothing in this API
may be called from the main thread**, enforced by convention in slice 0 and by
the repository layer from slice 1 on.

A first cut, to be refined against the pairing flow rather than designed ahead of
it:

    generate_seeds() -> Seeds                     // via the platform RNG
    Client.enroll(address, invitation, display_name, seeds) -> Enrolled
    Client.open(state, seeds) -> Client
    Client.snapshot() -> bytes

    Client.self_description() -> MemberRow        // who this device is
    Client.roster() -> [MemberRow]                // the family, per the roster
    Client.server_devices() -> [ServerDeviceRow]  // what Sund lists, for
                                                  // reconciliation — never the
                                                  // authority on membership
    Client.drain() -> [Received]                  // the pull step: receive,
                                                  // decrypt, apply, return
                                                  // outcomes + ledger entries
    Client.pump_outbox() -> OutboxReport

`server_devices()` and `roster()` being two calls is the roster spec's central
claim made visible in the type system. A single `members()` that quietly merged
them would be the injected-device bug with a convenient name.

The error model carries one hard requirement. `sund-client`'s
`agent::is_tls_failure` exists because rustls surfaces a pin mismatch as an
`io::Error` that the obvious source-walk misses, which would make an intercepting
network indistinguishable from an absent one — the exact outcome the pinning
contract §8.3 forbids. The FFI error enum must keep that distinction as a
separate variant, and the UI must render it as an identity failure, not as a
connectivity failure. It is the only error in the app whose wording is a security
property.

---

Build and CI

Native build:

- `cargo-ndk` invoked from a Gradle task wired before `preBuild`, producing
  `jniLibs` per ABI. Prefer a plain `Exec` task over a Rust-Android Gradle
  plugin: one file we control, and no dependency whose maintenance we do not
  follow.
- ABIs: `aarch64-linux-android` and `x86_64-linux-android` (device and
  emulator). Add `armeabi-v7a` only if a real family phone needs it — every ABI
  is another cross-compile in CI.
- Pin the NDK version explicitly in `build.gradle.kts`. An NDK bump that changes
  the API level silently is a bad afternoon.
- `uniffi-bindgen` as a binary target in the workspace, not `cargo install`-ed,
  so the generator version cannot drift from the `uniffi` dependency.
- Generated Kotlin goes into a build-directory source set and is **not**
  committed. Committed bindings rot against the Rust they claim to bind.

CI gets a fourth job alongside `core`, `contract` and `topology`:

- **`android`** — installs the NDK, builds the core for one ABI, generates the
  bindings, runs `assembleDebug` and the app's JVM unit tests. Per-commit. It is
  the slowest job in the file; keep it to one ABI until there is a reason not to.
- Instrumented tests (tier 4's platform half — background location, doze, the
  sharing indicator, UnifiedPush wake) join the nightly tier when slice 3 gives
  them something to assert. Not in slice 0.

---

Prerequisites on the development host

Present already: Rust 1.97.1, Docker 29.6.2 with Compose v5.3.1 (so the Sund
stack can be brought up locally exactly as CI does it).

To install:

- A JDK — whatever the Android Gradle Plugin in use supports; take the one
  Android Studio bundles rather than picking independently.
- Android Studio, or the command-line SDK tools plus the NDK. Studio is worth it
  from slice 1 on (layout inspector, emulator management, profiler).
- `rustup target add aarch64-linux-android x86_64-linux-android`
- `cargo install cargo-ndk`
- Membership of the `kvm` group for a hardware-accelerated emulator, and `adb`
  access to a physical device (udev rules).

Two physical phones are needed from slice 1 — the pairing ceremony is physical
co-presence, and an emulator pair does not exercise the part that matters.

---

Open questions for slice 0

1. Crate naming (`beacon-client` / `beacon-ffi`), settled before first commit.
2. Snapshot encoding — JSON is legible and diffable in tests; a compact binary
   encoding is smaller. Legibility probably wins at this size, but decide once.
3. minSdk. The predecessor's floor is a starting point, but background-location
   behaviour differs enough across versions that the floor is a testing cost, not
   just a compatibility one.
4. Whether the app's Room schema is introduced in slice 0 (for the ledger) or the
   ledger is held in memory until slice 2. Leaning: introduce it in slice 0 —
   the ledger is the one thing slice 0 displays, and an in-memory stand-in would
   be thrown away immediately.
