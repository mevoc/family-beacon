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

**Names settled (July 2026): `beacon-client` and `beacon-ffi`, as proposed.**
`beacon-client` reads as the Family Beacon client composed, next to `sund-client`
as the Sund client composed, and the `beacon-` prefix already means
"Family-Beacon-specific" across the workspace. The one ambiguity considered and
accepted: by analogy with `sund-client` the name could be read as "client of a
server called Beacon", and there is no such server — but "the Beacon client" is
what the app-side composition is called in every other sentence about it, so the
everyday reading is the right one. `beacon-core` was rejected because the
workspace directory is already `core/`, and `core/beacon-core` names the same
thing twice. Fix the cdylib's `[lib] name` explicitly in `beacon-ffi`'s manifest
when it lands, so the `.so` the Gradle build and `System.loadLibrary` reference
cannot drift from the crate name.

`beacon-client` was built in July 2026 to slice 0's surface; see below for what
that surface is and what it deliberately excludes.

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
  that already hold state. **Built literally**: byte zero is the version and the
  encoding starts at byte one, so the version is readable without committing to
  an encoding — which is what makes open question 2 reversible.
- **Ledger entries come out as values.** The receive path returns an outcome and
  a ledger entry together, deliberately and with no way to get one without the
  other, so the facade hands entries to the app and the app appends them to Room.
  The ledger is the one piece of state that grows without bound, and it is also
  the one the UI needs to query, filter and page — which is Room's job, not a
  blob's.
- **Seeds live in the platform keystore, not in the blob.** Two of them
  (`sigauth::DeviceKey` and `identity::IdentityKey`), generated at first run,
  passed into `open`. The app layer storing both is stated in `core/README.md`
  as a requirement on the app; this is where it lands. It stays at **two**: the
  session layer's pickle key is *derived* from the identity seed, domain-
  separated, rather than being a third secret whose loss would be silently
  unrecoverable. That also means the pickles inside the blob stay encrypted under
  a key that never leaves the keystore, so a blob that escapes the platform's
  at-rest encryption still yields no session state.
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

**What was built (July 2026), and how it differs from the cut above.** The
differences are all refinements the cut invited, not reversals:

- `enroll` returns `Applied<Client>` — the client *and* the ledger entries
  founding produced — rather than an `Enrolled`. Founding is a membership event,
  the ledger rule has no exemptions, and `Applied<T>` is the shape
  `beacon-roster` already uses for exactly this. Every future mutating call
  returns one, so the app cannot obtain an outcome without also obtaining the
  entries.
- `enroll` takes a `Profile` (`display_name`, `member_group`, `role`) rather than
  a display name alone. `Roster::found` needs all three, and defaulting the other
  two inside the facade would be inventing membership policy in the one crate
  that must not hold any.
- Every constructor has an `_with` twin taking an `HttpClient` and a
  `StampSource`. The `agent`-feature ones build the shipping pinned client; the
  twins are what the web client and the unit tests use.
- `open` reads the server address out of the blob rather than taking it again.
  The trust mode is part of the server's stored identity, and a client that
  accepted the address afresh on every open could be walked from pinned to WebPKI
  without anyone re-pairing.
- **`drain()` and `pump_outbox()` are held to slice 1**, both for reasons that
  are about correctness rather than effort. `drain` needs a channel-to-peer
  binding to know whose session decrypts a delivery, and `ChannelRecord`
  deliberately carries no peer — the pairing ceremony is what establishes that
  binding, so it is pairing's state to define, and building it now would be
  designing the pairing flow ahead of it. `pump_outbox` is worse: `DrainReport`
  carries no plaintext, so a drain cannot name the message type that went out,
  and a send path that cannot produce `LedgerEvent::Sent` would put an exemption
  in the ledger rule on day one. It lands with the enqueue path that knows the
  type. The composition already holds and persists sessions, channels and the
  outbox, so both are added as methods, not as fields.

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

`beacon-ffi` was built in July 2026 against **uniffi 0.32**, proc-macro mode with
no UDL, and both halves are proven: the cdylib cross-compiles to `arm64-v8a` and
`x86_64` under the pinned NDK, and `uniffi-bindgen` generates Kotlin from the
Android `.so` — which is the invocation the Gradle task will use. Four decisions
came out of the building, all cheap to reverse now and awkward later:

- **`[lib] name = "beacon_ffi"` is fixed in the manifest**, not derived from the
  package name. The Gradle copy and `System.loadLibrary` both depend on it, so a
  rename Cargo would treat as cosmetic is an `UnsatisfiedLinkError` at app start.
- **Mirror types, not re-exports.** Everything crossing the boundary is
  redeclared in `beacon-ffi` with a total `From` conversion. That keeps `uniffi`
  out of `beacon-client`'s dependency tree, gives the unbindable shapes
  (`[u8; 32]`, `&'static str`, `usize`, the generic `Applied<T>`) one place to
  change form, and turns drift into a compile error rather than an event the
  user is never shown.
- **The exported object wraps `Mutex<Client>`.** UniFFI objects are shared and
  must be `Sync`, and the mutating methods arrive in slice 1 — putting the mutex
  in now means they land without changing the type the app already holds. A
  poisoned mutex is fatal rather than recovered from: a panic inside the core
  left a state machine half-applied, and continuing would mean guessing which.
- **Blobs cross as `ByteArray`, both directions.** `&[u8]` binds to a direct
  `java.nio.ByteBuffer`, which would have left the app converting on the way in
  and not on the way out. One copy of a few kilobytes buys `open(snapshot())`
  being the obvious thing.

The `core` CI job now compiles `uniffi` and its bindgen dependency tree, which is
a real slowdown on a job that was previously fast. Worth watching; not worth
splitting the job over yet.

**The Gradle build and the `android` job were wired in July 2026** and the whole
chain is verified end to end: cargo-ndk cross-compiles `beacon-ffi`,
`uniffi-bindgen` generates Kotlin from the resulting `.so`, AGP compiles the app
against it, and `./gradlew assembleDebug` produces an APK carrying
`lib/arm64-v8a/libbeacon_ffi.so` and `lib/x86_64/libbeacon_ffi.so`. Both pins are
readable in the shipped artifact: the `.so`'s `.note.android.ident` records API
level 29 and NDK `r28c`/13676358.

Toolchain versions the bring-up settled, none of which were free choices:

| Component | Version | Why this one |
|---|---|---|
| AGP | 9.3.1 | The line that supports `compileSdk 37`, which is the platform the host has |
| Gradle | 9.5.0 | AGP 9.3.1's own floor — its version check refuses anything older |
| Kotlin | AGP's built-in | **`org.jetbrains.kotlin.android` must not be applied.** AGP 9 carries Kotlin support itself and applying the separate plugin is an error, not a redundancy. One fewer version to keep in step |
| JNA | 5.19.1 | What the generated bindings call through: `@aar` for the app, the plain jar for the JVM tests |

Four things the build wiring learned that are cheaper to read than to rediscover:

- **`cargo-ndk`'s platform flag is `-P`, not `-p`** — lowercase is cargo's own
  `--package`, and passing it makes cargo-ndk panic rather than complain. Its
  default is API **21**, eight levels below this app's floor, so passing it is
  not optional: a `.so` built against a different API level than the manifest
  claims fails on the oldest device anybody tests on, which is the last one to
  get tested.
- **AGP 9 removed `android.ndkDirectory` and replaced source-set `srcDir` with
  `directories`.** The NDK path is now built from the pin by hand, which is
  better than it sounds: the pin governs the Rust cross-compile directly instead
  of by way of whatever AGP resolved, and a missing NDK fails with the
  `sdkmanager` line to fix it rather than silently falling back to
  `$ANDROID_NDK_HOME`.
- **In a Gradle Kotlin DSL script, `java` resolves to the `JavaPluginExtension`,
  so `java.util.Properties` does not.** Import it.
- **The Rust `Display` impl does not cross the FFI.** UniFFI generates
  `message` as `"detail=…"`, so the *variant* is all the app can key off, and
  every user-facing sentence — including the pin-mismatch one, which is a
  security property — has to be written in Kotlin and localised there. That
  sharpens rather than weakens the error-model requirement: the reason
  `ServerIdentity` must stay a distinct variant is that it is the only thing the
  UI can dispatch on.

The `android` job holds to one ABI (`arm64-v8a`) and no emulator, per the plan
above. It additionally asserts that the APK actually contains
`libbeacon_ffi.so` — a build whose `jniLibs` wiring silently produced nothing
still assembles green, and the app then dies at first call with
`UnsatisfiedLinkError`. `setup-gradle` validates the committed wrapper jar.

CI gets a fourth job alongside `core`, `contract` and `topology`:

- **`android`** — installs the NDK, builds the core for one ABI, generates the
  bindings, runs `assembleDebug` and the app's JVM unit tests. Per-commit. It is
  the slowest job in the file; keep it to one ABI until there is a reason not to.
- Instrumented tests (tier 4's platform half — background location, doze, the
  sharing indicator, UnifiedPush wake) join the nightly tier when slice 3 gives
  them something to assert. Not in slice 0.

---

Prerequisites on the development host

The build host is a headless Ubuntu 24.04 server reached over SSH, so there is
no Android Studio in the loop: the SDK is installed with `cmdline-tools` and
everything below is command-line. Studio, if it is ever wanted for the layout
inspector or the profiler, belongs on a workstation pointed at a phone — never
on the build host.

Installed and verified (July 2026):

| Component | Version |
|---|---|
| Rust | 1.97.1, with `aarch64-linux-android` and `x86_64-linux-android` |
| cargo-ndk | 4.1.2 |
| JDK | OpenJDK 21.0.11 (headless) |
| cmdline-tools | 22.0 |
| SDK Platform | `platforms;android-37.1` |
| Build-Tools | `build-tools;37.0.0` |
| Platform-Tools | 37.0.0 (adb 1.0.41) |
| **NDK** | **`ndk;28.2.13676358`** — the pin for `build.gradle.kts` |
| Docker | 29.6.2, Compose v5.3.1 (stands the Sund stack up as CI does) |

`ANDROID_HOME`, `ANDROID_SDK_ROOT`, `ANDROID_NDK_HOME` and the two PATH entries
are exported from `~/.bashrc`. Note that a non-interactive shell does not read
it, so CI and any tooling that shells out must set them explicitly.

On the NDK choice: r29.0.14206865 is also stable, but the r28 line has three
patch releases behind it and is what the Rust Android toolchain has been most
exercised against. Bumping is one `sdkmanager` call and one line in the Gradle
build; starting on the mature line removes a variable from the first bring-up.
Verified by cross-compiling `sund-client` — rustls, ring, vodozemac,
ed25519-dalek and x25519-dalek all build clean for both ABIs.

One caution about the tooling itself: `sdkmanager` is deprecated in
cmdline-tools 22.0 in favour of an `android` CLI that collects usage metrics by
default (`--no-metrics` opts out). Prefer `sdkmanager` while it lasts, and if
the new CLI ends up in CI, pass the flag.

Two physical phones are needed from slice 1 — the pairing ceremony is physical
co-presence, and an emulator pair does not exercise the part that matters. With
the host headless, they reach it over the tailnet rather than over USB: enable
wireless debugging on the phone and `adb pair` / `adb connect` to its Tailscale
address. The pairing step is normally discovered over mDNS, which does not cross
a tailnet, so it has to be done by explicit address — worth proving out before
slice 1 depends on it.

An emulator is not needed until tier 4's instrumented tests. When it is, the
host has KVM, and it runs `-no-window` with screenshots pulled via
`adb exec-out screencap`.

---

Open questions for slice 0

1. ~~Crate naming (`beacon-client` / `beacon-ffi`), settled before first commit.~~
   **Closed (July 2026): as proposed.** Reasoning above, under The facade crate.
2. ~~Snapshot encoding.~~ **Closed (July 2026): JSON, behind the version byte.**
   Every layer already exports a serde-serialisable snapshot and `serde_json` is
   already a workspace dependency, so JSON costs nothing to adopt and buys a blob
   that is legible in a test failure and diffable between two devices that
   disagree about the family. The bytes a compact encoding would save are bytes
   nobody is paying for at this size. Because the version sits *outside* the
   encoding, changing this later is a version bump rather than a format sniff —
   which is the whole reason the version byte is where it is.
3. ~~minSdk.~~ **Closed (July 2026): 29 (Android 10).** Not the predecessor's 24.
   The deciding line is `ACCESS_BACKGROUND_LOCATION`, which does not exist below
   29: a lower floor means *two* background-location models to write, test and
   reason about, and slice 3's doze and OEM-battery-killer matrix doubles with
   it. The ethical argument points the same way — below 29 an app holds location
   with no notion of "background" at all, and "Allow all the time" as a
   deliberate settings-level grant is a transparency guarantee this product wants
   rather than a restriction it tolerates. Android 10 is seven years old in 2026;
   the cost is a tail of very old hardware. Still branching above the floor: 30
   (the background grant moves out of the app), 31 (approximate/precise,
   `PendingIntent` mutability), 33 (`POST_NOTIFICATIONS`), 34 (foreground service
   types).
4. Whether the app's Room schema is introduced in slice 0 (for the ledger) or the
   ledger is held in memory until slice 2. Leaning: introduce it in slice 0 —
   the ledger is the one thing slice 0 displays, and an in-memory stand-in would
   be thrown away immediately.
