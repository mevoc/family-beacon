# apps/android — the Family Beacon Android client

Android first, to a complete v1 safety core, before iOS or web start (CLAUDE.md
decision #10). The plan this follows is `docs/FamilyBeacon-AndroidPlan.md`; the
normative documents it must not contradict are `ETHICS.md`, `PRIVACY.md` and the
specs under `docs/`.

**Status: the build is wired, the app is not written.** `assembleDebug` produces
an APK carrying the Rust core, and the JVM tests call into it across the real
FFI boundary. There is no activity yet — the first screens land with the slice
that specifies them.

## Building

No Android Studio is involved: the build host is headless and everything below
is command line. Set `ANDROID_HOME`, then:

    ./gradlew assembleDebug          # both ABIs
    ./gradlew test                   # the JVM tests, across the FFI
    ./gradlew assembleDebug -Pbeacon.abis=arm64-v8a    # one ABI, as CI does

A non-interactive shell does not read `~/.bashrc`, and a Gradle daemon is such a
shell. The build resolves `cargo` itself (`$CARGO`, then `~/.cargo/bin/cargo`,
then `PATH`) and resolves the NDK from `ANDROID_HOME` plus the version pinned in
`app/build.gradle.kts` — but `ANDROID_HOME` itself must be exported, or set
`sdk.dir` in `local.properties`.

## How the Rust core gets in

Three plain `Exec` tasks in `app/build.gradle.kts`, wired in front of `preBuild`.
A plain `Exec` rather than one of the Rust-Android Gradle plugins is deliberate:
one file we control, and no dependency whose maintenance we do not follow.

    cargoBuildAndroid       cargo-ndk  ->  build/rust/jniLibs/<abi>/libbeacon_ffi.so
    generateUniffiBindings  that .so   ->  build/generated/uniffi/uniffi/beacon/beacon.kt
    cargoBuildHost          the same crate for this machine, for the JVM tests

Three things about that are load-bearing:

- **The generated Kotlin is never committed.** Committed bindings rot against the
  Rust they claim to bind. It is generated from the *Android* `.so`, so it binds
  exactly the artifact that ships in the APK, and `uniffi-bindgen` is a binary
  target in the Rust workspace so the generator cannot drift from the runtime.
- **The NDK is pinned in `app/build.gradle.kts` and handed to cargo-ndk**, so one
  pin governs both halves of the build. It is also passed the app's `minSdk` as
  the platform level — cargo-ndk otherwise defaults to API 21, and a `.so` built
  against a different level than the manifest claims fails on the oldest device
  anybody tests on.
- **The JVM tests load the host build through UniFFI's library-override hook.**
  That is what makes `./gradlew test` exercise the boundary rather than assert
  that generated Kotlin compiles — a build that only ran `assembleDebug` would
  stay green through a mismatched `uniffi` version or a library nothing loads.

## Two things to know before writing the app layer

- **Nothing in the core may be called from the main thread.** Every entry point
  blocks; none is async and none takes a callback. Drive it from WorkManager.
- **The Rust error sentences do not cross the FFI.** UniFFI generates `message`
  as `"detail=…"`, so every user-facing string is written here and localised
  here. That matters most for `ClientException.ServerIdentity`: a pin mismatch
  must read as "this is not the server you paired with" and never as a
  connectivity failure, and the *variant* is the only thing the UI can dispatch
  on.

## minSdk 29

Android 10, decided in July 2026 against the predecessor's 24.
`ACCESS_BACKGROUND_LOCATION` does not exist below 29, so a lower floor means two
background-location models rather than one. Reasoning in
`docs/FamilyBeacon-AndroidPlan.md` → Open questions for slice 0.
