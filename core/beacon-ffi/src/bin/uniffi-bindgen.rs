//! The bindings generator, as a binary target in this workspace.
//!
//! `docs/FamilyBeacon-AndroidPlan.md` → Build and CI asks for this rather than a
//! `cargo install`-ed tool, and the reason is narrow but real: the generator and
//! the `uniffi` runtime this crate links must be the same version, and a
//! globally installed binary drifts silently — the symptom is generated Kotlin
//! that compiles and then fails at the FFI boundary at run time. Here, Cargo
//! resolves both from one manifest, so they cannot disagree.
//!
//! Invoked by the Gradle task that produces `jniLibs`; see the crate docs for
//! the command line.

fn main() {
    uniffi::uniffi_bindgen_main();
}
