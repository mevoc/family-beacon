// The Android client of Family Beacon.
//
// Almost nothing lives here: the app is one module, and the interesting build
// logic — cross-compiling the Rust core and generating its bindings — is in
// `app/build.gradle.kts` next to the source set it feeds.

plugins {
    alias(libs.plugins.androidApplication) apply false
}
