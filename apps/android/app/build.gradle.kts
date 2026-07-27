import org.gradle.api.tasks.PathSensitivity.RELATIVE
// Imported rather than fully qualified: in a Gradle Kotlin DSL script `java`
// resolves to the JavaPluginExtension, so `java.util.Properties` does not.
import java.util.Properties

plugins {
    // Kotlin support is built into AGP from 9.0 on, and applying the separate
    // `org.jetbrains.kotlin.android` plugin alongside it is an error rather than
    // a redundancy. One fewer version to keep in step.
    alias(libs.plugins.androidApplication)
}

// ---------------------------------------------------------------------------
// The Rust core
//
// Three tasks, all plain `Exec`, wired in front of `preBuild`. A plain Exec
// rather than one of the Rust-Android Gradle plugins is deliberate
// (docs/FamilyBeacon-AndroidPlan.md → Build and CI): this is one file we
// control, and no dependency whose maintenance we do not follow.
//
//     cargoBuildAndroid    cross-compile beacon-ffi -> jniLibs/<abi>/libbeacon_ffi.so
//     generateUniffiBindings  the .so -> uniffi/beacon/beacon.kt
//     cargoBuildHost       the same crate for this machine, for the JVM tests
//
// The generated Kotlin is never committed. Committed bindings rot against the
// Rust they claim to bind, and the generator is a binary target in the Rust
// workspace precisely so its version cannot drift from the `uniffi` runtime the
// core links.
// ---------------------------------------------------------------------------

/** The NDK both halves of the build use. See the `android` block below. */
val pinnedNdk = "28.2.13676358"

/** The lowest Android version this app supports. */
val minimumSdk = 29

val coreDir = layout.projectDirectory.dir("../../../core").asFile
val jniLibsDir = layout.buildDirectory.dir("rust/jniLibs")
val bindingsDir = layout.buildDirectory.dir("generated/uniffi")

/** Android ABI to Rust target triple. */
val abiTargets = mapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "x86_64" to "x86_64-linux-android",
)

val requestedAbis: List<String> =
    providers.gradleProperty("beacon.abis").orNull
        ?.split(',')
        ?.map(String::trim)
        ?.filter(String::isNotEmpty)
        ?: abiTargets.keys.toList()

require(requestedAbis.isNotEmpty()) { "beacon.abis names no ABI" }
requestedAbis.forEach {
    require(it in abiTargets) { "unknown ABI `$it`; known: ${abiTargets.keys.joinToString()}" }
}

/**
 * Where cargo lives.
 *
 * Resolved rather than assumed, because a non-interactive shell does not read
 * `~/.bashrc` — the plan says so about this very host, and a Gradle daemon is
 * exactly such a shell. `CARGO` wins if it is set, so CI and a nix shell can
 * both say where.
 */
val cargoBin: String =
    providers.environmentVariable("CARGO").orNull
        ?: File(System.getProperty("user.home"), ".cargo/bin/cargo")
            .takeIf { it.canExecute() }
            ?.absolutePath
        ?: "cargo"

/**
 * The pinned NDK, resolved from the SDK by hand.
 *
 * AGP 9 no longer exposes `android.ndkDirectory`, and building the path from
 * [pinnedNdk] is the better answer anyway: the pin governs the Rust
 * cross-compile directly rather than by way of whatever AGP happened to
 * resolve. Missing is a hard failure with the `sdkmanager` line to fix it —
 * cargo-ndk would otherwise fall back to `$ANDROID_NDK_HOME` and silently build
 * against a different NDK than the one the app is pinned to.
 */
fun sdkFromLocalProperties(): String? {
    val file = rootProject.file("local.properties")
    if (!file.isFile) return null
    val properties = Properties()
    file.inputStream().use { stream -> properties.load(stream) }
    return properties.getProperty("sdk.dir")
}

val ndkHome: File by lazy {
    val sdk = providers.environmentVariable("ANDROID_HOME").orNull
        ?: providers.environmentVariable("ANDROID_SDK_ROOT").orNull
        ?: sdkFromLocalProperties()
        ?: error("Set ANDROID_HOME, or put sdk.dir in local.properties")

    File(sdk, "ndk/$pinnedNdk").also {
        require(it.isDirectory) {
            "NDK $pinnedNdk is not installed at $it — " +
                "run: sdkmanager --install \"ndk;$pinnedNdk\""
        }
    }
}

/**
 * The library name is fixed in `core/beacon-ffi/Cargo.toml` and repeated here
 * because three things have to agree on it: the file cargo-ndk writes, the file
 * this build copies into the APK, and the `System.loadLibrary` call inside the
 * generated bindings.
 */
val nativeLibrary = "libbeacon_ffi.so"

val cargoBuildAndroid by tasks.registering(Exec::class) {
    group = "rust"
    description = "Cross-compile beacon-ffi for ${requestedAbis.joinToString()}"

    workingDir = coreDir
    inputs.dir(coreDir.resolve("beacon-ffi/src")).withPathSensitivity(RELATIVE)
    inputs.dir(coreDir.resolve("beacon-client/src")).withPathSensitivity(RELATIVE)
    inputs.dir(coreDir.resolve("beacon-protocol/src")).withPathSensitivity(RELATIVE)
    inputs.dir(coreDir.resolve("beacon-roster/src")).withPathSensitivity(RELATIVE)
    inputs.dir(coreDir.resolve("sund-client/src")).withPathSensitivity(RELATIVE)
    inputs.file(coreDir.resolve("Cargo.lock"))
    inputs.property("abis", requestedAbis)
    inputs.property("ndk", pinnedNdk)
    outputs.dir(jniLibsDir)

    // cargo-ndk finds the toolchain through this, so the pin in the `android`
    // block below governs the Rust build too. Without it, cargo-ndk would take
    // whatever ANDROID_NDK_HOME the environment happens to hold — which is the
    // silent-API-level-bump the plan warns about.
    environment("ANDROID_NDK_HOME", ndkHome.absolutePath)

    commandLine(
        buildList {
            add(cargoBin)
            add("ndk")
            requestedAbis.forEach { add("-t"); add(it) }
            // Match the app's own floor. cargo-ndk defaults to API 21 — eight
            // levels below where this app starts — and a .so built against a
            // different API level than the manifest claims is a crash on the
            // oldest device anybody tests on, which is the last one to get
            // tested. Capital `-P`: lowercase is cargo's own `--package`.
            add("-P"); add(minimumSdk.toString())
            add("-o"); add(jniLibsDir.get().asFile.absolutePath)
            add("build")
            add("-p"); add("beacon-ffi")
        }
    )
}

val generateUniffiBindings by tasks.registering(Exec::class) {
    group = "rust"
    description = "Generate the Kotlin bindings from the cross-compiled library"
    dependsOn(cargoBuildAndroid)

    // Generated from an Android .so rather than a host one, so the bindings are
    // produced from exactly the artifact that ships in the APK.
    val fromAbi = requestedAbis.first()
    val library = jniLibsDir.map { it.file("$fromAbi/$nativeLibrary") }

    workingDir = coreDir
    inputs.file(library).withPathSensitivity(RELATIVE)
    outputs.dir(bindingsDir)

    argumentProviders.add {
        listOf(
            "run", "--quiet", "--bin", "uniffi-bindgen", "--",
            "generate",
            "--library", library.get().asFile.absolutePath,
            "--language", "kotlin",
            // ktlint is not on this host and its absence is only a formatting
            // warning; the build should not depend on it either way.
            "--no-format",
            "--out-dir", bindingsDir.get().asFile.absolutePath,
        )
    }
    executable = cargoBin
}

val cargoBuildHost by tasks.registering(Exec::class) {
    group = "rust"
    description = "Build beacon-ffi for this machine, so the JVM tests can load it"

    workingDir = coreDir
    inputs.dir(coreDir.resolve("beacon-ffi/src")).withPathSensitivity(RELATIVE)
    inputs.dir(coreDir.resolve("beacon-client/src")).withPathSensitivity(RELATIVE)
    inputs.file(coreDir.resolve("Cargo.lock"))
    outputs.file(coreDir.resolve("target/debug/$nativeLibrary"))

    commandLine(cargoBin, "build", "-p", "beacon-ffi")
}

android {
    namespace = "se.mevoc.beacon"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    // Pinned, not inherited. An NDK bump that silently changes the default API
    // level is a bad afternoon, and this value is also what `cargoBuildAndroid`
    // above hands to cargo-ndk.
    ndkVersion = pinnedNdk

    defaultConfig {
        applicationId = "se.mevoc.beacon"
        minSdk = minimumSdk
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"

        ndk { abiFilters += requestedAbis }
    }

    sourceSets {
        getByName("main") {
            // Both are build-directory outputs, not committed source: the
            // bindings are regenerated from the library they bind, and the
            // libraries are cross-compiled by the tasks above.
            kotlin.directories.add(bindingsDir.get().asFile.absolutePath)
            jniLibs.directories.add(jniLibsDir.get().asFile.absolutePath)
        }
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
        getByName("release") {
            // Unconfigured on purpose: slice 7 owns distribution, and a release
            // build that silently ships unsigned or unshrunk would be worse than
            // one that is obviously not set up yet.
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests {
            isReturnDefaultValues = true
        }
    }
}

// The Rust has to exist before anything is compiled against it.
tasks.named("preBuild") {
    dependsOn(generateUniffiBindings)
}

// The JVM tests load the *host* build of the same crate through UniFFI's
// library-override hook, so `./gradlew test` exercises the real FFI boundary
// rather than asserting that generated Kotlin compiles.
tasks.withType<Test>().configureEach {
    dependsOn(cargoBuildHost)
    systemProperty(
        "uniffi.component.beacon.libraryOverride",
        coreDir.resolve("target/debug/$nativeLibrary").absolutePath,
    )
}

dependencies {
    implementation(variantOf(libs.jna) { artifactType("aar") })

    testImplementation(libs.junit)
    testImplementation(libs.jna)
}
