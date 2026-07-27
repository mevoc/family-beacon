package se.mevoc.beacon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.beacon.ClientException
import uniffi.beacon.ProfileView
import uniffi.beacon.SeedsView
import uniffi.beacon.enroll
import uniffi.beacon.generateSeeds
import uniffi.beacon.open
import java.time.Instant

/**
 * The build's walking skeleton: Kotlin calling the real Rust core.
 *
 * These run on the JVM against the *host* build of `beacon-ffi`, loaded through
 * UniFFI's library-override hook (see `tasks.withType<Test>` in
 * `build.gradle.kts`). That is the point of them. A build that only ran
 * `assembleDebug` would prove that generated Kotlin compiles, and would stay
 * green while the boundary itself was broken — a mismatched `uniffi` version, a
 * library name nothing loads, a type that does not lower. Every assertion below
 * is a round trip through the FFI.
 *
 * None of them needs a server. Everything asserted here fails before a socket is
 * opened, which is what keeps them in the per-commit tier rather than the
 * contract tier.
 */
class FfiBoundaryTest {

    private fun seeds() = generateSeeds()

    @Test
    fun `seeds come back from the platform rng as two distinct keys`() {
        val seeds = seeds()

        assertEquals("a seed is 32 bytes", 32, seeds.device.size)
        assertEquals("a seed is 32 bytes", 32, seeds.identity.size)
        assertNotEquals(
            "the request-signing key and the protocol identity key are two keys, " +
                "and one RNG call filling both would be a plausible-looking bug",
            seeds.device.toList(),
            seeds.identity.toList(),
        )
    }

    @Test
    fun `an address that is not a sund address is refused before any socket opens`() {
        val thrown = runCatching {
            enroll(
                address = "https://beacon.example",
                invitation = "token",
                profile = ProfileView("phone", "founder", "adult"),
                seeds = seeds(),
                now = Instant.now(),
            )
        }.exceptionOrNull()

        assertTrue("expected an Address failure, got $thrown", thrown is ClientException.Address)
    }

    @Test
    fun `an empty state blob is an error rather than an empty family`() {
        val thrown = runCatching { open(ByteArray(0), seeds()) }.exceptionOrNull()

        assertTrue("expected a State failure, got $thrown", thrown is ClientException.State)
    }

    @Test
    fun `a state blob from a newer build is refused rather than guessed at`() {
        // Byte zero is the format version. This is the field-downgrade path: a
        // build that tried to parse a format it has never seen would be deciding
        // what that format means.
        val fromTheFuture = byteArrayOf(99) + """{"device_id":"dev_A"}""".toByteArray()

        val thrown = runCatching { open(fromTheFuture, seeds()) }.exceptionOrNull()

        assertTrue("expected a State failure, got $thrown", thrown is ClientException.State)
        // The detail string is what crosses; the generated `message` is
        // `"detail=…"`, so this reads the core's own words about what it found.
        assertTrue(
            "the refusal should name the version it found: ${thrown?.message}",
            thrown?.message?.contains("99") == true,
        )
    }

    @Test
    fun `a seed of the wrong length is refused rather than padded`() {
        // Padding would produce a different device identity from the one in the
        // keystore, and the symptom would arrive much later as 401s nobody can
        // explain.
        val truncated = SeedsView(device = ByteArray(32), identity = ByteArray(31))

        val thrown = runCatching { open(byteArrayOf(1), truncated) }.exceptionOrNull()

        assertTrue("expected a State failure, got $thrown", thrown is ClientException.State)
        assertTrue(
            "the refusal should name which seed was wrong: ${thrown?.message}",
            thrown?.message?.contains("identity") == true,
        )
    }

    @Test
    fun `the identity failure is dispatched on separately from the connectivity one`() {
        // The one error in the app whose wording is a security property: a pin
        // mismatch must never be renderable as "no connection". What crosses the
        // FFI is the *variant*, so this asserts the dispatch the UI will
        // actually perform — declared as the sealed parent so the `when` is a
        // real branch rather than a statically-known one.
        //
        // Worth knowing while writing that UI: UniFFI generates `message` as
        // `"detail=…"`. The Rust `Display` sentence does **not** cross, so the
        // user-facing wording is the app's to write, keyed off the variant and
        // localised. That is also why the variant has to stay distinct — it is
        // the only thing the app can key off.
        val cases: List<Pair<ClientException, String>> = listOf(
            ClientException.ServerIdentity("pin mismatch") to "identity",
            ClientException.Network("timeout") to "network",
        )

        for ((thrown, expected) in cases) {
            val branch = when (thrown) {
                is ClientException.ServerIdentity -> "identity"
                is ClientException.Network -> "network"
                else -> "other"
            }
            assertEquals(expected, branch)
        }

        assertTrue(
            "the detail is what crosses, and the UI may want to show it",
            ClientException.ServerIdentity("pin mismatch").message?.contains("pin mismatch") == true,
        )
    }
}
