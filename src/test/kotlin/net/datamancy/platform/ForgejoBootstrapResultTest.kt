package net.datamancy.platform

import kotlin.test.*

class ForgejoBootstrapResultTest {
    private val password = "aB1'\\!?%".repeat(8)
    private val output = "generated random password is '$password'\n" +
        "New user 'p0v3-bootstrap' has been successfully created!\n"

    @Test fun `parses full Forgejo 17 stdout only after success marker without leaking password in toString`() {
        val candidate = ForgejoBootstrapResult.parse(output.toByteArray())
        assertEquals(password, candidate.password)
        assertFalse(candidate.toString().contains(password))
    }

    @Test fun `upstream complexity alphabet may contain internal spaces quotes and backticks`() {
        val generated = "a B'\\`!Z".repeat(8)
        val line = "generated random password is '$generated'\nNew user 'p0v3-bootstrap' has been successfully created!\n"
        assertEquals(generated, ForgejoBootstrapResult.parse(line.toByteArray()).password)
    }

    @Test fun `printed password before account creation cannot masquerade as successful bootstrap`() {
        for (invalid in listOf(
            "generated random password is '$password'\n",
            output.replace("p0v3-bootstrap", "foreign"),
            output + "unaccounted extra output\n",
            output.replace(password, "a".repeat(63)),
            output.replace(password, " " + "a".repeat(63)),
            output.replace(password, "a".repeat(63) + " "),
            output.replace(password, "a".repeat(63) + "\n"),
        )) assertFails { ForgejoBootstrapResult.parse(invalid.toByteArray()) }
        assertFails { ForgejoBootstrapResult.parse(byteArrayOf(-1)) }
        assertFails { ForgejoBootstrapResult.parse(ByteArray(513) { 65 }) }
    }
}
