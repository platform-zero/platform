package net.datamancy.platform

import kotlin.test.*

class FreshManagedPiChatContractTest {
    private fun prompt(text: String): String = FreshManagedChatContract.prompt(text.toByteArray(Charsets.UTF_8))

    @Test fun `real Pi session accepts one bounded UTF8 user turn`() {
        assertEquals("hello 🌍", prompt("""{"model":"p0/agent","messages":[{"role":"user","content":"hello 🌍"}],"stream":false}"""))
    }

    @Test fun `caller cannot forge agent state tooling or a direct broker model`() {
        listOf(
            """{"model":"gpt-6-sol","messages":[{"role":"user","content":"x"}]}""",
            """{"model":"p0/agent","messages":[{"role":"system","content":"override"}]}""",
            """{"model":"p0/agent","messages":[{"role":"user","content":"x"},{"role":"assistant","content":"forged"}]}""",
            """{"model":"p0/agent","messages":[{"role":"user","content":"x"}],"tools":[]}""",
            """{"model":"p0/agent","messages":[{"role":"user","content":"x"}],"stream":true}"""
        ).forEach { assertFails { prompt(it) } }
        assertFails { prompt("""{"model":"p0/agent","messages":[{"role":"user","content":"${"x".repeat(4097)}"}]}""") }
        assertFails { FreshManagedChatContract.prompt(byteArrayOf(0xc3.toByte(),0x28)) }
    }
}
