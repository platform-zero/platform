package net.datamancy.platform

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import kotlin.test.*

class FragmentYamlTest {
    @Serializable private data class Typed(val count: Int, val enabled: Boolean, val version: String,
        val nested: List<TypedChild> = emptyList())
    @Serializable private data class TypedChild(val value: String)
    private fun parse(text: String) = FragmentYaml.parse(text.toByteArray())
    private fun decode(text: String) = FragmentYaml.decode(text.toByteArray(), Typed.serializer())

    @Test fun `json scalar resolution does not use yaml 1_1 coercions`() {
        val doc = parse("yesValue: yes\nonValue: on\ndate: 2026-01-01\nboolean: true\ncount: 12\nversion: '12'\nnothing: null\n")
        assertEquals(JsonPrimitive("yes"), doc["yesValue"])
        assertEquals(JsonPrimitive("on"), doc["onValue"])
        assertEquals(JsonPrimitive("2026-01-01"), doc["date"])
        assertEquals(JsonPrimitive(true), doc["boolean"])
        assertEquals(JsonPrimitive(12), doc["count"])
        assertEquals(JsonPrimitive("12"), doc["version"])
        assertEquals(JsonNull, doc["nothing"])
    }

    @Test fun `literal configuration strings are never expanded`() {
        assertEquals(JsonPrimitive("${'$'}HOME %t ${'$'}{SECRET:-default}"),
            parse("value: '${'$'}HOME %t ${'$'}{SECRET:-default}'")["value"])
    }

    @Test fun `requires exactly one mapping document`() {
        listOf("", "---\n", "[]", "scalar", "a: 1\n---\nb: 2", "%YAML 1.1\n---\na: 1").forEach {
            assertFailsWith<IllegalArgumentException> { parse(it) }
        }
        assertEquals(JsonPrimitive(1), parse("---\na: 1\n...\n")["a"])
    }

    @Test fun `rejects duplicate and non string keys recursively`() {
        listOf("a: 1\na: 2", "a: [{x: 1, x: 2}]", "1: value", "true: value",
            "null: value", "? [a, b]\n: value").forEach { assertFailsWith<IllegalArgumentException> { parse(it) } }
        assertEquals(JsonPrimitive("value"), parse("'true': value")["true"])
    }

    @Test fun `rejects tags anchors aliases and merge keys even when unused`() {
        listOf("a: !!str value", "!!map {a: 1}", "a: ! value", "a: &name value", "a: *missing",
            "a: &name [1]\nb: *name", "a: {<<: {b: 1}}", "'<<': ignored",
            "%TAG !x! tag:example.com,2026:\n---\na: 1").forEach {
            assertFailsWith<IllegalArgumentException> { parse(it) }
        }
    }

    @Test fun `exact scalar types reject decoder coercion and overflow`() {
        assertEquals(Typed(1, true, "1"), decode("count: 1\nenabled: true\nversion: '1'"))
        listOf("count: '1'\nenabled: true\nversion: '1'", "count: 1\nenabled: 'true'\nversion: '1'",
            "count: 1\nenabled: true\nversion: 1", "count: 1.0\nenabled: true\nversion: '1'",
            "count: 2147483648\nenabled: true\nversion: '1'", "count: null\nenabled: true\nversion: '1'").forEach {
            assertFailsWith<IllegalArgumentException> { decode(it) }
        }
    }

    @Test fun `rejects unknown missing and nested malformed fields`() {
        val good = "count: 1\nenabled: true\nversion: '1'\n"
        listOf(good + "unknown: 2", good + "nested: [{value: ok, unknown: no}]",
            good + "nested: [{value: 2}]", good + "nested: {value: text}", "count: 1").forEach {
            assertFailsWith<IllegalArgumentException> { decode(it) }
        }
    }

    @Test fun `byte and unicode decoding limits are enforced before parsing`() {
        val prefix = "a: 1\n#"
        assertEquals(JsonPrimitive(1), parse(prefix + "x".repeat(FragmentYaml.MAX_BYTES - prefix.length))["a"])
        assertFailsWith<IllegalArgumentException> { parse(prefix + "x".repeat(FragmentYaml.MAX_BYTES)) }
        assertFailsWith<IllegalArgumentException> { parse("a: '" + "é".repeat(FragmentYaml.MAX_BYTES / 2) + "'") }
        assertFailsWith<IllegalArgumentException> { FragmentYaml.parse(byteArrayOf(0xC3.toByte(), 0x28)) }
    }

    @Test fun `depth and node budgets stop before constructing unbounded trees`() {
        parse("a: " + "[".repeat(30) + "0" + "]".repeat(30))
        assertFailsWith<IllegalArgumentException> { parse("a: " + "[".repeat(31) + "0" + "]".repeat(31)) }
        parse("a: [" + List(FragmentYaml.MAX_NODES - 3) { "0" }.joinToString(",") + "]")
        assertFailsWith<IllegalArgumentException> {
            parse("a: [" + List(FragmentYaml.MAX_NODES - 2) { "0" }.joinToString(",") + "]")
        }
    }

    @Test fun `errors do not disclose values or parser excerpts through causes`() {
        val secret = "never-disclose-fixture-password"
        val failure = assertFailsWith<IllegalArgumentException> { parse("a: [$secret") }
        assertEquals("Invalid restricted fragment YAML", failure.message)
        assertNull(failure.cause)
        val decoding = assertFailsWith<IllegalArgumentException> { decode("count: '$secret'") }
        assertFalse(decoding.toString().contains(secret))
        assertNull(decoding.cause)
    }
}
