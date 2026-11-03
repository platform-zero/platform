package net.datamancy.platform

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class RuntimeStoreTest {
    @Test fun `closed identities preserve legacy wire bytes and bind isolated store explicitly`() {
        val legacy = PrivateDeploymentSpec(name = "unit", volumes = emptyList(), processes = listOf(
            RuntimeProcess("app", "example.test/app@sha256:" + "a".repeat(64), "b".repeat(64), 1000, readiness = listOf("check"))))
        val json = Json { encodeDefaults = true }
        assertFalse("store" in json.encodeToString(legacy))
        val isolated = legacy.copy(store = RuntimeStore.CANONICAL_V2)
        assertEquals(isolated, json.decodeFromString<PrivateDeploymentSpec>(json.encodeToString(isolated)))
        assertNotEquals(PrivateDeployment.expectedFingerprint(legacy, emptyMap()), PrivateDeployment.expectedFingerprint(isolated, emptyMap()))
        assertEquals(PrivateRootfulCommands.prefix, RuntimeStore.LEGACY.prefix())
        RuntimeStore.LEGACY.verifyConfiguration()
        val store = RuntimeStore.CANONICAL_V2
        assertTrue(store.prefix().contains("--module=${store.module}"))
        assertTrue(store.prefix().contains("--root=${store.graph}"))
        assertTrue(store.prefix().contains("--runroot=${store.run}"))
        assertTrue(store.prefix().contains("--network-config-dir=${store.network}"))
        assertTrue("lock_type = \"file\"" in store.configuration)
        assertTrue("tmp_dir = \"/run/p0-v3-canonical-v2/libpod\"" in store.configuration)
        assertFalse("num_locks" in store.configuration)
        val output = mutableListOf<String>()
        assertEquals(0, runCommand(arrayOf("release", "runtime-store-v2-policy"), output::add, { fail(it) }))
        assertEquals(store.configuration, Json.parseToJsonElement(output.single()).jsonObject.getValue("configuration").jsonPrimitive.content)
        assertFails { json.decodeFromString<PrivateDeploymentSpec>(json.encodeToString(isolated).replace("CANONICAL_V2", "DEFAULT")) }
    }
    @Test fun `file locks require null observation in exact isolated store and bounded complete object census`() {
        val store = RuntimeStore.CANONICAL_V2
        var locks = "null"
        var census = "owned-object\n"
        var exit = 0
        val commands = RuntimeCommands { args ->
            if (args.first() == "pod") assertEquals(listOf("pod", "ps", "-q", "--no-trunc"), args)
            if (args.first() == "info") RuntimeCommandResult(0,
                """{"store":{"graphRoot":"${store.graph}","runRoot":"${store.run}"},"host":{"freeLocks":$locks}}""")
            else RuntimeCommandResult(exit, census)
        }
        assertEquals(4093L, RuntimeLockBudget.available(commands, store))
        val omitted = RuntimeCommands { args -> commands.run(args).let { it.copy(output = it.output.replace("\"freeLocks\":null", "")) } }
        assertEquals(4093L, RuntimeLockBudget.available(omitted, store))
        locks = "0"; assertFails { RuntimeLockBudget.available(commands, store) }; locks = "null"
        exit = 1; assertFails { RuntimeLockBudget.available(commands, store) }; exit = 0
        census = "duplicate\nduplicate\n"; assertFails { RuntimeLockBudget.available(commands, store) }
        census = "bad/name"; assertFails { RuntimeLockBudget.available(commands, store) }
        census = (1..4097).joinToString("\n") { "object-$it" }; assertFails { RuntimeLockBudget.available(commands, store) }
        census = (1..2000).joinToString("\n") { "object-$it" }; assertEquals(0L, RuntimeLockBudget.available(commands, store))
        census = ""; assertEquals(4096L, RuntimeLockBudget.available(commands, store))
        assertFails { RuntimeLockBudget.available(commands) }
    }
}
