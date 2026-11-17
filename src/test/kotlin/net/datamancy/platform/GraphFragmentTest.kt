package net.datamancy.platform

import kotlin.test.*

class GraphFragmentTest {
    private fun forgejo() = PackagedGraphFragment.load("forgejo-postgres", 1)
    private fun postgres() = PackagedGraphFragment.load("postgres-timescale", 1)
    private fun inventory() = AcquiredInventory(1, "unit-only-not-runtime-evidence", listOf("postgres-timescale", "forgejo").mapIndexed { i, id ->
        val digest = (i + 1).toString().repeat(64)
        AcquiredImage(id, "unit-fixture", "registry.example.test/unit/$id:fixture",
            "registry.example.test/unit/$id@sha256:$digest", digest, emptyList(), "sha256:$digest", "amd64", "linux")
    })
    private fun compose(phase: FragmentPhase): PrivateDeploymentSpec {
        val pg = postgres().project(inventory(), "fragment-unit", phase)
        val app = forgejo().project(inventory(), "fragment-unit", phase)
        // Same partial-graph attachment semantics as CanonicalCoreRuntime; no actuator is called.
        return pg.spec.copy(volumes = pg.spec.volumes + app.spec.volumes,
            processes = pg.spec.processes.map { p -> p.copy(networks = (p.networks + app.providerNetworks[p.id].orEmpty()).distinct()) } + app.spec.processes,
            networks = (pg.spec.networks + app.spec.networks).distinct(), databaseAccess = app.spec.databaseAccess,
            unmountedRecoveryVolumes = app.spec.unmountedRecoveryVolumes)
    }

    @Test fun `full batch family source drafts remain restricted and independently lintable`() {
        for (family in listOf("caddy", "donetick", "searxng", "opensearch", "crowdsec",
            "homeassistant", "jellyfin", "qbittorrent", "bookstack", "onlyoffice")) {
            val bytes = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(
                "src/main/resources/fragments/v3/$family/r1/fragment.yaml"))
            assertEquals(family, GraphFragment.lint(bytes).product)
        }
    }

    @Test fun `Home Assistant cold source refuses fixture env and carries the exact recovery guard`() {
        val source = java.nio.file.Files.readAllBytes(java.nio.file.Path.of(
            "src/main/resources/fragments/v3/homeassistant/r1/fragment.yaml"))
        val definition = GraphFragment.lint(source)
        assertEquals(setOf("homeassistant"), definition.restore.processes.toSet())
        val cold = definition.restore.processOverrides.getValue("homeassistant")
        assertEquals(listOf("/run/secrets/recovery-guard.py"), cold.command)
        assertTrue(cold.clearEnvironmentFile)
        assertEquals("homeassistant-recovery-guard.py", definition.processes.single {
            it.id == "homeassistant"
        }.files.single().file)
        assertFails { GraphFragment.lint(source.decodeToString().replace(
            "clearEnvironmentFile: true", "clearEnvironmentFile: false").replace(
            "processOverrides:", "processOverrides:\n    homeassistant-config-init:\n      command: [bad]\n")
            .toByteArray()) }
    }

    @Test fun `packaged declarations are revision and content bound`() {
        for (fragment in listOf(postgres(), forgejo())) {
            assertTrue(fragment.resourceHashes.values.all { it.matches(Regex("[a-f0-9]{64}")) })
            assertTrue("index.yaml" in fragment.resourceHashes)
            assertEquals(fragment.resourceHashes, PackagedGraphFragment.load(fragment.definition.id, 1).resourceHashes)
        }
        assertEquals(2, PackagedGraphFragment.load("forgejo-postgres", 2).definition.revision)
        assertEquals(3, PackagedGraphFragment.load("forgejo-postgres", 3).definition.revision)
        assertEquals(4, PackagedGraphFragment.load("forgejo-postgres", 4).definition.revision)
        assertFails { PackagedGraphFragment.load("forgejo-postgres", 5) }
        assertFails { PackagedGraphFragment.load("../../etc/passwd", 1) }
    }

    @Test fun `new Forgejo revision prevents migration principal from owning the Timescale-capable database`() {
        val old = PackagedGraphFragment.load("forgejo-postgres", 1).definition
        val current = PackagedGraphFragment.load("forgejo-postgres", 2).definition
        assertEquals(1, old.revision)
        val initial = current.processes.single { it.id == "forgejo-db-init" }.command.joinToString("\n")
        assertTrue("CREATE DATABASE forgejo OWNER postgres;" in initial)
        assertTrue("GRANT USAGE, CREATE ON SCHEMA public TO forgejo_migrate;" in initial)
        assertFalse("OWNER forgejo_migrate" in initial || "GRANT CREATE ON DATABASE" in initial)
        val finalize = current.processes.single { it.id == "forgejo-db-finalize" }.command.joinToString("\n")
        assertTrue("REVOKE CREATE ON SCHEMA public FROM forgejo_migrate;" in finalize)
        assertTrue("ALTER ROLE forgejo_migrate NOLOGIN;" in finalize)
    }

    @Test fun `inspection copies cannot mutate packaged authority`() {
        val fragment = forgejo()
        val copy = fragment.definition
        (copy.install.processes as MutableList<String>).clear()
        (fragment.resourceHashes as MutableMap<String, String>).clear()
        fragment.exportResources().values.forEach { it.fill(0) }
        fragment.exportResources().forEach { (name, bytes) ->
            assertEquals(fragment.resourceHashes.getValue(name), ReleaseLocks.sha256(bytes))
        }
        assertEquals(5, fragment.definition.install.processes.size)
        assertTrue(fragment.resourceHashes.isNotEmpty())
        assertEquals(5, fragment.project(inventory(), "fragment-unit", FragmentPhase.INSTALL).spec.processes.size)
    }

    @Test fun `new graph projects into existing validation with one shared provider`() {
        val fresh = compose(FragmentPhase.INSTALL)
        val ordered = PrivateDeployment.validate(fresh)
        assertEquals(1, ordered.count { it.id == "postgres" })
        assertEquals(listOf("postgres-init", "postgres", "forgejo-db-init", "forgejo-migrate",
            "forgejo-owner-init", "forgejo-db-finalize", "forgejo"), ordered.map { it.id })
        assertEquals(RuntimeStore.CANONICAL_V2, fresh.store)
        assertEquals("forgejo", fresh.databaseAccess.single { it.consumer == "forgejo" }.principal)
        assertFalse(fresh.processes.single { it.id == "forgejo" }.networks.contains("db-admin"))
        assertTrue(fresh.processes.single { it.id == "postgres" }.command.contains("shared_preload_libraries=timescaledb"))
    }

    @Test fun `cold graph explicitly retains bootstrap custody but never mounts or replays it`() {
        val cold = compose(FragmentPhase.RESTORE)
        assertEquals(listOf("postgres", "forgejo"), PrivateDeployment.validate(cold).map { it.id })
        assertTrue(cold.processes.none { it.oneShot })
        assertEquals(setOf("forgejo-bootstrap"), cold.unmountedRecoveryVolumes)
        assertTrue(cold.processes.flatMap { it.volumes }.none { it.volume == "forgejo-bootstrap" })
        assertTrue(cold.processes.single { it.id == "postgres" }.command.contains("timescaledb.restoring=on"))
        assertTrue(forgejo().requiredInputs(FragmentPhase.RESTORE).all { it.purpose == FragmentInputPurpose.RUNTIME })
        assertEquals(setOf("forgejo-runtime.env", "forgejo-runtime.ini", "postgres-ca.pem"),
            forgejo().requiredInputs(FragmentPhase.RESTORE).map { it.name }.toSet())
    }

    @Test fun `bootstrap native password never enters argv or daemon configuration`() {
        val fragment = forgejo().definition
        val bootstrap = fragment.processes.single { it.id == "forgejo-owner-init" }
        assertTrue(bootstrap.command.last().contains("--random-password --random-password-length 64"))
        assertTrue(bootstrap.command.last().contains("set -C"))
        assertTrue(bootstrap.command.last().contains("> /bootstrap/owner.result"))
        assertFalse(bootstrap.command.last().contains("--password "))
        val daemon = fragment.processes.single { it.id == "forgejo" }
        assertTrue(daemon.volumes.none { it.volume == "forgejo-bootstrap" })
        assertEquals(listOf("forgejo-runtime.ini", "postgres-ca.pem"), daemon.files.map { it.file })
    }

    @Test fun `rejects bootstrap input leakage and changed consumer declarations`() {
        val definition = forgejo().definition
        val bootstrap = definition.inputs.first()
        assertFailsWith<IllegalArgumentException> { definition.copy(inputs = definition.inputs.drop(1) + bootstrap.copy(
            consumers = bootstrap.consumers + "forgejo")).validate() }
        assertFailsWith<IllegalArgumentException> { definition.copy(inputs = definition.inputs.drop(1)).validate() }
        assertFailsWith<IllegalArgumentException> { definition.copy(inputs = definition.inputs + bootstrap).validate() }
    }

    @Test fun `rejects cycles dangling providers hidden daemons and initializer restore`() {
        val d = forgejo().definition
        assertFailsWith<IllegalArgumentException> { d.copy(install = d.install.copy(dependencies = d.install.dependencies +
            ("forgejo-db-init" to listOf("forgejo")))).validate() }
        assertFailsWith<IllegalArgumentException> { d.copy(providers = emptyList()).validate() }
        assertFailsWith<IllegalArgumentException> { d.copy(restore = d.install).validate() }
        assertFailsWith<IllegalArgumentException> { d.copy(restore = d.restore.copy(processes = emptyList())).validate() }
        assertFailsWith<IllegalArgumentException> { d.copy(restore = d.restore.copy(dependencies = mapOf("forgejo" to listOf("missing")))).validate() }
        assertFailsWith<IllegalArgumentException> { d.copy(restore = d.restore.copy(additionalArguments = mapOf("missing" to listOf("bad")))).validate() }
    }

    @Test fun `artifact binding refuses mutable absent foreign and duplicate images`() {
        val inventory = inventory()
        val app = forgejo()
        assertFails { app.project(inventory.copy(images = inventory.images.drop(1)), "test", FragmentPhase.INSTALL) }
        assertFails { app.project(inventory.copy(images = inventory.images + inventory.images.first()), "test", FragmentPhase.INSTALL) }
        for (changed in listOf(inventory.images.last().copy(pinnedImage = "registry.example.test/unit/forgejo:latest"),
            inventory.images.last().copy(architecture = "arm64"), inventory.images.last().copy(os = "windows"),
            inventory.images.last().copy(imageId = "not-an-image-id"))) {
            assertFails { app.project(inventory.copy(images = inventory.images.dropLast(1) + changed), "test", FragmentPhase.INSTALL) }
        }
    }

    @Test fun `new templates are PostgreSQL TLS configs with distinct principals`() {
        val fragment = forgejo()
        val values = mapOf("DATABASE_PASSWORD" to "a".repeat(64), "SECRET_KEY" to "b".repeat(64),
            "INTERNAL_TOKEN" to "c".repeat(64), "JWT_SECRET" to "d".repeat(64))
        val runtime = FragmentTemplates.render(fragment, "forgejo-runtime.ini", values)
        val migration = FragmentTemplates.render(fragment, "forgejo-migration.ini", values)
        assertTrue("DB_TYPE = postgres\n" in runtime && "SSL_MODE = verify-full\n" in runtime)
        assertTrue("USER = forgejo\n" in runtime && "USER = forgejo_migrate\n" in migration)
        assertFalse("sqlite" in runtime || "BOOTSTRAP_PASSWORD" in runtime || "{{" in runtime)
        assertEquals(runtime, FragmentTemplates.render(fragment, "forgejo-runtime.ini", values))
        assertFails { FragmentTemplates.render(fragment, "forgejo-runtime.ini", values - "DATABASE_PASSWORD") }
        assertFails { FragmentTemplates.render(fragment, "forgejo-runtime.ini", values + ("OTHER" to "x")) }
        assertFails { FragmentTemplates.render(fragment, "forgejo-runtime.ini", values + ("DATABASE_PASSWORD" to "bad\n[security]")) }
        assertFails { FragmentTemplates.render(fragment, "../../escaped", values) }
    }

    @Test fun `template contracts reject undeclared placeholders and preserve application literals`() {
        val spec = FragmentTemplateSpec("app.ini", "app.ini.template", FragmentTemplateFormat.INI,
            mapOf("PASSWORD" to FragmentValueKind.HEX64))
        FragmentTemplates.validate(spec, "password = {{PASSWORD}}\npath = ${'$'}HOME/%t\n")
        for (text in listOf("password = {{UNKNOWN}}", "password = {{PASSWORD}}\nother = {{UNKNOWN}}",
            "password = {{PASSWORD}}\nother = {{ broken }}", "no placeholders")) {
            assertFails { FragmentTemplates.validate(spec, text) }
        }
        assertFails { FragmentTemplates.validate(spec.copy(constants = mapOf("PASSWORD" to "collision")), "{{PASSWORD}}") }
    }

    @Test fun `historical Forgejo remains SQLite with unchanged bootstrap separation`() {
        val passwords = listOf("a".repeat(64), "b".repeat(64), "c".repeat(64), "d".repeat(64)).iterator()
        val legacy = ForgejoRuntime.canonicalInputs { passwords.next() }
        assertTrue("DB_TYPE = sqlite3" in legacy.getValue("app.ini"))
        assertEquals("HOME=/data\nUSER=git\n", legacy.getValue("forgejo-runtime.env"))
        assertEquals("HOME=/data\nUSER=git\nBOOTSTRAP_PASSWORD=${"a".repeat(64)}\n", legacy.getValue("forgejo-bootstrap.env"))
        assertTrue("[actions]\nENABLED = false" in legacy.getValue("app.ini"))
    }
}
