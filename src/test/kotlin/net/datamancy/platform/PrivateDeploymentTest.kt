package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class PrivateDeploymentTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val imageId = "b".repeat(64)
    private fun spec() = PrivateDeploymentSpec(name = "unit", volumes = listOf(RuntimeVolume("data", 999)), processes = listOf(
        RuntimeProcess("init", image, imageId, 999, entrypoint = "/bin/sh", command = listOf("-ec", "initialize"),
            environmentFile = "app.env", volumes = listOf(RuntimeMount("data", "/data")), oneShot = true),
        RuntimeProcess("app", image, imageId, 999, dependencies = listOf("init"),
            volumes = listOf(RuntimeMount("data", "/data")), files = listOf(RuntimeFile("service.conf", "/etc/service.conf")), readiness = listOf("check"))))
    private fun fixture(block: (Path, PrivateDeploymentSpec, Fake) -> Unit) {
        val base = Files.createTempDirectory("private-runtime-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val root = Files.createDirectory(base.resolve("unit"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        for (file in listOf("app.env", "service.conf")) {
            Files.createFile(root.resolve(file), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            Files.writeString(root.resolve(file), "SECRET=unit-only-secret\n")
        }
        try { block(base, spec(), Fake(image, imageId)) }
        finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `explicit store dispatch is scoped and cannot adopt legacy ownership`() = fixture { base, old, fake ->
        val selected = old.copy(store = RuntimeStore.CANONICAL_V2)
        val runtime = PrivateDeployment(base, fake) {}
        assertFails { runtime.apply(selected) }
        assertTrue(fake.resources.isEmpty())
        fake.store = RuntimeStore.CANONICAL_V2
        assertTrue(runtime.apply(selected).any { it.state == "running" })
        assertTrue(runtime.status(selected).any { it.state == "running" })
        runtime.stop(selected)
        assertFails { runtime.apply(old) }
        assertEquals(RuntimeStore.LEGACY, old.store)
    }
    private class Fake(private val image: String, private val imageId: String) : RuntimeCommands {
        val calls = mutableListOf<List<String>>()
        val resources = mutableMapOf<Pair<String, String>, JsonObject>()
        var waitTimeouts = 0
        var failedJob = false
        var failedStop = false
        var uncleanStop = false
        var failReady = false
        var lookupFailure = false
        var wrongImage = false
        var wrongStore = false
        var store = RuntimeStore.LEGACY
        private fun state(status: String, exit: Int = 0) = buildJsonObject {
            put("Status", status); put("Running", status == "running"); put("ExitCode", exit); put("Pid", if (status == "running") 42 else 0)
        }
        override fun run(args: List<String>): RuntimeCommandResult {
            calls += args
            fun reply(value: String = "") = RuntimeCommandResult(0, value)
            fun labels() = buildJsonObject {
                args.filter { it.startsWith("--label=") }.forEach {
                    val pair = it.removePrefix("--label=").split('=', limit = 2); put(pair[0], pair[1])
                }
            }
            when (args[0]) {
                "info" -> return reply("""{"host":{"freeLocks":null,"security":{"rootless":false,"apparmorEnabled":true,"seccompEnabled":true}},"store":{"graphRoot":"${if (wrongStore) "/shared" else store.graph}","runRoot":"${store.run}"}}""")
                "image" -> return reply("""[{"Id":"${if (wrongImage) "c".repeat(64) else imageId}","Digest":"${image.substringAfter('@')}"}]""")
                "create" -> {
                    val name = args.single { it.startsWith("--name=") }.substringAfter('=')
                    resources["container" to name] = buildJsonObject {
                        put("Config", buildJsonObject {
                            put("Labels", labels()); put("User", args.single { it.startsWith("--user=") }.substringAfter('='))
                        })
                        put("Image", imageId); put("Id", "c".repeat(64))
                        val finalCaps = JsonArray(args.filter { it.startsWith("--cap-add=") }.map { JsonPrimitive("CAP_" + it.substringAfter('=')) })
                        put("EffectiveCaps", if (finalCaps.isEmpty()) JsonNull else finalCaps)
                        put("BoundingCaps", if (finalCaps.isEmpty()) JsonNull else finalCaps)
                        put("HostConfig", buildJsonObject {
                            put("Privileged", false); put("ReadonlyRootfs", true); put("PortBindings", buildJsonObject {
                                for (publication in args.filter { it.startsWith("--publish=") }) {
                                    val parts = publication.substringAfter('=').split(':')
                                    put(parts[2], buildJsonArray { add(buildJsonObject { put("HostIp", parts[0]); put("HostPort", parts[1]) }) })
                                }
                            })
                            put("PidMode", "private"); put("IpcMode", "shareable"); put("UTSMode", "private")
                            put("CgroupMode", "private"); put("UsernsMode", ""); put("NetworkMode", "bridge")
                            put("Memory", args.single { it.startsWith("--memory=") }.substringAfter('=').removeSuffix("m").toLong() * 1024 * 1024)
                            put("PidsLimit", 512); put("Devices", JsonArray(emptyList())); put("GroupAdd", JsonArray(emptyList())); put("VolumesFrom", JsonNull)
                            put("SecurityOpt", JsonArray(args.filter { it.startsWith("--security-opt=") }.map { JsonPrimitive(it.substringAfter('=')) }))
                            put("CapAdd", JsonArray(emptyList())) // NET_BIND_SERVICE is a Podman default capability.
                        })
                        put("NetworkSettings", buildJsonObject { put("Networks", buildJsonObject {
                            args.filter { it.startsWith("--network=") }.forEach {
                                put(it.substringAfter('='), buildJsonObject { put("IPAddress", "10.89.0.2") })
                            }
                        }) })
                        put("AppArmorProfile", args.find { it.startsWith("--security-opt=apparmor=") }?.substringAfterLast('=') ?: "containers-default")
                        put("Mounts", JsonArray(args.filter { it.startsWith("--volume=") }.map {
                            val parts = it.substringAfter('=').split(':')
                            buildJsonObject { put("Type", "volume"); put("Name", parts[0]); put("Destination", parts[1]) }
                        }))
                        put("State", state("created"))
                    }
                    return reply(name)
                }
                "start", "stop", "wait" -> {
                    if (args[0] == "stop" && failedStop) return RuntimeCommandResult(1, "interrupted stop")
                    if (args[0] == "wait" && waitTimeouts > 0) { waitTimeouts--; throw PrivateCommandTimeout() }
                    val name = args.last(); val key = "container" to name
                    val updated = resources.getValue(key).toMutableMap()
                    updated["State"] = state(if (args[0] == "start") "running" else "exited", if (failedJob && args[0] == "wait") 1 else if (uncleanStop && args[0] == "stop") 137 else 0)
                    resources[key] = JsonObject(updated)
                    return reply(if (args[0] == "wait") if (failedJob) "1" else "0" else name)
                }
                "exec" -> return RuntimeCommandResult(if (failReady) 1 else 0, "private diagnostic")
                "network", "volume", "container", "secret" -> {
                    if (args[0] == "volume" && args[1] == "import") return reply()
                    if (args[1] == "exists") return RuntimeCommandResult(if (lookupFailure) 125 else if (args[0] to args[2] in resources) 0 else 1, "")
                    if (args[1] == "inspect") return reply(JsonArray(listOf(resources.getValue(args[0] to args[2]))).toString())
                    if (args[1] == "create") {
                        val name = if (args[0] == "secret") args[args.size - 2] else args.last()
                        resources[args[0] to name] = buildJsonObject {
                            if (args[0] == "secret") put("Spec", buildJsonObject { put("Labels", labels()) })
                            else put(if (args[0] == "network") "labels" else "Labels", labels())
                            if (args[0] == "network") put("internal", "--internal" in args)
                        }
                        return reply(name)
                    }
                }
            }
            error("Unexpected fake command: ${args.first()}")
        }
    }
    private fun publicSpec(original: PrivateDeploymentSpec): PrivateDeploymentSpec = CaddyRuntime.publish(
        original.copy(store = RuntimeStore.CANONICAL_V2, processes = listOf(original.processes.last().copy(
            id = "caddy", dependencies = emptyList(), entrypoint = "/usr/bin/caddy", command = listOf("run"), environmentFile = "app.env"))),
        RuntimeIngressPublication("unit", setOf("web.datamancy.net"), "0.0.0.0"))

    @Test fun `only explicit canonical Caddy publishes exact HTTP HTTPS and isolated ACME egress`() = fixture { base, original, fake ->
        val spec = publicSpec(original)
        fake.store = RuntimeStore.CANONICAL_V2
        val runtime = PrivateDeployment(base, fake, ingressPortOwner = { PortOwner.FREE }) {}
        runtime.apply(spec)
        val create = fake.calls.single { it.first() == "create" }
        assertEquals(listOf("--publish=0.0.0.0:80:80/tcp", "--publish=0.0.0.0:443:443/tcp"), create.filter { it.startsWith("--publish=") })
        val networks = fake.calls.filter { it.take(2) == listOf("network", "create") }
        assertTrue("--internal" in networks.single { it.last().endsWith("-net") })
        assertFalse("--internal" in networks.single { it.last().endsWith("-ingress-egress") })
        val fingerprint = runtime.audit(spec).fingerprint
        assertEquals(PortOwner.OWNED_V3, runtime.ingressPortOwner(spec, fingerprint, 80))
        val target = runtime.withCaddyAdmin(spec, fingerprint, true) { it }
        assertEquals(CaddyAdminTarget(42, "c".repeat(64)), target)
        assertFails { runtime.withCaddyAdmin(spec, "f".repeat(64), false) { error("must not dispatch") } }
        assertFalse("ingress" in Json.encodeToString(original))
        runtime.stop(spec)
        assertFails { runtime.withCaddyAdmin(spec, fingerprint, true) { error("must not dispatch") } }
    }

    @Test fun `protected ports publication drift and public restore fail closed`() = fixture { base, original, fake ->
        val spec = publicSpec(original)
        fake.store = RuntimeStore.CANONICAL_V2
        for (owner in listOf(PortOwner.PROTECTED, PortOwner.UNKNOWN, PortOwner.OWNED_V3)) {
            assertFails { PrivateDeployment(base, fake, ingressPortOwner = { owner }) {}.apply(spec) }
        }
        assertTrue(fake.resources.isEmpty())
        val runtime = PrivateDeployment(base, fake, ingressPortOwner = { PortOwner.FREE }) {}
        assertFails { runtime.importCold(spec, emptyMap(), "a".repeat(64), base, emptyMap()) }
        assertTrue(fake.resources.isEmpty())
        runtime.apply(spec)
        val key = "container" to "p0v3-live-unit-caddy"
        val container = fake.resources.getValue(key)
        val host = container.getValue("HostConfig").jsonObject
        fake.resources[key] = JsonObject(container + ("HostConfig" to JsonObject(host + ("PortBindings" to buildJsonObject {}))))
        assertFails { runtime.audit(spec) }
        assertFails { runtime.withCaddyAdmin(spec, "a".repeat(64), false) { error("must not dispatch") } }
        assertFails { PrivateDeployment.validate(spec.copy(store = RuntimeStore.LEGACY)) }
        assertFails { PrivateDeployment.validate(spec.copy(ingress = spec.ingress!!.copy(approvedHosts = setOf("datamancy.net")))) }
        assertFails { PrivateDeployment.validate(spec.copy(ingress = spec.ingress!!.copy(listenAddress = "localhost"))) }
        assertFails { PrivateDeployment.validate(spec.copy(processes = spec.processes + original.processes.last().copy(networks = listOf("ingress-egress"), dependencies = emptyList()))) }
    }

    @Test fun `host port inventory never treats a listener as owned and fails closed on unreadable input`() {
        val header = "sl local_address rem_address st"
        assertEquals(PortOwner.FREE, inspectIngressPortOwner(80) { header + "\n" })
        assertEquals(PortOwner.PROTECTED, inspectIngressPortOwner(80) { header + "\n0: 00000000:0050 00000000:0000 0A\n" })
        assertEquals(PortOwner.FREE, inspectIngressPortOwner(443) { header + "\n0: 00000000:0050 00000000:0000 0A\n" })
        assertEquals(PortOwner.UNKNOWN, inspectIngressPortOwner(443) { error("denied") })
        assertEquals(PortOwner.UNKNOWN, inspectIngressPortOwner(443) { "invalid" })
        assertFails { inspectIngressPortOwner(2019) { header } }
    }

    @Test fun `backup lease survives fence release and excludes ordinary startup until verified finish`() = fixture { base, original, fake ->
        val spec = original.copy(name = "q-abcdef123456-unit")
        RuntimePreparation.prepare(spec, base) { mapOf("app.env" to "UNIT=1\n", "service.conf" to "unit\n") }
        val ordinary = PrivateDeployment(base, fake) {}
        ordinary.apply(spec)
        val access = RuntimeBackupAccess("q-abcdef123456", "cap-abcdef123456", "a".repeat(64))
        val backup = PrivateDeployment(base, fake, backupAccess = access) {}
        val ledger = Files.readAllBytes(base.resolve("${spec.name}/runtime.jobs"))
        backup.claimBackup(spec)
        assertFails { backup.claimBackup(spec) }
        assertFails { ordinary.apply(spec) }
        assertFails { ordinary.stage(spec, "app") }
        assertFails { ordinary.stop(spec) }
        assertEquals("running", ordinary.audit(spec).statuses.last().state)
        val foreign = PrivateDeployment(base, fake, backupAccess = access.copy(operation = "cap-111111111111")) {}
        assertFails { foreign.enterMaintenance(spec, "backup") }
        val fence = backup.enterMaintenance(spec, "backup")
        backup.withFrozen(spec, fence.id) { assertEquals(fence.id, it.fenceId) }
        assertFails { ordinary.leaveMaintenance(spec, fence.id) }
        assertFails { backup.finishBackup(spec) }
        backup.leaveMaintenance(spec, fence.id)
        assertFails { ordinary.apply(spec) } // Boot must still fail at this formerly unfenced boundary.
        backup.apply(spec)
        backup.finishBackup(spec)
        assertContentEquals(ledger, Files.readAllBytes(base.resolve("${spec.name}/runtime.jobs")))
        assertFalse(Files.exists(base.resolve("${spec.name}/runtime.backup")))
        assertEquals("running", ordinary.apply(spec).last().state)
        assertFails { backup.apply(spec) }
        assertEquals(2, ordinary.audit(spec).statuses.size)
        assertNotNull(backup.isolateBackup(spec)) // Stop-only cleanup can cover already released members.
    }
    @Test fun `backup claim refuses incomplete native import markers before lease creation`() = fixture { base, original, fake ->
        val spec = original.copy(name = "q-abcdef123456-unit")
        RuntimePreparation.prepare(spec, base) { mapOf("app.env" to "UNIT=1\n", "service.conf" to "unit\n") }
        val ordinary = PrivateDeployment(base, fake) {}
        ordinary.apply(spec)
        val root = base.resolve(spec.name)
        val intent = root.resolve("runtime.import.intent")
        Files.writeString(intent, "p0v3-native-volume-import-v1\n${ordinary.audit(spec).fingerprint}\n${"a".repeat(64)}\n")
        Files.setPosixFilePermissions(intent, PosixFilePermissions.fromString("rw-------"))
        val backup = PrivateDeployment(base, fake, backupAccess = RuntimeBackupAccess("q-abcdef123456", "cap-abcdef123456", "a".repeat(64))) {}
        assertFails { backup.claimBackup(spec) }
        assertFalse(Files.exists(root.resolve("runtime.backup")))
    }
    @Test fun `backup cannot adopt old fences or replay lost initialization records`() = fixture { base, original, fake ->
        val spec = original.copy(name = "q-abcdef123456-unit")
        RuntimePreparation.prepare(spec, base) { mapOf("app.env" to "UNIT=1\n", "service.conf" to "unit\n") }
        val ordinary = PrivateDeployment(base, fake) {}
        ordinary.apply(spec)
        val old = ordinary.enterMaintenance(spec, "update")
        val backup = PrivateDeployment(base, fake, backupAccess = RuntimeBackupAccess("q-abcdef123456", "cap-abcdef123456", "a".repeat(64))) {}
        assertFails { backup.claimBackup(spec) }
        ordinary.leaveMaintenance(spec, old.id); ordinary.apply(spec)
        backup.claimBackup(spec)
        val fence = backup.enterMaintenance(spec, "backup")
        backup.leaveMaintenance(spec, fence.id)
        val volumeKey = "volume" to "p0v3-live-${spec.name}-volume-data"
        val volume = assertNotNull(fake.resources.remove(volumeKey))
        val allocations = fake.calls.count { it.first() == "create" || it.getOrNull(1) == "create" }
        assertFails { backup.apply(spec) }
        assertEquals(allocations, fake.calls.count { it.first() == "create" || it.getOrNull(1) == "create" })
        fake.resources[volumeKey] = volume
        Files.delete(base.resolve("${spec.name}/runtime.jobs"))
        val before = fake.calls.count { it.first() == "start" }
        assertFails { backup.apply(spec) }
        assertEquals(before, fake.calls.count { it.first() == "start" })
        assertFails { backup.finishBackup(spec) }
        Files.writeString(base.resolve("${spec.name}/runtime.backup"), "{")
        assertFails { ordinary.apply(spec) }
        assertFails { backup.isolateBackup(spec) }
    }
    @Test fun `unclean stop retains failure but continues reverse isolation of other daemons`() = fixture { base, original, fake ->
        val spec = original.copy(processes = original.processes + original.processes.last().copy(id = "second", dependencies = listOf("app")))
        val runtime = PrivateDeployment(base, fake) {}
        runtime.apply(spec)
        fake.uncleanStop = true
        assertFails { runtime.enterMaintenance(spec, "update") }
        assertNotNull(runtime.maintenanceStatus(spec))
        assertTrue(runtime.status(spec).none { it.state == "running" })
        assertEquals(listOf("p0v3-live-unit-second", "p0v3-live-unit-app"), fake.calls.filter { it.first() == "stop" }.map { it.last() })
        assertFails { runtime.apply(spec) }
    }
    @Test fun `multiple internal networks are created and exact attachments enforced`() = fixture { base, original, fake ->
        val spec = original.copy(networks = listOf("net", "data"), processes = original.processes.map {
            it.copy(networks = if (it.id == "app") listOf("net", "data") else listOf("data"))
        })
        val runtime = PrivateDeployment(base, fake) {}
        runtime.apply(spec)
        assertEquals(2, fake.calls.count { it.take(2) == listOf("network", "create") && "--internal" in it })
        assertEquals(6, runtime.audit(spec).existingResources)
        val key = "container" to "p0v3-live-unit-app"
        val altered = fake.resources.getValue(key).toMutableMap()
        altered["NetworkSettings"] = buildJsonObject { put("Networks", buildJsonObject {
            put("p0v3-live-unit-net", buildJsonObject { put("IPAddress", "10.89.0.2") })
        }) }
        fake.resources[key] = JsonObject(altered)
        assertFails { runtime.audit(spec) }
        assertFails { runtime.apply(spec) }
    }
    @Test fun `fresh cold import verifies bytes and retains an initialization-free fenced target`() = fixture { base, original, fake ->
        val spec = original.copy(name = "q-abcdef123456-data", processes = listOf(original.processes.last().copy(dependencies = emptyList(), environmentFile = "app.env")))
        RuntimePreparation.prepare(spec, base) { mapOf("app.env" to "UNIT=1\n", "service.conf" to "unit\n") }
        val archive = Files.createFile(base.resolve("state.tar"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        Files.write(archive, VolumeTarTest.tar(VolumeTarTest.root(), VolumeTarTest.member("data")))
        val verify = Files.createDirectory(base.resolve("verify"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val runtime = PrivateDeployment(base, fake) {}
        val declaredHash = RecoveryCapsule.fileHash(archive)
        assertFails { runtime.importCold(spec, mapOf("data" to archive), "a".repeat(64), verify, mapOf("data" to "0".repeat(64))) }
        assertFalse(Files.exists(base.resolve("${spec.name}/runtime.import.intent")))
        val fence = runtime.importCold(spec, mapOf("data" to archive), "a".repeat(64), verify, mapOf("data" to declaredHash), restoreRoot = { _, _, _ -> }) { _, _, output -> Files.copy(archive, output); Unit }
        assertTrue(fake.calls.none { it.first() in setOf("start", "create", "wait") })
        assertTrue(Files.exists(base.resolve("${spec.name}/runtime.import.complete")))
        assertFalse(Files.exists(base.resolve("${spec.name}/runtime.jobs")))
        assertFails { runtime.importCold(spec, mapOf("data" to archive), "a".repeat(64), verify, mapOf("data" to declaredHash)) }
        assertFails { runtime.startImported(spec, "00000000-0000-0000-0000-000000000000") }
        val volume = fake.resources.keys.single { it.first == "volume" }
        val retainedVolume = fake.resources.remove(volume)!!
        val allocationCount = fake.calls.count { "create" in it }
        assertFails { runtime.startImported(spec, fence.id) }
        assertEquals(allocationCount, fake.calls.count { "create" in it })
        fake.resources[volume] = retainedVolume
        assertEquals("running", runtime.startImported(spec, fence.id).single().state)
        assertFails { runtime.startImported(spec, fence.id) }
        val retired = runtime.enterMaintenance(spec, "restore")
        assertFails { runtime.startImported(spec, retired.id) }
        assertTrue(fake.calls.filter { it.first() == "create" }.none { it.any { arg -> "initialize" in arg } })
    }
    @Test fun `failed imported readback blocks ordinary startup fence release and replay`() = fixture { base, original, fake ->
        val spec = original.copy(name = "q-abcdef123456-data", processes = listOf(original.processes.last().copy(dependencies = emptyList(), environmentFile = "app.env")))
        RuntimePreparation.prepare(spec, base) { mapOf("app.env" to "UNIT=1\n", "service.conf" to "unit\n") }
        val archive = Files.createFile(base.resolve("state.tar"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        Files.write(archive, VolumeTarTest.tar(VolumeTarTest.root(), VolumeTarTest.member("data")))
        val verify = Files.createDirectory(base.resolve("verify"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val runtime = PrivateDeployment(base, fake) {}
        val declaredHash = RecoveryCapsule.fileHash(archive)
        assertFails { runtime.importCold(spec, mapOf("data" to archive), "a".repeat(64), verify, mapOf("data" to declaredHash), restoreRoot = { _, _, _ -> }) { _, _, _ -> error("injected readback failure") } }
        val fence = assertNotNull(runtime.maintenanceStatus(spec))
        assertFails { runtime.leaveMaintenance(spec, fence.id) }
        assertFails { runtime.startImported(spec, fence.id) }
        assertFails { runtime.apply(spec) }
        assertFails { runtime.importCold(spec, mapOf("data" to archive), "a".repeat(64), verify, mapOf("data" to declaredHash)) }
        assertEquals(1, fake.calls.count { it.take(2) == listOf("volume", "import") })
        assertFalse(Files.exists(base.resolve("${spec.name}/runtime.import.complete")))
    }
    @Test fun `imported startup failure or interruption retains a fence and cannot replay partial daemons`() {
        for (interrupt in listOf(false, true)) fixture { base, original, fake ->
            val spec = original.copy(name = "q-abcdef123456-data", processes = listOf(original.processes.last().copy(dependencies = emptyList())))
            RuntimePreparation.prepare(spec, base) { mapOf("service.conf" to "unit\n") }
            val archive = base.resolve("state.tar")
            ReleasePrivateFiles.save(archive, VolumeTarTest.tar(VolumeTarTest.root(), VolumeTarTest.member("data")))
            val verify = privateControlDirectory(base.resolve("verify"))
            val runtime = PrivateDeployment(base, fake) {
                if (interrupt) throw InterruptedException("synthetic interrupted readiness") else error("synthetic readiness failure")
            }
            val fence = runtime.importCold(spec, mapOf("data" to archive), "a".repeat(64), verify,
                mapOf("data" to RecoveryCapsule.fileHash(archive)), restoreRoot = { _, _, _ -> }) { _, _, output -> Files.copy(archive, output); Unit }
            fake.failReady = true
            try {
                assertFails { runtime.startImported(spec, fence.id) }
                assertEquals(interrupt, Thread.currentThread().isInterrupted)
            } finally { Thread.interrupted() }
            val retained = assertNotNull(runtime.maintenanceStatus(spec))
            assertTrue(runtime.status(spec).all { it.state == "exited" })
            assertFails { runtime.startImported(spec, retained.id) }
            assertEquals(1, fake.calls.count { it.first() == "start" })
        }
        fixture { base, spec, fake ->
            val runtime = PrivateDeployment(base, fake) {}
            assertFails { runtime.startImported(spec, "unused") }
            val daemon = spec.copy(processes = listOf(spec.processes.last().copy(dependencies = emptyList(), environmentFile = "app.env")))
            assertFails { runtime.startImported(daemon, "unused") }
            assertTrue(fake.resources.isEmpty())
        }
    }

    @Test fun `generation fingerprints preserve existing marker bytes and are checked under the runtime lock`() = fixture { base, spec, fake ->
        val inputs = PrivateDeployment.inputNames(spec).associateWith { ReleaseLocks.sha256(Files.readAllBytes(base.resolve("unit/$it"))) }
        val expected = PrivateDeployment.expectedFingerprint(spec, inputs)
        val legacy = ReleaseLocks.sha256((Json.encodeToString(spec) + "\n" + inputs.toSortedMap().map { "${it.key}:${it.value}" }.joinToString("\n")).toByteArray())
        assertEquals(legacy, expected)
        assertFails { PrivateDeployment.expectedFingerprint(spec, emptyMap()) }
        assertFails { PrivateDeployment.expectedFingerprint(spec, inputs.mapValues { "invalid" }) }
        val runtime = PrivateDeployment(base, fake, boundFingerprints = mapOf(spec.name to expected)) {}
        val audit = runtime.audit(spec, true)
        assertEquals(expected, audit.fingerprint)
        assertEquals(0, audit.existingResources)
        assertNull(audit.maintenanceId)
        assertTrue(fake.calls.none { it.first() in setOf("create", "start", "stop") || it.getOrNull(1) == "create" })
        runtime.apply(spec, pristine = true)
        assertEquals("p0v3-private-runtime-v1\nunit\n$expected\n", Files.readString(base.resolve("unit/runtime.owner")))
        assertEquals(5, runtime.audit(spec).existingResources) // network, volume, secret, two containers
        assertFails { runtime.audit(spec, true) }
        fake.wrongImage = true
        assertFails { runtime.audit(spec) }
        fake.wrongImage = false
        val fence = runtime.enterMaintenance(spec, "update")
        assertEquals(fence.id, runtime.audit(spec).maintenanceId)
        fake.calls.clear()
        val changed = PrivateDeployment(base, fake, boundFingerprints = mapOf(spec.name to "c".repeat(64))) {}
        assertFails { changed.apply(spec) }
        assertTrue(fake.calls.isEmpty())
        Files.writeString(base.resolve("unit/app.env"), "SECRET=changed-unit-fixture\n")
        assertFails { runtime.audit(spec) }
        assertTrue(fake.calls.isEmpty())
    }

    @Test fun `fresh allocation is rechecked under lock after group preflight`() = fixture { base, spec, fake ->
        val inputs = PrivateDeployment.inputNames(spec).associateWith { ReleaseLocks.sha256(Files.readAllBytes(base.resolve("unit/$it"))) }
        val runtime = PrivateDeployment(base, fake, boundFingerprints = mapOf(spec.name to PrivateDeployment.expectedFingerprint(spec, inputs))) {}
        runtime.audit(spec, true)
        PrivateDeployment(base, fake) {}.provision(spec) // Another cooperating controller allocated after preflight.
        val resources = fake.resources.toMap()
        fake.calls.clear()
        assertFailsWith<IllegalArgumentException> { runtime.apply(spec, pristine = true) }
        assertEquals(resources, fake.resources)
        assertTrue(fake.calls.none { it.first() in setOf("create", "start", "stop") || it.getOrNull(1) == "create" })
    }

    @Test fun `cold read holds a checked fence and rejects running uncertain or changed state`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        assertFails { runtime.withFrozen(spec, "absent") { error("must not run") } }
        runtime.apply(spec)
        fake.failedStop = true
        assertFails { runtime.enterMaintenance(spec, "update") }
        val fence = assertNotNull(runtime.maintenanceStatus(spec))
        assertFails { runtime.withFrozen(spec, fence.id) { error("must not run while running") } }
        fake.failedStop = false
        runtime.enterMaintenance(spec, "update")
        assertFails { runtime.withFrozen(spec, "foreign") { error("must not run") } }
        val observation = runtime.withFrozen(spec, fence.id) { it }
        assertEquals(setOf("init"), observation.completedInitializers)
        assertEquals(ReleaseLocks.sha256(Files.readAllBytes(base.resolve("unit/runtime.jobs"))), observation.jobsSha256)
        assertTrue(observation.statuses.all { it.state == "exited" })
        assertFails { runtime.withFrozen(spec, fence.id) { Files.writeString(base.resolve("unit/app.env"), "changed-unit-input\n") } }
    }

    @Test fun `cold read explicitly binds absence of an initializer ledger when none are declared`() = fixture { base, spec, fake ->
        val daemonOnly = spec.copy(processes = listOf(spec.processes.last().copy(dependencies = emptyList())))
        Files.delete(base.resolve("unit/app.env")) // Unused input in this isolated unit fixture only.
        val runtime = PrivateDeployment(base, fake) {}
        runtime.apply(daemonOnly)
        val fence = runtime.enterMaintenance(daemonOnly, "update")
        assertFalse(Files.exists(base.resolve("unit/runtime.jobs")))
        val observed = runtime.withFrozen(daemonOnly, fence.id) { it }
        assertTrue(observed.completedInitializers.isEmpty())
        assertEquals(ReleaseLocks.sha256("no-initializers\n${observed.fingerprint}\n".toByteArray()), observed.jobsSha256)
    }

    @Test fun `cold read rejects unfinished initialization even when all resources are stopped`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        fake.failedJob = true
        assertFails { runtime.apply(spec) }
        val fence = runtime.enterMaintenance(spec, "update")
        assertFails { runtime.withFrozen(spec, fence.id) { error("uncertain initializer cannot be captured") } }
    }

    @Test fun `maintenance persists before stopping survives new controller and permits only explicit staging`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        runtime.apply(spec)
        val jobs = Files.readAllBytes(base.resolve("unit/runtime.jobs"))
        fake.failedStop = true
        assertFails { runtime.enterMaintenance(spec, "backup", "app") }
        val fence = assertNotNull(runtime.maintenanceStatus(spec))
        assertTrue(Files.exists(base.resolve("unit/runtime.maintenance")))
        val rebooted = PrivateDeployment(base, fake) {}
        fake.calls.clear()
        assertFails { rebooted.apply(spec) }
        assertFails { rebooted.provision(spec) }
        assertFails { rebooted.stage(spec, "init") }
        assertTrue(fake.calls.none { it.first() in setOf("create", "start", "stop") || it.getOrNull(1) == "create" })
        assertFails { rebooted.leaveMaintenance(spec, fence.id) }
        fake.failedStop = false
        assertEquals(fence, rebooted.enterMaintenance(spec, "backup", "app"))
        assertEquals(listOf("exited", "running"), rebooted.stage(spec, "app").map { it.state })
        assertContentEquals(jobs, Files.readAllBytes(base.resolve("unit/runtime.jobs")))
        assertFails { rebooted.leaveMaintenance(spec, fence.id) }
        assertFails { rebooted.enterMaintenance(spec, "restore") }
        rebooted.stop(spec)
        assertFails { rebooted.leaveMaintenance(spec, "stale-generation") }
        rebooted.leaveMaintenance(spec, fence.id)
        assertNull(rebooted.maintenanceStatus(spec))
        assertFails { rebooted.leaveMaintenance(spec, fence.id) }
        assertEquals("running", rebooted.apply(spec).last().state)
    }
    @Test fun `strict fence blocks unfinished initialization corrupt markers and orphan temporary files`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        assertFails { runtime.enterMaintenance(spec, "unknown") }
        assertFails { runtime.enterMaintenance(spec, "backup", "missing") }
        assertFails { runtime.enterMaintenance(spec, "backup", "init") }
        assertFails { runtime.apply(spec.copy(processes = spec.processes.map { it.copy(environmentFile = "runtime.maintenance") })) }
        assertFails { runtime.apply(spec.copy(processes = spec.processes.map { it.copy(files = listOf(RuntimeFile("runtime.maintenance", "/config"))) })) }
        assertTrue(fake.calls.isEmpty())
        val fence = runtime.enterMaintenance(spec, "backup", "app")
        assertFails { runtime.stage(spec, "app") }
        runtime.leaveMaintenance(spec, fence.id)
        runtime.apply(spec)
        val closed = runtime.enterMaintenance(spec, "update")
        assertFails { runtime.stage(spec, "app") }
        val marker = base.resolve("unit/runtime.maintenance")
        val good = Files.readAllBytes(marker)
        Files.writeString(marker, Files.readString(marker).replace("update", "backup"))
        assertFails { runtime.apply(spec) }
        assertFails { runtime.maintenanceStatus(spec) }
        runtime.stop(spec) // Safe stopping is allowed even if the fence is corrupt.
        Files.write(marker, good)
        runtime.leaveMaintenance(spec, closed.id)
        Files.writeString(base.resolve("unit/runtime.maintenance.tmp"), "interrupted write")
        fake.calls.clear()
        assertFails { runtime.apply(spec) }
        assertTrue(fake.calls.none { it.first() in setOf("start", "create", "stop") || it.getOrNull(1) == "create" })
        runtime.stop(spec)
        assertFails { runtime.maintenanceStatus(spec) }
    }
    @Test fun `real command plans provision privately and reapply without rerunning successful initialization`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        assertEquals(listOf("exited", "running"), runtime.apply(spec).map { it.state })
        val creates = fake.calls.filter { it.first() == "create" }
        assertEquals(2, creates.size)
        assertTrue(creates.all { "--read-only" in it && "--pull=never" in it && "--cap-drop=all" in it && it.none { arg -> arg.startsWith("--publish") } })
        assertTrue(creates.last().any { it.startsWith("--secret=") && "uid=999" in it })
        assertTrue(fake.calls.any { it.take(2) == listOf("network", "create") && "--internal" in it })
        val owner = Files.readAllBytes(base.resolve("unit/runtime.owner"))
        fake.calls.clear()
        assertEquals(2, runtime.apply(spec).size)
        assertTrue(fake.calls.none { it.first() in setOf("create", "start", "wait") || it.getOrNull(1) == "create" })
        assertContentEquals(owner, Files.readAllBytes(base.resolve("unit/runtime.owner")))
        assertEquals(listOf("exited", "exited"), runtime.stop(spec).map { it.state })
        assertEquals(1, fake.calls.count { it.first() == "stop" })
        assertEquals(listOf("exited", "running"), runtime.apply(spec).map { it.state })
        assertEquals(runtime.status(spec), runtime.apply(spec))
        assertTrue(fake.calls.none { it.first() == "rm" || it.getOrNull(1) == "rm" })
    }
    @Test fun `long initialization retries only its wait observer and preserves uncertain jobs at the bound`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        fake.waitTimeouts = 5
        assertFailsWith<IllegalStateException> { runtime.apply(spec) }
        assertEquals(1, fake.calls.count { it.first() == "start" })
        assertEquals(5, fake.calls.count { it.first() == "wait" })
        assertEquals("running", runtime.status(spec).first().state)
        fake.calls.clear()
        fake.waitTimeouts = 1
        assertEquals(listOf("exited", "running"), runtime.apply(spec).map { it.state })
        assertEquals(2, fake.calls.count { it.first() == "wait" })
        assertEquals(1, fake.calls.count { it.first() == "start" }) // Only the application starts; init was not replayed.
        assertEquals("p0v3-live-unit-app", fake.calls.single { it.first() == "start" }.last())
        assertEquals("Private Podman command timed out", PrivateCommandTimeout().message)
    }
    @Test fun `restore staging provisions resources without executing any application or initialization`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        assertTrue(runtime.provision(spec).all { it.state == "absent" })
        assertTrue(fake.calls.none { it.first() in setOf("create", "start", "wait") })
        assertEquals(runtime.status(spec), runtime.provision(spec))
        assertEquals(listOf("exited", "running"), runtime.apply(spec).map { it.state })
    }
    @Test fun `dependency staging binds full manifest and rejects live nonselected processes before mutation`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        assertFailsWith<IllegalArgumentException> { runtime.stage(spec, "unknown") }
        assertTrue(fake.calls.isEmpty())
        assertEquals(listOf("exited", "absent"), runtime.stage(spec, "init").map { it.state })
        val marker = Files.readAllBytes(base.resolve("unit/runtime.owner"))
        assertEquals(listOf("exited", "running"), runtime.stage(spec, "app").map { it.state })
        assertContentEquals(marker, Files.readAllBytes(base.resolve("unit/runtime.owner")))
        fake.calls.clear()
        assertFailsWith<IllegalArgumentException> { runtime.stage(spec, "init") }
        assertTrue(fake.calls.none { it.first() in setOf("start", "stop", "create", "wait") || it.getOrNull(1) == "create" })
        runtime.stop(spec)
        val journal = Files.readAllBytes(base.resolve("unit/runtime.jobs"))
        assertEquals(listOf("exited", "exited"), runtime.stage(spec, "init").map { it.state })
        assertContentEquals(journal, Files.readAllBytes(base.resolve("unit/runtime.jobs")))
        assertEquals(listOf("exited", "running"), runtime.apply(spec).map { it.state })
    }
    @Test fun `distroless readiness uses only the assigned private network address`() = fixture { base, spec, fake ->
        val httpSpec = spec.copy(processes = spec.processes.map {
            if (it.id == "app") it.copy(readiness = emptyList(), readinessHttpPort = 3100, readinessHttpPath = "/ready") else it
        })
        for (path in listOf("/../secret", "/./health", "/a/../health", "/health?key=secret", "/%2e%2e")) {
            assertFails { PrivateDeployment.validate(httpSpec.copy(processes = httpSpec.processes.map {
                it.copy(readinessHttpPath = path)
            })) }
        }
        assertEquals(2, PrivateDeployment.validate(httpSpec.copy(processes = httpSpec.processes.map {
            it.copy(readinessHttpPath = "/manifest.json")
        })).size)
        var calls = 0
        val runtime = PrivateDeployment(base, fake, httpReady = { address, port, path ->
            assertEquals("10.89.0.2", address); assertEquals(3100, port); assertEquals("/ready", path)
            calls++; calls > 1
        }, pause = {})
        assertEquals("running", runtime.apply(httpSpec).last().state)
        assertEquals(2, calls)
    }
    @Test fun `completed jobs survive container removal and uncertain missing jobs are never replayed`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        runtime.apply(spec)
        fake.resources.remove("container" to "p0v3-live-unit-init")
        fake.calls.clear()
        assertEquals("completed", runtime.apply(spec).first().state)
        assertTrue(fake.calls.none { it.first() in setOf("create", "start", "wait") })
        val journal = base.resolve("unit/runtime.jobs")
        Files.writeString(journal, Files.readString(journal).replace("\"completed\":[\"init\"]", "\"completed\":[]"))
        assertFailsWith<IllegalArgumentException> { runtime.apply(spec) }
    }
    @Test fun `lost in-flight initialization and container drift fail closed`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        fake.failedJob = true
        assertFails { runtime.apply(spec) }
        fake.resources.remove("container" to "p0v3-live-unit-init")
        fake.calls.clear()
        assertFailsWith<IllegalArgumentException> { runtime.apply(spec) }
        assertTrue(fake.calls.none { it.first() == "create" || it.first() == "start" })
    }
    @Test fun `security drift cannot hide behind correct ownership labels`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        runtime.apply(spec)
        val key = "container" to "p0v3-live-unit-app"
        val original = fake.resources.getValue(key)
        fake.resources[key] = JsonObject(original + ("Image" to JsonPrimitive("d".repeat(64))))
        fake.calls.clear()
        assertFailsWith<IllegalArgumentException> { runtime.apply(spec) }
        assertTrue(fake.calls.none { it.first() in setOf("stop", "start", "create") })
        val host = original.getValue("HostConfig").jsonObject
        val drift = mapOf("PidMode" to JsonPrimitive("host"), "IpcMode" to JsonPrimitive("host"),
            "UTSMode" to JsonPrimitive("host"), "CgroupMode" to JsonPrimitive("host"), "UsernsMode" to JsonPrimitive("auto"),
            "NetworkMode" to JsonPrimitive("host"), "Memory" to JsonPrimitive(0), "PidsLimit" to JsonPrimitive(-1),
            "Devices" to JsonArray(listOf(JsonPrimitive("/dev/sda"))), "GroupAdd" to JsonArray(listOf(JsonPrimitive("0"))),
            "VolumesFrom" to JsonArray(listOf(JsonPrimitive("foreign"))))
        drift.forEach { (field, value) ->
            fake.resources[key] = JsonObject(original + ("HostConfig" to JsonObject(host + (field to value))))
            fake.calls.clear()
            assertFailsWith<IllegalArgumentException>(field) { runtime.apply(spec) }
            assertTrue(fake.calls.none { it.first() in setOf("stop", "start", "create") })
        }
    }
    @Test fun `final OCI capabilities rather than relative CapAdd are audited`() = fixture { base, spec, fake ->
        val caddy = spec.copy(processes = spec.processes.map { if (it.id == "app") it.copy(id = "caddy", capabilities = listOf("NET_BIND_SERVICE")) else it })
        val runtime = PrivateDeployment(base, fake) {}
        assertEquals("running", runtime.apply(caddy).last().state)
        val key = "container" to "p0v3-live-unit-caddy"
        val original = fake.resources.getValue(key)
        for (field in listOf("EffectiveCaps", "BoundingCaps")) {
            for (caps in listOf(JsonNull, JsonArray(listOf(JsonPrimitive("CAP_SYS_ADMIN"))))) {
                fake.resources[key] = JsonObject(original + (field to caps))
                fake.calls.clear()
                assertFailsWith<IllegalArgumentException> { runtime.apply(caddy) }
                assertTrue(fake.calls.none { it.first() in setOf("stop", "start", "create") })
            }
        }
    }
    @Test fun `foreign resources and modified inputs fail before Podman mutations`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        runtime.apply(spec)
        val key = "container" to "p0v3-live-unit-app"
        val old = fake.resources.getValue(key)
        fake.resources[key] = JsonObject(old + ("Config" to buildJsonObject { put("Labels", buildJsonObject { put("owner", "unrelated") }) }))
        fake.calls.clear()
        assertFailsWith<IllegalArgumentException> { runtime.stop(spec) }
        assertTrue(fake.calls.none { it.first() in setOf("stop", "start", "create") })
        fake.resources[key] = old
        Files.writeString(base.resolve("unit/app.env"), "SECRET=changed\n")
        fake.calls.clear()
        assertFailsWith<IllegalArgumentException> { runtime.apply(spec) }
        assertTrue(fake.calls.isEmpty())
    }
    @Test fun `failed initialization is retained and never automatically replayed`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        fake.failedJob = true
        assertFailsWith<IllegalArgumentException> { runtime.apply(spec) }
        fake.calls.clear()
        assertFailsWith<IllegalArgumentException> { runtime.apply(spec) }
        assertTrue(fake.calls.none { it.first() == "start" })
        assertEquals(listOf("exited", "absent"), runtime.status(spec).map { it.state })
    }
    @Test fun `readiness failures and changed images retain owned state without claiming success`() = fixture { base, spec, fake ->
        val runtime = PrivateDeployment(base, fake) {}
        fake.wrongImage = true
        assertFailsWith<IllegalArgumentException> { runtime.apply(spec) }
        assertTrue(fake.calls.none { it.first() == "create" || it.getOrNull(1) == "create" })
        fake.wrongImage = false; fake.failReady = true
        assertFailsWith<IllegalStateException> { runtime.apply(spec) }
        fake.failReady = false
        assertEquals("running", runtime.apply(spec).last().state)
        fake.lookupFailure = true
        assertFailsWith<IllegalStateException> { runtime.stop(spec) }
    }
    @Test fun `invalid contracts public network foreign store and unknown files reject`() = fixture { base, spec, fake ->
        for (bad in listOf(spec.copy(name = "../other"), spec.copy(schemaVersion = 2), spec.copy(processes = spec.processes + spec.processes.first()),
            spec.copy(processes = listOf(spec.processes.first().copy(image = "example.org/app:latest"))),
            spec.copy(processes = spec.processes.map { it.copy(dependencies = listOf(if (it.id == "init") "app" else "init")) }),
            spec.copy(processes = spec.processes.map { it.copy(capabilities = listOf("SYS_ADMIN")) }),
            spec.copy(processes = spec.processes.map { it.copy(userId = 0) }))) {
            assertFailsWith<IllegalArgumentException> { PrivateDeployment.validate(bad) }
        }
        fake.wrongStore = true
        assertFailsWith<IllegalArgumentException> { PrivateDeployment(base, fake) {}.apply(spec) }
        fake.wrongStore = false
        Files.writeString(base.resolve("unit/unrelated"), "keep")
        assertFailsWith<IllegalArgumentException> { PrivateDeployment(base, fake) {}.apply(spec) }
        assertEquals("keep", Files.readString(base.resolve("unit/unrelated")))
    }
    @Test fun `foundation preparation generates protected credentials once without resetting them`() {
        val base = Files.createTempDirectory("foundation-runtime-")
        Files.setPosixFilePermissions(base, PosixFilePermissions.fromString("rwx------"))
        val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy").map {
            AcquiredImage(it, "upstream", "example.org/app:1", image, imageId, emptyList(), image.substringAfter('@'), "amd64", "linux")
        })
        try {
            val file = FoundationRuntime.prepare(inventory, base)
            val pg = Files.readAllBytes(base.resolve("foundation/postgres.env"))
            assertEquals(file, FoundationRuntime.prepare(inventory, base))
            assertContentEquals(pg, Files.readAllBytes(base.resolve("foundation/postgres.env")))
            assertEquals(FoundationRuntime.spec(inventory), PrivateDeployment.read(file))
            assertEquals(4, PrivateDeployment.validate(PrivateDeployment.read(file)).size)
            val identity = IdentityRuntime.prepare(inventory, base)
            val identitySpec = PrivateDeployment.read(identity)
            assertEquals(listOf("postgres-init", "postgres", "identity-db-init", "keycloak"), PrivateDeployment.validate(identitySpec).map { it.id })
            assertTrue(identitySpec.processes.all { it.apparmorProfile == "p0v3-private-v1" })
            val realmPath = base.resolve("identity/realm.json")
            val realmBefore = Files.readAllBytes(realmPath)
            assertEquals(identity, IdentityRuntime.prepare(inventory, base))
            assertContentEquals(realmBefore, Files.readAllBytes(realmPath))
            val realm = Json.parseToJsonElement(realmBefore.decodeToString()).jsonObject
            val user = realm.getValue("users").jsonArray.single().jsonObject
            assertEquals(setOf("UPDATE_PASSWORD", "CONFIGURE_TOTP"), user.getValue("requiredActions").jsonArray.map { it.jsonPrimitive.content }.toSet())
            assertTrue(user.getValue("credentials").jsonArray.single().jsonObject.getValue("temporary").jsonPrimitive.boolean)
            val matrixInventory = inventory.copy(images = inventory.images + inventory.images.first().copy(product = "synapse"))
            val matrix = SynapseRuntime.prepare(matrixInventory, base)
            assertEquals(matrix, SynapseRuntime.prepare(matrixInventory, base))
            assertEquals(listOf("postgres-init", "postgres", "synapse-db-init", "signing-key-init", "synapse"), PrivateDeployment.validate(PrivateDeployment.read(matrix)).map { it.id })
            val matrixConfig = Files.readString(base.resolve("synapse/homeserver.yaml"))
            assertTrue(matrixConfig.contains("federation_domain_whitelist: []"))
            assertTrue(matrixConfig.contains("enable_registration: false"))
            assertTrue(matrixConfig.contains("report_stats: false"))
            assertTrue(PrivateDeployment.read(matrix).processes.single { it.id == "synapse-db-init" }.command.last().contains("TEMPLATE template0"))
            assertFails { SynapseRuntime.spec(inventory) }
            assertFails { SynapseRuntime.inputs("https://unreviewed.example/") }
            val completeMatrixInventory = matrixInventory.copy(images = matrixInventory.images + listOf("element", "caddy").map { inventory.images.first().copy(product = it) })
            val matrixUi = MatrixRuntime.prepare(completeMatrixInventory, base, "matrix-ui")
            assertEquals(matrixUi, MatrixRuntime.prepare(completeMatrixInventory, base, "matrix-ui"))
            assertEquals(listOf("element-web", "caddy"), PrivateDeployment.validate(PrivateDeployment.read(matrixUi)).takeLast(2).map { it.id })
            assertTrue(Files.readString(base.resolve("matrix-ui/caddyfile")).contains("skip_install_trust"))
            assertTrue(Files.readString(base.resolve("matrix-ui/homeserver.yaml")).contains("public_baseurl: https://element:8443/"))
            assertTrue(Files.readString(base.resolve("matrix-ui/element.json")).contains("\"disable_guests\": true"))
            assertFails { MatrixRuntime.spec(matrixInventory) }
            val transferInventory = inventory.copy(images = listOf(inventory.images.first().copy(product = "qbittorrent")))
            val transfer = QbittorrentRuntime.prepare(transferInventory, base)
            assertEquals(transfer, QbittorrentRuntime.prepare(transferInventory, base))
            assertEquals(listOf("config-init", "qbittorrent"), PrivateDeployment.validate(PrivateDeployment.read(transfer)).map { it.id })
            val transferConfig = Files.readString(base.resolve("qbittorrent/qbittorrent.conf"))
            assertTrue(transferConfig.contains("Session\\DHTEnabled=false"))
            assertTrue(transferConfig.contains("WebUI\\LocalHostAuth=true"))
            assertTrue(QbittorrentRuntime.passwordSetting("unit-password", ByteArray(16)).startsWith("@ByteArray(AAAAAAAAAAAAAAAAAAAAAA==:"))
            assertFails { QbittorrentRuntime.passwordSetting("short", ByteArray(16)) }
            assertFails { QbittorrentRuntime.passwordSetting("unit-password", ByteArray(1)) }
            assertFails { QbittorrentRuntime.spec(inventory) }
            val notebookInventory = inventory.copy(images = listOf(inventory.images.first().copy(product = "jupyter-notebook")))
            val notebook = NotebookRuntime.prepare(notebookInventory, base)
            assertEquals(notebook, NotebookRuntime.prepare(notebookInventory, base))
            assertEquals(listOf("notebook-init", "notebook"), PrivateDeployment.validate(PrivateDeployment.read(notebook)).map { it.id })
            val notebookConfig = Files.readString(base.resolve("notebook/server.py"))
            assertTrue(notebookConfig.contains("allow_unauthenticated_access = False"))
            assertTrue(notebookConfig.contains("extension_manager = \"readonly\""))
            assertFalse(notebookConfig.contains("DummyAuthenticator"))
            assertFails { NotebookRuntime.spec(inventory) }
            val notebookSource = PrivateDeployment.read(notebook)
            val recovery = Files.createDirectory(base.resolve("notebook-recovery"))
            (SingleUserRestore.inputNames(notebookSource) + "source-spec.json").forEach { file ->
                val original = if (file == "source-spec.json") notebook else base.resolve("notebook").resolve(file)
                Files.copy(original, recovery.resolve(file))
                Files.setPosixFilePermissions(recovery.resolve(file), PosixFilePermissions.fromString("rw-------"))
            }
            val restoredNotebook = SingleUserRestore.prepare(notebookInventory, recovery, "notebook-restored", base)
            assertEquals(restoredNotebook, SingleUserRestore.prepare(notebookInventory, recovery, "notebook-restored", base))
            val restoreSpec = PrivateDeployment.read(restoredNotebook)
            assertEquals(listOf("restore-check", "notebook"), PrivateDeployment.validate(restoreSpec).map { it.id })
            assertTrue(restoreSpec.processes.first().command.last().contains(".p0v3-restore-complete"))
            Files.writeString(recovery.resolve("server.py"), "changed")
            assertFails { SingleUserRestore.prepare(notebookInventory, recovery, "notebook-restored", base) }
            assertFails { SingleUserRestore.spec(notebookSource, notebookInventory, notebookSource.name, "a".repeat(64)) }
            assertFails { SingleUserRestore.spec(notebookSource, notebookInventory, "other", "bad-hash") }
            assertFails { SingleUserRestore.spec(notebookSource, inventory.copy(images = emptyList()), "other", "a".repeat(64)) }
            assertFails { SingleUserRestore.spec(notebookSource.copy(volumes = notebookSource.volumes.map { it.copy(userId = 999) }), notebookInventory, "other", "a".repeat(64)) }
            val homeInventory = inventory.copy(images = listOf(inventory.images.first().copy(product = "homeassistant")))
            val home = HomeAssistantRuntime.prepare(homeInventory, base)
            assertEquals(home, HomeAssistantRuntime.prepare(homeInventory, base))
            assertEquals(listOf("config-init", "homeassistant"), PrivateDeployment.read(home).processes.map { it.id })
            val homeConfig = Files.readString(base.resolve("homeassistant/configuration.yaml"))
            assertTrue(homeConfig.contains("input_boolean.private_result"))
            assertFalse(homeConfig.contains("default_config:"))
            assertFails { HomeAssistantRuntime.spec(inventory) }
            val choresInventory = inventory.copy(images = listOf(inventory.images.first().copy(product = "donetick")))
            val chores = DonetickRuntime.prepare(choresInventory, base)
            assertEquals(chores, DonetickRuntime.prepare(choresInventory, base))
            assertEquals(2021, PrivateDeployment.read(chores).processes.single().readinessHttpPort)
            val choresConfig = Files.readString(base.resolve("donetick/selfhosted.yaml"))
            assertTrue(choresConfig.contains("log_raw_url: false"))
            assertTrue(choresConfig.contains("bridge:\n  enabled: false"))
            assertFails { DonetickRuntime.spec(inventory) }
            val mediaInventory = inventory.copy(images = listOf(inventory.images.first().copy(product = "jellyfin")))
            val media = JellyfinRuntime.prepare(mediaInventory, base)
            assertEquals(media, JellyfinRuntime.prepare(mediaInventory, base))
            val mediaSpec = PrivateDeployment.read(media)
            assertEquals(listOf("media-init", "jellyfin"), PrivateDeployment.validate(mediaSpec).map { it.id })
            assertTrue(mediaSpec.processes.first().oneShot)
            assertTrue(mediaSpec.processes.first().command.any { "sine=frequency=440:duration=3" in it })
            assertEquals("/Users/Public", mediaSpec.processes.last().readinessHttpPath)
            assertTrue(Files.readString(base.resolve("jellyfin/system.xml")).contains("<Enabled>false</Enabled>"))
            assertEquals(setOf("/config", "/cache", "/media"), mediaSpec.processes.last().volumes.map { it.target }.toSet())
            assertFails { JellyfinRuntime.spec(inventory) }
            val sqlInventory = inventory.copy(images = listOf("mariadb", "memcached").map { inventory.images.first().copy(product = it) })
            val sql = SqlCacheRuntime.prepare(sqlInventory, base)
            assertEquals(sql, SqlCacheRuntime.prepare(sqlInventory, base))
            val sqlSpec = PrivateDeployment.read(sql)
            assertEquals(listOf("mariadb-init", "mariadb", "memcached"), PrivateDeployment.validate(sqlSpec).map { it.id })
            assertTrue(sqlSpec.processes.first().oneShot)
            assertTrue(sqlSpec.processes.last().volumes.isEmpty())
            assertFails { SqlCacheRuntime.spec(inventory) }
            val plankaInventory = inventory.copy(images = inventory.images + inventory.images.first().copy(product = "planka"))
            val planka = PlankaRuntime.prepare(plankaInventory, base)
            assertEquals(planka, PlankaRuntime.prepare(plankaInventory, base))
            val plankaSpec = PrivateDeployment.read(planka)
            assertEquals(3, plankaSpec.processes.count { it.oneShot })
            assertEquals(listOf("planka-init"), plankaSpec.processes.last().dependencies)
            assertTrue(Files.readString(base.resolve("planka/planka.env")).contains("OUTGOING_PROXY=http://127.0.0.1:9"))
            assertFails { PlankaRuntime.spec(inventory) }
            val forgejoInventory = inventory.copy(images = listOf(inventory.images.first().copy(product = "forgejo")))
            val forgejo = ForgejoRuntime.prepare(forgejoInventory, base)
            assertEquals(forgejo, ForgejoRuntime.prepare(forgejoInventory, base))
            val forgejoSpec = PrivateDeployment.read(forgejo)
            assertEquals(listOf("forgejo-init", "forgejo"), PrivateDeployment.validate(forgejoSpec).map { it.id })
            assertTrue(forgejoSpec.processes.first().oneShot)
            val forgejoConfig = Files.readString(base.resolve("forgejo/app.ini"))
            assertTrue(forgejoConfig.contains("DISABLE_REGISTRATION = true"))
            assertTrue(forgejoConfig.contains("INSTALL_LOCK = true"))
            val jwt = forgejoConfig.lines().single { it.startsWith("JWT_SECRET = ") }.substringAfter(" = ")
            assertEquals(32, java.util.Base64.getUrlDecoder().decode(jwt).size)
            assertFails { ForgejoRuntime.spec(inventory) }
            val recovered = ForgejoRuntime.prepareRestore(forgejoInventory, base.resolve("forgejo"), base, "forgejo-restore")
            val recoveredSpec = PrivateDeployment.read(recovered)
            assertEquals(listOf("restore-check", "forgejo"), recoveredSpec.processes.map { it.id })
            assertTrue(recoveredSpec.processes.first().command.none { "admin user create" in it || " migrate" in it })
            assertEquals(recovered, ForgejoRuntime.prepareRestore(forgejoInventory, base.resolve("forgejo"), base, "forgejo-restore"))
            Files.writeString(base.resolve("forgejo-restore/forgejo.env"), "changed\n")
            assertFails { ForgejoRuntime.prepareRestore(forgejoInventory, base.resolve("forgejo"), base, "forgejo-restore") }
            val observabilityInventory = inventory.copy(images = inventory.images + listOf("prometheus", "grafana", "loki", "alloy", "alertmanager").map {
                inventory.images.first().copy(product = it)
            })
            val observability = ObservabilityRuntime.prepare(observabilityInventory, base)
            val observabilitySpec = PrivateDeployment.read(observability)
            assertEquals(5, PrivateDeployment.validate(observabilitySpec).size)
            assertTrue(observabilitySpec.processes.all { it.readinessHttpPort != null && it.readiness.isEmpty() })
            assertEquals(observability, ObservabilityRuntime.prepare(observabilityInventory, base))
            assertTrue(Files.readString(base.resolve("observability/config.alloy")).contains("http://loki:3100/loki/api/v1/push"))
            assertFails { FoundationRuntime.prepare(inventory.copy(images = inventory.images.dropLast(1)), base) }
            Files.delete(file)
            assertFailsWith<IllegalArgumentException> { FoundationRuntime.prepare(inventory, base) }
        } finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
