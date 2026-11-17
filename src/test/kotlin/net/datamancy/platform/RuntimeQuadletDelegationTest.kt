package net.datamancy.platform

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.file.StandardOpenOption.*
import kotlin.test.*

class RuntimeQuadletDelegationTest {
    private fun fixture(action: (Path, Path, Path, PrivateDeploymentSpec, String, String) -> Unit) {
        val root = Files.createTempDirectory("quadlet-delegate-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val generationBase = Files.createDirectory(root.resolve("generations"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val runtimeBase = Files.createDirectory(root.resolve("runtime"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val spec = FragmentAssemblyFixture.plan().specs.single()
            val generation = "q-aabbccddeeff"
            val generationRoot = Files.createDirectory(generationBase.resolve(generation),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val memberRoot = Files.createDirectory(runtimeBase.resolve(spec.name),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val hashes = PrivateDeployment.inputNames(spec).associateWith { name ->
                val value = "fixture:$name\n"
                ReleasePrivateFiles.save(memberRoot.resolve(name), value.toByteArray())
                ReleaseLocks.sha256(value.toByteArray())
            }
            val fingerprint = PrivateDeployment.expectedFingerprint(spec, hashes)
            val plan = FragmentAssemblyFixture.plan()
            val bundle = GenerationBundle(plan.generation,
                listOf(GenerationPin(GenerationMember(spec.name), "c".repeat(64), hashes, fingerprint, spec)), 2048)
            val encoded = Json { encodeDefaults = true }.encodeToString(bundle).toByteArray()
            ReleasePrivateFiles.save(generationRoot.resolve("bundle.json"), encoded)
            val bundleHash = ReleaseLocks.sha256(encoded)
            ReleasePrivateFiles.save(generationRoot.resolve("stage.intent.json"),
                Json { encodeDefaults = true }.encodeToString(GenerationIntent("stage", bundleHash)).toByteArray())
            val process = spec.processes.single { it.id == "forgejo" }
            val install = QuadletInstallIntent(generation = generation, bundleSha256 = bundleHash, member = spec.name,
                specSha256 = RuntimeQuadlets.render(spec).specSha256, filesSha256 = emptyMap(), stagedDestinations = emptyList())
            val original = Json { encodeDefaults = true }.encodeToString(install).toByteArray()
            ReleasePrivateFiles.save(generationRoot.resolve("quadlet-install-${spec.name}.intent.json"), original)
            ReleasePrivateFiles.save(generationRoot.resolve("quadlet-install-${spec.name}.result.json"),
                Json { encodeDefaults = true }.encodeToString(QuadletInstallResult(
                    intentSha256 = ReleaseLocks.sha256(original),
                    installedAuditSha256 = mapOf("postgres" to "e".repeat(64),
                        process.id to "e".repeat(64)))).toByteArray())
            ReleasePrivateFiles.save(memberRoot.resolve("runtime.quadlet.env"),
                "P0_RUNTIME_FINGERPRINT=$fingerprint\n".toByteArray())
            action(generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint)
        } finally { FragmentAssemblyFixture.remove(root) }
    }

    @Test fun `delegated admission checks live native locks inputs and exact installed result`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val memberRoot = runtimeBase.resolve(spec.name)
        val genLock = generationBase.resolve("generation.lock")
        val memberLock = memberRoot.resolve("runtime.lock")
        val process = spec.processes.single { it.id == "forgejo" }
        var ownerGone = false
        val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) },
            startTicks = { pid -> QuadletNativeLockProof.startTicks(pid) + if (ownerGone) 1 else 0 })
        FileChannel.open(genLock, CREATE_NEW, READ, WRITE,
            java.nio.file.LinkOption.NOFOLLOW_LINKS).use { g ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE,
                java.nio.file.LinkOption.NOFOLLOW_LINKS).use { m ->
                Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                g.lock().use { m.lock().use {
                    val intent = delegation.begin("q-aabbccddeeff", bundleHash, spec, process, "start", fingerprint)
                    assertEquals(ProcessHandle.current().pid(), intent.ownerPid)
                    assertEquals(intent, delegation.authorize("q-aabbccddeeff", spec.name, process.id, "start"))
                    assertFails { delegation.begin("q-aabbccddeeff", bundleHash, spec, process, "start", fingerprint) }
                    val input = memberRoot.resolve(PrivateDeployment.inputNames(spec).first())
                    val original = Files.readAllBytes(input)
                    Files.writeString(input, "changed")
                    assertFails { delegation.authorize("q-aabbccddeeff", spec.name, process.id, "start") }
                    Files.write(input, original)
                    assertEquals(intent.installedAuditSha256, delegation.acknowledge(
                        "q-aabbccddeeff", spec.name, process.id, "start").installedAuditSha256)
                    assertFails { delegation.authorize("q-aabbccddeeff", spec.name, process.id, "start") }
                    assertEquals(intent, delegation.authorize("q-aabbccddeeff", spec.name, process.id,
                        "start", afterStartAck = true))
                    ownerGone = true
                    assertFails { delegation.authorize("q-aabbccddeeff", spec.name, process.id,
                        "start", afterStartAck = true) }
                    ownerGone = false
                    assertFails { delegation.authorize("q-aabbccddeeff", spec.name, process.id,
                        "start", afterStartAck = true) } // Reacquired PID cannot revive revoked start.
                } }
            }
        }
        assertFails { delegation.authorize("q-aabbccddeeff", spec.name, process.id, "start") }
    }

    @Test fun `living original owner loses only generation lock after alias FD close and helper refuses launch`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val generationLock = generationBase.resolve("generation.lock")
        val memberLock = runtimeBase.resolve(spec.name).resolve("runtime.lock")
        val process = spec.processes.single { it.id == "forgejo" }
        val delegated = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) })
        FileChannel.open(generationLock, CREATE_NEW, READ, WRITE).use { generation ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { member ->
                listOf(generationLock, memberLock).forEach { Files.setPosixFilePermissions(it,
                    PosixFilePermissions.fromString("rw-------")) }
                generation.lock().use { member.lock().use {
                    delegated.begin("q-aabbccddeeff", bundleHash, spec, process, "start", fingerprint)
                    assertEquals(QuadletOwnerProof.VERIFIED,
                        QuadletNativeLockProof.classify(ProcessHandle.current().pid(),
                            QuadletNativeLockProof.startTicks(ProcessHandle.current().pid()),
                            generationLock, memberLock))
                    FileChannel.open(generationLock, READ).use { assertEquals(0L, it.size()) }
                    val failure = assertFailsWith<IllegalArgumentException> {
                        delegated.authorize("q-aabbccddeeff", spec.name, process.id, "start")
                    }
                    assertContains(failure.message.orEmpty(), "GENERATION_LOCK_MISSING")
                    assertTrue(ProcessHandle.current().isAlive)
                    assertTrue(QuadletNativeLockProof.heldBy(memberLock, ProcessHandle.current().pid()))
                } }
                // Same PID and inode are re-locked, but the original start
                // delegation remains revoked after its first failed proof.
                generation.lock().use { member.lock().use {
                    assertEquals(QuadletOwnerProof.VERIFIED,
                        QuadletNativeLockProof.classify(ProcessHandle.current().pid(),
                            QuadletNativeLockProof.startTicks(ProcessHandle.current().pid()),
                            generationLock, memberLock))
                    assertContains(assertFailsWith<IllegalArgumentException> {
                        delegated.authorize("q-aabbccddeeff", spec.name, process.id, "start")
                    }.message.orEmpty(), "revoked")
                } }
            }
        }
    }

    @Test fun `systemd success cannot substitute for missing helper ACK or original custody`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, _ ->
        val bundle = Json.decodeFromString<GenerationBundle>(Files.readString(generationRoot.resolve("bundle.json")))
        val genLock = generationBase.resolve("generation.lock")
        val memberLock = runtimeBase.resolve(spec.name).resolve("runtime.lock")
        var starts = 0
        var readies = 0
        val stage = RuntimeQuadletOwnerStage(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) },
            manager = QuadletUnitManager { action, _ -> if (action == "start") starts++ },
            resources = { _, _, _ -> }, ready = { _, _, _ -> readies++; error("Never ready without ACK") })
        FileChannel.open(genLock, CREATE_NEW, READ, WRITE).use { g ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { m ->
                Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                g.lock().use { m.lock().use {
                    assertFails { stage.stage(bundle, bundleHash, bundle.members.single()) }
                    assertEquals(1, starts)
                    assertEquals(0, readies)
                    assertNotNull(RuntimeMaintenance.read(runtimeBase.resolve(spec.name),
                        bundle.members.single().runtimeFingerprint))
                } }
            }
        }
    }

    @Test fun `post-exit guard independently fences and stops exact CID after killed helper and owner`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val memberRoot = runtimeBase.resolve(spec.name)
        val genLock = generationBase.resolve("generation.lock")
        val memberLock = memberRoot.resolve("runtime.lock")
        val p = spec.processes.single { it.id == "forgejo" }
        val cid = "f".repeat(64)
        val generated = listOf("/usr/bin/podman", "run", p.image)
        var ownerKilled = false // Simulated PID exit is distinct from a live owner's missing lock.
        var running = true
        var stops = 0
        val native = RuntimeCommands { args -> when (args) {
            listOf("container", "inspect", "p0v3-live-${spec.name}-${p.id}") -> RuntimeCommandResult(0,
                """[{"Id":"$cid","Name":"p0v3-live-${spec.name}-${p.id}","Image":"sha256:${p.imageId}",
                    "Config":{"Image":"${p.image}","Labels":{"io.p0v3.private-deployment":"${spec.name}",
                    "io.p0v3.runtime-fingerprint":"$fingerprint"}},
                    "State":{"Running":$running,"Status":"${if (running) "running" else "exited"}"}}]""")
            listOf("container", "stop", "--time=30", cid) -> {
                stops++; running = false; RuntimeCommandResult(0, cid)
            }
            else -> error("Unexpected guard effect $args")
        } }
        val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) })
        val guard = RuntimeQuadletUnitRun(generationRoot, delegation,
            generated = { _, _ -> generated }, native = native, runtimeRoot = runtimeBase,
            generationBase = generationBase, guardInstalled = { _, _ -> "e".repeat(64) },
            guardController = { }, ownerProof = { if (ownerKilled) QuadletOwnerProof.PID_MISSING else QuadletOwnerProof.VERIFIED })
        FileChannel.open(genLock, CREATE_NEW, READ, WRITE).use { g ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { m ->
                Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                g.lock().use { m.lock().use {
                    delegation.begin("q-aabbccddeeff", bundleHash, spec, p, "start", fingerprint)
                    delegation.acknowledge("q-aabbccddeeff", spec.name, p.id, "start")
                    val startBytes = ReleasePrivateFiles.read(generationRoot.resolve(
                        "quadlet-delegate-${spec.name}-${p.id}-start.intent.json"), 8192)
                    val original = QuadletLaunchIntent(delegationSha256 = ReleaseLocks.sha256(startBytes),
                        member = spec.name, process = p.id, generatedArgvSha256 = "b".repeat(64),
                        fingerprint = fingerprint)
                    ReleasePrivateFiles.save(generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.intent.json"),
                        Json { encodeDefaults = true }.encodeToString(original).toByteArray())
                    guard.guard("q-aabbccddeeff", spec.name, p.id)
                    assertEquals(0, stops) // Controlled StopUnit: a live owner must not be treated as lost.
                } }
            }
        }
        assertEquals(0, stops)
        ownerKilled = true
        val launchBytes = ReleasePrivateFiles.read(generationRoot.resolve(
            "quadlet-launch-${spec.name}-${p.id}.intent.json"), 8192)
        val acknowledged = QuadletLaunchResult(intentSha256 = ReleaseLocks.sha256(launchBytes),
            containerId = cid, imageId = p.imageId, nativeAcknowledged = true)
        ReleasePrivateFiles.save(generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.result.json"),
            Json { encodeDefaults = true }.encodeToString(acknowledged).toByteArray())
        guard.guard("q-aabbccddeeff", spec.name, p.id)
        assertEquals(1, stops)
        assertFalse(running)
        assertNotNull(RuntimeMaintenance.read(memberRoot, fingerprint))
        assertTrue(Files.exists(generationRoot.resolve("quadlet-owner-loss-${spec.name}-${p.id}.result.json")))
        guard.guard("q-aabbccddeeff", spec.name, p.id)
        assertEquals(1, stops)
    }

    @Test fun `post-exit guard cannot convert a live owners uncertain lock proof into an owner-death stop`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val p = spec.processes.single { it.id == "forgejo" }
        val generationLock = generationBase.resolve("generation.lock")
        val memberLock = runtimeBase.resolve(spec.name).resolve("runtime.lock")
        val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) })
        FileChannel.open(generationLock, CREATE_NEW, READ, WRITE).use { gen ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { mem ->
                listOf(generationLock, memberLock).forEach { Files.setPosixFilePermissions(it,
                    PosixFilePermissions.fromString("rw-------")) }
                gen.lock().use { mem.lock().use {
                    delegation.begin("q-aabbccddeeff", bundleHash, spec, p, "start", fingerprint)
                    delegation.acknowledge("q-aabbccddeeff", spec.name, p.id, "start")
                    val delegated = ReleasePrivateFiles.read(generationRoot.resolve(
                        "quadlet-delegate-${spec.name}-${p.id}-start.intent.json"), 8192)
                    ReleasePrivateFiles.save(generationRoot.resolve(
                        "quadlet-launch-${spec.name}-${p.id}.intent.json"), Json { encodeDefaults = true }
                        .encodeToString(QuadletLaunchIntent(delegationSha256 = ReleaseLocks.sha256(delegated),
                            member = spec.name, process = p.id, generatedArgvSha256 = "b".repeat(64),
                            fingerprint = fingerprint)).toByteArray())
                    val guard = RuntimeQuadletUnitRun(generationRoot, delegation,
                        native = RuntimeCommands { error("No native command on uncertain living owner proof") },
                        runtimeRoot = runtimeBase, generationBase = generationBase,
                        guardInstalled = { _, _ -> "e".repeat(64) }, guardController = { },
                        ownerProof = { QuadletOwnerProof.MEMBER_LOCK_MISSING })
                    val failure = assertFailsWith<IllegalArgumentException> {
                        guard.guard("q-aabbccddeeff", spec.name, p.id)
                    }
                    assertContains(failure.message.orEmpty(), "MEMBER_LOCK_MISSING")
                    assertFalse(Files.exists(generationRoot.resolve(
                        "quadlet-owner-loss-${spec.name}-${p.id}.intent.json")))
                    assertNull(RuntimeMaintenance.read(runtimeBase.resolve(spec.name), fingerprint))
                } }
            }
        }
    }

    @Test fun `post-exit guard rejects a changed CID without stopping a foreign workload`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val memberRoot = runtimeBase.resolve(spec.name)
        val p = spec.processes.single { it.id == "forgejo" }
        val originalCid = "f".repeat(64)
        val foreignCid = "a".repeat(64)
        var stops = 0
        val native = RuntimeCommands { args -> when (args) {
            listOf("container", "inspect", "p0v3-live-${spec.name}-${p.id}") -> RuntimeCommandResult(0,
                """[{"Id":"$foreignCid","Name":"p0v3-live-${spec.name}-${p.id}","Image":"sha256:${p.imageId}",
                    "Config":{"Image":"${p.image}","Labels":{"io.p0v3.private-deployment":"${spec.name}",
                    "io.p0v3.runtime-fingerprint":"$fingerprint"}},
                    "State":{"Running":true,"Status":"running"}}]""")
            else -> { stops++; error("Guard must never stop a CID different from its original ACK: $args") }
        } }
        val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) })
        val guard = RuntimeQuadletUnitRun(generationRoot, delegation, native = native, runtimeRoot = runtimeBase,
            generationBase = generationBase, guardInstalled = { _, _ -> "e".repeat(64) }, guardController = { },
            ownerProof = { QuadletOwnerProof.PID_MISSING }) // Explicit simulated dead owner; no live-lock inference.
        val genLock = generationBase.resolve("generation.lock")
        val memberLock = memberRoot.resolve("runtime.lock")
        FileChannel.open(genLock, CREATE_NEW, READ, WRITE).use { g ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { m ->
                Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                g.lock().use { m.lock().use {
                    delegation.begin("q-aabbccddeeff", bundleHash, spec, p, "start", fingerprint)
                    delegation.acknowledge("q-aabbccddeeff", spec.name, p.id, "start")
                } }
            }
        }
        val start = ReleasePrivateFiles.read(generationRoot.resolve(
            "quadlet-delegate-${spec.name}-${p.id}-start.intent.json"), 8192)
        val launchPath = generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.intent.json")
        ReleasePrivateFiles.save(launchPath, Json { encodeDefaults = true }.encodeToString(
            QuadletLaunchIntent(delegationSha256 = ReleaseLocks.sha256(start), member = spec.name,
                process = p.id, generatedArgvSha256 = "b".repeat(64), fingerprint = fingerprint)).toByteArray())
        ReleasePrivateFiles.save(generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.result.json"),
            Json { encodeDefaults = true }.encodeToString(QuadletLaunchResult(
                intentSha256 = ReleaseLocks.sha256(ReleasePrivateFiles.read(launchPath, 8192)),
                containerId = originalCid, imageId = p.imageId, nativeAcknowledged = true)).toByteArray())
        assertFails { guard.guard("q-aabbccddeeff", spec.name, p.id) }
        assertEquals(0, stops)
        assertNotNull(RuntimeMaintenance.read(memberRoot, fingerprint))
        assertFalse(Files.exists(generationRoot.resolve("quadlet-owner-loss-${spec.name}-${p.id}.result.json")))
    }

    @Test fun `simultaneous owner-loss guards serialize shared fence and stop both original CIDs`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val processes = listOf("postgres", "forgejo").map { id -> spec.processes.single { it.id == id } }
        val originalCids = mapOf("postgres" to "a".repeat(64), "forgejo" to "f".repeat(64))
        val running = java.util.concurrent.ConcurrentHashMap(processes.associate { it.id to true })
        val stopped = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
        val native = RuntimeCommands { args -> when {
            args.size == 3 && args.take(2) == listOf("container", "inspect") -> {
                val p = processes.single { args[2] == "p0v3-live-${spec.name}-${it.id}" }
                val cid = originalCids.getValue(p.id)
                RuntimeCommandResult(0, """[{"Id":"$cid","Name":"p0v3-live-${spec.name}-${p.id}",
                    "Image":"sha256:${p.imageId}","Config":{"Image":"${p.image}",
                    "Labels":{"io.p0v3.private-deployment":"${spec.name}",
                    "io.p0v3.runtime-fingerprint":"$fingerprint"}},
                    "State":{"Running":${running[p.id]},"Status":"${if (running[p.id] == true) "running" else "exited"}"}}]""")
            }
            args.size == 4 && args.take(3) == listOf("container", "stop", "--time=30") -> {
                val p = processes.single { originalCids[it.id] == args[3] }
                assertEquals(true, running.replace(p.id, true, false))
                stopped.add(p.id)
                RuntimeCommandResult(0, args[3])
            }
            else -> error("Unexpected native owner-loss effect: $args")
        } }
        val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) })
        val guard = RuntimeQuadletUnitRun(generationRoot, delegation, native = native, runtimeRoot = runtimeBase,
            generationBase = generationBase, guardInstalled = { _, _ -> "e".repeat(64) }, guardController = { },
            ownerProof = { QuadletOwnerProof.PID_MISSING }) // Two independent dead-owner helpers share exclusion.
        val genLock = generationBase.resolve("generation.lock")
        val memberLock = runtimeBase.resolve(spec.name).resolve("runtime.lock")
        FileChannel.open(genLock, CREATE_NEW, READ, WRITE).use { g ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { m ->
                Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                g.lock().use { m.lock().use {
                    for (p in processes) {
                        delegation.begin("q-aabbccddeeff", bundleHash, spec, p, "start", fingerprint)
                        delegation.acknowledge("q-aabbccddeeff", spec.name, p.id, "start")
                        val start = ReleasePrivateFiles.read(generationRoot.resolve(
                            "quadlet-delegate-${spec.name}-${p.id}-start.intent.json"), 8192)
                        val intent = generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.intent.json")
                        ReleasePrivateFiles.save(intent, Json { encodeDefaults = true }.encodeToString(
                            QuadletLaunchIntent(delegationSha256 = ReleaseLocks.sha256(start),
                                member = spec.name, process = p.id,
                                generatedArgvSha256 = "b".repeat(64), fingerprint = fingerprint)).toByteArray())
                        ReleasePrivateFiles.save(generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.result.json"),
                            Json { encodeDefaults = true }.encodeToString(QuadletLaunchResult(
                                intentSha256 = ReleaseLocks.sha256(ReleasePrivateFiles.read(intent, 8192)),
                                containerId = originalCids.getValue(p.id), imageId = p.imageId,
                                nativeAcknowledged = true)).toByteArray())
                    }
                } }
            }
        }
        val pool = java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val futures = processes.map { p -> pool.submit { guard.guard("q-aabbccddeeff", spec.name, p.id) } }
            futures.forEach { it.get(20, java.util.concurrent.TimeUnit.SECONDS) }
        } finally { pool.shutdownNow() }
        assertEquals(setOf("postgres", "forgejo"), stopped)
        assertNotNull(RuntimeMaintenance.read(runtimeBase.resolve(spec.name), fingerprint))
        processes.forEach { p ->
            assertTrue(Files.exists(generationRoot.resolve("quadlet-owner-loss-${spec.name}-${p.id}.result.json")))
        }
    }

    @Test fun `foreground helper retains CID before exiting only after authorized stop`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val genLock = generationBase.resolve("generation.lock")
        val memberLock = runtimeBase.resolve(spec.name).resolve("runtime.lock")
        val p = spec.processes.single { it.id == "forgejo" }
        val cid = "d".repeat(64)
        var running = true
        var created = true // A real Podman CID exists before foreground run starts it.
        val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) })
        val native = RuntimeCommands { args -> when (args) {
            listOf("container", "ls", "--all", "--format", "{{.Names}}") -> RuntimeCommandResult(0, "")
            listOf("container", "inspect", "p0v3-live-${spec.name}-${p.id}") -> RuntimeCommandResult(0,
                """[{"Id":"$cid","Name":"p0v3-live-${spec.name}-${p.id}","Image":"sha256:${p.imageId}",
                    "Config":{"Image":"${p.image}","Labels":{"io.p0v3.private-deployment":"${spec.name}",
                    "io.p0v3.runtime-fingerprint":"$fingerprint"}},
                    "State":{"Status":"${if (created) "created" else if (running) "running" else "exited"}",
                    "Running":${running && !created},"Pid":${if (created) 0 else 1234}}}]""")
            else -> error("Unexpected native command $args")
        } }
        val runner = RuntimeQuadletUnitRun(generationRoot, delegation,
            generated = { _, _ -> listOf("/usr/bin/podman", "run", p.image) }, native = native,
            foreground = { _, check, observed, _, stopping ->
                check()
                assertFalse(observed()) // Exact CREATED is pending; do not commit the CID yet.
                assertFalse(Files.exists(generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.result.json")))
                created = false
                assertTrue(observed())
                assertFalse(stopping())
                assertTrue(Files.exists(generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.result.json")))
                assertTrue(observed())
                assertFails { delegation.authorize("q-aabbccddeeff", spec.name, p.id, "start") }
                delegation.begin("q-aabbccddeeff", bundleHash, spec, p, "stop", fingerprint)
                assertTrue(stopping())
                check()
                val delegatedStop = ReleasePrivateFiles.read(generationRoot.resolve(
                    "quadlet-delegate-${spec.name}-${p.id}-stop.intent.json"), 8192)
                val stop = QuadletStopIntent(delegationSha256 = ReleaseLocks.sha256(delegatedStop),
                    member = spec.name, process = p.id, containerId = cid, fingerprint = fingerprint)
                val encoded = Json { encodeDefaults = true }.encodeToString(stop).toByteArray()
                ReleasePrivateFiles.save(generationRoot.resolve("quadlet-stop-${spec.name}-${p.id}.intent.json"), encoded)
                running = false
                ReleasePrivateFiles.save(generationRoot.resolve("quadlet-stop-${spec.name}-${p.id}.result.json"),
                    Json { encodeDefaults = true }.encodeToString(QuadletStopResult(
                        intentSha256 = ReleaseLocks.sha256(encoded), containerId = cid, stopped = true,
                        nativeStopAcknowledged = true)).toByteArray())
                // Podman run may return a signal exit status after a successful
                // separately acknowledged systemd ExecStop of this exact CID.
                RuntimeCommandResult(143, "")
            }, runtimeRoot = runtimeBase, kernelConfinement = { _, _, _, pid -> assertEquals(1234L, pid) })
        FileChannel.open(genLock, CREATE_NEW, READ, WRITE).use { g ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { m ->
                Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                g.lock().use { m.lock().use {
                    delegation.begin("q-aabbccddeeff", bundleHash, spec, p, "start", fingerprint)
                    delegation.acknowledge("q-aabbccddeeff", spec.name, p.id, "start")
                    assertEquals(cid, runner.run("q-aabbccddeeff", spec.name, p.id).containerId)
                } }
            }
        }
    }

    @Test fun `failed generated translation denies before native launch intent`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val genLock = generationBase.resolve("generation.lock")
        val memberLock = runtimeBase.resolve(spec.name).resolve("runtime.lock")
        val p = spec.processes.single { it.id == "forgejo" }
        val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) })
        val runner = RuntimeQuadletUnitRun(generationRoot, delegation,
            generated = { _, _ -> error("No generator or native process permitted") },
            native = RuntimeCommands { error("No native process permitted") },
            launch = { _, _ -> error("No native launch permitted") }, runtimeRoot = runtimeBase)
        FileChannel.open(genLock, CREATE_NEW, READ, WRITE).use { g ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { m ->
                Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                g.lock().use { m.lock().use {
                    delegation.begin("q-aabbccddeeff", bundleHash, spec, p, "start", fingerprint)
                    delegation.acknowledge("q-aabbccddeeff", spec.name, p.id, "start")
                    assertFails { runner.run("q-aabbccddeeff", spec.name, p.id) }
                    assertFalse(Files.exists(generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.intent.json")))
                } }
            }
        }
    }

    @Test fun `owner death after helper ACK but before gated ExecStart denies native launch`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val memberRoot = runtimeBase.resolve(spec.name)
        val genLock = generationBase.resolve("generation.lock")
        val memberLock = memberRoot.resolve("runtime.lock")
        val p = spec.processes.single { it.id == "forgejo" }
        var dead = false
        val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) },
            startTicks = { pid -> QuadletNativeLockProof.startTicks(pid) + if (dead) 1 else 0 })
        var launches = 0
        val runner = RuntimeQuadletUnitRun(generationRoot, delegation,
            generated = { _, _ -> dead = true; listOf("/usr/bin/podman", "run", p.image) },
            native = RuntimeCommands { args -> when (args) {
                listOf("container", "ls", "--all", "--format", "{{.Names}}") -> RuntimeCommandResult(0, "")
                else -> error("Native inspect must not run before launch")
            } }, launch = { _, _ -> launches++; error("Launch must be denied") }, mockForegroundCustody = true)
        FileChannel.open(genLock, CREATE_NEW, READ, WRITE).use { g ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { m ->
                Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                g.lock().use { m.lock().use {
                    delegation.begin("q-aabbccddeeff", bundleHash, spec, p, "start", fingerprint)
                    delegation.acknowledge("q-aabbccddeeff", spec.name, p.id, "start")
                    assertFails { runner.run("q-aabbccddeeff", spec.name, p.id) }
                    assertEquals(0, launches)
                    dead = false
                    assertFails { runner.run("q-aabbccddeeff", spec.name, p.id) }
                    assertEquals(0, launches)
                } }
            }
        }
    }

    @Test fun `owner death during and after native launch fences and stops exact retained CID`() {
        for (phase in listOf("during", "after")) fixture {
            generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
            val memberRoot = runtimeBase.resolve(spec.name)
            val genLock = generationBase.resolve("generation.lock")
            val memberLock = memberRoot.resolve("runtime.lock")
            val p = spec.processes.single { it.id == "forgejo" }
            var dead = false
            var running = false
            var starts = 0
            var stops = 0
            val cid = "b".repeat(64)
            val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
                installed = { _, _ -> "e".repeat(64) },
                startTicks = { pid -> QuadletNativeLockProof.startTicks(pid) + if (dead) 1 else 0 })
            val native = RuntimeCommands { args -> when (args) {
                listOf("container", "ls", "--all", "--format", "{{.Names}}") -> RuntimeCommandResult(0, "")
                listOf("container", "inspect", "p0v3-live-${spec.name}-${p.id}") -> RuntimeCommandResult(0,
                    """[{"Id":"$cid","Name":"p0v3-live-${spec.name}-${p.id}",
                       "Image":"sha256:${p.imageId}","Config":{"Image":"${p.image}",
                       "Labels":{"io.p0v3.private-deployment":"${spec.name}",
                       "io.p0v3.runtime-fingerprint":"$fingerprint"}},
                       "State":{"Status":"${if (running) "running" else "exited"}","Running":$running}}]""".trimIndent())
                listOf("container", "stop", "--time=30", cid) -> {
                    stops++; running = false; RuntimeCommandResult(0, cid)
                }
                else -> error("Unrecognized containment command: $args")
            } }
            val runner = RuntimeQuadletUnitRun(generationRoot, delegation,
                generated = { _, _ -> listOf("/usr/bin/podman", "run", p.image) }, native = native,
                launch = { _, check ->
                    starts++; running = true; dead = true
                    if (phase == "during") check()
                    RuntimeCommandResult(0, cid)
                }, runtimeRoot = runtimeBase, mockForegroundCustody = true,
                ownerProof = { QuadletOwnerProof.VERIFIED }) // Mock flips lease identity while the fixture deliberately holds both locks.
            FileChannel.open(genLock, CREATE_NEW, READ, WRITE).use { g ->
                FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { m ->
                    Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                    Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                    g.lock().use { m.lock().use {
                        delegation.begin("q-aabbccddeeff", bundleHash, spec, p, "start", fingerprint)
                        delegation.acknowledge("q-aabbccddeeff", spec.name, p.id, "start")
                        assertFails { runner.run("q-aabbccddeeff", spec.name, p.id) }
                        assertEquals(1, starts)
                        assertEquals(1, stops)
                        assertFalse(running)
                        assertTrue(Files.exists(generationRoot.resolve("quadlet-owner-loss-${spec.name}-${p.id}.result.json")))
                        assertFalse(Files.exists(generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.result.json")))
                        assertNotNull(RuntimeMaintenance.read(memberRoot, fingerprint))
                        dead = false
                        assertFails { runner.run("q-aabbccddeeff", spec.name, p.id) }
                        assertEquals(1, starts)
                    } }
                }
            }
        }
    }

    @Test fun `stop and stop-post retain original CID with no second Podman stop`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val memberRoot = runtimeBase.resolve(spec.name)
        val genLock = generationBase.resolve("generation.lock")
        val memberLock = memberRoot.resolve("runtime.lock")
        val process = spec.processes.single { it.id == "forgejo" }
        val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) })
        var running = true
        var stops = 0
        val cid = "b".repeat(64)
        val native = RuntimeCommands { args ->
            when (args) {
                listOf("container", "inspect", "p0v3-live-${spec.name}-${process.id}") -> RuntimeCommandResult(0,
                    """[{"Id":"$cid","Name":"p0v3-live-${spec.name}-${process.id}",
                      "Image":"sha256:${process.imageId}","Config":{"Image":"${process.image}",
                      "Labels":{"io.p0v3.private-deployment":"${spec.name}",
                      "io.p0v3.runtime-fingerprint":"$fingerprint"}},
                      "State":{"Status":"${if (running) "running" else "exited"}","Running":$running}}]""".trimIndent())
                listOf("container", "stop", "--time=30", cid) -> {
                    stops++; running = false; RuntimeCommandResult(0, cid)
                }
                else -> error("Foreign Podman effect: $args")
            }
        }
        val stop = RuntimeQuadletStop(generationRoot, delegation, native)
        // A stage-failure isolation fence must block new starts, not prevent an owned stop.
        ReleasePrivateFiles.save(generationRoot.resolve("isolate.intent.json"),
            Json { encodeDefaults = true }.encodeToString(GenerationIntent("isolate", bundleHash)).toByteArray())
        FileChannel.open(genLock, CREATE_NEW, READ, WRITE).use { g ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { m ->
                Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                g.lock().use { m.lock().use {
                    delegation.begin("q-aabbccddeeff", bundleHash, spec, process, "stop", fingerprint)
                    val original = stop.stop("q-aabbccddeeff", spec.name, process.id)
                    assertEquals(cid, original.containerId)
                    assertTrue(original.nativeStopAcknowledged)
                    assertEquals(original, stop.stop("q-aabbccddeeff", spec.name, process.id))
                    assertEquals(1, stops)
                } }
            }
        }
    }

    @Test fun `lost native stop ACK records independent readback and never replays`() = fixture {
        generationBase, generationRoot, runtimeBase, spec, bundleHash, fingerprint ->
        val memberRoot = runtimeBase.resolve(spec.name)
        val genLock = generationBase.resolve("generation.lock")
        val memberLock = memberRoot.resolve("runtime.lock")
        val p = spec.processes.single { it.id == "forgejo" }
        val delegation = RuntimeQuadletDelegation(generationRoot, runtimeBase, generationBase,
            installed = { _, _ -> "e".repeat(64) })
        var running = true
        var stops = 0
        val cid = "b".repeat(64)
        val native = RuntimeCommands { args -> when (args) {
            listOf("container", "inspect", "p0v3-live-${spec.name}-${p.id}") -> RuntimeCommandResult(0,
                """[{"Id":"$cid","Name":"p0v3-live-${spec.name}-${p.id}",
                   "Image":"sha256:${p.imageId}","Config":{"Image":"${p.image}",
                   "Labels":{"io.p0v3.private-deployment":"${spec.name}",
                   "io.p0v3.runtime-fingerprint":"$fingerprint"}},
                   "State":{"Status":"${if (running) "running" else "exited"}","Running":$running}}]""".trimIndent())
            listOf("container", "stop", "--time=30", cid) -> {
                stops++; running = false; throw IllegalStateException("lost native ACK")
            }
            else -> error("Unexpected native effect")
        } }
        FileChannel.open(genLock, CREATE_NEW, READ, WRITE).use { g ->
            FileChannel.open(memberLock, CREATE_NEW, READ, WRITE).use { m ->
                Files.setPosixFilePermissions(genLock, PosixFilePermissions.fromString("rw-------"))
                Files.setPosixFilePermissions(memberLock, PosixFilePermissions.fromString("rw-------"))
                g.lock().use { m.lock().use {
                    delegation.begin("q-aabbccddeeff", bundleHash, spec, p, "stop", fingerprint)
                    val stop = RuntimeQuadletStop(generationRoot, delegation, native)
                    assertFails { stop.stop("q-aabbccddeeff", spec.name, p.id) }
                    assertFails { stop.stop("q-aabbccddeeff", spec.name, p.id) }
                    assertEquals(1, stops)
                    assertFalse(Files.exists(generationRoot.resolve("quadlet-stop-${spec.name}-${p.id}.result.json")))
                    val reconciled = Files.readString(generationRoot.resolve("quadlet-stop-${spec.name}-${p.id}.reconciliation.json"))
                    assertContains(reconciled, "\"observedStopped\":true")
                } }
            }
        }
    }

    @Test fun `closing any descriptor to POSIX locked inode loses owner proof even while owner lives`() {
        val path = Files.createTempFile("quadlet-posix-close-", ".lock")
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        try {
            val pid = ProcessHandle.current().pid()
            FileChannel.open(path, READ, WRITE).use { owner ->
                owner.lock().use {
                    assertTrue(QuadletNativeLockProof.heldBy(path, pid))
                    FileChannel.open(path, READ).use { other -> assertEquals(0L, other.size()) }
                    assertTrue(ProcessHandle.current().isAlive)
                    assertFalse(QuadletNativeLockProof.heldBy(path, pid))
                }
            }
        } finally { Files.deleteIfExists(path) }
    }

    @Test fun `bounded owner proof rechecks transient member miss but never admits persistent loss`() {
        val pid = ProcessHandle.current().pid()
        val ticks = QuadletNativeLockProof.startTicks(pid)
        val gen = Path.of("/tmp/transient-generation-lock")
        val member = Path.of("/tmp/transient-member-lock")
        var probes = 0
        val recovered = QuadletNativeLockProof.classifyStableEvidence(pid, ticks, gen, member,
            held = { path, _ -> path == gen || ++probes > 1 })
        assertEquals(QuadletOwnerProof.PROOF_UNAVAILABLE, recovered.proof)
        assertEquals(QuadletOwnerProof.MEMBER_LOCK_MISSING, recovered.first)
        assertEquals(QuadletOwnerProof.VERIFIED, recovered.second)
        assertEquals(2, probes)
        assertEquals(QuadletOwnerProof.MEMBER_LOCK_MISSING,
            QuadletNativeLockProof.classifyStable(pid, ticks, gen, member,
                held = { path, _ -> path == gen }))
    }

    @Test fun `many concurrent independent native proof snapshots cannot close the original lock inode`() {
        val generation = Files.createTempFile("quadlet-proof-generation-", ".lock")
        val member = Files.createTempFile("quadlet-proof-member-", ".lock")
        listOf(generation, member).forEach {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rw-------"))
        }
        try {
            val pid = ProcessHandle.current().pid()
            val ticks = QuadletNativeLockProof.startTicks(pid)
            FileChannel.open(generation, READ, WRITE).use { g ->
                FileChannel.open(member, READ, WRITE).use { m ->
                    g.lock().use { m.lock().use {
                        val threads = java.util.concurrent.Executors.newFixedThreadPool(8)
                        try {
                            val results = (1..320).map { threads.submit<QuadletStableOwnerProof> {
                                QuadletNativeLockProof.classifyStableEvidence(pid, ticks, generation, member)
                            } }.map { it.get(25, java.util.concurrent.TimeUnit.SECONDS) }
                            assertTrue(results.all { it.proof == QuadletOwnerProof.VERIFIED &&
                                it.first == QuadletOwnerProof.VERIFIED && it.second == null })
                            assertTrue(g.isOpen && m.isOpen)
                        } finally { threads.shutdownNow() }
                    } }
                }
            }
        } finally {
            Files.deleteIfExists(generation)
            Files.deleteIfExists(member)
        }
    }

    @Test fun `blocked live owner retains both POSIX locks longer than failed StartUnit interval`() {
        val generation = Files.createTempFile("quadlet-wait-generation-", ".lock")
        val member = Files.createTempFile("quadlet-wait-member-", ".lock")
        listOf(generation, member).forEach { Files.setPosixFilePermissions(it,
            PosixFilePermissions.fromString("rw-------")) }
        try {
            val pid = ProcessHandle.current().pid()
            val ticks = QuadletNativeLockProof.startTicks(pid)
            FileChannel.open(generation, READ, WRITE).use { genOwner ->
                FileChannel.open(member, READ, WRITE).use { memberOwner ->
                    genOwner.lock().use { memberOwner.lock().use {
                        val child = ProcessBuilder("/usr/bin/sleep", "27").start()
                        try {
                            repeat(6) {
                                assertEquals(QuadletOwnerProof.VERIFIED,
                                    QuadletNativeLockProof.classify(pid, ticks, generation, member))
                                Thread.sleep(5_000)
                            }
                            assertTrue(child.waitFor(3, java.util.concurrent.TimeUnit.SECONDS))
                            assertEquals(QuadletOwnerProof.VERIFIED,
                                QuadletNativeLockProof.classify(pid, ticks, generation, member))
                        } finally { if (child.isAlive) child.destroyForcibly() }
                    } }
                }
            }
        } finally { Files.deleteIfExists(generation); Files.deleteIfExists(member) }
    }

    @Test fun `owner proof distinguishes live descriptor-close loss from dead owner and unavailable evidence`() {
        val generation = Files.createTempFile("quadlet-generation-posix-", ".lock")
        val member = Files.createTempFile("quadlet-member-posix-", ".lock")
        listOf(generation, member).forEach { Files.setPosixFilePermissions(it,
            PosixFilePermissions.fromString("rw-------")) }
        try {
            val pid = ProcessHandle.current().pid()
            val ticks = QuadletNativeLockProof.startTicks(pid)
            FileChannel.open(generation, READ, WRITE).use { genOwner ->
                FileChannel.open(member, READ, WRITE).use { memberOwner ->
                    genOwner.lock().use {
                        memberOwner.lock().use {
                            fun classification() = QuadletNativeLockProof.classify(pid, ticks, generation, member)
                            assertEquals(QuadletOwnerProof.VERIFIED, classification())
                            FileChannel.open(generation, READ).use { assertEquals(0L, it.size()) }
                            assertEquals(QuadletOwnerProof.GENERATION_LOCK_MISSING, classification())
                            assertEquals(QuadletOwnerProof.START_TICKS_CHANGED,
                                QuadletNativeLockProof.classify(pid, ticks + 1, generation, member))
                            assertEquals(QuadletOwnerProof.PROOF_UNAVAILABLE,
                                QuadletNativeLockProof.classify(pid, ticks, generation, member,
                                    held = { _, _ -> error("injected unreadable proof") }))
                            FileChannel.open(member, READ).use { assertEquals(0L, it.size()) }
                            assertEquals(QuadletOwnerProof.BOTH_LOCKS_MISSING, classification())
                            assertTrue(ProcessHandle.current().isAlive)
                        }
                    }
                }
            }
            assertEquals(QuadletOwnerProof.PID_MISSING,
                QuadletNativeLockProof.classify(Long.MAX_VALUE, ticks, generation, member))
        } finally { Files.deleteIfExists(generation); Files.deleteIfExists(member) }
    }

    @Test fun `native lock proof identifies the actual owner and refuses release or other PID`() {
        val path = Files.createTempFile("quadlet-native-lock-", ".lock")
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        try {
            val pid = ProcessHandle.current().pid()
            assertTrue(QuadletNativeLockProof.startTicks(pid) > 0)
            FileChannel.open(path, READ, WRITE).use { channel ->
                assertFalse(QuadletNativeLockProof.heldBy(path, pid))
                channel.lock().use {
                    assertTrue(QuadletNativeLockProof.heldBy(path, pid))
                    assertFalse(QuadletNativeLockProof.heldBy(path, pid + 1))
                }
                assertFalse(QuadletNativeLockProof.heldBy(path, pid))
            }
        } finally { Files.deleteIfExists(path) }
    }
}
