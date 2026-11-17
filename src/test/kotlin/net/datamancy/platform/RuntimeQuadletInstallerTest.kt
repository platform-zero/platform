package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.Json
import kotlinx.serialization.decodeFromString
import kotlin.test.*

class RuntimeQuadletInstallerTest {
    private fun fixture(action: (Path, PrivateDeploymentSpec) -> Unit) {
        val root = Files.createTempDirectory("quadlet-exclusive-test-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val spec = FragmentAssemblyFixture.plan().specs.single()
            val generation = root.resolve("q-aabbccddeeff")
            Files.createDirectory(generation, PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")))
            action(generation, spec)
        } finally { FragmentAssemblyFixture.remove(root) }
    }

    @Test fun `exclusive copy rejects conflicting file symlink ancestor and unsafe directory`() = fixture { root, _ ->
        val uid = UnixSystem().uid
        val destination = root.resolve("quadlet/safe/unit.container")
        RuntimeQuadletRootCopy.createExclusive(destination, "original".toByteArray(), root, uid)
        assertEquals(PosixFilePermissions.fromString("rwxr-xr-x"),Files.getPosixFilePermissions(destination.parent))
        assertEquals("original", Files.readString(destination))
        assertFails { RuntimeQuadletRootCopy.createExclusive(destination, "replacement".toByteArray(), root, uid) }
        assertEquals("original", Files.readString(destination))
        val link = root.resolve("foreign")
        Files.createSymbolicLink(link, root.resolve("quadlet"))
        assertFails { RuntimeQuadletRootCopy.createExclusive(link.resolve("safe/foreign.container"), byteArrayOf(1), root, uid) }
        val writable = root.resolve("writable")
        Files.createDirectory(writable)
        Files.setPosixFilePermissions(writable, PosixFilePermissions.fromString("rwxrwxrwx"))
        assertFails { RuntimeQuadletRootCopy.createExclusive(writable.resolve("unit.container"), byteArrayOf(1), root, uid) }
        assertFails { RuntimeQuadletRootCopy.createExclusive(root.resolve("missing/../unsafe"), byteArrayOf(1), root, uid) }
    }

    @Test fun `partial install retains original intent and refuses rerun even after failure`() = fixture { root, spec ->
        val base = root.parent
        val source = base.resolve("source")
        val systemd = base.resolve("systemd")
        Files.createDirectory(source); Files.createDirectory(systemd)
        val actions = mutableListOf<List<String>>()
        val installer = RuntimeQuadletInstaller(source, systemd,
            effect = { args -> actions += args; error("injected privileged copy failure") },
            audit = { _, _ -> error("No installed audit on partial install") }, controller = { })
        assertFails { installer.install(root, "q-aabbccddeeff", "a".repeat(64), spec) }
        assertTrue(Files.exists(root.resolve("quadlet-install-${spec.name}.intent.json")))
        assertFalse(Files.exists(root.resolve("quadlet-install-${spec.name}.result.json")))
        assertEquals(1, actions.size)
        assertEquals("quadlet-copy", actions.single()[4])
        assertFails { installer.install(root, "q-aabbccddeeff", "a".repeat(64), spec) }
        assertEquals(1, actions.size)
    }

    @Test fun `complete disabled install copies then reloads then audits and journals before any start`() = fixture { root, spec ->
        val base=root.parent
        val source=base.resolve("source");val systemd=base.resolve("systemd")
        Files.createDirectory(source);Files.createDirectory(systemd)
        Files.setPosixFilePermissions(source,PosixFilePermissions.fromString("rwxr-xr-x"))
        Files.setPosixFilePermissions(systemd,PosixFilePermissions.fromString("rwxr-xr-x"))
        val events=mutableListOf<String>()
        val uid=UnixSystem().uid
        val installer=RuntimeQuadletInstaller(source,systemd,effect={ args ->
            when(args.lastOrNull()) {
                "daemon-reload" -> {
                    assertEquals(listOf("/usr/bin/sudo","-n","/usr/bin/systemctl","daemon-reload"),args)
                    events+="reload"
                }
                else -> {
                    assertEquals("quadlet-copy",args[4]);events+="copy"
                    val bytes=Files.readAllBytes(Path.of(args[5]))
                    assertEquals(args[7],ReleaseLocks.sha256(bytes))
                    RuntimeQuadletRootCopy.createExclusive(Path.of(args[6]),bytes,base,uid)
                }
            }
        },audit={ checked,p ->
            assertEquals(spec,checked)
            assertEquals("reload",events[spec.processes.size*2])
            assertTrue(events.drop(spec.processes.size*2+1).all { it=="audit" })
            val sourceFile=source.resolve(RuntimeQuadlets.unit(checked,p)+".container")
            val dropIn=systemd.resolve(RuntimeQuadlets.unit(checked,p)+".service.d/50-p0-lifecycle.conf")
            assertTrue(Files.isRegularFile(sourceFile))
            assertTrue(Files.isRegularFile(dropIn))
            events+="audit"
            ReleaseLocks.sha256(Files.readAllBytes(sourceFile)+Files.readAllBytes(dropIn))
        },controller={})
        val result=installer.install(root,"q-aabbccddeeff","a".repeat(64),spec)
        val intentPath=root.resolve("quadlet-install-${spec.name}.intent.json")
        val resultPath=root.resolve("quadlet-install-${spec.name}.result.json")
        val original=Json.decodeFromString<QuadletInstallResult>(Files.readString(resultPath))
        assertEquals(result,original)
        assertEquals(ReleaseLocks.sha256(Files.readAllBytes(intentPath)),result.intentSha256)
        assertEquals(spec.processes.map { it.id }.toSet(),result.installedAuditSha256.keys)
        assertEquals(spec.processes.size*2,events.count { it=="copy" })
        assertEquals(1,events.count { it=="reload" })
        assertEquals(spec.processes.size,events.count { it=="audit" })
        assertEquals("reload",events[spec.processes.size*2])
        assertTrue(events.drop(spec.processes.size*2+1).all { it=="audit" })
        assertFails { installer.install(root,"q-aabbccddeeff","a".repeat(64),spec) }
    }

    @Test fun `destination arriving after preflight cannot be overwritten`() = fixture { root, spec ->
        val base = root.parent
        val source = base.resolve("source"); val systemd = base.resolve("systemd")
        Files.createDirectory(source); Files.createDirectory(systemd)
        Files.setPosixFilePermissions(source, PosixFilePermissions.fromString("rwxr-xr-x"))
        Files.setPosixFilePermissions(systemd, PosixFilePermissions.fromString("rwxr-xr-x"))
        var attempts = 0
        var raced: Path? = null
        val installer = RuntimeQuadletInstaller(source, systemd, effect = { args ->
            attempts++
            assertEquals("quadlet-copy", args[4])
            val destination = Path.of(args[6])
            raced = destination
            // Model another writer winning the race after the owner's absence preflight.
            if (attempts == 1) RuntimeQuadletRootCopy.createExclusive(destination,
                "foreign-original".toByteArray(), base, UnixSystem().uid)
            RuntimeQuadletRootCopy.createExclusive(destination, Files.readAllBytes(Path.of(args[5])),
                base, UnixSystem().uid)
        }, audit = { _, _ -> error("Incomplete install cannot audit") }, controller = { })
        val failure = assertFails { installer.install(root, "q-aabbccddeeff", "a".repeat(64), spec) }
        assertTrue(Files.exists(requireNotNull(raced)), "Race setup failed: $failure")
        assertEquals(1, attempts)
        assertEquals("foreign-original", Files.readString(requireNotNull(raced)))
        assertTrue(Files.exists(root.resolve("quadlet-install-${spec.name}.intent.json")))
        assertFalse(Files.exists(root.resolve("quadlet-install-${spec.name}.result.json")))
    }

    @Test fun `conflicting destination rejects before original intent and effect`() = fixture { root, spec ->
        val base = root.parent
        val source = base.resolve("source"); val systemd = base.resolve("systemd")
        Files.createDirectory(source); Files.createDirectory(systemd)
        val first = RuntimeQuadlets.render(spec).files.keys.first()
        Files.createSymbolicLink(source.resolve(first), root.resolve("absent"))
        val installer = RuntimeQuadletInstaller(source, systemd, effect = { error("Effect must not run") },
            audit = { _, _ -> error("Audit must not run") }, controller = { })
        assertFails { installer.install(root, "q-aabbccddeeff", "a".repeat(64), spec) }
        assertFalse(Files.exists(root.resolve("quadlet-install-${spec.name}.intent.json")))
    }

    @Test fun `privileged copy binding refuses foreign generation member destination and forged source order`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val rendered = RuntimeQuadlets.render(spec)
        val files = rendered.files.mapKeys { (relative, _) ->
            (if (relative.endsWith(".container")) Path.of("/etc/containers/systemd/p0-v3")
             else Path.of("/etc/systemd/system")).resolve(relative).toString()
        }.mapValues { ReleaseLocks.sha256(it.value.toByteArray()) }.toSortedMap()
        val destination = Path.of(files.keys.first())
        val member = spec.name
        val generation = "q-aabbccddeeff"
        val controller = spec.fragmentBinding!!.controllerSha256!!
        val intent = QuadletInstallIntent(generation = generation, bundleSha256 = "a".repeat(64),
            member = member, specSha256 = rendered.specSha256, filesSha256 = files,
            stagedDestinations = files.keys.toList())
        val bundle = GenerationBundle(FragmentAssemblyFixture.plan().generation,
            listOf(GenerationPin(GenerationMember(member), "b".repeat(64), emptyMap(), "c".repeat(64), spec)), 4096)
        assertTrue(RuntimeQuadletRootCopy.authorizes(intent, bundle, generation, member, 0,
            destination, files.getValue(destination.toString()), controller))
        assertFalse(RuntimeQuadletRootCopy.authorizes(intent.copy(generation = "q-000000000000"), bundle,
            generation, member, 0, destination, files.getValue(destination.toString()), controller))
        assertFalse(RuntimeQuadletRootCopy.authorizes(intent, bundle, "q-000000000000", member,
            0, destination, files.getValue(destination.toString()), controller))
        assertFalse(RuntimeQuadletRootCopy.authorizes(intent, bundle, generation, "q-000000000000-foreign",
            0, destination, files.getValue(destination.toString()), controller))
        assertFalse(RuntimeQuadletRootCopy.authorizes(intent, bundle, generation, member, 1,
            destination, files.getValue(destination.toString()), controller))
        assertFalse(RuntimeQuadletRootCopy.authorizes(intent, bundle, generation, member, 0,
            Path.of("/etc/systemd/system/p0v3-q-000000000000-foreign.service.d/50-p0-lifecycle.conf"),
            files.getValue(destination.toString()), controller))
        assertFalse(RuntimeQuadletRootCopy.authorizes(intent.copy(specSha256 = "d".repeat(64)), bundle,
            generation, member, 0, destination, files.getValue(destination.toString()), controller))
        assertFalse(RuntimeQuadletRootCopy.authorizes(intent, bundle, generation, member, 0,
            destination, files.getValue(destination.toString()), "e".repeat(64)))
    }

    @Test fun `child keeping output open cannot bypass effect timeout`() {
        val begin = System.nanoTime()
        assertFails { quadletInstallEffect(listOf("/usr/bin/sleep", "5"), 1) }
        assertTrue((System.nanoTime() - begin) / 1_000_000 < 4000, "Effect timeout must bound the child")
    }
}
