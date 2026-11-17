package net.datamancy.platform

import kotlin.test.*

/** Real generator only: fixture image digests are deliberately NOT pullable application evidence. */
class RuntimeQuadletRealIntegrationTest {
    @Test fun `pinned native generator translates the packaged graph without installing units`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val diagnostic = RuntimeQuadletDiagnostics.verify(spec, RuntimeQuadlets.render(spec)) { args, units ->
            RuntimeQuadletDiagnostics.invoke(args, units).also { println(it.output) }
        }
        assertEquals("5.4.2", diagnostic.generatorVersion)
        assertEquals(spec.processes.size, diagnostic.services.size)
        assertFalse(diagnostic.runtimeAdmitted || diagnostic.effectiveInstalledUnitsVerified)
        assertTrue(diagnostic.lifecycleDropInsRequired)
    }

    @Test fun `pinned generator command grammar is exact and expandable without shell execution`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val fingerprint = "f".repeat(64)
        for (p in spec.processes) {
            val original = RuntimeQuadletGeneratedStart.fromPinnedGenerator(spec, p)
            val expanded = RuntimeQuadletGeneratedStart.expand(original, spec, p, fingerprint,
                if (p.oneShot) "a".repeat(64) else null)
            assertEquals("/usr/bin/podman", expanded.first())
            assertTrue(expanded.contains("--cidfile=/run/${RuntimeQuadlets.unit(spec, p)}.cid"),
                "Exact systemd cidfile specifier must expand for ${p.id}")
            assertTrue(expanded.contains(p.image))
            assertTrue(expanded.any { it == "io.p0v3.runtime-fingerprint=$fingerprint" })
            if (p.oneShot) assertTrue(expanded.any { it == "io.p0v3.initializer-intent=${"a".repeat(64)}" })
            else assertFalse(expanded.any { it.contains("initializer-intent") })
        }
    }

    @Test fun `real POSIX owner death revokes both native lock proofs`() {
        val root = java.nio.file.Files.createTempDirectory("quadlet-owner-death-")
        val first = root.resolve("generation.lock")
        val second = root.resolve("runtime.lock")
        try {
            java.nio.file.Files.createFile(first); java.nio.file.Files.createFile(second)
            listOf(first, second).forEach {
                java.nio.file.Files.setPosixFilePermissions(it,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
            }
            val script = "import fcntl,sys; a=open(sys.argv[1],'r+'); b=open(sys.argv[2],'r+'); " +
                "fcntl.lockf(a,fcntl.LOCK_EX); fcntl.lockf(b,fcntl.LOCK_EX); print('held',flush=True); sys.stdin.read()"
            val child = ProcessBuilder("/usr/bin/python3", "-c", script, first.toString(), second.toString())
                .redirectErrorStream(true).start()
            try {
                assertEquals("held", child.inputStream.bufferedReader().readLine())
                val pid = child.pid()
                assertTrue(QuadletNativeLockProof.startTicks(pid) > 0)
                assertTrue(QuadletNativeLockProof.heldBy(first, pid))
                assertTrue(QuadletNativeLockProof.heldBy(second, pid))
                child.destroyForcibly()
                assertTrue(child.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
                assertFalse(QuadletNativeLockProof.heldBy(first, pid))
                assertFalse(QuadletNativeLockProof.heldBy(second, pid))
            } finally { if (child.isAlive) child.destroyForcibly() }
        } finally { java.nio.file.Files.walk(root).use {
            it.sorted(Comparator.reverseOrder()).forEach(java.nio.file.Files::delete) } }
    }

    @Test fun `native independent processes distinguish live lock loss and actual owner death`() {
        val root = java.nio.file.Files.createTempDirectory("quadlet-cross-process-proof-")
        val generation = root.resolve("generation.lock")
        val member = root.resolve("runtime.lock")
        val mode = java.nio.file.attribute.PosixFilePermissions.fromString("rw-------")
        val childScript = "import fcntl,sys; a=open(sys.argv[1],'r+'); b=open(sys.argv[2],'r+'); " +
            "fcntl.lockf(a,fcntl.LOCK_EX); fcntl.lockf(b,fcntl.LOCK_EX); print('held',flush=True); " +
            "assert sys.stdin.readline().strip()=='drop-generation'; " +
            "x=open(sys.argv[1],'r+'); x.close(); print('generation-lost',flush=True); " +
            "assert sys.stdin.readline().strip()=='reacquire-generation'; " +
            "fcntl.lockf(a,fcntl.LOCK_EX); print('generation-reacquired',flush=True); sys.stdin.read()"
        val probeScript = "import fcntl,sys; f=open(sys.argv[1],'r+'); " +
            "fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB); print('acquired',flush=True)"
        try {
            listOf(generation, member).forEach { java.nio.file.Files.createFile(it)
                java.nio.file.Files.setPosixFilePermissions(it, mode) }
            val owner = ProcessBuilder("/usr/bin/python3", "-c", childScript,
                generation.toString(), member.toString()).redirectErrorStream(true).start()
            try {
                val messages = owner.inputStream.bufferedReader()
                assertEquals("held", messages.readLine())
                val pid = owner.pid()
                val ticks = QuadletNativeLockProof.startTicks(pid)
                fun proof() = QuadletNativeLockProof.classify(pid, ticks, generation, member)
                fun probe(path: java.nio.file.Path): Boolean {
                    val contender = ProcessBuilder("/usr/bin/python3", "-c", probeScript, path.toString())
                        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                        .redirectError(ProcessBuilder.Redirect.DISCARD).start()
                    try {
                        assertTrue(contender.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
                        return contender.exitValue() == 0
                    } finally { if (contender.isAlive) contender.destroyForcibly() }
                }
                assertEquals(QuadletOwnerProof.VERIFIED, proof())
                assertFalse(probe(generation)); assertFalse(probe(member))
                assertEquals(QuadletOwnerProof.VERIFIED, proof())
                owner.outputStream.write("drop-generation\n".toByteArray()); owner.outputStream.flush()
                assertEquals("generation-lost", messages.readLine())
                assertTrue(owner.isAlive)
                assertEquals(QuadletOwnerProof.GENERATION_LOCK_MISSING, proof())
                assertTrue(probe(generation)); assertFalse(probe(member))
                owner.outputStream.write("reacquire-generation\n".toByteArray()); owner.outputStream.flush()
                assertEquals("generation-reacquired", messages.readLine())
                assertEquals(QuadletOwnerProof.VERIFIED, proof()) // Instantaneous proof, NOT continuous custody.
                assertFalse(probe(generation)); assertFalse(probe(member))
                owner.outputStream.close()
                assertTrue(owner.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
                assertEquals(QuadletOwnerProof.PID_MISSING, proof())
                assertTrue(probe(generation)); assertTrue(probe(member))
            } finally { if (owner.isAlive) owner.destroyForcibly() }
        } finally { java.nio.file.Files.walk(root).use {
            it.sorted(Comparator.reverseOrder()).forEach(java.nio.file.Files::delete) } }
    }

    @Test fun `generator discovers nested owned Quadlet directory without touching installed units`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val bundle = RuntimeQuadlets.render(spec)
        val root = java.nio.file.Files.createTempDirectory("quadlet-location-")
        val nested = java.nio.file.Files.createDirectory(root.resolve("p0-v3"))
        try {
            bundle.files.filterKeys { it.endsWith(".container") }.forEach { (name, text) ->
                java.nio.file.Files.writeString(nested.resolve(name), text)
            }
            val result = RuntimeQuadletDiagnostics.invoke(listOf("--dryrun"), root)
            assertEquals(0, result.exitCode)
            RuntimeQuadletDiagnostics.audit(spec, result.output)
            assertTrue(result.output.contains("---${RuntimeQuadlets.unit(spec, spec.processes.first())}.service---"))
        } finally { java.nio.file.Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(java.nio.file.Files::delete) } }
    }

    @Test fun `native generated start can satisfy installed unit policy only with an audited synthetic dropin`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val bundle = RuntimeQuadlets.render(spec)
        val root = java.nio.file.Files.createTempDirectory("quadlet-native-effective-")
        try {
            bundle.files.filterKeys { it.endsWith(".container") }.forEach { (name, text) ->
                java.nio.file.Files.writeString(root.resolve(name), text)
            }
            val generated = RuntimeQuadletDiagnostics.invoke(listOf("--dryrun"), root)
            assertEquals(0, generated.exitCode)
            for (p in listOf(spec.processes.single { it.id == "forgejo" },
                spec.processes.single { it.id == "forgejo-owner-init" })) {
                val unit = RuntimeQuadlets.unit(spec, p)
                val section = generated.output.substringAfter("---$unit.service---").substringBefore("\n---")
                val start = section.lines().single { it.startsWith("ExecStart=/usr/bin/podman ") }.substringAfter('=')
                val effective = RuntimeQuadletEffectiveAuditTest().show(spec, p, start)
                    .replace("Type=notify", if (p.oneShot) "Type=oneshot" else "Type=notify")
                val digest = RuntimeQuadletEffectiveAudit.audit(spec, bundle, p,
                    bundle.files.getValue("$unit.container").toByteArray(),
                    bundle.files.getValue("$unit.service.d/50-p0-lifecycle.conf").toByteArray(), effective,
                    RuntimeQuadletGeneratedStart.parse(spec, p, start))
                assertTrue(digest.matches(Regex("[a-f0-9]{64}")))
                if (p.oneShot) assertFails { RuntimeQuadletEffectiveAudit.audit(spec, bundle, p,
                    bundle.files.getValue("$unit.container").toByteArray(),
                    bundle.files.getValue("$unit.service.d/50-p0-lifecycle.conf").toByteArray(),
                    effective, RuntimeQuadletGeneratedStart.parse(spec, p,
                        start.replace("io.p0v3.initializer-intent=\${P0_INITIALIZER_INTENT}",
                            "io.p0v3.initializer-intent=unknown"))) }
            }
            // This is still synthetic systemctl output. An effective installed unit has not been inspected.
        } finally { java.nio.file.Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(java.nio.file.Files::delete) } }
    }
}
