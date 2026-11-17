package net.datamancy.platform

import java.nio.file.Files
import java.security.MessageDigest
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertEquals

class ManagedLaneRecoveryTest {
    private fun hash(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
        .joinToString("") { "%02x".format(it) }
    @Test fun offlineTargetProjectionIsDeterministicAndNeverReusesSourceAuthority(): Unit {
        val sourceGen = "q-012345abcdef"
        val targetGen = "q-123456abcdef"
        val laneId = UUID.randomUUID().toString()
        val session = "source-lane"
        val sourceRoot = "/sandbox/$sourceGen/managed"
        val original = """
            schema_version = 5
            id = "$laneId"
            name = "$session"
            container_name = "worklane-$session-$laneId"
            session_name = "$session"
            container_home = "/home/dev"
            profile_name = "v3"
            created_at = "2026-11-09T00:00:00Z"
            [profile]
            image = "localhost/worklane-v3@sha256:${"a".repeat(64)}"
            agent = "pi"
            terminal_backend = "tuios-v3"
            embedded_containerfile = false
            network = "none"
            runtime = "systemd"
            mount_codex_credentials = false
            mount_gh_credentials = false
            [[profile.mounts]]
            source = "$sourceRoot/control/run/broker.sock"
            target = "/run/worklane-pi/broker.sock"
            read_only = true
        """.trimIndent().toByteArray()
        val source = ManagedLanePlan(sourceGen, ManagedLaneKind.entries.map { kind ->
            ManagedLaneSpec(kind, laneId, "8d345319-3dbc-436e-a609-1584dd08ec35", session,
                "home", "home/workspace", if (kind == ManagedLaneKind.WORKLANE) 1024 else 0,
                if (kind == ManagedLaneKind.WORKLANE) 2048 else 0)
        }, ManagedLaneHostBinding(ActivationInput("/usr/local/bin/worklane", "b".repeat(64)),
            ActivationInput("/usr/bin/podman", "c".repeat(64)),
            ActivationInput("$sourceRoot/inputs/target-lane.toml", hash(original)),
            ActivationInput("$sourceRoot/control/storage.conf", "d".repeat(64)),
            ManagedBrokerServiceBinding("e".repeat(64), "f".repeat(64),
                ActivationInput("$sourceRoot/inputs/broker.json", "1".repeat(64)))))
        val image = ManagedLaneImageBinding(
            ActivationInput("/externally-verified/p0v3-worklane-v3.oci.tar", "f".repeat(64)),
            1048576, 2097152, "sha256:${"a".repeat(64)}", "localhost/worklane-v3@sha256:${"a".repeat(64)}",
            "sha256:${"a".repeat(64)}", listOf("sha256:${"b".repeat(64)}"))
        val first = ManagedLaneRecovery.projectPlan(source, targetGen, original, image)
        val second = ManagedLaneRecovery.projectPlan(source, targetGen, original, image)
        assertEquals(image, first.plan.native.imageArchive)
        assertEquals(first.plan, second.plan)
        assertTrue(first.targetManifestBytes.contentEquals(second.targetManifestBytes))
        assertTrue(first.plan.lanes.first().laneId != laneId && first.plan.lanes.first().session != session)
        assertFalse(first.targetManifestBytes.decodeToString().contains("worklane-$session-$laneId"))
        assertTrue(first.targetManifestBytes.decodeToString().contains("image = \"${image.expectedImageId}\""))
        assertTrue(first.targetManifestBytes.decodeToString().contains("image_digest = \"${image.expectedImageId}\""))
        assertFalse(first.targetManifestBytes.decodeToString().contains(image.sourceImageReference))
        assertFalse(first.targetManifestBytes.decodeToString().contains("$sourceRoot/control/run/broker.sock"))
        assertTrue(first.targetStorageConfigBytes.decodeToString().contains("$targetGen/managed/control/podman-graph"))
        val secondHop = ManagedLaneRecovery.projectPlan(first.plan, "q-abcdef123456", first.targetManifestBytes, image)
        assertTrue(secondHop.targetManifestBytes.decodeToString().contains("image = \"${image.expectedImageId}\""))
        val foreignBinding = image.copy(sourceImageReference = "foreign.example/other@sha256:${"a".repeat(64)}")
        assertFailsWith<IllegalArgumentException> {
            ManagedLaneRecovery.projectPlan(first.plan, "q-abcdef123456", first.targetManifestBytes, foreignBinding)
        }
        assertFailsWith<IllegalArgumentException> { ManagedLaneRecovery.projectPlan(source, sourceGen, original, image) }
        assertFailsWith<IllegalArgumentException> { ManagedLaneRecovery.projectPlan(source, targetGen,
            original.decodeToString().replace("network = \"none\"", "network = \"outbound\"").toByteArray(), image) }
        assertFailsWith<IllegalArgumentException> { ManagedLaneRecovery.projectPlan(source, targetGen, original,
            image.copy(sourceImageReference = "foreign.example/other@sha256:${"a".repeat(64)}")) }
    }
    @Test fun originalUnacknowledgedToolAttemptRemainsInertAcrossColdProjection(): Unit {
        val root = Files.createTempDirectory("managed-uncertain")
        try {
            val sessions = Files.createDirectories(root.resolve("sessions/--original-workspace--"))
            Files.writeString(sessions.resolve("original.jsonl"), listOf(
                """{"type":"message","message":{"role":"assistant","content":[{"type":"toolCall","id":"tool-lost-ack"},{"type":"toolCall","id":"tool-complete"}]}}""",
                """{"type":"message","message":{"role":"toolResult","toolCallId":"tool-complete","content":[]}}"""
            ).joinToString("\n", postfix = "\n"))
            assertEquals(listOf("tool-lost-ack"), ManagedLaneRecovery.originalUncertainToolCalls(root.resolve("sessions")))
            Files.createSymbolicLink(root.resolve("sessions/foreign"), root.resolve("sessions/--original-workspace--"))
            assertFailsWith<IllegalArgumentException> {
                ManagedLaneRecovery.originalUncertainToolCalls(root.resolve("sessions"))
            }
        } finally { Files.walk(root).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
    }
    @Test fun coldArchivePreservesOriginalTranscriptButExcludesLiveAuthority(): Unit {
        val root = Files.createTempDirectory("managed-cold-tar")
        try {
            val source = Files.createDirectories(root.resolve("source"))
            val history = Files.createDirectories(source.resolve(".pi/agent/sessions"))
            val content = "{\"type\":\"message\",\"historical\":true}\n".toByteArray()
            Files.write(history.resolve("original.jsonl"), content)
            Files.createDirectories(source.resolve(".worklane"))
            Files.writeString(source.resolve(".worklane/lane.toml"), "historical source identity")
            Files.writeString(source.resolve(".pi/agent/auth.json"), "never capture live Pi credential")
            Files.writeString(source.resolve(".bashrc"), "original shell preferences")
            Files.writeString(source.resolve(".profile"), "original profile")
            Files.createDirectories(source.resolve(".cache"))
            Files.writeString(source.resolve(".cache/historical-note"), "original user cache")
            val workspace = Files.createDirectories(source.resolve("workspace"))
            Files.writeString(workspace.resolve("user.txt"), "workspace is its own archive")
            Files.writeString(workspace.resolve("auth.json"), "ordinary project data, NOT Pi credentials")
            val git = Files.createDirectories(workspace.resolve("project/.git"))
            Files.writeString(git.resolve("HEAD"), "ref: refs/heads/main\\n")
            val descriptor = ManagedLaneRecovery.exportTar(source, root.resolve("home.tar"),
                "home", System.currentTimeMillis() + 300000, 64L * 1024 * 1024)
            val workspaceArchive = ManagedLaneRecovery.exportTar(workspace, root.resolve("workspace.tar"),
                "workspace", System.currentTimeMillis() + 300000, 64L * 1024 * 1024)
            val sessions = ManagedLaneRecovery.exportTar(history, root.resolve("transcripts.tar"),
                "transcripts", System.currentTimeMillis() + 300000, 64L * 1024 * 1024)
            assertTrue(descriptor.sha256.matches(Regex("[a-f0-9]{64}")) &&
                sessions.sha256.matches(Regex("[a-f0-9]{64}")))
            val entries = VolumeTar.inspect(root.resolve("home.tar"), com.sun.security.auth.module.UnixSystem().uid.toInt())
            val transcriptEntries = VolumeTar.inspect(root.resolve("transcripts.tar"),
                com.sun.security.auth.module.UnixSystem().uid.toInt())
            assertTrue(transcriptEntries.any { it.path == "original.jsonl" && it.sha256 == hash(content) })
            assertFalse(entries.any { it.path == ".pi/agent/auth.json" || it.path.endsWith("lane.toml") ||
                it.path.startsWith("workspace") || it.path.startsWith(".pi/agent/sessions") })
            assertTrue(entries.any { it.path == ".bashrc" } && entries.any { it.path == ".profile" } &&
                entries.any { it.path == ".cache/historical-note" })
            val workspaceEntries = VolumeTar.inspect(root.resolve("workspace.tar"),
                com.sun.security.auth.module.UnixSystem().uid.toInt())
            assertTrue(workspaceArchive.bytes > 1024 &&
                workspaceEntries.any { it.path == "auth.json" } &&
                workspaceEntries.any { it.path == "project/.git/HEAD" })
            ManagedLaneRecovery.importTar(root.resolve("home.tar"), root.resolve("target"),
                root.resolve("readback.tar"), "home", System.currentTimeMillis() + 300000, 64L * 1024 * 1024)
            ManagedLaneRecovery.importTar(root.resolve("workspace.tar"), root.resolve("target/workspace"),
                root.resolve("readback-workspace.tar"), "workspace", System.currentTimeMillis() + 300000,
                64L * 1024 * 1024)
            ManagedLaneRecovery.importTar(root.resolve("transcripts.tar"), root.resolve("target/.pi/agent/sessions"),
                root.resolve("readback-transcripts.tar"), "transcripts", System.currentTimeMillis() + 300000,
                64L * 1024 * 1024)
            assertTrue(Files.readAllBytes(root.resolve("target/.pi/agent/sessions/original.jsonl")).contentEquals(content))
            assertTrue(Files.readString(root.resolve("target/workspace/auth.json")).startsWith("ordinary project") &&
                Files.readString(root.resolve("target/workspace/project/.git/HEAD")).startsWith("ref:"))
            assertFalse(Files.exists(root.resolve("target/.pi/agent/auth.json")))
        } finally { Files.walk(root).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
    }
    @Test fun exactLiveAuthorityExclusionsNeverEraseOrdinaryHomeOrGit(): Unit {
        for (path in listOf("home/.pi/agent/auth.json", "home/.pi/agent/auth.json.lock",
                "home/.worklane/lane.toml", "home/run/worklane-pi/broker.sock",
                "home/.local/share/worklane/agent-work/p0v3-live.md",
                "manifests/v3-pi-process", "manifests/v3-pi-process/lane.credential.json",
                "manifests/v3-pi-process/lane.bridge.json"))
            assertFalse(ManagedLaneRecovery.allowedPath(path))
        for (path in listOf("home/.bashrc", "home/.profile", "home/.cache/historical-note",
                "home/.git/HEAD", "workspace/project/.git/config", "workspace/auth.json",
                "workspace/runtime.json", "workspace/subproject/proof.json",
                "manifests/worklane-v5.db", "manifests/nonsecret-lane.json"))
            assertTrue(ManagedLaneRecovery.allowedPath(path))
        for (path in listOf("home/../run/secret", "workspace//empty", "home/absolute\\npath"))
            assertFalse(ManagedLaneRecovery.allowedPath(path))
    }
    @Test fun historicalBytesRemainInertAndNewIdentityRequired(): Unit {
        val root = Files.createTempDirectory("managed-projection")
        try {
            val home = Files.createDirectories(root.resolve("home/workspace"))
            val bytes = "original source oracle, not recreated".toByteArray()
            Files.write(home.resolve("original.txt"), bytes)
            val source = ManagedLaneSourceOracle("q-012345abcdef", UUID.randomUUID().toString(), "a".repeat(64),
                mapOf("home/workspace/original.txt" to hash(bytes)), listOf("tool-uncertain"), "source-session")
            val target = ManagedLaneRecovery.project(source, "q-123456abcdef", UUID.randomUUID().toString(), "target-session")
            assertFalse(target.toolReplayPermitted)
            assertFalse(target.sourceIdentityAdopted)
            ManagedLaneRecovery.verifyOriginal(target, root)
            Files.write(home.resolve("original.txt"), "changed".toByteArray())
            assertFailsWith<IllegalArgumentException> { ManagedLaneRecovery.verifyOriginal(target, root) }
            assertFailsWith<IllegalArgumentException> {
                ManagedLaneRecovery.project(source.copy(paths = mapOf("home/.pi/agent/auth.json" to hash(bytes))),
                    "q-123456abcdef", UUID.randomUUID().toString(), "target-session")
            }
            assertFailsWith<IllegalArgumentException> {
                ManagedLaneRecovery.project(source, source.sourceGeneration, UUID.randomUUID().toString(), "target-session")
            }
        } finally { Files.walk(root).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
    }
}
