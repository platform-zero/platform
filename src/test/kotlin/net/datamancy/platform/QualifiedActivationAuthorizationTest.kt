package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

/** Synthetic verifier responses and local subprocess fixtures only; no deployed controller or service invoked. */
class QualifiedActivationAuthorizationTest {
    private val json = Json { encodeDefaults = true }
    private val h = "a".repeat(64)
    private val deployment = ReleaseDeploymentBinding("q-abcdef123456", h, h, "b".repeat(64))
    private fun temporary(action: (Path) -> Unit) {
        val root = Files.createTempDirectory("authority-unit-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try { action(root) } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `distinct signed legacy bootstrap has no invented consumed permit`(): Unit {
        val source = ReleaseGeneration("q-111111111111", "a".repeat(64))
        val pin = ActivationInput("/mnt/media/p0-v3/release-bootstrap-anchors/unit.anchor.json", "b".repeat(64))
        val bootstrap = ActiveSiteBootstrap(approval = pin,
            signature = pin.copy(path = "/mnt/media/p0-v3/release-bootstrap-anchors/unit.anchor.sig"),
            nativeInspection = pin.copy(path = "/mnt/media/p0-v3/release-bootstrap-anchors/unit.native.json"),
            routeObservation = pin.copy(path = "/mnt/media/p0-v3/release-bootstrap-anchors/unit.route.json"),
            source = source, siteId = "unit", hosts = listOf("boards.datamancy.net"), sitePolicySha256 = h)
        val bytes = json.encodeToString(bootstrap)
        assertFalse(bytes.contains("consumedPermitSha256"))
        assertFalse(bytes.contains("qualificationSnapshotId"))
        assertFails { json.decodeFromString<ActiveSiteSelection>(bytes) }
        assertEquals(bootstrap, json.decodeFromString<ActiveSiteBootstrap>(bytes))
        val selected = ActiveSiteSelection(ordinal = 1, siteId = "unit", hosts = bootstrap.hosts,
            deployment = ReleaseDeploymentBinding(source.id, source.bundleSha256, h, h),
            previousHeadSha256 = h, source = source, transactionId = "unit", activationJournalHead = h,
            consumedPermitSha256 = h, consumptionSha256 = h,
            qualificationSnapshotId = "cap-111111111111", selectedTrialId = "trial-two")
        assertFalse(json.encodeToString(selected).contains("fresh"), "Historical selection bytes stay default-omitted")
    }
    @Test fun `missing independently pinned original registry cannot be created by read-only site admission`(): Unit = temporary { root ->
        val registryRoot = root.resolve("active-sites") // Missing on purpose: never create from a caller claim.
        val transaction = root.resolve("transaction.jsonl")
        val source = ReleaseGeneration("q-111111111111", "a".repeat(64))
        val consumed = Path.of("/mnt/media/p0-v3/release-activation-consumptions/q-abcdef123456.consumed.json")
        val registry = ActiveSiteRegistry(registryRoot, transaction, "unit", setOf("boards.datamancy.net"), source, consumed)
        assertFails { registry.admitOriginal(deployment) }
        assertFails { registry.requireCommitted(deployment, requireCompleted = true) }
        assertFalse(Files.exists(registryRoot))
    }
    private inner class Fixture(val root: Path) {
        private fun input(name: String, text: String): ActivationInput {
            val path = root.resolve(name); ReleasePrivateFiles.save(path, text.toByteArray()); return ActivationInput(path.toString(), ReleaseLocks.sha256(text.toByteArray()))
        }
        val artifacts = input("artifacts", json.encodeToString(ActivationArtifactClosure(controllers = mapOf("platform" to h, "acceptance" to h),
            images = mapOf("unit" to ActivationImagePin("example.test/app@sha256:$h", h)), assets = emptyMap())))
        val candidate = buildJsonObject {
            for (field in listOf("implementationSha256", "artifactsSha256", "configurationSha256", "acceptanceSha256", "sitePolicySha256"))
                put(field, if (field == "artifactsSha256") artifacts.sha256 else h)
        }
        val evidence = ActivationEvidenceBinding(input("inventory", "{}"), input("manifest", "{}"), input("candidate", candidate.toString()), artifacts,
            root.resolve("qualification.jsonl").toString(), h, h)
        val journal = root.resolve("transaction.jsonl")
        val binding: ReleaseActivationBinding
        var controllerChecks = 0
        var liveChecks = 0
        var changedLive = false
        var changedController = false
        var mode = ""
        var calls = mutableListOf<String>()
        init {
            TransactionJournal.append(journal, "activation-unit", h, Phase.PREPARED, null, null, deployment)
            for (phase in listOf(Phase.FROZEN, Phase.SNAPSHOT_VERIFIED, Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED))
                TransactionJournal.appendExisting(journal, phase, if (phase == Phase.FROZEN) null else "cap-000000000002")
            binding = ReleaseActivationBinding("activation-unit", h, TransactionJournal.verify(journal).last().hash, deployment)
        }
        fun permit(binding: JsonElement) = buildJsonObject {
            put("schemaVersion", 1); put("binding", binding); put("candidate", candidate); put("qualificationHead", h)
            put("secondTrialId", "trial-2"); put("snapshotId", "cap-000000000002")
            put("evaluationHashes", buildJsonObject { put("trial-1", h); put("trial-2", h) })
        }
        val process = AcceptanceControllerProcess { args, directory ->
            assertEquals(root, directory); assertEquals(root.resolve("pinned/bin/p0-v3-acceptance").toString(), args.first())
            calls += args[1]
            if (mode == "exit") return@AcceptanceControllerProcess RuntimeCommandResult(1, "synthetic refusal")
            if (mode == "malformed") return@AcceptanceControllerProcess RuntimeCommandResult(0, "{}")
            val permit = permit(Json.parseToJsonElement(args[7]))
            if (args[1] == "activation-verify") return@AcceptanceControllerProcess RuntimeCommandResult(0, permit.toString())
            assertEquals("activation-consume", args[1]); assertEquals(ReleaseLocks.sha256(permit.toString().toByteArray()), args[8])
            val claim = ReleasePrivateFiles.read(journal)
            assertEquals(ReleaseLocks.sha256(claim), args[10]); assertEquals(root.toString(), args[11])
            val receipt = buildJsonObject {
                put("schemaVersion", 1); put("generation", deployment.generationId); put("permitSha256", args[8])
                put("activationJournalHead", TransactionJournal.verify(journal).last().hash); put("qualificationHead", h); put("claimJournalSha256", args[10])
            }
            if (mode != "no-persistence") ReleasePrivateFiles.save(root.resolve("${deployment.generationId}.consumed.json"), buildJsonObject {
                put("permit", permit); put("consumption", receipt); put("claimJournal", claim.decodeToString())
            }.toString().toByteArray())
            if (mode == "lost-consume-ack") error("Synthetic lost acknowledgement")
            RuntimeCommandResult(0, if (mode == "foreign-receipt") "{}" else receipt.toString())
        }
        fun authority(binding: ActivationEvidenceBinding = evidence) = QualifiedActivationAuthorization(binding, journal, root, root.resolve("pinned"),
            { controllerChecks++; check(!changedController) }, { actual, identity -> liveChecks++; assertEquals(deployment, actual); assertEquals(candidate, identity); check(!changedLive) }, process)
        fun claim(permit: String) = TransactionJournal.appendExisting(journal, Phase.ACTIVATION_STARTED, "cap-000000000002", binding.acceptedJournalHead, permit).hash
    }
    @Test fun `production bridge rechecks pinned inputs controller live binding and durable single use before returning`(): Unit = temporary { root ->
        val f = Fixture(root); val authority = f.authority()
        assertFails { f.authority(f.evidence.copy(acceptanceControllerSha256 = "b".repeat(64))).verify(f.binding) }
        val permit = authority.verify(f.binding); val claim = f.claim(permit)
        authority.consume(f.binding, permit, claim)
        assertEquals(listOf("activation-verify", "activation-verify", "activation-consume"), f.calls)
        assertEquals(2, f.liveChecks); assertEquals(3, f.controllerChecks)
        assertFails { authority.consume(f.binding, permit, claim) }
        assertFails { authority.verify(f.binding) }
        assertEquals(Phase.ACTIVATION_STARTED, TransactionJournal.verify(f.journal).last().phase) // Authority does not commit or open writes.
    }
    @Test fun `stale transaction changed controller live bindings definitions and foreign responses refuse authorization`(): Unit {
        for (failure in listOf("head", "controller", "live", "input", "exit", "malformed")) temporary { root ->
            val f = Fixture(root); val authority = f.authority()
            when (failure) {
                "controller" -> f.changedController = true
                "live" -> f.changedLive = true
                "input" -> Files.writeString(Path.of(f.evidence.manifest.path), "changed")
                else -> f.mode = failure
            }
            assertFails { authority.verify(if (failure == "head") f.binding.copy(acceptedJournalHead = "b".repeat(64)) else f.binding) }
            assertFalse(Files.exists(root.resolve("${deployment.generationId}.consumed.json")))
        }
    }
    @Test fun `consumption never trusts acknowledgements without durable exact receipt and never replays unknown effects`(): Unit {
        for (mode in listOf("no-persistence", "foreign-receipt", "lost-consume-ack", "live")) temporary { root ->
            val f = Fixture(root); val authority = f.authority(); val permit = authority.verify(f.binding); val claim = f.claim(permit)
            assertFails { authority.consume(f.binding, "b".repeat(64), claim) }
            assertFails { authority.consume(f.binding, permit, "b".repeat(64)) }
            f.mode = mode; f.changedLive = mode == "live"
            assertFails { authority.consume(f.binding, permit, claim) }
            assertEquals(Phase.ACTIVATION_STARTED, TransactionJournal.verify(f.journal).last().phase)
            // Even without a receipt, the transaction claim prevents entering activation again.
            assertFails { authority.verify(f.binding) }
        }
    }
    @Test fun `local verifier subprocess is bounded and uses a clean environment`(): Unit = temporary { root ->
        fun script(name: String, text: String): Path {
            val path = root.resolve(name); Files.writeString(path, "#!/bin/sh\n$text\n")
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------")); return path
        }
        val good = script("unit-ok", "printf '%s' \"\$JAVA_HOME:\$HOME:\${JAVA_TOOL_OPTIONS-unset}\"")
        val result = LocalAcceptanceControllerProcess().run(listOf(good.toString()), root)
        assertEquals(0, result.exitCode); assertEquals("/usr/lib/jvm/java-21-openjdk-amd64:$root:unset", result.output)
        val empty = script("unit-fail", "exit 7")
        assertEquals(7, LocalAcceptanceControllerProcess().run(listOf(empty.toString()), root).exitCode)
        val slow = script("unit-slow", "exec /bin/sleep 5")
        assertFails { LocalAcceptanceControllerProcess(10).run(listOf(slow.toString()), root) }
        Thread.currentThread().interrupt()
        try { assertFailsWith<InterruptedException> { LocalAcceptanceControllerProcess().run(listOf(slow.toString()), root) }; assertTrue(Thread.currentThread().isInterrupted) }
        finally { Thread.interrupted() }
        val excessive = script("unit-excess", "/usr/bin/head -c 4194305 /dev/zero")
        assertFails { LocalAcceptanceControllerProcess().run(listOf(excessive.toString()), root) }
        assertFails { LocalAcceptanceControllerProcess(0).run(listOf(good.toString()), root) }
    }
}
