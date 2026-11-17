package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.security.MessageDigest
import java.util.zip.GZIPOutputStream
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import java.util.TreeMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

class ManagedLaneRuntimeTest {
    private fun tar(entries: List<Pair<String, ByteArray>>, kinds: Map<String, Char> = emptyMap()): ByteArray {
        val output = ByteArrayOutputStream()
        for ((path, data) in entries) {
            val header = ByteArray(512)
            path.toByteArray().copyInto(header)
            fun octal(at: Int, width: Int, value: Long) {
                value.toString(8).padStart(width - 1, '0').toByteArray().copyInto(header, at)
            }
            octal(100, 8, 420); octal(108, 8, 0); octal(116, 8, 0)
            octal(124, 12, data.size.toLong()); octal(136, 12, 0)
            "ustar".toByteArray().copyInto(header, 257)
            "00".toByteArray().copyInto(header, 263)
            header[156] = (kinds[path] ?: '0').code.toByte()
            for (i in 148..155) header[i] = 32
            val sum = header.sumOf { it.toInt() and 255 }
            octal(148, 8, sum.toLong())
            output.write(header); output.write(data)
            output.write(ByteArray((512 - (data.size % 512)) % 512))
        }
        output.write(ByteArray(1024))
        return output.toByteArray()
    }
    private fun plan(): ManagedLanePlan {
        val id = UUID.randomUUID().toString()
        val generation = "q-012345abcdef"
        val native = ManagedLaneHostBinding(ActivationInput("/usr/local/bin/worklane", "a".repeat(64)),
            ActivationInput("/usr/bin/podman", "b".repeat(64)),
            ActivationInput("/sandbox/$generation/managed/inputs/target-lane.toml", "c".repeat(64)),
            ActivationInput("/sandbox/$generation/managed/control/storage.conf", "d".repeat(64)),
            ManagedBrokerServiceBinding("e".repeat(64), "1".repeat(64),
                ActivationInput("/sandbox/$generation/managed/inputs/broker.json", "f".repeat(64))))
        return ManagedLanePlan(generation, ManagedLaneKind.entries.map { kind ->
            ManagedLaneSpec(kind, id, "8d345319-3dbc-436e-a609-1584dd08ec35", "managed-lane", "home", "home/workspace",
                if (kind == ManagedLaneKind.WORKLANE) 512 else 0,
                if (kind == ManagedLaneKind.WORKLANE) 1024 else 0)
        }, native)
    }
    @Test fun `fresh human owner maps to managed Pi lane without becoming its service principal`() {
        val base = plan()
        val owner = "a5e2cab1-851b-49fe-8f14-6b40f8712447"
        base.copy(ownerSubject = owner).validate(base.generation)
        assertFailsWith<IllegalArgumentException> {
            base.copy(ownerSubject = base.lanes.single { it.kind == ManagedLaneKind.PI }.subject)
                .validate(base.generation)
        }
        assertFailsWith<IllegalArgumentException> { base.copy(ownerSubject = "legacy-user").validate(base.generation) }
    }

    @Test fun sharedPhysicalResourceAndNoCallerHooks(): Unit {
        val plan = plan()
        plan.validate("q-012345abcdef")
        assertEquals(768L, plan.memoryReservationMiB)
        assertEquals(1152L, plan.diskReservationMiB)
        assertEquals(320L, plan.pidsReservation)
        assertEquals(setOf("worklane", "tuios", "pi"), plan.capabilities)
        assertFailsWith<IllegalArgumentException> { plan.validate("q-987654abcdef") }
        assertFailsWith<IllegalArgumentException> {
            plan.copy(lanes = plan.lanes.map { it.copy(home = "/run/secrets") }).validate(plan.generation)
        }
        assertFailsWith<IllegalArgumentException> {
            plan.copy(lanes = plan.lanes.map { it.copy(memoryMiB = 512) }).validate(plan.generation)
        }
    }
    @Test fun prepareIsolationRequiresNativeFreshPodmanGraphNotRegistryOnly(): Unit {
        val cold = Json.parseToJsonElement("""{"state":"created"}""").jsonObject
        val actualImport = Json.parseToJsonElement("""{"state":"absent"}""").jsonObject
        val running = Json.parseToJsonElement("""{"state":"running"}""").jsonObject
        val unknown = Json.parseToJsonElement("""{"state":"unknown"}""").jsonObject
        val noContainers = Json.parseToJsonElement("[]").jsonArray
        val staleContainer = Json.parseToJsonElement("""[{"Names":["managed-stale"],"State":"running"}]""").jsonArray
        assertTrue(managedPrepareNativeIsolation(cold, noContainers))
        assertTrue(managedPrepareNativeIsolation(actualImport, noContainers))
        assertFalse(managedPrepareNativeIsolation(running, noContainers))
        assertFalse(managedPrepareNativeIsolation(unknown, noContainers))
        assertFalse(managedPrepareNativeIsolation(actualImport, staleContainer))
        assertFalse(managedPrepareNativeIsolation(cold, staleContainer))
        assertFalse(managedPrepareNativeIsolation(running, staleContainer))
    }
    @Test fun managedImportReadsOnlyRecoverySegmentsLogicalComponentTreeWithoutFlatDuplicate(): Unit {
        val transfer = Files.createTempDirectory("managed-logical-import")
        try {
            val component = transfer.resolve("home")
            Files.createDirectory(component)
            val logical = component.resolve("tree.tar")
            Files.write(logical, tar(listOf("source.txt" to "original bytes".toByteArray())))
            assertEquals(logical, managedLogicalImportArchive(transfer, "home"))
            Files.write(transfer.resolve("home.tar"), Files.readAllBytes(logical))
            Files.delete(logical)
            assertFailsWith<java.nio.file.NoSuchFileException> {
                managedLogicalImportArchive(transfer, "home") // Flat CAPTURE layout cannot bypass logical IMPORT.
            }
            Files.createSymbolicLink(logical, transfer.resolve("home.tar"))
            assertFailsWith<IllegalArgumentException> { managedLogicalImportArchive(transfer, "home") }
            assertFailsWith<IllegalArgumentException> { managedLogicalImportArchive(transfer, "../home") }
        } finally {
            Files.walk(transfer).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }
    @Test fun historicalIntentBytesDefaultOmitNewAggregateReleaseLimit(): Unit {
        val old = ManagedLaneIntent("q-012345abcdef", UUID.randomUUID().toString(),
            ManagedLaneOperation.PREPARE, "old-operation", "a".repeat(64))
        val bytes = Json { encodeDefaults = true }.encodeToString(old)
        assertFalse("maximumBytes" in bytes)
        val historicalPlan = plan()
        assertFalse("imageArchive" in Json { encodeDefaults = true }.encodeToString(historicalPlan))
        assertFailsWith<IllegalArgumentException> {
            ManagedLaneRuntime.real(Path.of("/sandbox/${historicalPlan.generation}"), historicalPlan)
        }
        val image = ManagedLaneImageBinding(ActivationInput("/verified-assets/worklane-v3.oci.tar",
            "9".repeat(64)), 1048576, 2097152, "sha256:${"8".repeat(64)}",
            "localhost/worklane-v3@sha256:${"7".repeat(64)}", "sha256:${"7".repeat(64)}",
            listOf("sha256:${"6".repeat(64)}"))
        val withImage = historicalPlan.copy(native = historicalPlan.native.copy(imageArchive = image))
        withImage.validate(historicalPlan.generation)
        assertEquals(historicalPlan.diskReservationMiB + 3, withImage.diskReservationMiB)
        assertTrue("imageArchive" in Json { encodeDefaults = true }.encodeToString(withImage))
        assertTrue("\"sourceCaptureSha256\":null" in bytes)
        assertTrue("\"deadlineEpochMillis\":null" in bytes)
        val captured = old.copy(operation = ManagedLaneOperation.CAPTURE,
            maximumBytes = ManagedLaneRecovery.METADATA_RESERVE_BYTES + 4096)
        assertTrue("\"maximumBytes\":${captured.maximumBytes}" in Json { encodeDefaults = true }.encodeToString(captured))
    }
    @Test fun uncertainEffectRetainsIntentAndNeverRetries(): Unit {
        val root = Files.createTempDirectory("managed-uncertain")
        try {
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
            val plan = plan()
            plan.lanes.forEach { Files.createDirectory(root.resolve(it.kind.name.lowercase()),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))) }
            val lane = plan.lanes[0]
            val backend = object : ManagedLaneBackend {
                override fun prepare(lane: ManagedLaneSpec, root: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence {
                    error("lost acknowledgement")
                }
                override fun start(lane: ManagedLaneSpec, root: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence = error("unexpected")
                override fun isolate(lane: ManagedLaneSpec, root: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence = error("unexpected")
                override fun capture(lane: ManagedLaneSpec, root: Path, destination: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence = error("unexpected")
                override fun import(lane: ManagedLaneSpec, root: Path, projection: Path, intent: ManagedLaneIntent, intentHash: String): ManagedLaneEvidence = error("unexpected")
                override fun attest(lane: ManagedLaneSpec, root: Path, evidence: ManagedLaneEvidence): ManagedLaneEvidence = error("unexpected")
            }
            val runtime = ManagedLaneRuntime(root, plan, backend)
            val transfer = root.resolve("original-capture")
            val deadline = System.currentTimeMillis() + 3600000
            assertFailsWith<IllegalArgumentException> {
                runtime.operate(lane, ManagedLaneOperation.CAPTURE, "budget-missing",
                    transfer = transfer, deadlineEpochMillis = deadline)
            }
            assertFailsWith<IllegalArgumentException> {
                runtime.operate(lane, ManagedLaneOperation.CAPTURE, "budget-too-small",
                    transfer = transfer, deadlineEpochMillis = deadline,
                    maximumBytes = ManagedLaneRecovery.METADATA_RESERVE_BYTES)
            }
            assertFalse(Files.exists(root.resolve("worklane/capture-budget-missing.intent.json")))
            assertFalse(Files.exists(root.resolve("worklane/capture-budget-too-small.intent.json")))
            assertFailsWith<IllegalStateException> { runtime.operate(lane, ManagedLaneOperation.PREPARE, "attempt-1") }
            assertTrue(Files.exists(root.resolve("worklane/prepare-attempt-1.intent.json")))
            assertFalse(Files.exists(root.resolve("worklane/prepare-attempt-1.result.json")))
            assertFailsWith<IllegalArgumentException> { runtime.operate(lane, ManagedLaneOperation.PREPARE, "attempt-1") }
        } finally {
            Files.walk(root).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test fun standardMetadataOnlyOciTarRootIsNotTraversableAndStillCountsOnlyRealFiles(): Unit {
        val root = tar(listOf("." to byteArrayOf(), "app.bin" to ByteArray(1024) { 4 }),
            mapOf("." to '5'))
        val tree = TreeMap<String, Long>()
        val census=ManagedLaneOciArchive.censusLayer(ByteArrayInputStream(root),
            MessageDigest.getInstance("SHA-256"),tree,0,4096,10485760,System.currentTimeMillis()+60000)
        assertEquals(root.size.toLong(),census.first)
        assertTrue("app.bin" in tree)
        assertFalse("." in tree)
        val traversal=tar(listOf("." to byteArrayOf(), "../escape" to byteArrayOf(1)),mapOf("." to '5'))
        assertFailsWith<IllegalArgumentException> {
            ManagedLaneOciArchive.censusLayer(ByteArrayInputStream(traversal),
                MessageDigest.getInstance("SHA-256"),TreeMap(),0,4096,10485760,System.currentTimeMillis()+60000)
        }
    }
    @Test fun originalOciPaxLongPathsAndWhiteoutKeepExactLayeredVfsBound(): Unit {
        fun paxRecord(key: String, value: String): ByteArray {
            val content = "$key=$value\n"
            var length = content.length + 2
            while (true) {
                val next = length.toString().length + 1 + content.toByteArray().size
                if (next == length) return "$length $content".toByteArray()
                length = next
            }
        }
        val original = tar(listOf("original.bin" to ByteArray(2048) { 9 }))
        val tree = TreeMap<String, Long>()
        val deadline = System.currentTimeMillis() + 60000
        val hash = MessageDigest.getInstance("SHA-256")
        val first = ManagedLaneOciArchive.censusLayer(ByteArrayInputStream(original), hash,
            tree, 0, 4096, 10485760, deadline)
        assertTrue(first.first == original.size.toLong() && first.second > 2048)
        val longPath = "workspace/" + "original-".repeat(20) + "name.bin"
        val second = tar(listOf("PaxHeaders.0" to paxRecord("path", longPath),
            "short.bin" to ByteArray(1024) { 7 }, ".wh.original.bin" to byteArrayOf()),
            mapOf("PaxHeaders.0" to 'x'))
        val next = ManagedLaneOciArchive.censusLayer(ByteArrayInputStream(second),
            MessageDigest.getInstance("SHA-256"), tree, first.second, 4096, 10485760, deadline)
        assertTrue(next.first == second.size.toLong() && next.second > 1024)
        assertFalse("original.bin" in tree)
        assertTrue(longPath in tree)
        val invalidSize = tar(listOf("PaxHeaders.0" to paxRecord("size", "not-a-decimal"),
            "short.bin" to byteArrayOf()), mapOf("PaxHeaders.0" to 'x'))
        assertFailsWith<IllegalArgumentException> {
            ManagedLaneOciArchive.censusLayer(ByteArrayInputStream(invalidSize),
                MessageDigest.getInstance("SHA-256"), TreeMap(), 0, 4096, 10485760, deadline)
        }
        val unsafeLink = tar(listOf("PaxHeaders.0" to paxRecord("linkpath", "../../escape"),
            "short.bin" to byteArrayOf()), mapOf("PaxHeaders.0" to 'x', "short.bin" to '2'))
        assertFailsWith<IllegalArgumentException> {
            ManagedLaneOciArchive.censusLayer(ByteArrayInputStream(unsafeLink),
                MessageDigest.getInstance("SHA-256"), TreeMap(), 0, 4096, 10485760, deadline)
        }
        val imageRootAbsolute = tar(listOf("PaxHeaders.0" to paxRecord("linkpath", "/usr/bin/node"),
            "etc/alternatives/node" to byteArrayOf()),
            mapOf("PaxHeaders.0" to 'x', "etc/alternatives/node" to '2'))
        ManagedLaneOciArchive.censusLayer(ByteArrayInputStream(imageRootAbsolute),
            MessageDigest.getInstance("SHA-256"), TreeMap(), 0, 4096, 10485760, deadline)
        val safeParent = tar(listOf("PaxHeaders.0" to paxRecord("linkpath", "../lib/node"),
            "usr/bin/node" to byteArrayOf()), mapOf("PaxHeaders.0" to 'x', "usr/bin/node" to '2'))
        ManagedLaneOciArchive.censusLayer(ByteArrayInputStream(safeParent),
            MessageDigest.getInstance("SHA-256"), TreeMap(), 0, 4096, 10485760, deadline)
        val parentEscape = tar(listOf("PaxHeaders.0" to paxRecord("linkpath", "../../../../host"),
            "usr/bin/node" to byteArrayOf()), mapOf("PaxHeaders.0" to 'x', "usr/bin/node" to '2'))
        assertFailsWith<IllegalArgumentException> {
            ManagedLaneOciArchive.censusLayer(ByteArrayInputStream(parentEscape),
                MessageDigest.getInstance("SHA-256"), TreeMap(), 0, 4096, 10485760, deadline)
        }
        val sparse = tar(listOf("PaxHeaders.0" to paxRecord("GNU.sparse.realsize", "1073741824"),
            "short.bin" to byteArrayOf()), mapOf("PaxHeaders.0" to 'x'))
        assertFailsWith<IllegalArgumentException> {
            ManagedLaneOciArchive.censusLayer(ByteArrayInputStream(sparse),
                MessageDigest.getInstance("SHA-256"), TreeMap(), 0, 4096, 10485760, deadline)
        }
    }

    @Test fun pinnedOciLayerCensusMustBoundVfsBeforeAnyNativeImageLoad(): Unit {
        fun sha(data: ByteArray): String = "sha256:" + MessageDigest.getInstance("SHA-256")
            .digest(data).joinToString("") { "%02x".format(it) }
        val rawLayer = ByteArray(1024)
        val compressed = ByteArrayOutputStream().also { GZIPOutputStream(it).use { gzip -> gzip.write(rawLayer) } }.toByteArray()
        val layerDigest = sha(compressed)
        val config = """{"os":"linux","architecture":"amd64","rootfs":{"type":"layers","diff_ids":["${sha(rawLayer)}"]}}""".toByteArray()
        val configDigest = sha(config)
        val manifest = """{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"$configDigest","size":${config.size}},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"$layerDigest","size":${compressed.size}}]}""".toByteArray()
        val manifestDigest = sha(manifest)
        val index = """{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"$manifestDigest","size":${manifest.size},"platform":{"os":"linux","architecture":"amd64"}}]}""".toByteArray()
        val archive = tar(listOf("oci-layout" to """{"imageLayoutVersion":"1.0.0"}""".toByteArray(),
            "index.json" to index,
            "blobs/sha256/${configDigest.removePrefix("sha256:")}" to config,
            "blobs/sha256/${manifestDigest.removePrefix("sha256:")}" to manifest,
            "blobs/sha256/${layerDigest.removePrefix("sha256:")}" to compressed))
        val file = Files.createTempFile("managed-local-oci", ".tar")
        try {
            Files.write(file, archive)
            // The complete uncompressed scratch must be reserved BEFORE native load.
            val floor = 512L * 1024 * 1024 + archive.size + rawLayer.size
            val pinned = ManagedLaneImageBinding(ActivationInput(file.toString(), sha(archive).removePrefix("sha256:")),
                archive.size.toLong(), floor, configDigest,
                "localhost/worklane-v3@$manifestDigest", manifestDigest, listOf(sha(rawLayer)))
            val deadline = System.currentTimeMillis() + 60000
            ManagedLaneOciArchive.inspect(file, pinned, deadline) // Pure source fixture; never starts Podman.
            assertFailsWith<IllegalArgumentException> {
                ManagedLaneOciArchive.inspect(file, pinned.copy(maximumUnpackedBytes = floor - 1), deadline)
            }
            assertFailsWith<IllegalArgumentException> {
                ManagedLaneOciArchive.inspect(file, pinned.copy(expectedManifestDigest = sha(index)), deadline)
            }
            assertFailsWith<IllegalArgumentException> {
                ManagedLaneOciArchive.inspect(file, pinned.copy(expectedLayerDiffIds = listOf(sha(manifest))), deadline)
            }
        } finally { Files.deleteIfExists(file) }
    }
}
