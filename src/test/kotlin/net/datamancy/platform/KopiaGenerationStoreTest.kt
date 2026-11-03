package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class KopiaGenerationStoreTest {
    private val image = AcquiredImage("kopia", "unit", "unit", "example.test/kopia@sha256:" + "a".repeat(64), "b".repeat(64), emptyList(), "sha256:" + "a".repeat(64), "amd64", "linux")
    private val generation = "q-123456789abc"
    private val cap = "cap-abcdef123456"
    private val native = """{"id":"${"c".repeat(32)}","source":{"host":"$generation","userName":"p0v3","path":"/source"},"rootEntry":{"type":"d","obj":"k${"d".repeat(40)}","summ":{"files":2,"size":1024,"dirs":2,"symlinks":0,"numFailed":0}}}"""
    private class Fake(val native: String) : RuntimeCommands {
        val calls = mutableListOf<List<String>>()
        var failPhase: String? = null
        var timeoutPhase: String? = null
        var badImage = false
        var badStore = false
        var wrongRoot = false
        var snapshotOutput: String? = null
        var retentionBefore: String? = null
        var retentionAfter: String? = null
        var retentionPredelete: String? = null
        var retentionObservation: String? = null
        var interruptPhase: String? = null
        var onStart: (String) -> Unit = {}
        override fun run(args: List<String>): RuntimeCommandResult {
            calls += args
            val output = when (args.first()) {
                "info" -> """{"host":{"security":{"rootless":false,"apparmorEnabled":true,"seccompEnabled":true}},"store":{"graphRoot":"${if (badStore) "/wrong" else PrivateRootfulCommands.ROOT}","runRoot":"${PrivateRootfulCommands.RUN}"}}"""
                "image" -> """[{"Id":"${if (badImage) "c".repeat(64) else "b".repeat(64)}","Digest":"sha256:${"a".repeat(64)}"}]"""
                "create" -> "unit-container"
                "start" -> {
                    val name = args.last()
                    onStart(name)
                    if (interruptPhase != null && name.endsWith(interruptPhase!!)) throw InterruptedException("unit interruption")
                    if (timeoutPhase != null && name.endsWith(timeoutPhase!!)) throw PrivateCommandTimeout()
                    if (failPhase != null && name.endsWith(failPhase!!)) return RuntimeCommandResult(1, "")
                    when {
                        name.endsWith("-before") -> retentionBefore!!
                        name.endsWith("-predelete") -> retentionPredelete ?: retentionBefore!!
                        name.endsWith("-after") -> retentionAfter!!
                        name.endsWith("-snapshot") -> snapshotOutput ?: native
                        "-observe-" in name || name.endsWith("-bootstrap-observe") -> retentionObservation ?: "[${if (wrongRoot) native.replace("k" + "d".repeat(40), "k" + "e".repeat(40)) else native}]"
                        "-restore-" in name -> {
                            val create = calls.last { it.first() == "create" }
                            val output = Path.of(create.single { ":/restore:" in it }.removePrefix("--volume=").substringBefore(":/restore:"))
                            Files.createDirectory(output.resolve("recovered"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                            ""
                        }
                        else -> ""
                    }
                }
                else -> error("Unexpected fake command")
            }
            return RuntimeCommandResult(0, output)
        }
    }
    private fun fixture(block: (Path, Path, Path, Path, CapsuleManifest, Map<String, Path>, Fake, KopiaGenerationStore) -> Unit) {
        val root = Files.createTempDirectory("kopia-store-unit-")
        fun dir(name: String) = Files.createDirectory(root.resolve(name), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val repository = dir("store").resolve("repository")
        val key = dir("custody").resolve("key.env")
        val operation = dir(cap)
        val file = Files.createFile(root.resolve("unit-source"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        Files.writeString(file, "unit-only, not a native snapshot")
        val payloads = mapOf("source/bundle.json" to file)
        val manifest = CapsuleManifest(id = cap, generation = generation, bundleSha256 = "e".repeat(64), members = emptyList(), files = RecoveryCapsule.describe(payloads))
        val fake = Fake(native)
        try { block(root, repository, key, operation, manifest, payloads, fake, KopiaGenerationStore(image, fake)) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `networkless pinned snapshots reuse custody and repository without bootstrap replay`() = fixture { root, repo, key, op, manifest, payloads, fake, store ->
        val receipt = store.snapshot(repo, key, op, manifest, payloads)
        assertEquals("c".repeat(32), receipt.snapshotId)
        assertFalse(Files.exists(op.resolve("payload")))
        assertFalse(Files.exists(repo.parent.resolve("snapshot.pending.json")))
        val originalKey = Files.readAllBytes(key)
        val next = Files.createDirectory(root.resolve("cap-111111111111"))
        Files.setPosixFilePermissions(next, PosixFilePermissions.fromString("rwx------"))
        store.snapshot(repo, key, next, manifest.copy(id = next.fileName.toString()), payloads)
        assertContentEquals(originalKey, Files.readAllBytes(key))
        val creates = fake.calls.filter { it.first() == "create" }
        assertEquals(1, creates.count { it.any { a -> a.endsWith("-initialize") } })
        assertTrue(creates.all { "--network=none" in it && "--read-only" in it && "--pull=never" in it && "--cap-drop=all" in it })
        assertTrue(creates.all { it.none { arg -> arg.startsWith("--publish") || arg.contains("KOPIA_PASSWORD=") } })
        val restore = Files.createDirectory(root.resolve("q-111111111111"))
        Files.setPosixFilePermissions(restore, PosixFilePermissions.fromString("rwx------"))
        store.restore(repo, key, restore, receipt, restore.resolve("recovered"))
        val command = fake.calls.last { it.first() == "create" }
        assertTrue(command.any { it == "--volume=$repo:/repository:ro,nosuid,nodev,noexec" })
        assertTrue(command.any { it == "--volume=${restore.resolve("restore-output")}:/restore:rw,nosuid,nodev,noexec" })
        assertFalse(command.any { ":/source:" in it })
        assertTrue(Files.isDirectory(restore.resolve("recovered")))
        assertFails { store.restore(repo, key, restore, receipt, restore.resolve("recovered")) }
        assertFails { store.snapshot(repo, key, op, manifest, payloads) }
    }
    @Test fun `existing repository bootstrap verifies external custody and original snapshot without initialization`() = fixture { root, repo, key, op, manifest, payloads, fake, store ->
        val receipt = store.snapshot(repo, key, op, manifest, payloads)
        fun dir(path: Path) = Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val recoveredRepo = dir(dir(root.resolve("recovered-store")).resolve("repository"))
        val bootstrap = dir(root.resolve("bootstrap"))
        val original = Files.readAllBytes(key)
        val start = fake.calls.size
        assertFails { store.bootstrapRepository(recoveredRepo, key, bootstrap, receipt, "0".repeat(64)) }
        assertEquals(start, fake.calls.size)
        val binding = store.bootstrapRepository(recoveredRepo, key, bootstrap, receipt, ReleaseLocks.sha256(original))
        assertEquals(receipt.generation, binding.generation)
        assertContentEquals(original, Files.readAllBytes(key))
        val commands = fake.calls.drop(start).filter { it.first() == "create" }
        assertEquals(2, commands.size)
        assertTrue(commands.all { "--volume=$recoveredRepo:/repository:ro,nosuid,nodev,noexec" in it })
        assertTrue(commands.none { it.last().contains("repository create") || it.last().contains("snapshot create") })
        assertFails { store.bootstrapRepository(recoveredRepo, key, bootstrap, receipt, ReleaseLocks.sha256(original)) }
        val restore = dir(root.resolve("q-333333333333"))
        store.restore(recoveredRepo, key, restore, receipt, restore.resolve("recovered"))
        assertEquals(receipt, Json.decodeFromString<KopiaSnapshotReceipt>(Files.readString(recoveredRepo.parent.resolve("bootstrap.complete.json"))))
    }
    @Test fun `uncertain bootstrap retains intent and never fabricates completion or regenerates custody`() = fixture { root, repo, key, op, manifest, payloads, fake, store ->
        val receipt = store.snapshot(repo, key, op, manifest, payloads)
        fun dir(path: Path) = Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val recoveredRepo = dir(dir(root.resolve("recovered-store")).resolve("repository"))
        val bootstrap = dir(root.resolve("bootstrap"))
        val original = Files.readAllBytes(key)
        fake.timeoutPhase = "bootstrap-verify"
        assertFailsWith<PrivateCommandTimeout> { store.bootstrapRepository(recoveredRepo, key, bootstrap, receipt, ReleaseLocks.sha256(original)) }
        assertTrue(Files.exists(recoveredRepo.parent.resolve("bootstrap.intent.json")))
        assertFalse(Files.exists(recoveredRepo.parent.resolve("bootstrap.complete.json")))
        val calls = fake.calls.size
        assertFails { store.bootstrapRepository(recoveredRepo, key, bootstrap, receipt, ReleaseLocks.sha256(original)) }
        assertEquals(calls, fake.calls.size)
        assertContentEquals(original, Files.readAllBytes(key))
    }
    @Test fun `failed upload is never retried as a new snapshot identity`() = fixture { root, repo, key, op, manifest, payloads, fake, store ->
        fake.failPhase = "snapshot"
        assertFails { store.snapshot(repo, key, op, manifest, payloads) }
        assertTrue(Files.exists(repo.parent.resolve("snapshot.pending.json")))
        val count = fake.calls.size
        val other = Files.createDirectory(root.resolve("other")); Files.setPosixFilePermissions(other, PosixFilePermissions.fromString("rwx------"))
        assertFails { store.snapshot(repo, key, other, manifest.copy(id = "cap-111111111111"), payloads) }
        assertEquals(count, fake.calls.size)
    }
    @Test fun `lost snapshot acknowledgement retains unknown intent and blocks new writes`() = fixture { root, repo, key, op, manifest, payloads, fake, store ->
        fake.timeoutPhase = "snapshot"
        assertFailsWith<PrivateCommandTimeout> { store.snapshot(repo, key, op, manifest, payloads) }
        assertTrue(Files.exists(op.resolve("snapshot.intent.json")))
        assertFalse(Files.exists(op.resolve("snapshot.result.json")))
        assertTrue(Files.exists(repo.parent.resolve("snapshot.pending.json")))
        val count = fake.calls.size
        val next = Files.createDirectory(root.resolve("next")); Files.setPosixFilePermissions(next, PosixFilePermissions.fromString("rwx------"))
        assertFails { store.snapshot(repo, key, next, manifest.copy(id = "cap-111111111111"), payloads) }
        assertEquals(count, fake.calls.size)
    }
    @Test fun `partial repository initialization cannot regenerate credentials`() = fixture { root, repo, key, op, manifest, payloads, fake, store ->
        fake.failPhase = "initialize"
        assertFails { store.snapshot(repo, key, op, manifest, payloads) }
        val bytes = Files.readAllBytes(key)
        fake.failPhase = null
        assertFails { store.snapshot(repo, key, op, manifest, payloads) }
        assertContentEquals(bytes, Files.readAllBytes(key))
    }
    @Test fun `image store source and native response binding fail closed`() = fixture { _, repo, key, op, manifest, payloads, fake, store ->
        fake.badStore = true
        assertFails { store.snapshot(repo, key, op, manifest, payloads) }
        fake.badStore = false; fake.badImage = true
        assertFails { store.snapshot(repo, key, op, manifest, payloads) }
        assertFalse(Files.exists(key))
        fake.badImage = false
        assertFails { store.snapshot(repo, key, op, manifest.copy(files = emptyList()), payloads) }
        fake.snapshotOutput = native.replace("/source", "/foreign")
        assertFails { store.snapshot(repo, key, op, manifest, payloads) }
        assertTrue(Files.exists(repo.parent.resolve("snapshot.pending.json")))
    }
    @Test fun `native size errors symlinks and incomplete snapshots fail before writable restore`() {
        for ((from, to) in listOf("\"size\":1024" to "\"size\":999999999999", "\"files\":2" to "\"files\":3", "\"symlinks\":0" to "\"symlinks\":1", "\"numFailed\":0" to "\"numFailed\":1")) {
            fixture { _, repo, key, op, manifest, payloads, fake, store ->
                fake.snapshotOutput = native.replace(from, to)
                assertFails { store.snapshot(repo, key, op, manifest, payloads) }
                assertTrue(Files.exists(repo.parent.resolve("snapshot.pending.json")))
            }
        }
    }
    private fun retentionFixture(block: (Path, Path, Path, Path, CapsuleManifest, Map<String, Path>, Fake, KopiaGenerationStore, KopiaRetentionProtection) -> Unit) =
        fixture { root, repo, key, op, manifest, payloads, fake, store ->
            val receipt = store.snapshot(repo, key, op, manifest, payloads)
            val receipts = (1..6).map { n -> receipt.copy(id = "cap-" + n.toString(16).padStart(12, '0'),
                snapshotId = n.toString(16).padStart(32, '0'), rootObjectId = "k" + n.toString(16).padStart(40, '0')) }
            val values = receipts.mapIndexed { index, r ->
                val reasons = when (index) { 5 -> "[\"latest-1\",\"daily-1\",\"weekly-1\"]"; 4 -> "[\"latest-2\"]"; else -> "[]" }
                native.replace("c".repeat(32), r.snapshotId).replace("k" + "d".repeat(40), r.rootObjectId)
                    .dropLast(1) + ",\"pins\":[\"${r.id}\"],\"startTime\":\"2025-01-0${index + 1}T03:00:00Z\",\"retentionReason\":$reasons}"
            }
            fake.retentionBefore = values.joinToString(",", "[", "]")
            fake.retentionAfter = values.filterIndexed { i, _ -> i != 3 }.joinToString(",", "[", "]")
            val protection = KopiaRetentionProtection("f".repeat(64), receipts, setOf(receipts[2].snapshotId), receipts.take(2).map { it.snapshotId }.toSet())
            block(root, repo, key, op, manifest, payloads, fake, store, protection)
        }

    @Test fun `native retention preserves references and functional points without changing pins or ids`() = retentionFixture { _, repo, key, _, _, _, fake, store, protection ->
        var locked = false
        fake.onStart = { name ->
            assertTrue(locked)
            assertFailsWith<java.nio.channels.OverlappingFileLockException> { ReleasePrivateFiles.locked(repo.parent) {} }
            if (name.endsWith("-delete")) {
                assertTrue(Files.exists(repo.parent.resolve("retention.pending.json")))
                assertTrue(Files.exists(repo.parent.resolve("retention-r-123456789abc/plan.json")))
                assertTrue(Files.exists(repo.parent.resolve("retention-r-123456789abc/delete.intent.json")))
            }
        }
        val result = store.retain(repo, key, generation, "r-123456789abc", KopiaRetentionAuthority { action ->
            locked = true
            try { action(protection) } finally { locked = false }
        })
        assertFalse(locked)
        assertEquals(listOf(protection.receipts[3].snapshotId), result.plan.delete)
        assertEquals(5, result.plan.retain.size)
        assertEquals(protection.referenceHeadSha256, result.plan.referenceHeadSha256)
        assertTrue(Files.exists(repo.parent.resolve("retention-r-123456789abc/complete.json")))
        assertFalse(Files.exists(repo.parent.resolve("retention.pending.json")))
        val scripts = fake.calls.filter { it.first() == "create" }.map { it.last() }
        assertEquals(1, scripts.count { "snapshot delete --delete ${result.plan.delete.single()}" in it })
        assertTrue(scripts.any { "--keep-daily=7 --keep-weekly=4" in it })
        assertTrue(scripts.none { "snapshot pin" in it || "snapshot expire" in it || "--all-snapshots-for-source" in it })
        assertFails { store.retain(repo, key, generation, "r-123456789abc", KopiaRetentionAuthority { it(protection) }) }
    }

    @Test fun `additional native pins prevent deletion and unchanged metadata is required`() = retentionFixture { _, repo, key, _, _, _, fake, store, protection ->
        val pin = "\"${protection.receipts[3].id}\""
        fake.retentionBefore = fake.retentionBefore!!.replace("\"pins\":[$pin]", "\"pins\":[$pin,\"external-hold\"]")
        fake.retentionAfter = fake.retentionBefore
        val result = store.retain(repo, key, generation, "r-123456789abc", KopiaRetentionAuthority { it(protection) })
        assertTrue(result.plan.delete.isEmpty())
        assertTrue(fake.calls.none { it.last().contains("snapshot delete") })
        assertFails { KopiaRetention.verifyAfter(fake.retentionBefore!!, fake.retentionAfter!!.replace("external-hold", "changed"), result.plan) }
        // Ranking can legitimately change after deletion, but contents and pins cannot.
        KopiaRetention.verifyAfter(fake.retentionBefore!!, fake.retentionAfter!!.replace("daily-1", "daily-2"), result.plan)
    }

    @Test fun `unknown deletion remains pending across ids and prevents capture and restore`() {
        for (failure in listOf("timeout", "exit", "interrupt", "readback")) retentionFixture { root, repo, key, op, manifest, payloads, fake, store, protection ->
            when (failure) {
                "timeout" -> fake.timeoutPhase = "-delete"
                "exit" -> fake.failPhase = "-delete"
                "interrupt" -> fake.interruptPhase = "-delete"
                else -> fake.retentionAfter = fake.retentionBefore
            }
            assertFails { store.retain(repo, key, generation, "r-123456789abc", KopiaRetentionAuthority { it(protection) }) }
            if (failure == "interrupt") assertTrue(Thread.interrupted())
            assertTrue(Files.exists(repo.parent.resolve("retention.pending.json")))
            val calls = fake.calls.size
            assertFails { store.retain(repo, key, generation, "r-111111111111", KopiaRetentionAuthority { it(protection) }) }
            assertFails { store.snapshot(repo, key, op, manifest, payloads) }
            assertFails { store.restore(repo, key, root, protection.receipts.first(), root.resolve("recovered")) }
            assertEquals(calls, fake.calls.size)
            assertFalse(Files.exists(repo.parent.resolve("retention-r-123456789abc/complete.json")))
        }
    }

    @Test fun `retention reconciliation observes unchanged partial and deleted sets without releasing uncertainty`() {
        for (status in listOf("unchanged", "partial", "deletion-observed", "foreign", "protected")) retentionFixture { _, repo, key, _, _, _, fake, store, original ->
            val protection = if (status == "partial") original.copy(referencedSnapshotIds = emptySet()) else original
            fake.timeoutPhase = "-delete"
            assertFails { store.retain(repo, key, generation, "r-123456789abc", KopiaRetentionAuthority { it(protection) }) }
            fake.timeoutPhase = null
            fake.retentionObservation = when (status) {
                "unchanged" -> fake.retentionBefore
                "foreign" -> fake.retentionAfter!!.replace(original.receipts[0].snapshotId, "a".repeat(32))
                "protected" -> fake.retentionAfter!!.replace(original.receipts[0].rootObjectId, "k" + "e".repeat(40))
                else -> fake.retentionAfter
            }
            val pending = Files.readAllBytes(repo.parent.resolve("retention.pending.json"))
            val calls = fake.calls.size
            if (status in listOf("foreign", "protected")) {
                assertFails { store.observeRetention(repo, key, generation, "r-111111111111") }
            } else {
                val observed = store.observeRetention(repo, key, generation, "r-111111111111")
                assertEquals(status, observed.status)
                assertEquals(if (status == "unchanged") emptyList() else listOf(original.receipts[3].snapshotId), observed.removed)
            }
            assertContentEquals(pending, Files.readAllBytes(repo.parent.resolve("retention.pending.json")))
            val creates = fake.calls.drop(calls).filter { it.first() == "create" }
            assertEquals(1, creates.size)
            assertTrue(creates.single().contains("--volume=$repo:/repository:ro,nosuid,nodev,noexec"))
            assertTrue(creates.single().last().contains("snapshot list"))
            assertFails { store.observeRetention(repo, key, generation, "r-111111111111") }
            assertFails { store.retain(repo, key, generation, "r-222222222222", KopiaRetentionAuthority { it(protection) }) }
        }
    }

    @Test fun `failed retention policy cannot be adopted as a deletion plan`() = retentionFixture { _, repo, key, _, _, _, fake, store, protection ->
        fake.failPhase = "-policy"
        assertFails { store.retain(repo, key, generation, "r-123456789abc", KopiaRetentionAuthority { it(protection) }) }
        val calls = fake.calls.size
        assertFails { store.observeRetention(repo, key, generation, "r-111111111111") }
        assertEquals(calls, fake.calls.size)
    }

    @Test fun `retention refuses foreign incomplete missing duplicate or changed census before deletion`() {
        for (failure in listOf("foreign", "incomplete", "root", "pin", "time", "reasons", "duplicate", "receipt", "reference", "verified", "race", "ambiguous")) {
            retentionFixture { _, repo, key, _, _, _, fake, store, original ->
                var protection = original
                val text = fake.retentionBefore!!
                when (failure) {
                    "foreign" -> fake.retentionBefore = text.replace("/source", "/foreign")
                    "incomplete" -> fake.retentionBefore = text.replace("\"source\":", "\"incomplete\":\"failed\",\"source\":")
                    "root" -> fake.retentionBefore = text.replace(protection.receipts[0].rootObjectId, "k" + "e".repeat(40))
                    "pin" -> fake.retentionBefore = text.replace("\"${protection.receipts[0].id}\"", "\"foreign-pin\"")
                    "time" -> fake.retentionBefore = text.replace("2025-01-01T03:00:00Z", "bad")
                    "reasons" -> fake.retentionBefore = text.replace("latest-2", "unknown")
                    "duplicate" -> fake.retentionBefore = text.replace(protection.receipts[0].snapshotId, protection.receipts[1].snapshotId)
                    "receipt" -> protection = protection.copy(receipts = protection.receipts.drop(1))
                    "reference" -> protection = protection.copy(referencedSnapshotIds = setOf("a".repeat(32)))
                    "verified" -> protection = protection.copy(functionallyVerifiedSnapshotIds = setOf("a".repeat(32), "b".repeat(32)))
                    "race" -> fake.retentionPredelete = text.replace("2025-01-01T03:00:00Z", "2025-01-01T03:01:00Z")
                    "ambiguous" -> {
                        val old = protection.receipts[0]
                        protection = protection.copy(receipts = listOf(old.copy(rootObjectId = protection.receipts[3].snapshotId)) + protection.receipts.drop(1))
                        fake.retentionBefore = text.replace(old.rootObjectId, protection.receipts[3].snapshotId)
                    }
                }
                assertFails(failure) { store.retain(repo, key, generation, "r-123456789abc", KopiaRetentionAuthority { it(protection) }) }
                assertTrue(fake.calls.none { it.first() == "create" && "snapshot delete" in it.last() }, failure)
            }
        }
    }

    @Test fun `retention requires completed snapshots qualified minimum and matching custody artifacts`() = retentionFixture { _, repo, key, _, _, _, fake, store, protection ->
        val authority = KopiaRetentionAuthority { it(protection) }
        assertFails { store.retain(repo, key, generation, "../bad", authority) }
        assertFails { store.retain(repo, key, generation, "r-123456789abc", KopiaRetentionAuthority { it(protection.copy(functionallyVerifiedSnapshotIds = emptySet())) }) }
        assertFails { store.retain(repo, key, generation, "r-123456789abc", KopiaRetentionAuthority {
            it(protection.copy(receipts = protection.receipts.map { r -> r.copy(imageId = "c".repeat(64)) }))
        }) }
        ReleasePrivateFiles.save(repo.parent.resolve("snapshot.pending.json"), "uncertain".toByteArray())
        val count = fake.calls.size
        assertFails { store.retain(repo, key, generation, "r-123456789abc", authority) }
        assertEquals(count, fake.calls.size)
        assertFails { KopiaRetention.inventory("[]") }
        assertFails { KopiaRetention.inventory(" ".repeat(1048577)) }
    }

    @Test fun `preexisting interruption never starts a worker`() = fixture { _, repo, key, op, manifest, payloads, fake, store ->
        Thread.currentThread().interrupt()
        try {
            assertFails { store.snapshot(repo, key, op, manifest, payloads) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertTrue(fake.calls.isEmpty())
    }

    @Test fun `changed custody or snapshot object refuses restoration before writable mount`() = fixture { root, repo, key, op, manifest, payloads, fake, store ->
        val receipt = store.snapshot(repo, key, op, manifest, payloads)
        val restore = Files.createDirectory(root.resolve("restore")); Files.setPosixFilePermissions(restore, PosixFilePermissions.fromString("rwx------"))
        fake.wrongRoot = true
        assertFails { store.restore(repo, key, restore, receipt, restore.resolve("recovered")) }
        assertFalse(Files.exists(restore.resolve("restore-output")))
        Files.writeString(key, "KOPIA_PASSWORD=wrong\n")
        assertFails { store.restore(repo, key, restore, receipt, restore.resolve("recovered")) }
        assertFails { KopiaGenerationStore.validate(receipt.copy(rootObjectId = "../../foreign")) }
        assertFails { KopiaGenerationStore.validate(receipt.copy(snapshotId = "invalid")) }
        assertFails { KopiaGenerationStore.validate(receipt.copy(files = 0)) }
        assertFails { KopiaGenerationStore(image.copy(product = "foreign"), fake) }
        assertEquals(64, KopiaGenerationStore.receiptHash(receipt).length)
    }
}
