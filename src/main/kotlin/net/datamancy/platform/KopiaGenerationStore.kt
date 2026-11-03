package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Native Kopia identity, not a custom encrypted capsule or a functional-restore attestation. */
@Serializable internal data class KopiaSnapshotReceipt(val schemaVersion: Int = 1, val id: String,
    val generation: String, val bundleSha256: String, val snapshotId: String, val rootObjectId: String,
    val manifestSha256: String, val files: Int, val plaintextBytes: Long, val image: String, val imageId: String)
@Serializable internal data class KopiaCaptureOutcome(val id: String, val bundleSha256: String, val passed: Boolean,
    val snapshot: KopiaSnapshotReceipt? = null, val failureType: String? = null)
@Serializable internal data class KopiaRepositoryBinding(val generation: String, val image: String, val imageId: String,
    val custodySha256: String)

internal interface GenerationSnapshotStore {
    fun snapshot(repository: Path, custody: Path, operation: Path, manifest: CapsuleManifest, payloads: Map<String, Path>): KopiaSnapshotReceipt
    fun restore(repository: Path, custody: Path, operation: Path, receipt: KopiaSnapshotReceipt, destination: Path)
}

/** Pinned, networkless Kopia worker containers. Source is a bounded declared staging tree, never host-wide.
 * Repository and custody are separate. No automatic retention, updates, snapshot actions or operation replay.
 * A failed/unknown worker is retained with its intent; another operation cannot finish partial initialization.
 */
internal class KopiaGenerationStore(private val image: AcquiredImage, private val commands: RuntimeCommands,
    private val runtimeStore: RuntimeStore = RuntimeStore.LEGACY) : GenerationSnapshotStore {
    companion object {
        private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
        private val mode = PosixFilePermissions.fromString("rw-------")
        private val dirMode = PosixFilePermissions.fromString("rwx------")
        fun receiptHash(receipt: KopiaSnapshotReceipt) = ReleaseLocks.sha256(json.encodeToString(receipt).toByteArray())
        fun validate(receipt: KopiaSnapshotReceipt) {
            require(receipt.schemaVersion == 1 && receipt.id.matches(Regex("cap-[a-f0-9]{12}")) &&
                receipt.generation.matches(Regex("q-[a-f0-9]{12}")) && receipt.snapshotId.matches(Regex("[a-f0-9]{32,64}")) &&
                receipt.rootObjectId.matches(Regex("[a-z0-9]{20,100}")) && receipt.bundleSha256.matches(Regex("[a-f0-9]{64}")) &&
                receipt.manifestSha256.matches(Regex("[a-f0-9]{64}")) && receipt.files in 1..4096 &&
                receipt.plaintextBytes in 1..RecoveryCapsule.MAX_TOTAL && receipt.imageId.matches(Regex("[a-f0-9]{64}")) &&
                receipt.image.matches(Regex("[a-z0-9./_-]+@sha256:[a-f0-9]{64}"))) { "Invalid Kopia snapshot binding" }
        }
        fun real(inventory: AcquiredInventory, store: RuntimeStore = RuntimeStore.LEGACY) =
            KopiaGenerationStore(inventory.images.single { it.product == "kopia" }, PrivateRootfulCommands(store = store), store)
        private fun directory(path: Path) {
            require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path && Files.isDirectory(path, NOFOLLOW_LINKS) &&
                Files.getPosixFilePermissions(path) == dirMode &&
                (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid) { "Owned private Kopia directory required" }
        }
        private fun mkdir(path: Path) {
            directory(path.parent)
            Files.createDirectory(path, PosixFilePermissions.asFileAttribute(dirMode))
            FileChannel.open(path.parent, READ).use { it.force(true) }
        }
        private fun save(path: Path, bytes: ByteArray) {
            require(bytes.size in 1..1048576)
            directory(path.parent)
            FileChannel.open(path, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(mode)).use {
                val data = ByteBuffer.wrap(bytes); while (data.hasRemaining()) it.write(data); it.force(true)
            }
            FileChannel.open(path.parent, READ).use { it.force(true) }
        }
        private fun read(path: Path): ByteArray { RecoveryCapsule.guard(path, 1048576); return Files.readAllBytes(path) }
    }
    init {
        require(image.product == "kopia" && image.os == "linux" && image.architecture == "amd64" &&
            image.pinnedImage.matches(Regex("[a-z0-9./_-]+@sha256:[a-f0-9]{64}")) && image.imageId.matches(Regex("[a-f0-9]{64}")))
    }
    private fun run(args: List<String>): RuntimeCommandResult {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("Kopia operation interrupted before effect")
        return try { commands.run(args) } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt(); throw failure
        }
    }
    private fun call(args: List<String>): String {
        val result = run(args)
        check(result.exitCode == 0) { "Kopia worker operation failed; retain journal and inspect only its owned container" }
        return result.output.trim()
    }
    private fun preflight() {
        val info = Json.parseToJsonElement(call(listOf("info", "--format", "json"))).jsonObject
        val store = info.getValue("store").jsonObject; val security = info.getValue("host").jsonObject.getValue("security").jsonObject
        require(store.getValue("graphRoot").jsonPrimitive.content == runtimeStore.graph &&
            store.getValue("runRoot").jsonPrimitive.content == runtimeStore.run &&
            !security.getValue("rootless").jsonPrimitive.boolean && security.getValue("apparmorEnabled").jsonPrimitive.boolean &&
            security.getValue("seccompEnabled").jsonPrimitive.boolean) { "Dedicated confined store required" }
        require(runtimeStore == RuntimeStore.LEGACY || info.getValue("host").jsonObject["freeLocks"] in listOf(null, JsonNull)) {
            "Isolated file-lock backend required"
        }
        val observed = Json.parseToJsonElement(call(listOf("image", "inspect", image.pinnedImage))).jsonArray.single().jsonObject
        require(observed.getValue("Id").jsonPrimitive.content.removePrefix("sha256:") == image.imageId &&
            observed.getValue("Digest").jsonPrimitive.content == image.pinnedImage.substringAfter('@')) { "Kopia image identity changed" }
    }
    private fun worker(repository: Path, custody: Path, operation: Path, generation: String, capture: String, phase: String,
        script: String, extra: List<String> = emptyList(), writable: Boolean = false): String {
        directory(repository); directory(operation); read(custody)
        require(phase.matches(Regex("[a-z0-9-]{1,80}")))
        val name = "p0v3-kopia-$generation-$capture-$phase"
        val args = listOf("create", "--name=$name", "--pull=never", "--network=none", "--read-only", "--cap-drop=all",
            "--security-opt=no-new-privileges", "--security-opt=apparmor=p0v3-private-v1", "--user=${UnixSystem().uid}:${UnixSystem().gid}",
            "--memory=1024m", "--pids-limit=128", "--image-volume=ignore", "--tmpfs=/tmp:rw,nosuid,nodev,size=128m",
            "--label=io.p0v3.kopia-generation=$generation", "--label=io.p0v3.kopia-capture=$capture",
            "--env-file=$custody", "--env=HOME=/tmp", "--env=KOPIA_CONFIG_PATH=/tmp/repository.config", "--env=KOPIA_CACHE_DIRECTORY=/tmp/cache",
            "--env=KOPIA_CHECK_FOR_UPDATES=false", "--volume=$repository:/repository:${if (writable) "rw" else "ro"},nosuid,nodev,noexec") +
            extra + listOf("--entrypoint=/bin/sh", image.pinnedImage, "-ec", "set -eu\numask 077\n$script")
        // Exclusive durable intent precedes container creation, not just snapshot submission.
        save(operation.resolve("$phase.intent.json"), json.encodeToString(mapOf("container" to name,
            "argvSha256" to ReleaseLocks.sha256(json.encodeToString(args).toByteArray()), "runtimeStore" to runtimeStore.name)).toByteArray())
        call(args)
        val result = run(listOf("start", "--attach", name))
        save(operation.resolve("$phase.result.json"), json.encodeToString(mapOf("exitCode" to result.exitCode)).toByteArray())
        check(result.exitCode == 0) { "Kopia worker failed; no snapshot or initialization replay permitted" }
        return result.output.trim()
    }
    private val kopia = "/usr/bin/kopia --disable-file-logging --no-persist-credentials"
    private fun connect(readonly: Boolean) = "$kopia repository connect filesystem --path=/repository ${if (readonly) "--readonly" else ""} --no-check-for-updates >/dev/null"
    private fun binding(repository: Path, custody: Path, generation: String): KopiaRepositoryBinding {
        val recorded = json.decodeFromString<KopiaRepositoryBinding>(read(repository.parent.resolve("repository.binding.json")).decodeToString())
        require(recorded == KopiaRepositoryBinding(generation, image.pinnedImage, image.imageId, ReleaseLocks.sha256(read(custody)))) {
            "Kopia repository custody or artifact binding changed"
        }
        val bootstrap = repository.parent.resolve("bootstrap.complete.json")
        if (Files.exists(bootstrap, NOFOLLOW_LINKS)) {
            val receipt = json.decodeFromString<KopiaSnapshotReceipt>(read(bootstrap).decodeToString())
            validate(receipt)
            require(receipt.generation == generation && receipt.image == image.pinnedImage && receipt.imageId == image.imageId)
            require(read(repository.parent.resolve("bootstrap.intent.json")).contentEquals(
                json.encodeToString(mapOf("receiptSha256" to receiptHash(receipt), "custodySha256" to recorded.custodySha256)).toByteArray()))
        } else require(Json.parseToJsonElement(read(repository.parent.resolve("initialize.result.json")).decodeToString()).jsonObject.getValue("exitCode").jsonPrimitive.int == 0) {
            "Incomplete Kopia initialization; no credential regeneration"
        }
        return recorded
    }
    private fun nativeRoot(native: JsonObject, generation: String, files: Int, bytes: Long): JsonObject {
        require(native["incomplete"]?.jsonPrimitive?.contentOrNull.orEmpty().isEmpty()) { "Incomplete native Kopia snapshot" }
        val source = native.getValue("source").jsonObject
        require(source.getValue("path").jsonPrimitive.content == "/source" && source.getValue("host").jsonPrimitive.content == generation &&
            source.getValue("userName").jsonPrimitive.content == "p0v3") { "Foreign native snapshot source" }
        val root = native.getValue("rootEntry").jsonObject
        val summary = root.getValue("summ").jsonObject
        require(root.getValue("type").jsonPrimitive.content == "d" && summary.getValue("files").jsonPrimitive.int == files + 1 &&
            summary.getValue("size").jsonPrimitive.long in (bytes + 1)..(bytes + 1048576) &&
            summary.getValue("dirs").jsonPrimitive.int in 1..(files * 8 + 1) && summary.getValue("symlinks").jsonPrimitive.int == 0 &&
            summary.getValue("numFailed").jsonPrimitive.int == 0) { "Kopia tree exceeds the exact declared recovery payload boundary" }
        return root
    }
    override fun snapshot(repository: Path, custody: Path, operation: Path, manifest: CapsuleManifest, payloads: Map<String, Path>): KopiaSnapshotReceipt =
        ReleasePrivateFiles.locked(repository.parent) {
            noPendingRetention(repository)
            snapshotLocked(repository, custody, operation, manifest, payloads)
        }
    private fun snapshotLocked(repository: Path, custody: Path, operation: Path, manifest: CapsuleManifest, payloads: Map<String, Path>): KopiaSnapshotReceipt {
        require(manifest.id.matches(Regex("cap-[a-f0-9]{12}")) && manifest.generation.matches(Regex("q-[a-f0-9]{12}")))
        directory(repository.parent); directory(custody.parent); directory(operation)
        require(!operation.startsWith(repository) && !custody.startsWith(repository) && !repository.startsWith(operation))
        RecoverySegments.validate(manifest)
        RecoveryControllerPayloads.validate(manifest)
        require(manifest.files == RecoveryCapsule.describe(payloads)) { "Snapshot source differs from declared payloads" }
        require(!Files.exists(repository.parent.resolve("snapshot.pending.json"), NOFOLLOW_LINKS)) { "Uncertain snapshot retained; reconcile, never resubmit with another ID" }
        preflight()
        val parent = repository.parent
        if (!Files.exists(parent.resolve("repository.binding.json"), NOFOLLOW_LINKS)) {
            require(!Files.exists(repository, NOFOLLOW_LINKS) && !Files.exists(custody, NOFOLLOW_LINKS) &&
                !Files.exists(parent.resolve("initialize.intent.json"), NOFOLLOW_LINKS)) { "Partial Kopia initialization retained" }
            // Binding intent first; a crash cannot silently generate different custody on another snapshot.
            save(parent.resolve("initialize.scope.json"), json.encodeToString(mapOf("generation" to manifest.generation)).toByteArray())
            save(custody, "KOPIA_PASSWORD=${RuntimePreparation.password()}\n".toByteArray())
            save(parent.resolve("repository.binding.json"), json.encodeToString(KopiaRepositoryBinding(manifest.generation,
                image.pinnedImage, image.imageId, ReleaseLocks.sha256(read(custody)))).toByteArray())
            mkdir(repository)
            worker(repository, custody, parent, manifest.generation, manifest.id, "initialize",
                "$kopia repository create filesystem --path=/repository --no-check-for-updates >/dev/null", writable = true)
        }
        binding(repository, custody, manifest.generation)
        val source = operation.resolve("payload"); mkdir(source)
        for ((name, path) in payloads) {
            val destination = source.resolve(name)
            require(destination.normalize() == destination && destination.startsWith(source))
            var parentPath = source
            for (part in name.split('/').dropLast(1)) {
                parentPath = parentPath.resolve(part)
                if (!Files.exists(parentPath, NOFOLLOW_LINKS)) mkdir(parentPath)
                directory(parentPath)
            }
            Files.copy(path, destination); Files.setPosixFilePermissions(destination, mode)
            FileChannel.open(destination, WRITE).use { it.force(true) }
        }
        save(source.resolve("manifest.json"), json.encodeToString(manifest).toByteArray())
        require(RecoveryCapsule.describe(payloads) == manifest.files &&
            RecoveryCapsule.describe(payloads.mapValues { (name, _) -> source.resolve(name) }) == manifest.files) {
            "Staged snapshot bytes differ from authenticated source"
        }
        save(parent.resolve("snapshot.pending.json"), json.encodeToString(mapOf("generation" to manifest.generation, "capture" to manifest.id)).toByteArray())
        val output = worker(repository, custody, operation, manifest.generation, manifest.id, "snapshot",
            connect(false) + "\n$kopia snapshot create --json --fail-fast --force-hash=100 --parallel=1 --upload-limit-mb=8193 --no-send-snapshot-report --pin=${manifest.id} --override-source=p0v3@${manifest.generation}:/source /source",
            listOf("--volume=$source:/source:ro,nosuid,nodev,noexec"), writable = true)
        save(operation.resolve("snapshot.native.json"), output.toByteArray())
        val parsed = Json.parseToJsonElement(output)
        val native = (if (parsed is JsonArray) parsed.single() else parsed).jsonObject
        val root = nativeRoot(native, manifest.generation, manifest.files.size, manifest.files.sumOf { it.bytes })
        val receipt = KopiaSnapshotReceipt(id = manifest.id, generation = manifest.generation, bundleSha256 = manifest.bundleSha256,
            snapshotId = native.getValue("id").jsonPrimitive.content, rootObjectId = root.getValue("obj").jsonPrimitive.content,
            manifestSha256 = RecoveryCapsule.fileHash(source.resolve("manifest.json")), files = manifest.files.size,
            plaintextBytes = manifest.files.sumOf { it.bytes }, image = image.pinnedImage, imageId = image.imageId)
        validate(receipt)
        worker(repository, custody, operation, manifest.generation, manifest.id, "verify", connect(true) + "\n$kopia snapshot verify --verify-files-percent=100 >/dev/null")
        save(operation.resolve("snapshot.complete.json"), json.encodeToString(receipt).toByteArray())
        // Delete only this attempt's own plaintext staging tree, never source data or repository bytes.
        Files.walk(source).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        Files.delete(parent.resolve("snapshot.pending.json"))
        FileChannel.open(parent, READ).use { it.force(true) }
        return receipt
    }
    override fun restore(repository: Path, custody: Path, operation: Path, receipt: KopiaSnapshotReceipt, destination: Path) =
        ReleasePrivateFiles.locked(repository.parent) {
            noPendingRetention(repository)
            restoreLocked(repository, custody, operation, receipt, destination)
        }
    private fun restoreLocked(repository: Path, custody: Path, operation: Path, receipt: KopiaSnapshotReceipt, destination: Path) {
        validate(receipt)
        require(receipt.image == image.pinnedImage && receipt.imageId == image.imageId)
        directory(operation); directory(destination.parent)
        require(destination.parent == operation && destination.fileName.toString() == "recovered" && !Files.exists(destination, NOFOLLOW_LINKS) &&
            !operation.startsWith(repository) && !repository.startsWith(operation)) { "Fresh isolated Kopia restoration required" }
        binding(repository, custody, receipt.generation); preflight()
        val listed = worker(repository, custody, operation, receipt.generation, receipt.id, "observe-${operation.fileName}",
            connect(true) + "\n$kopia snapshot list --all --json")
        val selected = Json.parseToJsonElement(listed).jsonArray.map { it.jsonObject }.single {
            it.getValue("id").jsonPrimitive.content == receipt.snapshotId
        }
        require(nativeRoot(selected, receipt.generation, receipt.files, receipt.plaintextBytes).getValue("obj").jsonPrimitive.content == receipt.rootObjectId) {
            "Kopia snapshot identity differs from receipt"
        }
        // Mount only fresh output scratch, not the controller journal or other runtime inputs.
        val output = operation.resolve("restore-output"); mkdir(output)
        worker(repository, custody, operation, receipt.generation, receipt.id, "restore-${operation.fileName}",
            connect(true) + "\n$kopia snapshot verify --verify-files-percent=100 >/dev/null\n" +
                "$kopia snapshot restore --no-overwrite-files --no-overwrite-directories --no-overwrite-symlinks --skip-owners --flush-files ${receipt.rootObjectId} /restore/recovered >/dev/null",
            listOf("--volume=$output:/restore:rw,nosuid,nodev,noexec"))
        directory(output.resolve("recovered"))
        Files.move(output.resolve("recovered"), destination, java.nio.file.StandardCopyOption.ATOMIC_MOVE)
        FileChannel.open(operation, READ).use { it.force(true) }
    }

    /** Recover control binding for an existing repository from externally retained receipt and custody digest.
     * Does not synthesize source journals, functional evidence, promotion rights or initialize repository/custody.
     * Caller anchors both expected values outside this recovered filesystem. Failure leaves a non-replayable intent.
     */
    fun bootstrapRepository(repository: Path, custody: Path, operation: Path, receipt: KopiaSnapshotReceipt,
        expectedCustodySha256: String): KopiaRepositoryBinding = ReleasePrivateFiles.locked(repository.parent) {
        validate(receipt)
        require(receipt.image == image.pinnedImage && receipt.imageId == image.imageId &&
            expectedCustodySha256.matches(Regex("[a-f0-9]{64}")))
        directory(repository); directory(operation); directory(custody.parent)
        require(!operation.startsWith(repository) && !repository.startsWith(operation) && !custody.startsWith(repository) &&
            operation != repository.parent && !custody.startsWith(operation))
        val secret = read(custody)
        require(ReleaseLocks.sha256(secret) == expectedCustodySha256) { "Recovered custody differs from external anchor" }
        require(secret.decodeToString(throwOnInvalidSequence = true).matches(Regex("KOPIA_PASSWORD=[A-Za-z0-9_-]{24,256}\\n"))) {
            "Only scoped repository password custody is accepted"
        }
        val parent = repository.parent
        for (name in listOf("repository.binding.json", "initialize.scope.json", "initialize.intent.json", "snapshot.pending.json",
            "retention.pending.json", "bootstrap.intent.json", "bootstrap.complete.json"))
            require(!Files.exists(parent.resolve(name), NOFOLLOW_LINKS)) { "Existing or uncertain repository control state; no bootstrap replay" }
        preflight()
        val intent = json.encodeToString(mapOf("receiptSha256" to receiptHash(receipt), "custodySha256" to expectedCustodySha256)).toByteArray()
        save(parent.resolve("bootstrap.intent.json"), intent)
        val native = worker(repository, custody, operation, receipt.generation, receipt.id, "bootstrap-observe",
            connect(true) + "\n$kopia snapshot list --all --json --show-identical")
        val selected = Json.parseToJsonElement(native).jsonArray.map { it.jsonObject }.single {
            it.getValue("id").jsonPrimitive.content == receipt.snapshotId
        }
        require(nativeRoot(selected, receipt.generation, receipt.files, receipt.plaintextBytes).getValue("obj").jsonPrimitive.content == receipt.rootObjectId)
        save(operation.resolve("bootstrap.native.json"), native.toByteArray())
        worker(repository, custody, operation, receipt.generation, receipt.id, "bootstrap-verify",
            connect(true) + "\n$kopia snapshot verify --verify-files-percent=100 >/dev/null")
        require(ReleaseLocks.sha256(read(custody)) == expectedCustodySha256)
        val binding = KopiaRepositoryBinding(receipt.generation, image.pinnedImage, image.imageId, expectedCustodySha256)
        save(parent.resolve("repository.binding.json"), json.encodeToString(binding).toByteArray())
        save(parent.resolve("bootstrap.complete.json"), json.encodeToString(receipt).toByteArray())
        binding
    }

    private fun noPendingRetention(repository: Path) {
        require(!Files.exists(repository.parent.resolve("retention.pending.json"), NOFOLLOW_LINKS)) {
            "Uncertain Kopia retention retained; no new operation or automatic replay"
        }
    }

    /** Read-only reconciliation evidence. Never resends deletion or releases a pending-operation fence. */
    fun observeRetention(repository: Path, custody: Path, generation: String, observation: String): KopiaRetentionObservation =
        ReleasePrivateFiles.locked(repository.parent) {
            require(generation.matches(Regex("q-[a-f0-9]{12}")) && observation.matches(Regex("r-[a-f0-9]{12}")))
            val pending = json.decodeFromString<Map<String, String>>(ReleasePrivateFiles.read(repository.parent.resolve("retention.pending.json")).decodeToString())
            require(pending.keys == setOf("generation", "id", "referenceHeadSha256") && pending.getValue("generation") == generation)
            val id = pending.getValue("id"); require(id.matches(Regex("r-[a-f0-9]{12}")))
            val operation = repository.parent.resolve("retention-$id")
            val planBytes = ReleasePrivateFiles.read(operation.resolve("plan.json"))
            val plan = json.decodeFromString<KopiaRetentionPlan>(planBytes.decodeToString())
            require(plan.schemaVersion == 1 && plan.id == id && plan.generation == generation &&
                plan.referenceHeadSha256 == pending.getValue("referenceHeadSha256"))
            val before = ReleasePrivateFiles.read(operation.resolve("before.native.json"), 1048576).decodeToString()
            binding(repository, custody, generation); preflight()
            val output = operation.resolve("observe-$observation"); mkdir(output)
            val after = worker(repository, custody, output, generation, id, "observe-$observation",
                connect(true) + "\n$kopia snapshot list --all --json --retention --show-identical")
            save(output.resolve("inventory.native.json"), after.toByteArray())
            val removed = KopiaRetention.observe(before, after, plan)
            val result = KopiaRetentionObservation(observation, ReleaseLocks.sha256(planBytes), ReleaseLocks.sha256(after.toByteArray()),
                removed, when { removed == plan.delete -> "deletion-observed"; removed.isEmpty() -> "unchanged"; else -> "partial" })
            save(output.resolve("observation.json"), json.encodeToString(result).toByteArray())
            result
        }

    /** Low-level actuator only. The whole-release controller must supply a locked, verified reference authority.
     * No default authority, public deletion CLI, pin rewriting, broad expire, or physical blob cleanup.
     */
    fun retain(repository: Path, custody: Path, generation: String, id: String,
        authority: KopiaRetentionAuthority): KopiaRetentionResult = authority.withProtection { protection ->
        ReleasePrivateFiles.locked(repository.parent) {
            require(id.matches(Regex("r-[a-f0-9]{12}")) && generation.matches(Regex("q-[a-f0-9]{12}")))
            noPendingRetention(repository)
            require(!Files.exists(repository.parent.resolve("snapshot.pending.json"), NOFOLLOW_LINKS)) {
                "Uncertain snapshot prevents retention"
            }
            binding(repository, custody, generation); preflight()
            // Validate custody/receipts before any policy change, even though only deletion needs the native census.
            require(protection.receipts.size in 2..128 && protection.functionallyVerifiedSnapshotIds.size >= 2)
            protection.receipts.forEach {
                validate(it)
                require(it.generation == generation && it.image == image.pinnedImage && it.imageId == image.imageId)
            }
            val operation = repository.parent.resolve("retention-$id"); mkdir(operation)
            val pending = json.encodeToString(mapOf("generation" to generation, "id" to id,
                "referenceHeadSha256" to protection.referenceHeadSha256)).toByteArray()
            save(repository.parent.resolve("retention.pending.json"), pending)
            val source = "p0v3@$generation:/source"
            worker(repository, custody, operation, generation, id, "policy", connect(false) +
                "\n$kopia policy set $source --keep-latest=2 --keep-hourly=0 --keep-daily=7 --keep-weekly=4 --keep-monthly=0 --keep-annual=0 --ignore-identical-snapshots=false >/dev/null", writable = true)
            fun observe(phase: String): String {
                val text = worker(repository, custody, operation, generation, id, phase,
                    connect(true) + "\n$kopia snapshot list --all --json --retention --show-identical")
                save(operation.resolve("$phase.native.json"), text.toByteArray())
                return text
            }
            val before = observe("before")
            val plan = KopiaRetention.plan(id, generation, before, protection) { native, receipt ->
                require(nativeRoot(native, generation, receipt.files, receipt.plaintextBytes).getValue("obj").jsonPrimitive.content == receipt.rootObjectId)
            }
            // Kopia delete accepts root IDs as a fallback. Refuse even a potential ambiguous identifier.
            val roots = KopiaRetention.inventory(before).values.map { it.getValue("rootEntry").jsonObject.getValue("obj").jsonPrimitive.content }
            require(plan.delete.none { it in roots }) { "Ambiguous Kopia manifest/root identity" }
            save(operation.resolve("plan.json"), json.encodeToString(plan).toByteArray())
            if (plan.delete.isNotEmpty()) {
                val checked = observe("predelete")
                require(KopiaRetention.inventory(checked) == KopiaRetention.inventory(before)) { "Kopia inventory changed before deletion" }
                worker(repository, custody, operation, generation, id, "delete", connect(false) +
                    "\n$kopia snapshot delete --delete ${plan.delete.joinToString(" ")} >/dev/null", writable = true)
            }
            val after = observe("after")
            KopiaRetention.verifyAfter(before, after, plan)
            val result = KopiaRetentionResult(plan, ReleaseLocks.sha256(after.toByteArray()))
            save(operation.resolve("complete.json"), json.encodeToString(result).toByteArray())
            ReleasePrivateFiles.removeExact(repository.parent.resolve("retention.pending.json"), pending)
            result
        }
    }
}
