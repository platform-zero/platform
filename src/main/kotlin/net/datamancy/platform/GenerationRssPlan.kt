package net.datamancy.platform

import java.net.URI
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Sealed before a generation hash exists. No future deployment/enrollment digest in this plan. */
@Serializable internal data class GenerationRssPlan(val schemaVersion: Int = 1,
    val controllerSha256: String, val artifactClosure: ActivationInput, val mastodonOrigin: String,
    val intervalSeconds: Int = 900) {
    fun validate() {
        require(schemaVersion == 1 && controllerSha256.matches(Regex("[a-f0-9]{64}")) &&
            artifactClosure.sha256.matches(Regex("[a-f0-9]{64}")) && intervalSeconds in 300..86400)
        val path = Path.of(artifactClosure.path)
        require(path.isAbsolute && path.normalize() == path)
        val uri = URI(mastodonOrigin)
        require(uri.scheme == "https" && uri.host != null && uri.host.endsWith(".datamancy.net") &&
            '*' !in uri.host && uri.userInfo == null && uri.port == -1 && uri.rawPath.isEmpty() &&
            uri.rawQuery == null && uri.rawFragment == null) { "Exact approved RSS HTTPS origin required" }
    }
    companion object {
        const val MEMORY_MIB = 512L
        const val DISK_MIB = 128L
        fun validateOwnership(request: GenerationRequest, ownership: BoundSiteOwnership?) {
            val inert = request.recoveredRssPlan
            if (inert != null) {
                inert.validate()
                require(request.rssPlan == null && request.store == RuntimeStore.CANONICAL_V2 &&
                    ownership?.contract?.routes?.none { it.host == URI(inert.mastodonOrigin).host } != false) {
                    "Recovered RSS plan may not carry live scheduler or RSS site-publication authority"
                }
                return
            }
            val plan = request.rssPlan ?: return
            plan.validate()
            require(request.store == RuntimeStore.CANONICAL_V2 && ownership != null) { "Managed RSS requires sealed canonical ownership" }
            val host = URI(plan.mastodonOrigin).host
            require(host in ownership.approvedHosts && ownership.contract.routes.any {
                it.host == host && it.product == "mastodon"
            }) { "RSS origin is not an owned approved Mastodon route" }
        }
        /** Explicit feature-owned cold projection: the original authenticated source remains in
         * the capsule, while the recovered generation carries no scheduler, enrollment or live
         * publication plan. The retained recoveredRssPlan is inert recapture lineage only;
         * RSS controller payloads are imported separately as inert state.
         * Never use the generic fresh initializer on this recovered target. */
        fun coldRecoveryTarget(source: GenerationRequest, projected: GenerationRequest): GenerationRequest {
            val original = source.rssPlan ?: source.recoveredRssPlan
            require(original != null && (source.rssPlan == null) != (source.recoveredRssPlan == null) &&
                projected.rssPlan == source.rssPlan && projected.recoveredRssPlan == source.recoveredRssPlan &&
                projected.id != source.id && source.store == RuntimeStore.CANONICAL_V2 &&
                projected.store == RuntimeStore.CANONICAL_V2) {
                "Managed RSS cold projection requires exactly one authenticated live-or-inert source plan and fresh canonical target"
            }
            original.validate()
            // Explicit type, not a live plan: the next cold capture must preserve original RSS
            // checkpoints, token custody and uncertain outbox without enabling a scheduler.
            return projected.copy(rssPlan = null, recoveredRssPlan = original)
        }
        /** Fresh preparation only; never reset checkpoints or invent bot tokens. */
        fun prepare(root: Path) {
            val mode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
            val rss = Files.createDirectory(root.resolve("rss"), mode)
            val state = Files.createDirectory(rss.resolve("state"), mode)
            Files.createDirectory(rss.resolve("tokens"), mode)
            RssStateStore(state).initializeFresh()
            ReleasePrivateFiles.sync(rss); ReleasePrivateFiles.sync(root)
        }
    }
}

internal interface RssEnrollmentAuthority {
    fun preflight(root: Path, binding: RssScheduleBinding)
    fun claim(root: Path, binding: RssScheduleBinding, digest: String)
    fun complete(root: Path, binding: RssScheduleBinding, digest: String)
    fun verify(root: Path, binding: RssScheduleBinding, digest: String)
}

@Serializable private data class GenerationRssEnrollment(val schemaVersion: Int = 1, val generation: String,
    val bundleSha256: String, val planSha256: String, val scheduleRoot: String, val bindingSha256: String,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val ownedAdoptionSha256: String? = null)

/** One authoritative scheduler root per sealed generation. Duplicate roots cannot evade the RSS lock.
 * Original assembly records are immutable; OWNED candidate admission also reads real imported
 * startup/migration and source-adoption observations. Enrollment holds controller RSS exclusion
 * before its scheduler lock, and never takes a generation lock before RSS exclusion. */
internal class GenerationRssEnrollmentAuthority(private val generations: Path = GenerationRuntime.BASE,
    private val identityHttp: RssHttp = JdkRssHttp()) : RssEnrollmentAuthority {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    /** Genuine OWNED candidate: original source state/tokens are compared BEFORE enrollment,
     * and an immutable adoption digest is recorded. Later ticks may legitimately advance the
     * candidate checkpoint without retroactively failing its original-data provenance. */
    private fun ownedAdoption(generation: Path, bundle: GenerationBundle, bundleSha256: String): String {
        require(generations == GenerationRuntime.BASE && bundle.request.id == generation.fileName.toString())
        val lineage = requireNotNull(bundle.ownedUpdate).also { it.validate() }
        OwnedReleaseUpdates.validate(bundle)
        val original = OwnedReleaseUpdates.original(lineage)
        require(original.request.rssPlan == bundle.request.rssPlan && bundle.request.recoveredRssPlan == null)
        val source = generations.resolve(lineage.intent.source.id)
        val sourceBytes = ReleasePrivateFiles.read(source.resolve("bundle.json"), 4194304)
        require(ReleaseLocks.sha256(sourceBytes) == lineage.intent.source.bundleSha256 &&
            json.decodeFromString<GenerationBundle>(sourceBytes.decodeToString(throwOnInvalidSequence = true)) == original)
        val heldBytes = ReleasePrivateFiles.read(source.resolve("backups/${lineage.snapshot.id}/held.json"), 1048576)
        val held = json.decodeFromString<GenerationHeldCapture>(heldBytes.decodeToString(throwOnInvalidSequence = true))
        held.validate()
        require(held.snapshot == lineage.snapshot && held.access.generation == source.fileName.toString() &&
            held.access.bundleSha256 == lineage.intent.source.bundleSha256)
        val imported = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
            generation.resolve("stage.result.json"), 1048576).decodeToString(throwOnInvalidSequence = true))
        val started = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
            generation.resolve("owned-start.result.json"), 1048576).decodeToString(throwOnInvalidSequence = true))
        require(imported.action == "restore-import" && imported.passed && imported.failureType == null &&
            started.action == "owned-start" && started.passed && started.failureType == null &&
            imported.bundleSha256 == bundleSha256 && started.bundleSha256 == bundleSha256) {
            "Owned RSS candidate needs actual imported and natively started target results"
        }
        val transactionRoot = generations.parent.resolve("release-transactions")
        ReleasePrivateFiles.directory(transactionRoot)
        val matches = Files.list(transactionRoot).use { entries -> entries.filter { entry ->
            entry.fileName.toString().matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
                Files.isDirectory(entry, NOFOLLOW_LINKS) && entry.toRealPath() == entry &&
                Files.exists(entry.resolve("request.json"), NOFOLLOW_LINKS)
        }.limit(4097).toList() }
        require(matches.size <= 4096)
        val requests = matches.mapNotNull { entry -> runCatching {
            json.decodeFromString<ReleaseTransactionRequest>(ReleasePrivateFiles.read(
                entry.resolve("request.json"), 1048576).decodeToString(throwOnInvalidSequence = true))
        }.getOrNull()?.takeIf { it.updatePreparation?.intent == lineage.intent && it.snapshotId == lineage.snapshot.id }
            ?.let { entry to it } }
        require(requests.size == 1) { "Owned RSS target needs one immutable original update request" }
        val (transaction, request) = requests.single()
        ReleasePrivateFiles.directory(transaction)
        val preparation = requireNotNull(request.updatePreparation)
        preparation.validate(lineage.intent.source, lineage.intent.targetGeneration, generations)
        val pending = ReleasePrivateFiles.read(generation.resolve("planka-migration/pending.json"), 1048576)
        val migration = json.decodeFromString<PlankaMigrationRequest>(pending.decodeToString(throwOnInvalidSequence = true))
        val result = json.decodeFromString<PlankaMigrationResult>(ReleasePrivateFiles.read(
            generation.resolve("planka-migration/${preparation.migrationOperation}.result.json"), 1048576)
            .decodeToString(throwOnInvalidSequence = true))
        require(transaction.fileName.toString() == request.transactionId && migration.operation == preparation.migrationOperation &&
            migration.generation == bundle.request.id && migration.bundleSha256 == bundleSha256 &&
            migration.snapshotId == lineage.snapshot.id && result.operation == migration.operation &&
            result.requestSha256 == ReleaseLocks.sha256(pending) && result.passed &&
            result.migrationRoleRetired && result.failureType == null) {
            "Owned candidate Planka migration principal must be natively retired"
        }
        val native = GenerationRuntime.real().inspect(bundle.request.id, bundleSha256)
        require(native.members.isNotEmpty() && native.members.map { it.name }.toSet() ==
            bundle.members.map { it.spec.name }.toSet() && native.members.all { member ->
                member.existingResources > 0 && member.maintenanceId == null &&
                    member.statuses.isNotEmpty() && member.statuses.all { it.state == "running" }
            }) { "Owned RSS candidate is not the actually running imported cohort" }
        val byName = original.members.associateBy { it.member.name }
        require(bundle.members.all { it.inputHashes == byName.getValue(it.member.name).inputHashes }) {
            "Owned RSS credential revision or original member input was recreated"
        }
        val originalFiles = linkedMapOf<String, Path>()
        val names = RssControllerPayloads.capture(source, originalFiles)
        val accounts = names.filter { it.startsWith("controller/rss/tokens/") }.toSet()
        require(accounts == RssPacks.load().map { "controller/rss/tokens/${it.feed.account}.token" }.toSet() +
            "controller/rss/tokens/rss_observer.token") {
            "The original 47 RSS bots and separate observer credential must survive the owned import"
        }
        val adoption = names.joinToString("\n") { name ->
            "$name:${ReleaseLocks.sha256(ReleasePrivateFiles.read(originalFiles.getValue(name), 4194304))}"
        }.toByteArray()
        if (!Files.exists(generation.resolve("rss-enrollment.intent.json"), NOFOLLOW_LINKS)) {
            for (name in names) {
                val originalData = ReleasePrivateFiles.read(originalFiles.getValue(name), 4194304)
                val targetPath = generation.resolve("rss").resolve(name.removePrefix("controller/rss/"))
                require(ReleasePrivateFiles.read(targetPath, 4194304).contentEquals(originalData)) {
                    "Candidate did not import the exact original RSS checkpoint or principal custody: $name"
                }
            }
        }
        return ReleaseLocks.sha256(adoption)
    }
    private fun checked(root: Path, binding: RssScheduleBinding, digest: String): Pair<Path, ByteArray> {
        RssSchedule.validate(binding)
        require(digest.matches(Regex("[a-f0-9]{64}")) &&
            digest == ReleaseLocks.sha256(json.encodeToString(binding).toByteArray())) { "RSS binding digest changed" }
        val generation = generations.resolve(binding.deployment.generationId)
        val bytes = ReleasePrivateFiles.read(generation.resolve("bundle.json"))
        require(ReleaseLocks.sha256(bytes) == binding.deployment.bundleSha256) { "RSS generation bundle changed" }
        val bundle = json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(bundle.request.id == binding.deployment.generationId && bundle.recoverySourceKopia == null &&
            bundle.recoverySourceArchiveSha256 == null) { "Recovered state is not RSS publication authority" }
        SiteOwnerships.checkSealed(bundle)
        val ownedAdoptionSha256 = if (bundle.ownedUpdate == null) {
            val predecessor = bundle.request.predecessorDisposition
            if (predecessor != null) GenerationCiPreEffectContinuation.verify(generation, predecessor)
            val memberPredecessor = bundle.request.memberPredecessorDisposition
            if (memberPredecessor != null) GenerationCiMemberPreEffectContinuation.verify(generation,memberPredecessor)
            val resultFile = if (memberPredecessor != null) GenerationCiMemberPreEffectContinuation.RESULT else
                if (predecessor == null) "assembly.result.json" else GenerationCiPreEffectContinuation.RESULT
            val intentFile = if (memberPredecessor != null) GenerationCiMemberPreEffectContinuation.INTENT else
                if (predecessor == null) "assembly.intent.json" else GenerationCiPreEffectContinuation.INTENT
            val ownershipFile = if (memberPredecessor != null) GenerationCiMemberPreEffectContinuation.OWNERSHIP else
                if (predecessor == null) "ownership.intent.json" else GenerationCiPreEffectContinuation.OWNERSHIP
            val prepared = json.decodeFromString<AssemblyPreparationOutcome>(
                ReleasePrivateFiles.read(generation.resolve(resultFile)).decodeToString(throwOnInvalidSequence = true))
            require(prepared.passed && prepared.bundleSha256 == binding.deployment.bundleSha256 &&
                prepared.assemblySha256 == bundle.assemblySha256 &&
                prepared.assemblySha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(generation.resolve(intentFile))) &&
                ReleasePrivateFiles.read(generation.resolve(ownershipFile)).contentEquals(json.encodeToString(bundle.ownership).toByteArray())) {
                "RSS generation preparation is incomplete or foreign"
            }
            null
        } else {
            require(binding.deployment.sitePolicySha256 == requireNotNull(bundle.ownedUpdate).intent.sitePolicySha256)
            ownedAdoption(generation, bundle, binding.deployment.bundleSha256)
        }
        GenerationRssPlan.validateOwnership(bundle.request, bundle.ownership)
        val plan = requireNotNull(bundle.request.rssPlan) { "Generation has no sealed RSS plan" }
        // A fresh feature bootstrap owns 47 distinct new bot principals plus
        // one observer. Empty checkpoints alone cannot authorize publishing;
        // enrollment requires the exact minted, generation-bound custody set.
        val tokenRoot = generation.resolve("rss/tokens")
        ReleasePrivateFiles.directory(tokenRoot)
        val expectedTokens = RssPacks.load().map { "${it.feed.account}.token" }.toSet() + "rss_observer.token"
        val actualTokens = Files.list(tokenRoot).use { entries ->
            entries.limit(257).map { it.fileName.toString() }.toList().toSet()
        }
        require(expectedTokens.size == 48 && actualTokens == expectedTokens &&
            expectedTokens.all { MastodonRssSender.privateToken(tokenRoot.resolve(it)).isNotBlank() }) {
            "All 47 fresh RSS bot credentials and the observer must be present before native enrollment"
        }
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(plan.artifactClosure.path))) == plan.artifactClosure.sha256) {
            "RSS controller artifact closure changed"
        }
        require(root == generation.resolve("rss/schedule") &&
            binding.stateDirectory == generation.resolve("rss/state").toString() &&
            binding.tokenDirectory == generation.resolve("rss/tokens").toString() &&
            binding.controllerSha256 == plan.controllerSha256 && binding.artifactClosure == plan.artifactClosure &&
            binding.mastodonOrigin == plan.mastodonOrigin && binding.intervalSeconds == plan.intervalSeconds) {
            "RSS enrollment differs from sealed generation plan"
        }
        val record = GenerationRssEnrollment(generation = bundle.request.id, bundleSha256 = binding.deployment.bundleSha256,
            planSha256 = ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()), scheduleRoot = root.toString(),
            bindingSha256 = digest, ownedAdoptionSha256 = ownedAdoptionSha256)
        return generation to json.encodeToString(record).toByteArray()
    }
    override fun preflight(root: Path, binding: RssScheduleBinding) {
        val (generation, _) = checked(root, binding, ReleaseLocks.sha256(json.encodeToString(binding).toByteArray()))
        RssQualificationIntents.requireClear(generation)
        require(!Files.exists(generation.resolve("rss-enrollment.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(generation.resolve("rss-enrollment.complete.json"), NOFOLLOW_LINKS)) {
            "Generation RSS enrollment already attempted; reconcile, never replace"
        }
        // GET-only native identity readback of newly provisioned bots precedes
        // schedule enrollment; named files alone grant no publication authority.
        // The same release-bound HTTP origin/TLS policy is used for real ticks.
        val sender = MastodonRssSender(URI(binding.mastodonOrigin), { account ->
            MastodonRssSender.privateToken(generation.resolve("rss/tokens/$account.token"))
        }, identityHttp)
        val ids = RssPacks.load().map { sender.verifyAccount(it.feed.account) }
        val observer = sender.verifyObserver()
        require(ids.size == 47 && ids.distinct().size == 47 && observer !in ids) {
            "Fresh RSS tokens do not identify 47 bots and a distinct native observer"
        }
    }
    override fun claim(root: Path, binding: RssScheduleBinding, digest: String) {
        preflight(root, binding)
        val (generation, record) = checked(root, binding, digest)
        ReleasePrivateFiles.save(generation.resolve("rss-enrollment.intent.json"), record)
    }
    override fun complete(root: Path, binding: RssScheduleBinding, digest: String) {
        val (generation, record) = checked(root, binding, digest)
        require(ReleasePrivateFiles.read(generation.resolve("rss-enrollment.intent.json")).contentEquals(record))
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("binding.json"))) == digest &&
            ReleasePrivateFiles.read(root.resolve("enrolled")).decodeToString() == digest)
        ReleasePrivateFiles.save(generation.resolve("rss-enrollment.complete.json"), record)
    }
    override fun verify(root: Path, binding: RssScheduleBinding, digest: String) {
        val (generation, record) = checked(root, binding, digest)
        require(ReleasePrivateFiles.read(generation.resolve("rss-enrollment.intent.json")).contentEquals(record) &&
            ReleasePrivateFiles.read(generation.resolve("rss-enrollment.complete.json")).contentEquals(record)) {
            "Missing, uncertain or foreign generation RSS enrollment"
        }
    }
}
