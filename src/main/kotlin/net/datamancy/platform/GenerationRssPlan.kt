package net.datamancy.platform

import java.net.URI
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
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
            val plan = request.rssPlan ?: return
            plan.validate()
            require(request.store == RuntimeStore.CANONICAL_V2 && ownership != null) { "Managed RSS requires sealed canonical ownership" }
            val host = URI(plan.mastodonOrigin).host
            require(host in ownership.approvedHosts && ownership.contract.routes.any {
                it.host == host && it.product == "mastodon"
            }) { "RSS origin is not an owned approved Mastodon route" }
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
    val bundleSha256: String, val planSha256: String, val scheduleRoot: String, val bindingSha256: String)

/** One authoritative scheduler root per sealed generation. Duplicate roots cannot evade the RSS lock.
 * Only immutable generation records are read; enrollment is serialized by the schedule lock and
 * exclusive generation claim, so no generation-lock -> RSS-lock inversion is introduced. */
internal class GenerationRssEnrollmentAuthority(private val generations: Path = GenerationRuntime.BASE) : RssEnrollmentAuthority {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
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
        require(bundle.ownedUpdate == null) { "Owned-update RSS enrollment requires its native completion authority" }
        val prepared = json.decodeFromString<AssemblyPreparationOutcome>(
            ReleasePrivateFiles.read(generation.resolve("assembly.result.json")).decodeToString(throwOnInvalidSequence = true))
        require(prepared.passed && prepared.bundleSha256 == binding.deployment.bundleSha256 &&
            prepared.assemblySha256 == bundle.assemblySha256 &&
            prepared.assemblySha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(generation.resolve("assembly.intent.json"))) &&
            ReleasePrivateFiles.read(generation.resolve("ownership.intent.json")).contentEquals(json.encodeToString(bundle.ownership).toByteArray())) {
            "RSS generation preparation is incomplete or foreign"
        }
        GenerationRssPlan.validateOwnership(bundle.request, bundle.ownership)
        val plan = requireNotNull(bundle.request.rssPlan) { "Generation has no sealed RSS plan" }
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
            planSha256 = ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()), scheduleRoot = root.toString(), bindingSha256 = digest)
        return generation to json.encodeToString(record).toByteArray()
    }
    override fun preflight(root: Path, binding: RssScheduleBinding) {
        val (generation, _) = checked(root, binding, ReleaseLocks.sha256(json.encodeToString(binding).toByteArray()))
        require(!Files.exists(generation.resolve("rss-enrollment.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(generation.resolve("rss-enrollment.complete.json"), NOFOLLOW_LINKS)) {
            "Generation RSS enrollment already attempted; reconcile, never replace"
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
