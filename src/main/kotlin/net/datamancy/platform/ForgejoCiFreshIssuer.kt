package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** The NEW Forgejo is a dependency of its CI token, not a pre-existing issuer.
 * Read the one-use freshly created admin credential only from this generation's
 * original rootful Forgejo bootstrap volume. Authenticate over sealed private
 * TLS, verify the exact trusted repository commit, journal BEFORE the first
 * token-issuing GET, then seal token bytes (never stdout, argv, unit or logs).
 * A missing result or token is uncertain; no new GET or replacement token.
 */
@Serializable internal data class ForgejoCiFreshIssueIntent(val generation: String, val bundleSha256: String,
    val sourcePlanSha256: String, val repository: String, val trustedCommit: String,
    val ownerBootstrapSha256: String)
@Serializable internal data class ForgejoCiFreshIssueResult(val intentSha256: String,
    val tokenSha256: String, val repository: String, val trustedCommit: String)
internal object ForgejoCiFreshIssuer {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    internal fun credential(bundle: GenerationBundle, root: Path): ByteArray {
        val owner = bundle.members.single { pin -> pin.spec.processes.any { it.id == "forgejo-owner-init" } }
        val spec = owner.spec
        require(spec.store == RuntimeStore.CANONICAL_V2 && spec.volumes.any { it.id == "forgejo-bootstrap" })
        val stage = json.parseToJsonElement(ReleasePrivateFiles.read(root.resolve("${spec.name}.stage.result.json"))
            .decodeToString(throwOnInvalidSequence = true)).jsonArray
        require(stage.any { s -> s.jsonObject.let { it["id"]?.jsonPrimitive?.content == "forgejo-owner-init" &&
            it["exitCode"]?.jsonPrimitive?.int == 0 && it["state"]?.jsonPrimitive?.content in setOf("completed", "exited") } })
        val name = "p0v3-live-${spec.name}-volume-forgejo-bootstrap"
        val observed = PrivateRootfulCommands(store = RuntimeStore.CANONICAL_V2).run(listOf("volume", "inspect", name))
        require(observed.exitCode == 0 && observed.output.length in 1..65536)
        val volume = json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
        val mount = Path.of(volume.getValue("Mountpoint").jsonPrimitive.content)
        require(volume.getValue("Name").jsonPrimitive.content == name && mount ==
            Path.of(RuntimeStore.CANONICAL_V2.graph).resolve("volumes/$name/_data"))
        val file = mount.resolve("owner.result")
        val helper = """import os,sys,stat
f=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW)
try:
 s=os.fstat(f)
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size<1 or s.st_size>8192 or s.st_mode&0o077: sys.exit(19)
 b=os.read(f,8193)
 if len(b)!=s.st_size: sys.exit(19)
 sys.stdout.buffer.write(b)
finally: os.close(f)
""".trimIndent()
        val child = ProcessBuilder("/usr/bin/sudo", "-n", "/usr/bin/python3", "-c", helper, file.toString())
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        return try {
            val bytes = child.inputStream.readNBytes(8193)
            require(child.waitFor(30, TimeUnit.SECONDS) && child.exitValue() == 0 && bytes.size in 1..8192)
            val text = bytes.decodeToString(throwOnInvalidSequence = true)
            val matches = Regex("generated random password is '([A-Za-z0-9!@#%^&*_.-]{20,128})'")
                .findAll(text).toList()
            require(matches.size == 1 && text.length <= 8192)
            matches.single().groupValues[1].toByteArray().also { bytes.fill(0) }
        } finally { if (child.isAlive) child.destroyForcibly() }
    }
    private fun intent(plan: ForgejoCiSourcePlan, bundle: GenerationBundle, root: Path, owner: ByteArray): ForgejoCiFreshIssueIntent =
        ForgejoCiFreshIssueIntent(plan.generation,
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)),
            ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()), plan.enrollment.repository,
            plan.enrollment.trustedCommit, ReleaseLocks.sha256(owner))
    fun issue(plan: ForgejoCiSourcePlan, bundle: GenerationBundle, root: Path): ForgejoCiSourcePlan {
        require(plan.freshIssuerBootstrap && !plan.freshRegistrationIssued &&
            bundle.request.forgejoCi == plan && bundle.recoverySourceKopia == null &&
            root == GenerationRuntime.BASE.resolve(plan.generation))
        val ci = root.resolve("ci"); ReleasePrivateFiles.directory(ci)
        require(!Files.exists(ci.resolve("fresh-issue.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(ci.resolve("fresh-issue.result.json"), NOFOLLOW_LINKS) &&
            !Files.exists(ci.resolve("fresh-registration.token"), NOFOLLOW_LINKS)) {
            "Original fresh CI issuance is uncertain or already consumed; no replay"
        }
        val owner = credential(bundle, root)
        try {
            val repoProof = json.parseToJsonElement(ReleasePrivateFiles.read(
                ci.resolve("fresh-repository.result.json"), 8192).decodeToString()).jsonObject
            require(repoProof.getValue("generation").jsonPrimitive.content == plan.generation &&
                repoProof.getValue("sourcePlanSha256").jsonPrimitive.content ==
                    ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()) &&
                repoProof.getValue("commit").jsonPrimitive.content == plan.enrollment.trustedCommit &&
                ReleasePrivateFiles.read(ci.resolve("fresh-push.result.json"), 128).decodeToString() ==
                    plan.enrollment.trustedCommit)
            val repository = plan.enrollment.repository
            val commit = plan.enrollment.trustedCommit
            val readback = ForgejoCiPrivateApi.freshRepository(plan, owner,
                "/api/v1/repos/$repository/git/commits/$commit")
            require(readback.status == 200 && readback.body.size in 1..65536 &&
                json.parseToJsonElement(readback.body.decodeToString()).jsonObject
                    .getValue("sha").jsonPrimitive.content == commit) {
                "The fresh private Forgejo does not own the pinned trusted checkout"
            }
            val claim = intent(plan, bundle, root, owner)
            val bytes = json.encodeToString(claim).toByteArray()
            ReleasePrivateFiles.save(ci.resolve("fresh-issue.intent.json"), bytes)
            // Forgejo v17's repository-scoped GET may mint a new token. Its
            // HTTP result is NEVER replayed if the response is lost.
            val response = ForgejoCiPrivateApi.freshRepository(plan, owner,
                "/api/v1/repos/$repository/actions/runners/registration-token")
            require(response.status == 200 && response.body.size in 20..4096)
            val payload = json.parseToJsonElement(response.body.decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(payload.keys == setOf("token"))
            val token = payload.getValue("token").jsonPrimitive.content.toByteArray()
            try {
                require(token.size in 20..4096 && token.all { it.toInt().toChar() in '!'..'~' })
                val pin = ActivationInput(ci.resolve("fresh-registration.token").toString(), ReleaseLocks.sha256(token))
                ReleasePrivateFiles.save(Path.of(pin.path), token)
                val result = ForgejoCiFreshIssueResult(ReleaseLocks.sha256(bytes), pin.sha256, repository, commit)
                ReleasePrivateFiles.save(ci.resolve("fresh-issue.result.json"), json.encodeToString(result).toByteArray())
                return plan.copy(freshIssuerBootstrap = false, freshRegistrationIssued = true,
                    registrationToken = pin).also { it.validate(plan.generation) }
            } finally { token.fill(0); response.body.fill(0) }
        } finally { owner.fill(0) }
    }
    fun attest(plan: ForgejoCiSourcePlan, bundle: GenerationBundle, root: Path): Boolean {
        val original = bundle.request.forgejoCi ?: return false
        if (!original.freshIssuerBootstrap || !plan.freshRegistrationIssued || original.generation != plan.generation ||
            original.copy(freshIssuerBootstrap = false, freshRegistrationIssued = true,
                registrationToken = plan.registrationToken) != plan) return false
        val ci = root.resolve("ci")
        val input = ReleasePrivateFiles.read(ci.resolve("fresh-issue.intent.json"), 8192)
        val claim = json.decodeFromString<ForgejoCiFreshIssueIntent>(input.decodeToString())
        val result = json.decodeFromString<ForgejoCiFreshIssueResult>(ReleasePrivateFiles.read(
            ci.resolve("fresh-issue.result.json"), 8192).decodeToString())
        val token = ReleasePrivateFiles.read(ci.resolve("fresh-registration.token"), 4096)
        return try {
            claim.generation == original.generation && claim.bundleSha256 == ReleaseLocks.sha256(
                ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)) &&
                claim.sourcePlanSha256 == ReleaseLocks.sha256(json.encodeToString(original).toByteArray()) &&
                claim.repository == original.enrollment.repository && claim.trustedCommit == original.enrollment.trustedCommit &&
                result.intentSha256 == ReleaseLocks.sha256(input) && result.repository == claim.repository &&
                result.trustedCommit == claim.trustedCommit && result.tokenSha256 == plan.registrationToken.sha256 &&
                ReleaseLocks.sha256(token) == result.tokenSha256
        } finally { token.fill(0) }
    }
}
