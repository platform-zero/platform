package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Stage the pinned CLI once into UID 784's private generation directory.
 * Source remains root-only; no credentials, registration RPC or application
 * effect. An absent original install result is uncertain and MUST NOT replay.
 */
@Serializable internal data class ForgejoCiBinaryInstallIntent(val generation: String,
    val bundleSha256: String, val sourceSha256: String, val accountPath: String)
@Serializable internal data class ForgejoCiBinaryInstallResult(val intentSha256: String,
    val installedSha256: String, val accountUid: Int = 784)
internal object ForgejoCiNativeBinaryStage {
    private val json = Json { encodeDefaults = true }
    fun installedPath(plan: ForgejoCiSourcePlan): Path = Path.of(
        "/home/webservices-lab-ci-runner/.local/share/p0v3-ci/${plan.generation}/forgejo-runner")
    private fun run(vararg args: String): String {
        val process = ProcessBuilder(args.toList()).redirectError(ProcessBuilder.Redirect.DISCARD).start()
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly(); error("Native CI binary handoff timed out; preserve original intent")
        }
        require(process.exitValue() == 0) { "Native CI binary handoff uncertain; preserve original intent" }
        return process.inputStream.readNBytes(2048).decodeToString(throwOnInvalidSequence = true).trim()
    }
    fun stage(plan: ForgejoCiSourcePlan, root: Path, bundleSha256: String) {
        plan.validate(plan.generation)
        require(root == GenerationRuntime.BASE.resolve(plan.generation) &&
            bundleSha256.matches(Regex("[a-f0-9]{64}")))
        val ci = root.resolve("ci")
        val accountBytes = ReleasePrivateFiles.read(ci.resolve("account-stage.result.json"), 8192)
        val account = json.decodeFromString<ForgejoCiAccountStageResult>(accountBytes.decodeToString())
        val accountIntent = ReleasePrivateFiles.read(ci.resolve("account-stage.intent.json"), 16384)
        require(account.accountUid == 784 && account.intentSha256 == ReleaseLocks.sha256(accountIntent))
        val source = Path.of(plan.runnerBinary.path)
        require(Files.isRegularFile(source, NOFOLLOW_LINKS) &&
            RecoveryCapsule.fileHash(source) == plan.runnerBinary.sha256 && Files.isExecutable(source))
        val target = installedPath(plan)
        val intent = ForgejoCiBinaryInstallIntent(plan.generation, bundleSha256, plan.runnerBinary.sha256,
            target.toString())
        val intentFile = ci.resolve("runner-binary-install.intent.json")
        require(!Files.exists(intentFile, NOFOLLOW_LINKS) &&
            !Files.exists(ci.resolve("runner-binary-install.result.json"), NOFOLLOW_LINKS)) {
            "Existing or uncertain CI runner binary install cannot be replayed"
        }
        val bytes = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(intentFile, bytes)
        run("/usr/bin/sudo", "-n", "/usr/bin/install", "-m", "0700", "-o", "784", "-g", "784",
            "--", source.toString(), target.toString())
        require(run("/usr/bin/sudo", "-n", "-u", plan.dedicatedAccount, "--",
            "/usr/bin/stat", "-c", "%u:%a:%F", "--", target.toString()) == "784:700:regular file")
        val digest = run("/usr/bin/sudo", "-n", "-u", plan.dedicatedAccount, "--",
            "/usr/bin/sha256sum", "--", target.toString()).substringBefore(' ')
        require(digest == plan.runnerBinary.sha256)
        ReleasePrivateFiles.save(ci.resolve("runner-binary-install.result.json"),
            json.encodeToString(ForgejoCiBinaryInstallResult(ReleaseLocks.sha256(bytes), digest)).toByteArray())
    }
    fun verifyInstalled(plan: ForgejoCiSourcePlan, root: Path, bundleSha256: String) {
        val ci = root.resolve("ci")
        val intentBytes = ReleasePrivateFiles.read(ci.resolve("runner-binary-install.intent.json"), 2048)
        val intent = json.decodeFromString<ForgejoCiBinaryInstallIntent>(intentBytes.decodeToString())
        val result = json.decodeFromString<ForgejoCiBinaryInstallResult>(ReleasePrivateFiles.read(
            ci.resolve("runner-binary-install.result.json"), 2048).decodeToString())
        require(intent == ForgejoCiBinaryInstallIntent(plan.generation, bundleSha256,
            plan.runnerBinary.sha256, installedPath(plan).toString()) &&
            result == ForgejoCiBinaryInstallResult(ReleaseLocks.sha256(intentBytes), plan.runnerBinary.sha256))
        require(run("/usr/bin/sudo", "-n", "-u", plan.dedicatedAccount, "--",
            "/usr/bin/stat", "-c", "%u:%a:%F", "--", installedPath(plan).toString()) == "784:700:regular file")
        require(run("/usr/bin/sudo", "-n", "-u", plan.dedicatedAccount, "--",
            "/usr/bin/sha256sum", "--", installedPath(plan).toString()).substringBefore(' ') == plan.runnerBinary.sha256)
    }
}
