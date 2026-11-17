package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** One-use, dedicated-account native Forgejo v3.5.1 registration. Never use the
 * historical entrypoint's delete-and-register-again recovery loop. The runner
 * source's interactive mode reads its token from stdin; --no-interactive needs
 * --token on argv, so it is explicitly forbidden here. This does NOT start the
 * daemon: the effective rootless OCI guard must be independently admitted first.
 */
@Serializable internal data class ForgejoCiRegistrationIntent(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val planSha256: String,
    val configSha256: String, val runnerBinarySha256: String, val registrationTokenSha256: String)
@Serializable internal data class ForgejoCiRegistrationResult(val intentSha256: String,
    val registrationSha256: String, val runnerId: Long, val runnerUuid: String,
    val runnerName: String, val instance: String)

internal object ForgejoCiNativeRegistration {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val home = Path.of("/home/webservices-lab-ci-runner")
    private fun scoped(plan: ForgejoCiSourcePlan): Path = home.resolve(".local/share/p0v3-ci/${plan.generation}")
    private fun account(vararg args: String): ProcessBuilder = ProcessBuilder(
        listOf("/usr/bin/sudo", "-n", "-u", "webservices-lab-ci-runner", "--") + args.toList())
    private fun output(command: ProcessBuilder): String {
        val child = command.redirectErrorStream(true).start()
        if (!child.waitFor(15, TimeUnit.SECONDS)) { child.destroyForcibly(); error("CI account readback timed out") }
        val bytes = child.inputStream.readNBytes(8193)
        require(child.exitValue() == 0 && bytes.size <= 8192) { "CI account readback failed" }
        return bytes.decodeToString(throwOnInvalidSequence = true).trim()
    }
    private fun verifyAccountPath(path: Path, mode: String) {
        // UID 1000 must not acquire traversal rights into UID 784's 0700 home.
        // GNU stat without -L lstat's the leaf; each parent below home is
        // checked separately. No site secret or .runner content is returned.
        require(path.isAbsolute && path.normalize() == path && path.startsWith(home))
        val octal = if (mode == "rwx------") "700" else if (mode == "rw-------") "600"
            else if (mode == "rw-r--r--") "644" else error("Unknown account-owned file mode")
        val kind = if (octal == "700") "directory" else "regular file"
        require(output(account("/usr/bin/stat", "-c", "%u:%a:%F", "--", path.toString())) ==
            "784:$octal:$kind") { "Foreign rootless CI path" }
    }
    private fun preflight(plan: ForgejoCiSourcePlan, root: Path, bundleSha256: String): Pair<Path, ByteArray> {
        plan.validate(plan.generation)
        require(root == GenerationRuntime.BASE.resolve(plan.generation) &&
            bundleSha256.matches(Regex("[a-f0-9]{64}")))
        ReleasePrivateFiles.directory(root)
        val bundleBytes = ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)
        require(ReleaseLocks.sha256(bundleBytes) == bundleSha256)
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        val ci = root.resolve("ci")
        require(bundle.request.id == plan.generation && ((
            (bundle.request.forgejoCi == plan || ForgejoCiFreshIssuer.attest(plan, bundle, root)) &&
            bundle.request.recoveredForgejoCi == null && bundle.recoverySourceKopia == null) ||
            (bundle.request.recoveredForgejoCiTarget == plan && bundle.request.forgejoCi == null &&
                bundle.recoverySourceKopia != null &&
                bundle.request.ciRecoveryGrant?.targetPlan(requireNotNull(bundle.request.recoveredForgejoCi)) == plan &&
                Files.exists(ci.resolve("revoke-original.result.json"), NOFOLLOW_LINKS) &&
                ForgejoCiNativeRecovery.authenticatedResult(bundle, root) != null))) {
            "CI registration requires a sealed fresh original or a verified revoked recovery lineage"
        }
        SiteOwnerships.checkSealed(bundle)
        ReleasePrivateFiles.directory(ci)
        require((Files.getAttribute(home, "unix:uid", NOFOLLOW_LINKS) as Number).toInt() == 784)
        val directory = scoped(plan)
        verifyAccountPath(home.resolve(".local"), "rwx------")
        verifyAccountPath(home.resolve(".local/share"), "rwx------")
        verifyAccountPath(home.resolve(".local/share/p0v3-ci"), "rwx------")
        verifyAccountPath(directory, "rwx------")
        val configPath = directory.resolve("runner-config.yaml")
        val registration = directory.resolve(".runner")
        verifyAccountPath(directory.resolve("guard-state"), "rwx------")
        val stageBytes = ReleasePrivateFiles.read(ci.resolve("account-stage.intent.json"), 8192)
        val stage = json.decodeFromString<ForgejoCiAccountStageIntent>(
            stageBytes.decodeToString(throwOnInvalidSequence = true))
        val stageResult = json.decodeFromString<ForgejoCiAccountStageResult>(ReleasePrivateFiles.read(
            ci.resolve("account-stage.result.json"), 8192).decodeToString(throwOnInvalidSequence = true))
        require(stage.generation == plan.generation && stage.bundleSha256 == bundleSha256 &&
            stageResult.intentSha256 == ReleaseLocks.sha256(stageBytes) &&
            stageResult.files == stage.files && stageResult.accountUid == 784)
        for ((name, expected) in stage.files) {
            val path = directory.resolve(name)
            verifyAccountPath(path, if (name == "transport-ca.pem") "rw-r--r--" else "rw-------")
            require(output(account("/usr/bin/sha256sum", path.toString())).substringBefore(' ') == expected &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(ci.resolve(name), 131072)) == expected) {
                "Rootless account source differs from sealed generation: $name"
            }
        }
        require(output(account("/usr/bin/python3", "-c",
            "import os,sys; sys.exit(1 if os.path.lexists(sys.argv[1]) else 0)",
            registration.toString())) == "" &&
            !Files.exists(ci.resolve("registration.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(ci.resolve("registration.result.json"), NOFOLLOW_LINKS)) {
            "Existing CI registration or uncertain attempt may not be replayed"
        }
        val config = ReleasePrivateFiles.read(ci.resolve("runner-config.yaml"), 65536)
        require(output(account("/usr/bin/sha256sum", configPath.toString())).substringBefore(' ') ==
            ReleaseLocks.sha256(config)) { "Account config differs from sealed source" }
        val runner = Path.of(plan.runnerBinary.path)
        require(Files.isRegularFile(runner, NOFOLLOW_LINKS) &&
            RecoveryCapsule.fileHash(runner) == plan.runnerBinary.sha256 &&
            Files.isExecutable(runner)) { "Unauthenticated Forgejo runner binary" }
        ForgejoCiNativeBinaryStage.verifyInstalled(plan, root, bundleSha256)
        val token = GenerationRuntime.privateInput(Path.of(plan.registrationToken.path))
        require(ReleaseLocks.sha256(token) == plan.registrationToken.sha256 &&
            token.size in 20..4096 && token.all { it.toInt().toChar() in '!'..'~' })
        return configPath to token
    }
    fun register(plan: ForgejoCiSourcePlan, root: Path, bundleSha256: String): ForgejoCiRegistrationResult {
        val (config, token) = preflight(plan, root, bundleSha256)
        val ci = root.resolve("ci")
        val configHash = ReleaseLocks.sha256(ReleasePrivateFiles.read(ci.resolve("runner-config.yaml"), 65536))
        val intent = ForgejoCiRegistrationIntent(generation = plan.generation, bundleSha256 = bundleSha256,
            planSha256 = ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()),
            configSha256 = configHash, runnerBinarySha256 = plan.runnerBinary.sha256,
            registrationTokenSha256 = plan.registrationToken.sha256)
        val bytes = json.encodeToString(intent).toByteArray()
        // This is BEFORE the first possible Forgejo registration RPC. Missing
        // result is uncertain even if the child was interrupted or timed out.
        ReleasePrivateFiles.save(ci.resolve("registration.intent.json"), bytes)
        val instance = "https://forgejo.datamancy.net/"
        val name = "p0v3-ci-${plan.generation}"
        val binary = ForgejoCiNativeBinaryStage.installedPath(plan).toString()
        // Pinned v3.5.1 uses os.Create for .runner; force a private umask
        // before exec so the server-issued runner token never becomes 0644.
        val child = account("/bin/sh", "-c", "umask 077; exec \"\$@\"", "--",
            binary, "--config", config.toString(), "register")
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD).start()
        try {
            child.outputStream.use { stdin ->
                stdin.write("$instance\n".toByteArray())
                stdin.write(token)
                stdin.write('\n'.code)
                stdin.write("$name\n".toByteArray())
                stdin.flush()
            }
            require(child.waitFor(90, TimeUnit.SECONDS) && child.exitValue() == 0) {
                "Forgejo registration result unavailable; preserve intent and reconcile original RPC"
            }
        } finally {
            if (child.isAlive) child.destroyForcibly()
            token.fill(0)
        }
        val path = scoped(plan).resolve(".runner")
        verifyAccountPath(path, "rw-------")
        val digest = output(account("/usr/bin/sha256sum", path.toString())).substringBefore(' ')
        require(digest.matches(Regex("[a-f0-9]{64}")))
        // The jq projection cannot return or log the registration token. Both
        // stdout and stderr of registration itself were discarded.
        val projection = output(account("/usr/bin/jq", "-c",
            "{id,uuid,name,address,labels,token_present:(.token|type==\"string\" and length>0)}", path.toString()))
        val observed = json.parseToJsonElement(projection).jsonObject
        require(observed.getValue("token_present").jsonPrimitive.content == "true" &&
            observed.getValue("name").jsonPrimitive.content == name &&
            observed.getValue("address").jsonPrimitive.content == instance &&
            observed.getValue("labels").jsonArray.map { it.jsonPrimitive.content } ==
                listOf("p0v3-rootless-oci:docker://${plan.enrollment.jobImage}"))
        val result = ForgejoCiRegistrationResult(ReleaseLocks.sha256(bytes), digest,
            observed.getValue("id").jsonPrimitive.content.toLong().also { require(it > 0) },
            observed.getValue("uuid").jsonPrimitive.content.also { require(it.isNotBlank()) }, name, instance)
        ReleasePrivateFiles.save(ci.resolve("registration.result.json"), json.encodeToString(result).toByteArray())
        return result
    }
}
