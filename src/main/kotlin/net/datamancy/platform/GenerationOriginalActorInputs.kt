package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Bind controller case grants to the EXACT original selected one-shot inputs.
 * Runs under the already-held INSTALL owner/native locks before the first
 * application journey. No identity creation, account readback or custody stage.
 */
internal object GenerationOriginalActorInputs {
    private val json = Json { ignoreUnknownKeys = false }
    private val hash = Regex("[a-f0-9]{64}")
    private fun context(scope: QualificationControlScope, service: String): JsonObject {
        val source = requireNotNull(scope.contexts)
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(source.path), 4194304)) == source.sha256)
        val map = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(source.path), 4194304)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val entries = map.filterKeys { it.startsWith("$service--") }
        require(entries.isNotEmpty())
        val owner = entries.values.mapNotNull { it.jsonObject["ownerCredentialFile"]?.jsonPrimitive?.content }.distinct().single()
        val outsider = entries.values.mapNotNull { it.jsonObject["outsiderCredentialFile"]?.jsonPrimitive?.content }.distinct().single()
        require(owner != outsider)
        if (service == "donetick") {
            val appNonMember = entries.values.mapNotNull {
                it.jsonObject["appNonMemberCredentialFile"]?.jsonPrimitive?.content }.distinct().single()
            require(setOf(owner, outsider, appNonMember).size == 3) {
                "Donetick app-test principal cannot alias the gateway-denied outsider"
            }
        }
        return entries.values.first { "ownerCredentialFile" in it.jsonObject }.jsonObject
    }
    fun credential(scope: QualificationControlScope, service: String, actor: String): JsonObject {
        require(actor in setOf("owner", "outsider") || service == "donetick" && actor == "appNonMember")
        val path = Path.of(context(scope, service).getValue("${actor}CredentialFile").jsonPrimitive.content)
        require(path.isAbsolute && path.normalize() == path &&
            path.startsWith(GenerationRuntime.BASE.resolve(scope.generationId)) &&
            Files.isRegularFile(path, NOFOLLOW_LINKS))
        val obj = json.parseToJsonElement(ReleasePrivateFiles.read(path, 16384)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(obj.keys == setOf("username", "password") &&
            obj.getValue("username").jsonPrimitive.content.matches(Regex("[a-zA-Z0-9_.@-]{3,128}")) &&
            obj.getValue("password").jsonPrimitive.content.matches(hash))
        return obj
    }
    fun apiGrant(scope: QualificationControlScope, actor: String): JsonObject {
        require(actor in setOf("owner", "outsider"))
        val field = if (actor == "owner") "bookstackApiGrantFile" else "outsiderBookstackApiGrantFile"
        val path = Path.of(context(scope, "bookstack").getValue(field).jsonPrimitive.content)
        require(path.isAbsolute && path.normalize() == path &&
            path.startsWith(GenerationRuntime.BASE.resolve(scope.generationId)) &&
            Files.isRegularFile(path, NOFOLLOW_LINKS))
        val obj = json.parseToJsonElement(ReleasePrivateFiles.read(path, 16384)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(obj.keys == setOf("tokenId", "secret") &&
            obj.getValue("tokenId").jsonPrimitive.content.matches(Regex("p0v3-[a-f0-9]{32}")) &&
            obj.getValue("secret").jsonPrimitive.content.matches(hash))
        return obj
    }
    /** The original signup input is pinned by the sealed generation bundle. Its
     * additional email/displayName fields must never be confused with the
     * minimal recovery actor credential. Require both original process ACKs.
     */
    fun requireOriginalDonetick(scope: QualificationControlScope, bundle: GenerationBundle,
        root: Path, runtimeBase: Path = PrivateDeployment.BASE) {
        require(bundle.request.id == scope.generationId && root == GenerationRuntime.BASE.resolve(scope.generationId) &&
            bundle.recoverySourceKopia == null && bundle.recoverySourceArchiveSha256 == null)
        val pin = bundle.members.single { member -> member.spec.processes.any { it.id == "donetick-actors-init" } }
        val initializer = pin.spec.processes.single { it.id == "donetick-actors-init" }
        val daemon = pin.spec.processes.single { it.id == "donetick" }
        require(initializer.oneShot && initializer.networks == listOf("donetick-enroll") &&
            "donetick-enroll" !in daemon.networks &&
            "donetick-actors-init" in daemon.dependencies)
        val status = json.parseToJsonElement(ReleasePrivateFiles.read(root.resolve(
            "quadlet-member-${pin.spec.name}-donetick-actors-init.result.json"), 8192)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(status.getValue("bundleSha256").jsonPrimitive.content == scope.bundleSha256 &&
            status.getValue("containerId").jsonPrimitive.content.matches(hash) &&
            status.getValue("status").jsonObject.getValue("state").jsonPrimitive.content == "completed" &&
            status.getValue("status").jsonObject.getValue("exitCode").jsonPrimitive.int == 0)
        for ((actor, suffix, nativeName) in listOf(
            Triple("owner", "owner", "owner"), Triple("outsider", "outsider", "outsider"),
            Triple("appNonMember", "app-nonmember", "app-nonmember"))) {
            val name = "donetick-$suffix-signup.json"
            val original = ReleasePrivateFiles.read(runtimeBase.resolve(pin.spec.name).resolve(name), 16384)
            require(ReleaseLocks.sha256(original) == pin.inputHashes.getValue(name))
            val signup = json.parseToJsonElement(original.decodeToString(throwOnInvalidSequence = true)).jsonObject
            val grant = credential(scope, "donetick", actor)
            require(signup.getValue("username") == grant.getValue("username") &&
                signup.getValue("password") == grant.getValue("password") &&
                signup.getValue("username").jsonPrimitive.content == nativeName) {
                "Controller actor grant differs from original sealed Donetick signup input"
            }
        }
    }
}
