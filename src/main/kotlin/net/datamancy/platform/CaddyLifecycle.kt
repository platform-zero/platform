package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class HttpsLifecycleRequest(val schemaVersion: Int = 1, val action: String,
    val operation: String, val runtimeManifest: String, val runtimeFingerprint: String, val binding: CaddySiteBinding,
    val expectedConfiguration: String? = null, val nonces: Map<String, String> = emptyMap(),
    val environment: String? = null, val expectedIntent: String? = null)
@Serializable internal data class PrivatePkiLifecycleRequest(val schemaVersion: Int = 1, val action: String,
    val site: String, val authority: String, val operation: String, val profile: PrivatePkiProfile? = null,
    val previousOperation: String? = null, val previousSha256: String? = null)
@Serializable internal data class PrivatePkiLifecycleResult(val operation: String, val caSha256: String,
    val issueSha256: String? = null, val renewAfter: String? = null)

/** Typed runtime entrypoints. Never grants release activation or prints private key material. */
internal class CaddyLifecycle(private val control: (HttpsLifecycleRequest) -> CaddyHttpsProvisioner,
    private val observation: (HttpsLifecycleRequest) -> AcmeObservation) {
    companion object {
        private val json = Json { encodeDefaults = true }
        private inline fun <reified T> readRequest(path: Path): T = try {
            json.decodeFromString(ReleaseLocks.privateBytes(path).decodeToString(throwOnInvalidSequence = true))
        } catch (_: kotlinx.serialization.SerializationException) {
            throw IllegalArgumentException("Invalid private lifecycle request; contents withheld")
        }
        fun readHttps(path: Path): HttpsLifecycleRequest = readRequest(path)
        fun readPrivatePki(path: Path): PrivatePkiLifecycleRequest = readRequest(path)
        private fun spec(request: HttpsLifecycleRequest): PrivateDeploymentSpec {
            val spec = PrivateDeployment.read(Path.of(request.runtimeManifest))
            PrivateDeployment.validate(spec)
            require(spec.store == RuntimeStore.CANONICAL_V2 && spec.ingress != null)
            NamespaceCaddyTransport.checkBinding(request.binding, spec)
            return spec
        }
        fun real(): CaddyLifecycle = CaddyLifecycle({ request ->
            val spec = spec(request)
            require(request.binding.site.matches(Regex("[a-z][a-z0-9-]{0,39}")))
            val base = privateControlDirectory(Path.of("/mnt/media/p0-v3/caddy-https"))
            val root = privateControlDirectory(base.resolve(request.binding.site))
            CaddyHttpsProvisioner.inRuntime(root, request.binding, spec, request.runtimeFingerprint)
        }, { request ->
            val spec = spec(request)
            val runtime = PrivateDeployment.real(mapOf(spec.name to request.runtimeFingerprint))
            PublicHttp01Observation(request.binding.approvedHosts) { port -> runtime.ingressPortOwner(spec, request.runtimeFingerprint, port) }
        })
        fun privatePki(request: PrivatePkiLifecycleRequest,
            authority: (String, String) -> ManagedPrivatePki = { site, name ->
                val base = privateControlDirectory(Path.of("/mnt/media/p0-v3/private-pki"))
                val siteRoot = privateControlDirectory(base.resolve(site))
                ManagedPrivatePki.real(site, name, privateControlDirectory(siteRoot.resolve(name)))
            }): PrivatePkiLifecycleResult {
            require(request.schemaVersion == 1 && request.action in setOf("initialize", "issue", "renew") &&
                listOf(request.site, request.authority).all { it.matches(Regex("[a-z][a-z0-9-]{0,39}")) } &&
                request.operation.matches(Regex("pki-[a-f0-9]{16}")))
            when (request.action) {
                "initialize" -> require(request.profile == null && request.previousOperation == null && request.previousSha256 == null)
                "issue" -> require(request.profile != null && request.previousOperation == null && request.previousSha256 == null)
                "renew" -> require(request.profile == null && request.previousOperation?.matches(Regex("pki-[a-f0-9]{16}")) == true &&
                    request.previousSha256?.matches(Regex("[a-f0-9]{64}")) == true)
            }
            val signer = authority(request.site, request.authority)
            if (request.action == "initialize") return PrivatePkiLifecycleResult(request.operation, signer.initialize(request.operation))
            val issue = if (request.action == "issue") signer.issue(request.operation, requireNotNull(request.profile))
                else signer.renew(request.operation, requireNotNull(request.previousOperation), requireNotNull(request.previousSha256))
            return PrivatePkiLifecycleResult(issue.operation, issue.caSha256,
                ReleaseLocks.sha256(json.encodeToString(issue).toByteArray()), issue.renewAfter)
        }
    }
    fun execute(request: HttpsLifecycleRequest): HttpsProvisionResult {
        require(request.schemaVersion == 1 && request.action in setOf("stage-http01", "provision", "reconcile") &&
            request.operation.matches(Regex("r-[a-f0-9]{12}")) && request.runtimeFingerprint.matches(Regex("[a-f0-9]{64}")))
        if (request.action == "reconcile") require(request.expectedIntent?.matches(Regex("[a-f0-9]{64}")) == true &&
            request.expectedConfiguration == null && request.nonces.isEmpty() && request.environment == null)
        else require(request.expectedConfiguration?.matches(Regex("[a-f0-9]{64}")) == true && request.expectedIntent == null &&
            request.nonces.keys == request.binding.approvedHosts &&
            (if (request.action == "provision") request.environment in AcmeEnvironment.entries.map { it.name } else request.environment == null))
        val controller = control(request)
        return when (request.action) {
            "stage-http01" -> controller.stageHttp01(request.operation, requireNotNull(request.expectedConfiguration), request.nonces,
                observation(request)::portOwner)
            "provision" -> controller.provision(request.operation, requireNotNull(request.expectedConfiguration), request.nonces,
                AcmeEnvironment.valueOf(requireNotNull(request.environment)), observation(request))
            else -> controller.reconcile(request.operation, requireNotNull(request.expectedIntent))
        }
    }
}

internal fun privateControlDirectory(path: Path): Path {
    require(path.isAbsolute && path.normalize() == path && path.parent.toRealPath() == path.parent)
    if (!Files.exists(path, NOFOLLOW_LINKS)) {
        Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(path.parent)
    }
    ReleasePrivateFiles.directory(path)
    return path
}
