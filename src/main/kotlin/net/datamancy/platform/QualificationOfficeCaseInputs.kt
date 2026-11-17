package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.net.URI
import java.security.cert.CertificateFactory
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.*

/** Source account/callback projection only. C1 authenticates the selected source pin and
 * completed WEB predecessor before calling; the native QClient owns mounts and effects. */
internal data class QualificationOfficeInputs(val context: Map<String, JsonElement>,
    val privateFiles: List<ActivationInput>)

internal object QualificationOfficeCaseInputs {
    private val json = Json { isLenient = false }
    private val digest = Regex("[a-f0-9]{64}")
    private val roles = listOf("owner", "reader", "outsider")
    private val officeHosts = mapOf("office.datamancy.net" to "onlyoffice",
        "files.datamancy.net" to "seafile")
    private const val nativeApiHost = "files-native.datamancy.net"

    /** Exactly the graph-declared Seafile app-token API, never the GROUP browser host.
     * The selected Caddy's owner-locked current SNI/PKIX readback supplies both IP
     * and CA. Stage only its singleton reviewed CA, not a new DNS alias or route. */
    fun nativeApi(caseDir: Path, target: GenerationBundle, bundleSha256: String,
        phase: String, isolationProofSha256: String?, proposed: JsonObject): QualificationOfficeInputs {
        require(phase in setOf("INSTALL","RESTORE") && target.request.store == RuntimeStore.CANONICAL_V2 &&
            target.request.id.matches(Regex("q-[a-f0-9]{12}")) && bundleSha256.matches(digest) &&
            target.members.size == 1 && (target.recoverySourceKopia != null) == (phase == "RESTORE") &&
            ((phase == "INSTALL" && isolationProofSha256 == null) ||
                (phase == "RESTORE" && isolationProofSha256?.matches(digest) == true)) &&
            "nativeApi" !in proposed && caseDir.isAbsolute && caseDir.normalize() == caseDir)
        val pin = target.members.single()
        require(pin.spec.name == "${target.request.id}-v2" && pin.spec.fragmentBinding?.phase == phase)
        val manifest = QualificationPrivateTls.selectedManifest(requireNotNull(pin.spec.fragmentBinding))
        val binding = CanonicalPrivateIngressTrust.requireHost(manifest,pin.spec,"seafile",nativeApiHost)
        require(binding.mode == PrivateIngressTrustMode.POST_START_CADDY_CA && binding.process == "seafile-files")
        val generation = GenerationRuntime.BASE.resolve(target.request.id)
        val native = CanonicalCaddyServedLeafReadback(generation,target,bundleSha256,manifest)
        val receipt = native.verify(nativeApiHost)
        val observedBytes = ReleasePrivateFiles.read(Path.of(receipt.path),8192)
        require(ReleaseLocks.sha256(observedBytes) == receipt.sha256)
        val served = json.decodeFromString<CaddyServedLeafReadback>(observedBytes.decodeToString())
        val endpoint = native.verifiedPrivateEndpoint(nativeApiHost)
        val address = QualificationRssIngressSource.address(endpoint,requireNotNull(URI(endpoint).host),
            served.privateNetwork,served.caSha256,served.caSha256,served.servedLeafDerSha256,
            served.servedLeafDerSha256)
        require(served.generation == target.request.id && served.bundleSha256 == bundleSha256 &&
            served.member == pin.spec.name && served.fingerprint == pin.runtimeFingerprint &&
            served.hostname == nativeApiHost && served.product == "seafile" &&
            served.routePolicies == binding.routePolicies && served.mode == binding.mode &&
            nativeApiHost in served.exactDnsSans && served.caddyCid.matches(digest))
        val root = CanonicalCaddyCaseTlsBundle(generation,target,bundleSha256,manifest)
            .verify(setOf(nativeApiHost))
        val bytes = ReleasePrivateFiles.read(Path.of(root.path),65536)
        require(ReleaseLocks.sha256(bytes) == root.sha256 &&
            bytes.decodeToString(throwOnInvalidSequence=true).contains("-----BEGIN CERTIFICATE-----") &&
            ReleaseLocks.sha256(bytes) == served.caSha256)
        val directory = caseDir.resolve("owner-proofs")
        ReleasePrivateFiles.directory(caseDir)
        if (!Files.exists(directory,NOFOLLOW_LINKS)) {
            Files.createDirectory(directory,PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(caseDir)
        }
        ReleasePrivateFiles.directory(directory)
        val staged = directory.resolve("files-native-api-ca.pem")
        ReleasePrivateFiles.save(staged,bytes)
        val context = buildJsonObject {
            put("originalHost",nativeApiHost); put("port",443); put("address",address)
            put("caFile","/case/owner-proofs/files-native-api-ca.pem")
            put("caSha256",root.sha256); put("leafSha256",served.servedLeafDerSha256)
            put("generationId",target.request.id); put("bundleSha256",bundleSha256)
            if (phase == "RESTORE") put("isolationProofSha256",requireNotNull(isolationProofSha256))
        }
        return QualificationOfficeInputs(mapOf("nativeApi" to context),listOf(ActivationInput(staged.toString(),root.sha256)))
    }

    /** Called by C1 only for its isolated RESTORE target, after current Caddy SNI/PKIX
     * readback and selected two-host trust bundle have been verified. No caller IP,
     * predicted ingress or separately assembled topology is an input. */
    fun restoreBridges(target: GenerationBundle, bundleSha256: String, roots: ActivationInput,
        isolationProofSha256: String, proposed: JsonObject,
        read: (Path) -> ByteArray = { ReleasePrivateFiles.read(it, 65536) }): Map<String,JsonElement> {
        require(target.recoverySourceKopia != null && target.members.size == 1 &&
            target.request.store == RuntimeStore.CANONICAL_V2 &&
            target.request.id.matches(Regex("q-[a-f0-9]{12}")) && bundleSha256.matches(digest) &&
            isolationProofSha256.matches(digest) && roots.sha256.matches(digest) &&
            listOf("bridge", "bridges", "targetIsolationProofSha256").none { it in proposed })
        val pin = target.members.single()
        require(pin.spec.name == "${target.request.id}-v2" &&
            pin.spec.fragmentBinding?.phase == "RESTORE")
        val manifest = QualificationPrivateTls.selectedManifest(requireNotNull(pin.spec.fragmentBinding))
        val bindings = officeHosts.mapValues { (host, product) ->
            CanonicalPrivateIngressTrust.requireHost(manifest,pin.spec,product,host)
        }
        val native = CanonicalCaddyServedLeafReadback(GenerationRuntime.BASE.resolve(target.request.id),
            target,bundleSha256,manifest)
        val observations = officeHosts.keys.associateWith { host ->
            val verified = native.verify(host)
            val bytes = read(Path.of(verified.path))
            require(ReleaseLocks.sha256(bytes) == verified.sha256)
            json.decodeFromString<CaddyServedLeafReadback>(
                bytes.decodeToString(throwOnInvalidSequence = true))
        }
        val endpoints = officeHosts.keys.associateWith(native::verifiedPrivateEndpoint)
        val issuers = bindings.mapValues { (_, binding) ->
            require(binding.mode == PrivateIngressTrustMode.GRAPH_ISSUED_LEAF)
            source(pin,requireNotNull(binding.caInput),read)
        }
        val leafShas = bindings.mapValues { (_, binding) ->
            val pem = source(pin,requireNotNull(binding.leafInput),read)
            ReleaseLocks.sha256(CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(pem)).encoded)
        }
        val nativeBinding = CanonicalPrivateIngressTrust.requireHost(manifest,pin.spec,"seafile",nativeApiHost)
        require(nativeBinding.mode == PrivateIngressTrustMode.POST_START_CADDY_CA)
        val nativeReceipt = native.verify(nativeApiHost)
        val nativeBytes = read(Path.of(nativeReceipt.path))
        require(ReleaseLocks.sha256(nativeBytes) == nativeReceipt.sha256)
        val nativeObserved = json.decodeFromString<CaddyServedLeafReadback>(nativeBytes.decodeToString())
        val nativeRoot = CanonicalCaddyCaseTlsBundle(GenerationRuntime.BASE.resolve(target.request.id),
            target,bundleSha256,manifest).verify(setOf(nativeApiHost))
        val nativePem = read(Path.of(nativeRoot.path))
        require(ReleaseLocks.sha256(nativePem) == nativeRoot.sha256 &&
            nativeObserved.caSha256 == nativeRoot.sha256 &&
            nativeObserved.servedLeafDerSha256.matches(digest))
        val rootsBytes = read(Path.of(roots.path))
        require(ReleaseLocks.sha256(rootsBytes) == roots.sha256)
        val pairPem = issuers.toSortedMap().values.map {
            it.decodeToString(throwOnInvalidSequence = true).trimEnd()
        }.distinct().joinToString("\n",postfix="\n").encodeToByteArray()
        // Office Android's selected guest pair omits native API trust; its
        // native client receives the independently verified singleton above.
        // WEB/HEADLESS C1 selects the graph-authorized triple instead.
        val selectedNative = if (rootsBytes.contentEquals(pairPem)) null else nativePem
        return validatedRestoreBridges(target.request.id,bundleSha256,pin,bindings,observations,
            endpoints,issuers,leafShas,rootsBytes,roots.sha256,isolationProofSha256,selectedNative)
    }

    /** Isolated deterministic check for foreign target, CA and swapped host mapping faults.
     * C1 supplies every parameter above from the selected graph and live owner readbacks. */
    internal fun validatedRestoreBridges(targetGeneration: String, bundleSha256: String,
        pin: GenerationPin, bindings: Map<String,PrivateIngressTrustBinding>,
        observations: Map<String,CaddyServedLeafReadback>, endpoints: Map<String,String>,
        issuers: Map<String,ByteArray>, leafShas: Map<String,String>, rootsPem: ByteArray, rootsSha256: String,
        isolationProofSha256: String, nativeIssuerPem: ByteArray? = null): Map<String,JsonElement> {
        val hosts = officeHosts.keys
        require(bindings.keys == hosts && observations.keys == hosts && endpoints.keys == hosts &&
            issuers.keys == hosts && leafShas.keys == hosts &&
            targetGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            pin.spec.name == "$targetGeneration-v2" &&
            pin.spec.fragmentBinding?.phase == "RESTORE" &&
            bundleSha256.matches(digest) && isolationProofSha256.matches(digest) &&
            rootsSha256.matches(digest) && ReleaseLocks.sha256(rootsPem) == rootsSha256)
        // Identical normalization/order to CanonicalCaddyCaseTlsBundle's selected
        // pair: this must be the pinned selected trust PEM, not merely one host CA.
        val selectedPem = issuers + (if (nativeIssuerPem == null) emptyMap() else
            mapOf(nativeApiHost to nativeIssuerPem))
        val expectedPem = selectedPem.toSortedMap().values.map { pem ->
            pem.decodeToString(throwOnInvalidSequence = true).trimEnd()
        }.distinct().joinToString("\n",postfix="\n").encodeToByteArray()
        require(rootsPem.contentEquals(expectedPem) && rootsPem.size in 512..65536)
        val bridges = hosts.associateWith { host ->
            val binding = bindings.getValue(host); val observation = observations.getValue(host)
            val endpoint = URI(endpoints.getValue(host))
            val address = QualificationRssIngressSource.address(endpoints.getValue(host),
                requireNotNull(endpoint.host),observation.privateNetwork,observation.caSha256,
                ReleaseLocks.sha256(issuers.getValue(host)),observation.servedLeafDerSha256,
                leafShas.getValue(host))
            require(binding.hostname == host && binding.product == officeHosts.getValue(host) &&
                binding.mode == PrivateIngressTrustMode.GRAPH_ISSUED_LEAF &&
                observation.generation == targetGeneration && observation.bundleSha256 == bundleSha256 &&
                observation.member == pin.spec.name && observation.fingerprint == pin.runtimeFingerprint &&
                observation.hostname == host && observation.product == binding.product &&
                observation.routePolicies == binding.routePolicies && observation.mode == binding.mode &&
                host in observation.exactDnsSans && observation.caddyCid.matches(digest) &&
                observation.privateNetwork == "ingress-control")
            buildJsonObject {
                put("originalHost",host); put("port",443); put("address",address)
                put("isolationProofSha256",isolationProofSha256)
            }
        }
        require(observations.values.map { it.caddyCid }.toSet().size == 1 &&
            bridges.values.map { it.getValue("address") }.toSet().size == 1)
        return mapOf("bridge" to bridges.getValue("office.datamancy.net"),
            "bridges" to buildJsonObject { put("files.datamancy.net",bridges.getValue("files.datamancy.net")) })
    }

    private fun source(pin: GenerationPin, file: String, read: (Path) -> ByteArray): ByteArray {
        require(pin.spec.name.matches(Regex("q-[a-f0-9]{12}-v2")) &&
            pin.inputHashes.containsKey(file) && pin.spec.store == RuntimeStore.CANONICAL_V2)
        val bytes = read(PrivateDeployment.BASE.resolve(pin.spec.name).resolve(file))
        require(bytes.size in 1..65536)
        require(ReleaseLocks.sha256(bytes) == pin.inputHashes.getValue(file)) {
            "Office original source input changed"
        }
        return bytes
    }

    /** Existing original Seafile provisioner supplies both native and Android users.
     * No separate Android enrollment issuer or device revision is invented. */
    fun prepareSeafile(caseDir: Path, phase: String, surface: String, sourcePin: GenerationPin,
        proposed: JsonObject,
        read: (Path) -> ByteArray = { ReleasePrivateFiles.read(it,65536) }): QualificationOfficeInputs {
        require(phase in setOf("INSTALL", "RESTORE") && surface in setOf("HEADLESS", "ANDROID", "WEB"))
        val users = json.parseToJsonElement(source(sourcePin,"seafile-users.json",read)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(users.keys == roles.toSet() && roles.all { users.getValue(it).jsonPrimitive.content.matches(digest) } &&
            roles.map { users.getValue(it).jsonPrimitive.content }.toSet().size == roles.size)
        val provisioner = source(sourcePin,"seafile-users.py",read)
            .decodeToString(throwOnInvalidSequence = true)
        require("email=role+'@localhost.invalid'" in provisioner &&
            "ccnet_api.add_emailuser(email,password" in provisioner)
        val accounts = buildJsonObject { roles.forEach { role -> put(role,buildJsonObject {
            put("username","$role@localhost.invalid"); put("password",users.getValue(role))
        }) } }
        val scoped = buildJsonObject { listOf("owner","outsider").forEach { put(it,accounts.getValue(it)) } }
        val fields = when (surface) {
            "HEADLESS" -> mapOf("credentialsFile" to accounts)
            "WEB" -> mapOf("scopedAccountFile" to accounts)
            else -> mapOf("credentialsFile" to scoped,"nativeCredentialsFile" to accounts)
        }
        require(fields.keys.none { it in proposed } &&
            "deviceAccountRevisionProofSha256" !in proposed &&
            "sourceAccountRevisionProofSha256" !in proposed)
        val root = caseDir.resolve("owner-proofs")
        ReleasePrivateFiles.directory(caseDir)
        if (!Files.exists(root,NOFOLLOW_LINKS)) {
            Files.createDirectory(root,PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(caseDir)
        }
        ReleasePrivateFiles.directory(root)
        val pins = fields.map { (field, value) ->
            val path = root.resolve("seafile-$field.json")
            val bytes = value.toString().encodeToByteArray()
            ReleasePrivateFiles.save(path,bytes)
            field to ActivationInput(path.toString(),ReleaseLocks.sha256(bytes))
        }.toMap()
        return QualificationOfficeInputs(pins.mapValues { JsonPrimitive(it.value.path) },pins.values.toList())
    }

    /** `sourcePin` is C1's authenticated INSTALL pin, or its authenticated stopped-source
     * Kopia pin for RESTORE. `originalWebOracle` is the C1-verified original WEB oracle,
     * never the caller's context or a new current-phase document. */
    fun prepare(caseDir: Path, phase: String, surface: String, sourcePin: GenerationPin,
        originalWebOracle: JsonObject?, proposed: JsonObject,
        read: (Path) -> ByteArray = { ReleasePrivateFiles.read(it, 65536) }): QualificationOfficeInputs {
        require(phase in setOf("INSTALL", "RESTORE") && surface in setOf("WEB", "HEADLESS", "ANDROID"))
        require(caseDir.isAbsolute && caseDir.normalize() == caseDir)
        ReleasePrivateFiles.directory(caseDir)
        val users = json.parseToJsonElement(source(sourcePin, "seafile-users.json", read).decodeToString(
            throwOnInvalidSequence = true)).jsonObject
        require(users.keys == roles.toSet() && roles.all { role ->
            users.getValue(role).jsonPrimitive.content.matches(digest)
        } && roles.map { users.getValue(it).jsonPrimitive.content }.toSet().size == 3)
        val provisioner = source(sourcePin, "seafile-users.py", read).decodeToString(throwOnInvalidSequence = true)
        require("email=role+'@localhost.invalid'" in provisioner &&
            "ccnet_api.add_emailuser(email,password" in provisioner) {
            "Original Seafile role-to-account provisioner changed"
        }
        val accounts = buildJsonObject {
            for (role in roles) put(role, buildJsonObject {
                put("username", "$role@localhost.invalid")
                put("password", users.getValue(role).jsonPrimitive.content)
            })
        }
        if (surface != "WEB" || phase == "RESTORE") {
            val oracle = requireNotNull(originalWebOracle) { "Completed original Office WEB oracle required" }
            require(oracle.keys == setOf("documentId", "documentName", "documentSha256",
                "seafileRepositoryId", "owner", "editor", "deniedUser", "ownerMarker", "editorMarker") &&
                oracle.getValue("seafileRepositoryId").jsonPrimitive.content
                    .matches(Regex("[a-f0-9-]{36}")) &&
                oracle.getValue("documentName").jsonPrimitive.content
                    .matches(Regex("p0v3-[a-f0-9]{32}\\.docx")) &&
                oracle.getValue("documentId").jsonPrimitive.content ==
                    oracle.getValue("seafileRepositoryId").jsonPrimitive.content + ":/" +
                    oracle.getValue("documentName").jsonPrimitive.content &&
                oracle.getValue("ownerMarker").jsonPrimitive.content
                    .matches(Regex("Native owner edit [a-f0-9]{24}")) &&
                oracle.getValue("editorMarker").jsonPrimitive.content
                    .matches(Regex("Native second editor [a-f0-9]{24}")) &&
                oracle.getValue("owner").jsonPrimitive.content == "owner@localhost.invalid" &&
                oracle.getValue("editor").jsonPrimitive.content == "reader@localhost.invalid" &&
                oracle.getValue("deniedUser").jsonPrimitive.content == "outsider@localhost.invalid" &&
                oracle.getValue("documentSha256").jsonPrimitive.content.matches(digest)) {
                "Original Office WEB principals/document differ from sealed Seafile accounts"
            }
        } else require(originalWebOracle == null) { "Office WEB INSTALL cannot inherit an oracle" }

        val fields = when (surface) {
            "WEB" -> listOf("seafileAccountsFile")
            "HEADLESS" -> listOf("seafileCredentialsFile", "officeJwtSecretFile")
            else -> listOf("scopedAccountFile", "nativeCredentialsFile")
        }
        require(fields.none { it in proposed } &&
            "sourceOfficeOracle" !in proposed &&
            "seafileInstalledClientReceiptSha256" !in proposed &&
            "ownerBridgeSha256" !in proposed && "ownerAdoptionSha256" !in proposed) {
            "Office owner input cannot be caller-proposed or predicted before guest start"
        }
        val scoped = buildJsonObject {
            for ((role, original) in listOf("owner" to "owner", "editor" to "reader",
                    "deniedUser" to "outsider")) put(role, accounts.getValue(original))
        }
        val secrets = if (surface == "HEADLESS") {
            val settings = source(sourcePin, "seafile-seahub-settings.py", read)
                .decodeToString(throwOnInvalidSequence = true)
            val keys = Regex("(?m)^\\s*ONLYOFFICE_JWT_SECRET='([a-f0-9]{64})'\\s*$")
                .findAll(settings).toList()
            require(keys.size == 1) { "Original callback JWT absent or ambiguous" }
            val key = keys.single().groupValues[1]
            val office = json.parseToJsonElement(source(sourcePin, "onlyoffice-office.json", read)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val secret = office.getValue("services").jsonObject.getValue("CoAuthoring").jsonObject
                .getValue("secret").jsonObject
            require(listOf("browser", "inbox", "outbox").all { purpose ->
                secret.getValue(purpose).jsonObject.getValue("string").jsonPrimitive.content == key
            }) { "Office callback key differs from selected original Seafile/Office inputs" }
            key
        } else null
        val content = when (surface) {
            "WEB" -> mapOf("seafileAccountsFile" to accounts.toString().encodeToByteArray())
            "HEADLESS" -> mapOf("seafileCredentialsFile" to accounts.toString().encodeToByteArray(),
                "officeJwtSecretFile" to (requireNotNull(secrets) + "\n").encodeToByteArray())
            else -> mapOf("scopedAccountFile" to scoped.toString().encodeToByteArray(),
                "nativeCredentialsFile" to accounts.toString().encodeToByteArray())
        }
        // Complete all source, principal and callback checks before any projection effect.
        val directory = caseDir.resolve("owner-proofs")
        if (!Files.exists(directory, NOFOLLOW_LINKS)) {
            Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(caseDir)
        }
        ReleasePrivateFiles.directory(directory)
        val outputs = content.map { (field, bytes) ->
            val path = directory.resolve("office-" + field + ".json")
            ReleasePrivateFiles.save(path, bytes)
            field to ActivationInput(path.toString(), ReleaseLocks.sha256(bytes))
        }.toMap()
        return QualificationOfficeInputs(outputs.mapValues { JsonPrimitive(it.value.path) }, outputs.values.toList())
    }

    /** C1 invokes this only AFTER its native guest audit, installed Seadroid audit and
     * guest-trust gate have completed. Readbacks bind existing receipts, not future hashes. */
    fun bindPostStart(caseDir: Path, context: JsonObject, invocationId: String,
        generationId: String): String {
        ReleasePrivateFiles.directory(caseDir)
        val path = caseDir.resolve("owner-proofs/seafile-installed-client.json")
        require(context.getValue("seafileInstalledClientReceiptFile").jsonPrimitive.content == path.toString() &&
            "seafileInstalledClientReceiptSha256" !in context && "ownerBridgeSha256" !in context &&
            "ownerAdoptionSha256" !in context)
        val guest = json.parseToJsonElement(ReleasePrivateFiles.read(
            caseDir.resolve("qualification-guest-gate.json"), 65536).decodeToString()).jsonObject
        val trust = json.parseToJsonElement(ReleasePrivateFiles.read(
            caseDir.resolve("qualification-guest-trust-gate.json"), 65536).decodeToString()).jsonObject
        val bytes = ReleasePrivateFiles.read(path, 65536)
        val receipt = json.parseToJsonElement(bytes.decodeToString()).jsonObject
        val sha = ReleaseLocks.sha256(bytes)
        require(guest.keys == setOf("invocationId", "containerId", "ownerBridgeSha256") &&
            trust.keys == setOf("invocationId", "generationId", "caSha256", "ownerBridgeSha256",
                "ownerAdoptionSha256", "seafileInstalledClientReceiptSha256") &&
            receipt.keys == setOf("schemaVersion", "invocationId", "generationId", "api", "serial",
                "packageName", "apkSha256", "signerSha256", "guestCaAdoptionSha256") &&
            guest.getValue("invocationId").jsonPrimitive.content == invocationId &&
            trust.getValue("invocationId").jsonPrimitive.content == invocationId &&
            receipt.getValue("invocationId").jsonPrimitive.content == invocationId &&
            trust.getValue("generationId").jsonPrimitive.content == generationId &&
            receipt.getValue("generationId").jsonPrimitive.content == generationId &&
            receipt.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            trust.getValue("caSha256") == context.getValue("caSha256") &&
            trust.getValue("ownerBridgeSha256") == guest.getValue("ownerBridgeSha256") &&
            trust.getValue("ownerAdoptionSha256") == receipt.getValue("guestCaAdoptionSha256") &&
            trust.getValue("seafileInstalledClientReceiptSha256").jsonPrimitive.content == sha &&
            receipt.getValue("api") == context.getValue("android").jsonObject.getValue("api") &&
            receipt.getValue("serial") == context.getValue("android").jsonObject.getValue("serial") &&
            receipt.getValue("packageName").jsonPrimitive.content == "com.seafile.seadroid2" &&
            receipt.getValue("apkSha256").jsonPrimitive.content ==
                context.getValue("seafileFixtureApkSha256").jsonPrimitive.content &&
            receipt.getValue("signerSha256").jsonPrimitive.content.matches(digest) &&
            listOf("containerId", "ownerBridgeSha256").all {
                guest.getValue(it).jsonPrimitive.content.matches(digest)
            } && listOf("caSha256", "ownerAdoptionSha256").all {
                trust.getValue(it).jsonPrimitive.content.matches(digest)
            }) { "Office original post-start owner guest, Seadroid or CA receipt changed" }
        return sha
    }
}
