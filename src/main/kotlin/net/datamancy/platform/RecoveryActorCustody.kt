package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Protected original INSTALL actor inputs, never an account-creation or credential-rotation path.
 * The owner supplies independently verified original issuance readbacks before staging. */
@Serializable internal data class RecoveryActorNativeIssuanceProof(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val originalContextsSha256: String,
    val service: String, val issuerKind: String, val credentialSha256: Map<String, String>,
    val ownerSubject: String, val outsiderSubject: String)

@Serializable internal data class RecoveryActorIssuanceReadback(val schemaVersion: Int = 1,
    val sourceGeneration: String, val sourceBundleSha256: String, val originalContextsSha256: String,
    val service: String, val issuerKind: String, val credentialSha256: Map<String, String>,
    val originalOwner: String, val originalOutsider: String, val nativeEvidence: ActivationInput)

@Serializable internal data class RecoveryActorCustodyManifest(val schemaVersion: Int = 1,
    val sourceGeneration: String, val sourceBundleSha256: String, val originalContextsSha256: String,
    val credentials: Map<String, String>, val issuanceReadbackSha256: Map<String, String>)

internal object RecoveryActorCustody {
    private val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
    private val services = setOf("bookstack", "erpnext", "firefly-iii", "forgejo", "donetick")
    private val names = services.flatMap { listOf("$it.owner", "$it.outsider") }.toSet() +
        setOf("bookstack.api-owner", "bookstack.api-outsider", "donetick.appNonMember",
            "donetick.sso-owner", "donetick.sso-appNonMember", "donetick.sso-outsider")
    private val hash = Regex("[a-f0-9]{64}")
    private val generation = Regex("q-[a-f0-9]{12}")
    private fun file(key: String) = "qualification-actors/${key.replace('.', '-')}.json"
    private fun issuance(service: String) = "qualification-actors/issuance-$service.json"
    fun allowed(name: String) = name == "controller/qualification-actors/manifest.json" ||
        names.any { name == "controller/${file(it)}" } ||
        services.any { name == "controller/${issuance(it)}" }
    private fun privateBytes(path: Path): ByteArray {
        val bytes = ReleasePrivateFiles.read(path, 16384)
        require(bytes.isNotEmpty() && bytes.size <= 16384)
        return bytes
    }
    private fun validateCredential(key: String, bytes: ByteArray) {
        val obj = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        if (key.startsWith("bookstack.api-")) require(obj.keys == setOf("tokenId", "secret") &&
            obj.getValue("tokenId").jsonPrimitive.content.matches(Regex("p0v3-[a-f0-9]{32}")) &&
            obj.getValue("secret").jsonPrimitive.content.matches(hash))
        else require(obj.keys == setOf("username", "password") &&
            obj.getValue("username").jsonPrimitive.content.matches(Regex("[a-zA-Z0-9_.@-]{3,128}")) &&
            obj.getValue("password").jsonPrimitive.content.matches(hash))
    }
    private fun valid(record: RecoveryActorCustodyManifest, root: Path, source: Boolean) {
        require(record.schemaVersion == 1 && record.sourceGeneration.matches(generation) &&
            record.sourceBundleSha256.matches(hash) && record.originalContextsSha256.matches(hash) &&
            record.credentials.keys == names && record.credentials.values.all(hash::matches) &&
            record.issuanceReadbackSha256.keys == services && record.issuanceReadbackSha256.values.all(hash::matches))
        if (source) require(root.fileName.toString() == record.sourceGeneration &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)) == record.sourceBundleSha256)
        record.issuanceReadbackSha256.forEach { (service, digest) ->
            val bytes = privateBytes(root.resolve(issuance(service)))
            require(ReleaseLocks.sha256(bytes) == digest) { "Original actor issuance evidence changed" }
            val readback = json.decodeFromString<RecoveryActorIssuanceReadback>(
                bytes.decodeToString(throwOnInvalidSequence = true))
            require(readback.schemaVersion == 1 && readback.service == service &&
                readback.sourceGeneration == record.sourceGeneration &&
                readback.sourceBundleSha256 == record.sourceBundleSha256 &&
                readback.originalContextsSha256 == record.originalContextsSha256 &&
                readback.credentialSha256 == record.credentials.filterKeys { it.startsWith("$service.") })
            if (source) {
                require(Path.of(readback.nativeEvidence.path) ==
                    root.resolve("qualification-issuance-native/$service.json"))
                val nativeBytes = privateBytes(Path.of(readback.nativeEvidence.path))
                require(ReleaseLocks.sha256(nativeBytes) == readback.nativeEvidence.sha256)
                val native = json.decodeFromString<RecoveryActorNativeIssuanceProof>(
                    nativeBytes.decodeToString(throwOnInvalidSequence = true))
                require(native.schemaVersion == 1 && native.generation == record.sourceGeneration &&
                    native.bundleSha256 == record.sourceBundleSha256 &&
                    native.originalContextsSha256 == record.originalContextsSha256 &&
                    native.service == service && native.issuerKind == readback.issuerKind &&
                    native.credentialSha256 == readback.credentialSha256 &&
                    native.ownerSubject == readback.originalOwner && native.outsiderSubject == readback.originalOutsider &&
                    native.ownerSubject != native.outsiderSubject)
            }
        }
        record.credentials.forEach { (key, digest) ->
            val bytes = privateBytes(root.resolve(file(key)))
            require(ReleaseLocks.sha256(bytes) == digest) { "Original actor grant changed" }
            validateCredential(key, bytes)
        }
        services.forEach { service ->
            val roles = if (service == "donetick") listOf("owner", "appNonMember", "outsider", "sso-owner", "sso-appNonMember", "sso-outsider") else listOf("owner", "outsider")
            val actors = roles.map { role -> json.parseToJsonElement(privateBytes(root.resolve(file("$service.$role")))
                .decodeToString(throwOnInvalidSequence = true)).jsonObject }
            require(actors.take(2).map { it.getValue("username") }.toSet().size == 2 &&
                (service != "donetick" || actors.take(3).map { it.getValue("username") }.toSet().size == 3 &&
                    actors[0].getValue("username").jsonPrimitive.content == "owner" &&
                    actors[1].getValue("username").jsonPrimitive.content == "app-nonmember" &&
                    actors[2].getValue("username").jsonPrimitive.content == "outsider" &&
                    actors[3].getValue("username") == actors[0].getValue("username") &&
                    actors[4].getValue("username") == actors[1].getValue("username") &&
                    actors[5].getValue("username") == actors[2].getValue("username")) &&
                actors.map { it.getValue("password") }.toSet().size == roles.size) {
                "Original actor identities and credentials must be distinct"
            }
        }
        val apiOwner = json.parseToJsonElement(privateBytes(root.resolve(file("bookstack.api-owner"))).decodeToString(throwOnInvalidSequence = true)).jsonObject
        val apiOutsider = json.parseToJsonElement(privateBytes(root.resolve(file("bookstack.api-outsider"))).decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(apiOwner.getValue("tokenId") != apiOutsider.getValue("tokenId") &&
            apiOwner.getValue("secret") != apiOutsider.getValue("secret")) { "BookStack outsider shares original owner API grant" }
    }
    /** Called by core once, under the original generation owner lock AFTER verified issuer readback
     * and BEFORE whole-generation capture. No original credential body goes into the manifest. */
    fun stage(sourceRoot: Path, sourceBundleSha256: String, contexts: ActivationInput,
        issuanceReadbacks: Map<String, ActivationInput>): RecoveryActorCustodyManifest {
        require(sourceRoot.fileName.toString().matches(generation) && sourceBundleSha256.matches(hash) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(sourceRoot.resolve("bundle.json"), 4194304)) == sourceBundleSha256 &&
            issuanceReadbacks.keys == services)
        require(contexts.sha256.matches(hash))
        val sourceBytes = ReleasePrivateFiles.read(Path.of(contexts.path), 4194304)
        require(sourceBytes.isNotEmpty() && ReleaseLocks.sha256(sourceBytes) == contexts.sha256)
        val map = json.parseToJsonElement(sourceBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val issuerBytes = issuanceReadbacks.mapValues { (_, input) ->
            val bytes = privateBytes(Path.of(input.path))
            require(ReleaseLocks.sha256(bytes) == input.sha256 && input.sha256.matches(hash))
            bytes
        }
        map.filterKeys { it.startsWith("donetick--") }.values.forEach {
            DonetickTripleActorContext.requireContext(it.jsonObject)
        }
        val originals = names.associateWith { name ->
            val (service, role) = name.split('.', limit = 2)
            val key = when (role) {
                "owner" -> "ownerCredentialFile"
                "outsider" -> "outsiderCredentialFile"
                "appNonMember" -> "appNonMemberCredentialFile"
                "sso-owner" -> "ownerSsoCredentialFile"
                "sso-appNonMember" -> "appNonMemberSsoCredentialFile"
                "sso-outsider" -> "gatewayOutsiderSsoCredentialFile"
                "api-owner" -> "bookstackApiGrantFile"
                else -> "outsiderBookstackApiGrantFile"
            }
            val candidates = map.filterKeys { it.startsWith("$service--") }.values.mapNotNull { case ->
                case.jsonObject[key]?.jsonPrimitive?.content
            }.distinct()
            require(candidates.size == 1) { "Original $name grant must have one issued source path" }
            privateBytes(Path.of(candidates.single())).also { validateCredential(name, it) }
        }
        issuerBytes.forEach { (service, bytes) ->
            val issuer = json.decodeFromString<RecoveryActorIssuanceReadback>(
                bytes.decodeToString(throwOnInvalidSequence = true))
            val related = names.filter { it.startsWith("$service.") }.toSet()
            val owner = json.parseToJsonElement(originals.getValue("$service.owner")
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val outsider = json.parseToJsonElement(originals.getValue("$service.outsider")
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val expectedKind = mapOf("bookstack" to "native-bookstack-grant-readback",
                "erpnext" to "native-erp-actor-readback", "firefly-iii" to "native-finance-credential-issuance",
                "forgejo" to "native-forgejo-actor-readback", "donetick" to "native-donetick-actor-readback").getValue(service)
            val nativeBytes = privateBytes(Path.of(issuer.nativeEvidence.path))
            val native = json.decodeFromString<RecoveryActorNativeIssuanceProof>(
                nativeBytes.decodeToString(throwOnInvalidSequence = true))
            if (service == "donetick") {
                val app = json.parseToJsonElement(originals.getValue("donetick.appNonMember")
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                val ssoOwner = json.parseToJsonElement(originals.getValue("donetick.sso-owner")
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                val ssoApp = json.parseToJsonElement(originals.getValue("donetick.sso-appNonMember")
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                val ssoGateway = json.parseToJsonElement(originals.getValue("donetick.sso-outsider")
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                require(listOf(owner, app, outsider).map { it.getValue("username") }.toSet().size == 3 &&
                    listOf(owner, app, outsider).map { it.getValue("password") }.toSet().size == 3 &&
                    ssoOwner.getValue("username") == owner.getValue("username") &&
                    ssoApp.getValue("username") == app.getValue("username") &&
                    ssoGateway.getValue("username") == outsider.getValue("username") &&
                    listOf(owner, app, outsider, ssoOwner, ssoApp, ssoGateway)
                        .map { it.getValue("password") }.toSet().size == 6 &&
                    ssoOwner.getValue("password") != ssoApp.getValue("password") &&
                    ssoOwner.getValue("password") != owner.getValue("password") &&
                    ssoApp.getValue("password") != app.getValue("password"))
            }
            require(issuer.schemaVersion == 1 && issuer.service == service && issuer.issuerKind == expectedKind &&
                issuer.sourceGeneration == sourceRoot.fileName.toString() &&
                issuer.sourceBundleSha256 == sourceBundleSha256 &&
                issuer.originalContextsSha256 == contexts.sha256 &&
                issuer.credentialSha256 == related.associateWith { ReleaseLocks.sha256(originals.getValue(it)) } &&
                issuer.originalOwner == owner.getValue("username").jsonPrimitive.content &&
                issuer.originalOutsider == outsider.getValue("username").jsonPrimitive.content &&
                issuer.originalOwner != issuer.originalOutsider &&
                Path.of(issuer.nativeEvidence.path) == sourceRoot.resolve("qualification-issuance-native/$service.json") &&
                issuer.nativeEvidence.sha256.matches(hash) &&
                ReleaseLocks.sha256(nativeBytes) == issuer.nativeEvidence.sha256 &&
                native.schemaVersion == 1 && native.generation == issuer.sourceGeneration &&
                native.bundleSha256 == issuer.sourceBundleSha256 &&
                native.originalContextsSha256 == issuer.originalContextsSha256 &&
                native.service == service && native.issuerKind == expectedKind &&
                native.credentialSha256 == issuer.credentialSha256 &&
                native.ownerSubject == issuer.originalOwner && native.outsiderSubject == issuer.originalOutsider) {
                "Original actor issuance lacks service-bound native evidence and credential subjects"
            }
        }
        val root = sourceRoot.resolve("qualification-actors")
        require(!Files.exists(root, NOFOLLOW_LINKS)) { "Actor grant custody already staged; no issuance replay" }
        Files.createDirectory(root, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(sourceRoot)
        originals.forEach { (key, bytes) -> ReleasePrivateFiles.save(sourceRoot.resolve(file(key)), bytes) }
        issuerBytes.forEach { (service, bytes) -> ReleasePrivateFiles.save(sourceRoot.resolve(issuance(service)), bytes) }
        val record = RecoveryActorCustodyManifest(sourceGeneration = sourceRoot.fileName.toString(),
            sourceBundleSha256 = sourceBundleSha256, originalContextsSha256 = contexts.sha256,
            credentials = originals.mapValues { ReleaseLocks.sha256(it.value) },
            issuanceReadbackSha256 = issuerBytes.mapValues { ReleaseLocks.sha256(it.value) })
        ReleasePrivateFiles.save(root.resolve("manifest.json"), json.encodeToString(record).encodeToByteArray())
        valid(record, sourceRoot, true)
        return record
    }
    fun capture(sourceRoot: Path, payloads: MutableMap<String, Path>): List<String> {
        val root = sourceRoot.resolve("qualification-actors")
        if (!Files.exists(root, NOFOLLOW_LINKS)) return emptyList()
        val record = json.decodeFromString<RecoveryActorCustodyManifest>(privateBytes(root.resolve("manifest.json")).decodeToString())
        valid(record, sourceRoot, true)
        val selected = listOf("controller/qualification-actors/manifest.json") + names.sorted().map { "controller/${file(it)}" } +
            services.sorted().map { "controller/${issuance(it)}" }
        require(Files.list(root).use { it.count() } == selected.size.toLong() && selected.none { it in payloads })
        selected.forEach { name -> payloads[name] = sourceRoot.resolve(name.removePrefix("controller/")) }
        return selected
    }
    fun validate(manifest: CapsuleManifest) {
        val selected = manifest.controllerFiles.filter(::allowed).toSet()
        require(selected.isEmpty() || selected == (listOf("controller/qualification-actors/manifest.json") +
            names.map { "controller/${file(it)}" } + services.map { "controller/${issuance(it)}" }).toSet()) { "Partial protected actor custody" }
    }
    fun verify(root: Path, expectedSource: String, expectedBundle: String): RecoveryActorCustodyManifest {
        val record = json.decodeFromString<RecoveryActorCustodyManifest>(privateBytes(
            root.resolve("qualification-actors/manifest.json")).decodeToString())
        require(record.sourceGeneration == expectedSource && record.sourceBundleSha256 == expectedBundle)
        valid(record, root, root.fileName.toString() == expectedSource)
        return record
    }
    /** Original first-use INSTALL inputs predate enrollment and custody. They are sealed,
     * case-context-pinned source files, never an invented post-native issuance receipt. */
    fun pinInstall(sourceRoot: Path, service: String, original: JsonObject): Pair<JsonObject, List<ActivationInput>> {
        require(service in services && sourceRoot.fileName.toString().matches(generation) &&
            original.keys.containsAll(setOf("ownerCredentialFile", "outsiderCredentialFile")))
        if (service == "donetick") DonetickTripleActorContext.requireContext(original)
        val keys = linkedMapOf("ownerCredentialFile" to "$service.owner",
            "outsiderCredentialFile" to "$service.outsider")
        if (service == "donetick") {
            keys["appNonMemberCredentialFile"] = "donetick.appNonMember"
            keys["ownerSsoCredentialFile"] = "donetick.sso-owner"
            keys["appNonMemberSsoCredentialFile"] = "donetick.sso-appNonMember"
            keys["gatewayOutsiderSsoCredentialFile"] = "donetick.sso-outsider"
        }
        if (service == "bookstack") require(("bookstackApiGrantFile" in original) ==
            ("outsiderBookstackApiGrantFile" in original))
        if (service == "bookstack" && original.containsKey("bookstackApiGrantFile")) {
            keys["bookstackApiGrantFile"] = "bookstack.api-owner"
            keys["outsiderBookstackApiGrantFile"] = "bookstack.api-outsider"
        }
        val pins = keys.map { (field, grant) ->
            val source = Path.of(original.getValue(field).jsonPrimitive.content)
            val expected = sourceRoot.resolve("qualification-original-actors/")
                .resolve("${grant.replace('.', '-')}.json")
            require(source.isAbsolute && source.normalize() == source && source == expected &&
                Files.isRegularFile(source, NOFOLLOW_LINKS)) { "Original first-use actor grant is not generation-local" }
            val bytes = privateBytes(source)
            validateCredential(grant, bytes)
            ActivationInput(source.toString(), ReleaseLocks.sha256(bytes))
        }
        require(pins.map { it.sha256 }.toSet().size == pins.size) {
            "Original owner and outsider share a first-use grant"
        }
        return original to pins
    }

    /** RESTORE never mints an actor: only replace the original credential path after verifying
     * authenticated source and target copies are byte-identical for the requested service. */
    fun project(sourceRoot: Path, targetRoot: Path, sourceBundle: String, service: String,
        originalContextsSha256: String, original: JsonObject): Pair<JsonObject, List<ActivationInput>> {
        require(service in services)
        if (service == "donetick") DonetickTripleActorContext.requireContext(original)
        val source = verify(sourceRoot, sourceRoot.fileName.toString(), sourceBundle)
        val target = verify(targetRoot, source.sourceGeneration, sourceBundle)
        require(target == source && source.originalContextsSha256 == originalContextsSha256) {
            "RESTORE context differs from original sealed actor context map"
        }
        val keys = linkedMapOf("ownerCredentialFile" to "$service.owner",
            "outsiderCredentialFile" to "$service.outsider")
        if (service == "donetick") {
            keys["appNonMemberCredentialFile"] = "donetick.appNonMember"
            keys["ownerSsoCredentialFile"] = "donetick.sso-owner"
            keys["appNonMemberSsoCredentialFile"] = "donetick.sso-appNonMember"
            keys["gatewayOutsiderSsoCredentialFile"] = "donetick.sso-outsider"
        }
        if (service == "bookstack" && original.containsKey("bookstackApiGrantFile")) {
            keys["bookstackApiGrantFile"] = "bookstack.api-owner"
            keys["outsiderBookstackApiGrantFile"] = "bookstack.api-outsider"
        }
        val rewritten = keys.mapValues { (contextKey, grant) ->
            require(Path.of(original.getValue(contextKey).jsonPrimitive.content).isAbsolute)
            val copied = targetRoot.resolve(file(grant))
            require(ReleaseLocks.sha256(privateBytes(copied)) == source.credentials.getValue(grant))
            JsonPrimitive(copied.toString())
        }
        return JsonObject(original + rewritten) to keys.values.map { grant ->
            ActivationInput(targetRoot.resolve(file(grant)).toString(), source.credentials.getValue(grant))
        }
    }
}
