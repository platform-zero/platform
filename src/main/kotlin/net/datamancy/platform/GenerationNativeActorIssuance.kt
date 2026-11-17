package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** Core-owned original case witness. An identity JSON alone is never an issuance
 * proof: the same owner-held whole INSTALL must have completed the native case,
 * its actual app/API oracle and native outsider-denial readback. */
@Serializable internal data class GenerationActorCaseWitness(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val originalContextsSha256: String,
    val service: String, val nativeClosure: ActivationInput, val nativeResult: ActivationInput,
    val nativeObservation: ActivationInput, val originalOracle: ActivationInput,
    val nativeAccountReadback: ActivationInput, val browserClosure: ActivationInput? = null)

internal object GenerationNativeActorIssuance {
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val services = linkedMapOf("bookstack" to "native-bookstack-grant-readback",
        "erpnext" to "native-erp-actor-readback", "firefly-iii" to "native-finance-credential-issuance",
        "forgejo" to "native-forgejo-actor-readback", "donetick" to "native-donetick-actor-readback")
    private val directoryMode = PosixFilePermissions.fromString("rwx------")
    private fun pin(path: Path, maximum: Int = 1048576): ActivationInput = ActivationInput(path.toString(),
        ReleaseLocks.sha256(ReleasePrivateFiles.read(path, maximum)))
    private fun read(pin: ActivationInput, maximum: Int = 1048576): JsonObject =
        json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(pin.path), maximum)
            .also { require(ReleaseLocks.sha256(it) == pin.sha256) }
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
    private fun directory(parent: Path, path: Path) {
        ReleasePrivateFiles.directory(parent)
        require(!Files.exists(path, NOFOLLOW_LINKS)) { "Original actor issuance is one-use; never replace uncertain proof" }
        Files.createDirectory(path, PosixFilePermissions.asFileAttribute(directoryMode))
        ReleasePrivateFiles.sync(parent)
    }
    private fun path(original: JsonObject, field: String): Path =
        Path.of(original.getValue(field).jsonPrimitive.content).also { candidate ->
            require(candidate.isAbsolute && candidate.normalize() == candidate)
        }
    private fun account(original: JsonObject, field: String): Pair<String, ActivationInput> {
        val value = path(original, field); val record = pin(value, 16384)
        val obj = read(record, 16384)
        require(obj.keys == setOf("username", "password") &&
            obj.getValue("username").jsonPrimitive.content.matches(Regex("[A-Za-z0-9_.@-]{3,128}")) &&
            obj.getValue("password").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")))
        return obj.getValue("username").jsonPrimitive.content to record
    }
    private fun nativeCase(root: Path, scope: QualificationControlScope, generation: String,
        service: String, surface: String, variant: String): Pair<OwnerCaseClosure, ActivationInput> {
        val key = "$service--workflow--${surface.lowercase()}--${variant.lowercase()}"
        val dir = Path.of(scope.artifactRoot).resolve(key)
        require(dir.isAbsolute && dir.normalize() == dir && dir.parent == Path.of(scope.artifactRoot))
        val closures = root.resolve("qualification-control/${scope.suiteId}/case-closures")
        ReleasePrivateFiles.directory(closures)
        val matches = Files.list(closures).use { paths -> paths.limit(257).filter { entry ->
            entry.fileName.toString().matches(Regex("case-[a-f0-9-]{36}\\.json")) &&
                runCatching {
                    val closure = json.decodeFromString<OwnerCaseClosure>(ReleasePrivateFiles.read(entry, 65536)
                        .decodeToString(throwOnInvalidSequence = true))
                    closure.caseDirectory == dir.toString() && closure.evidenceKey == key
                }.getOrDefault(false)
        }.toList() }
        require(matches.size == 1) { "Missing or ambiguous original native case closure: $key" }
        val originalPin = pin(matches.single(), 65536)
        val closure = json.decodeFromString<OwnerCaseClosure>(ReleasePrivateFiles.read(matches.single(), 65536)
            .decodeToString(throwOnInvalidSequence = true))
        require(closure.schemaVersion == 2 && closure.phase == "INSTALL" &&
            closure.caseDirectory == dir.toString() && closure.evidenceKey == key &&
            closure.result == pin(dir.resolve("result.json")) &&
            closure.context == pin(dir.resolve("context.json")) &&
            closure.caseIntent == pin(dir.resolve("intent.json"), 65536))
        val result = read(closure.result)
        val invocation = result.getValue("invocation").jsonObject
        val binding = invocation.getValue("binding").jsonObject
        require(result.getValue("passed").jsonPrimitive.boolean &&
            result.getValue("finished").jsonPrimitive.boolean &&
            result.getValue("exitCode").jsonPrimitive.int == 0 &&
            invocation.getValue("invocationId").jsonPrimitive.content == closure.invocationId &&
            binding.getValue("phase").jsonPrimitive.content == "INSTALL" &&
            binding.getValue("generationId").jsonPrimitive.content == generation &&
            closure.result.path == dir.resolve("result.json").toString())
        return closure to originalPin
    }
    fun verifyOriginal(root: Path, generation: String, bundleSha256: String,
        contextsSha256: String, service: String): GenerationActorCaseWitness {
        require(service in services && root == GenerationRuntime.BASE.resolve(generation) &&
            root.toRealPath() == root && contextsSha256.matches(Regex("[a-f0-9]{64}")))
        val witness = json.decodeFromString<GenerationActorCaseWitness>(ReleasePrivateFiles.read(
            root.resolve("qualification-issuance-native/$service.case-source.json"), 16384)
            .decodeToString(throwOnInvalidSequence = true))
        require(witness.schemaVersion == 1 && witness.generation == generation &&
            witness.bundleSha256 == bundleSha256 && witness.originalContextsSha256 == contextsSha256 &&
            witness.service == service && (service == "bookstack") == (witness.browserClosure != null))
        val closure = json.decodeFromString<OwnerCaseClosure>(ReleasePrivateFiles.read(
            Path.of(witness.nativeClosure.path), 65536).also {
                require(ReleaseLocks.sha256(it) == witness.nativeClosure.sha256)
            }.decodeToString(throwOnInvalidSequence = true))
        require(closure.phase == "INSTALL" && closure.result == witness.nativeResult &&
            closure.caseDirectory == Path.of(witness.nativeResult.path).parent.toString() &&
            closure.evidenceKey == "$service--workflow--headless--native" &&
            witness.nativeObservation.path == Path.of(closure.caseDirectory).resolve("native-result.json").toString() &&
            witness.originalOracle.path == Path.of(closure.caseDirectory).resolve("oracle.json").toString() &&
            read(witness.nativeResult).let { result ->
                result.getValue("passed").jsonPrimitive.boolean &&
                    result.getValue("finished").jsonPrimitive.boolean &&
                    result.getValue("exitCode").jsonPrimitive.int == 0 &&
                    result.getValue("observationSha256").jsonPrimitive.content == witness.nativeObservation.sha256 &&
                    result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content == witness.originalOracle.sha256
            })
        val observed = read(witness.nativeObservation)
        require(observed.getValue("serviceId").jsonPrimitive.content == service &&
            observed.getValue("generationId").jsonPrimitive.content == generation &&
            observed.getValue("phase").jsonPrimitive.content == "INSTALL" &&
            observed.getValue("assertions").jsonObject.values.all { it.jsonPrimitive.boolean } &&
            observed.getValue("assertions").jsonObject.containsKey("authorization-denial"))
        read(witness.originalOracle)
        val account = read(witness.nativeAccountReadback, 16384)
        require(witness.nativeAccountReadback.path == root.resolve(
            "qualification-issuance-native/$service.accounts.json").toString() &&
            account.getValue("service").jsonPrimitive.content == service &&
            account.getValue("generation").jsonPrimitive.content == generation &&
            account.getValue("bundleSha256").jsonPrimitive.content == bundleSha256 &&
            account.getValue("originalContextsSha256").jsonPrimitive.content == contextsSha256 &&
            account.getValue("owner").jsonPrimitive.content != account.getValue("outsider").jsonPrimitive.content &&
            account.getValue("native").jsonObject.isNotEmpty())
        witness.browserClosure?.let { browser ->
            val web = json.decodeFromString<OwnerCaseClosure>(ReleasePrivateFiles.read(Path.of(browser.path), 65536)
                .also { require(ReleaseLocks.sha256(it) == browser.sha256) }.decodeToString(throwOnInvalidSequence = true))
            require(web.phase == "INSTALL" && web.evidenceKey == "bookstack--workflow--web--browser" &&
                read(web.result).getValue("passed").jsonPrimitive.boolean)
        }
        return witness
    }

    fun produce(root: Path, bundleSha256: String, scope: QualificationControlScope): Map<String, ActivationInput> {
        val bundle = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)
            .also { require(ReleaseLocks.sha256(it) == bundleSha256) }.decodeToString(throwOnInvalidSequence = true))
        val live = GenerationNativeActorLiveQueries(root, bundle, bundleSha256, scope)
        return produceAtVerifiedBase(root, GenerationRuntime.BASE, bundleSha256, scope, live::read)
    }

    /** Case oracles alone do not prove that an account was enrolled. Native readbacks
     * must run against the original installed service with its original sealed grants;
     * do not issue recovery custody until all five independent queries are bound here.
     * There is intentionally no fallback to a test fixture or copied case oracle. */
    internal fun produceAtVerifiedBase(root: Path, generationBase: Path, bundleSha256: String,
        scope: QualificationControlScope, nativeQuery: ((String, JsonObject) -> JsonObject)? = null): Map<String, ActivationInput> {
        require(root == generationBase.resolve(scope.generationId) && root.toRealPath() == root &&
            scope.bundleSha256 == bundleSha256 && bundleSha256.matches(Regex("[a-f0-9]{64}")) &&
            scope.operation == "execute-staged")
        val contextPin = requireNotNull(scope.contexts)
        val allContexts = read(contextPin, 4194304)
        val generated = root.resolve("qualification-issuance-native")
        val issued = root.resolve("qualification-issuance")
        require(!Files.exists(generated, NOFOLLOW_LINKS) && !Files.exists(issued, NOFOLLOW_LINKS)) {
            "Original native actor issuance already attempted; no replay"
        }
        // All five real case closures and credentials must validate BEFORE the first
        // producer write. A failed/partial issuance keeps its directories, never retries.
        data class Proven(val service: String, val kind: String, val owner: String, val outsider: String,
            val appNonMember: String?, val hashes: Map<String, String>, val closure: ActivationInput, val result: ActivationInput,
            val observation: ActivationInput, val oracle: ActivationInput, val browser: ActivationInput?)
        val proven = services.map { (service, kind) ->
            val key = "$service--workflow--headless--native"
            val proposed = allContexts.getValue(key).jsonObject
            val (owner, ownerPin) = account(proposed, "ownerCredentialFile")
            val (outsider, outsiderPin) = account(proposed, "outsiderCredentialFile")
            require(owner != outsider && ownerPin.sha256 != outsiderPin.sha256)
            val hashes = linkedMapOf("$service.owner" to ownerPin.sha256, "$service.outsider" to outsiderPin.sha256)
            val appNonMember = if (service == "donetick") {
                DonetickTripleActorContext.requireContext(proposed)
                val (app, appPin) = account(proposed, DonetickTripleActorContext.appNative)
                val (ownerSso, ownerSsoPin) = account(proposed, DonetickTripleActorContext.ownerSso)
                val (appSso, appSsoPin) = account(proposed, DonetickTripleActorContext.appSso)
                val (gatewaySso, gatewaySsoPin) = account(proposed, DonetickTripleActorContext.gatewaySso)
                require(owner == "owner" && outsider == "outsider" && app == "app-nonmember" &&
                    ownerSso == owner && appSso == app && gatewaySso == outsider &&
                    setOf(ownerPin.sha256, outsiderPin.sha256, appPin.sha256,
                        ownerSsoPin.sha256, appSsoPin.sha256, gatewaySsoPin.sha256).size == 6) {
                    "Donetick app and gateway outsider cannot share original native or SSO grants"
                }
                hashes["donetick.appNonMember"] = appPin.sha256
                hashes["donetick.sso-owner"] = ownerSsoPin.sha256
                hashes["donetick.sso-appNonMember"] = appSsoPin.sha256
                hashes["donetick.sso-outsider"] = gatewaySsoPin.sha256
                app
            } else null
            if (service == "bookstack") for (role in listOf("owner", "outsider")) {
                val grant = path(proposed, if (role == "owner") "bookstackApiGrantFile" else "outsiderBookstackApiGrantFile")
                val pinned = pin(grant, 16384)
                val obj = read(pinned, 16384)
                require(obj.keys == setOf("tokenId", "secret") &&
                    obj.getValue("tokenId").jsonPrimitive.content.matches(Regex("p0v3-[a-f0-9]{32}")) &&
                    obj.getValue("secret").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")))
                hashes["bookstack.api-$role"] = pinned.sha256
            }
            require(hashes.values.toSet().size == hashes.size)
            val (closure, closurePin) = nativeCase(root, scope, scope.generationId, service, "HEADLESS", "NATIVE")
            val dir = Path.of(closure.caseDirectory)
            val caseContext = read(closure.context)
            (listOf("ownerCredentialFile", "outsiderCredentialFile") +
                if (service == "bookstack") listOf("bookstackApiGrantFile", "outsiderBookstackApiGrantFile")
                else if (service == "donetick") listOf("appNonMemberCredentialFile", "ownerSsoCredentialFile",
                    "appNonMemberSsoCredentialFile", "gatewayOutsiderSsoCredentialFile",
                    "appNonMemberSubject", "gatewayOutsiderSubject", "ownerIssuerSubjectUuid",
                    "appNonMemberIssuerSubjectUuid", "gatewayOutsiderIssuerSubjectUuid") else emptyList())
                .forEach { field -> require(caseContext.getValue(field) == proposed.getValue(field)) }
            val observed = pin(dir.resolve("native-result.json"))
            val oracle = pin(dir.resolve("oracle.json"))
            val result = read(closure.result)
            require(result.getValue("observationSha256").jsonPrimitive.content == observed.sha256 &&
                result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content == oracle.sha256)
            if (service == "donetick") {
                // Chore denial by a users-group app-test principal is NOT a
                // gateway denial of the designated group-excluded outsider.
                // Require its own native QClient assertion on the same original
                // case before *any* account issuance or recovery custody write.
                val proofPin = pin(dir.resolve("donetick-gateway-denial-proof.json"), 16384)
                require(result.getValue("artifactHashes").jsonObject
                    .getValue("donetick-gateway-denial-proof.json").jsonPrimitive.content == proofPin.sha256)
                val gateway = read(proofPin, 16384)
                require(gateway.keys == setOf("schemaVersion", "generationId", "invocationId", "phase",
                    "host", "gatewayOutsiderSubject", "gatewayOutsiderIssuerSubjectUuid", "httpStatus") &&
                    gateway.getValue("schemaVersion").jsonPrimitive.int == 1 &&
                    gateway.getValue("generationId").jsonPrimitive.content == scope.generationId &&
                    gateway.getValue("invocationId").jsonPrimitive.content == closure.invocationId &&
                    gateway.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                    gateway.getValue("host").jsonPrimitive.content == "donetick.datamancy.net" &&
                    gateway.getValue("gatewayOutsiderSubject").jsonPrimitive.content == outsider &&
                    gateway.getValue("gatewayOutsiderIssuerSubjectUuid") == proposed.getValue(
                        "gatewayOutsiderIssuerSubjectUuid") && gateway.getValue("httpStatus").jsonPrimitive.int == 403) {
                    "Distinct original gateway-denied actor did not receive native GROUP 403"
                }
            }
            val native = read(observed)
            val assertions = native.getValue("assertions").jsonObject
            require(native.getValue("schemaVersion").jsonPrimitive.int == 2 &&
                native.getValue("invocationId").jsonPrimitive.content == closure.invocationId &&
                native.getValue("generationId").jsonPrimitive.content == scope.generationId &&
                native.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                native.getValue("serviceId").jsonPrimitive.content == service &&
                native.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
                native.getValue("variant").jsonPrimitive.content == "NATIVE" &&
                native.getValue("journey").jsonPrimitive.content == "workflow" &&
                assertions.isNotEmpty() && assertions.values.all { it.jsonPrimitive.boolean } &&
                "authorization-denial" in assertions &&
                (service != "firefly-iii" || "synthetic-import" in assertions))
            val oracleJson = read(oracle)
            require((oracleJson["owner"] == null || oracleJson.getValue("owner").jsonPrimitive.content == owner) &&
                (service != "bookstack" || listOf("bookId", "pageId", "attachmentId").all {
                    oracleJson.getValue(it).jsonPrimitive.int > 0
                }) && (service != "firefly-iii" ||
                    (oracleJson.getValue("accountId").jsonPrimitive.int > 0 &&
                        oracleJson.getValue("transactionId").jsonPrimitive.int > 0 &&
                        listOf("firstUseOwnerName", "firstUseOutsiderName").all { it in oracleJson })))
            val browser = if (service == "bookstack") {
                val (web, webPin) = nativeCase(root, scope, scope.generationId, service, "WEB", "BROWSER")
                val webContext = read(web.context)
                for (field in listOf("ownerCredentialFile", "outsiderCredentialFile"))
                    require(webContext.getValue(field) == proposed.getValue(field))
                webPin
            } else null
            Proven(service, kind, owner, outsider, appNonMember, hashes, closurePin, closure.result,
                observed, oracle, browser)
        }
        // Complete all independent original service queries before the first
        // issuance proof is written. A missing GROUP SSO session, refused native
        // account or uncertain bootstrap leaves only query intents, never custody.
        val query = nativeQuery ?: error("Original service-native account readbacks are required before recovery issuance custody")
        val readbacks = proven.associate { source ->
            val native = query(source.service, read(source.oracle))
            require(native.getValue("owner").jsonPrimitive.content == source.owner &&
                (if (source.service == "donetick")
                    native.getValue("appNonMember").jsonPrimitive.content == source.appNonMember &&
                        "outsider" !in native // gateway-denied site outsider cannot have a GROUP token
                else native.getValue("outsider").jsonPrimitive.content == source.outsider) &&
                native.keys.size in 3..16)
            source.service to native
        }
        directory(root, generated)
        directory(root, issued)
        return proven.associate { source ->
            val accounts = generated.resolve("${source.service}.accounts.json")
            val live = buildJsonObject {
                put("service", source.service); put("generation", scope.generationId)
                put("bundleSha256", bundleSha256); put("originalContextsSha256", contextPin.sha256)
                put("owner", source.owner); put("outsider", source.outsider)
                put("native", readbacks.getValue(source.service))
            }
            ReleasePrivateFiles.save(accounts, json.encodeToString(live).encodeToByteArray())
            val witness = GenerationActorCaseWitness(generation = scope.generationId,
                bundleSha256 = bundleSha256, originalContextsSha256 = contextPin.sha256,
                service = source.service, nativeClosure = source.closure, nativeResult = source.result,
                nativeObservation = source.observation, originalOracle = source.oracle,
                nativeAccountReadback = pin(accounts, 16384), browserClosure = source.browser)
            ReleasePrivateFiles.save(generated.resolve("${source.service}.case-source.json"),
                json.encodeToString(witness).encodeToByteArray())
            val native = RecoveryActorNativeIssuanceProof(generation = scope.generationId,
                bundleSha256 = bundleSha256, originalContextsSha256 = contextPin.sha256,
                service = source.service, issuerKind = source.kind, credentialSha256 = source.hashes,
                ownerSubject = source.owner, outsiderSubject = source.outsider)
            val nativePath = generated.resolve("${source.service}.json")
            ReleasePrivateFiles.save(nativePath, json.encodeToString(native).encodeToByteArray())
            val readback = RecoveryActorIssuanceReadback(sourceGeneration = scope.generationId,
                sourceBundleSha256 = bundleSha256, originalContextsSha256 = contextPin.sha256,
                service = source.service, issuerKind = source.kind, credentialSha256 = source.hashes,
                originalOwner = source.owner, originalOutsider = source.outsider,
                nativeEvidence = pin(nativePath, 16384))
            val path = issued.resolve("${source.service}.json")
            ReleasePrivateFiles.save(path, json.encodeToString(readback).encodeToByteArray())
            source.service to pin(path, 16384)
        }
    }
}
