package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Holder-only custody of the completed same-phase Element original-owner PKCE session.
 * The Java issuer's bearer/refresh bytes are never serialized into an oracle, log or
 * caller result. QClient gets only a case-local copy of the current access bearer. */
internal object QualificationMatrixSessionProducer {
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val hex = Regex("[a-f0-9]{64}")
    private const val registered = "01J00000000000000000000001"
    private fun read(path: Path, max: Int = 65536) = ReleasePrivateFiles.read(path, max)
    private fun objectFile(path: Path): JsonObject = json.parseToJsonElement(read(path)
        .decodeToString(throwOnInvalidSequence = true)).jsonObject
    fun produce(caseDir: Path, currentNativeDir: Path, sourceNativeDir: Path,
        context: JsonObject, originalOracle: JsonObject,
        phase: String, generation: String, androidInvocationId: String,
        pin: GenerationPin, sourcePin: GenerationPin, roots: ActivationInput,
        bundle: GenerationBundle, bundleSha: String): Map<String, JsonElement> {
        require(phase in setOf("INSTALL", "RESTORE") && caseDir != currentNativeDir &&
            currentNativeDir.parent == caseDir.parent && pin.spec.name == "$generation-v2" &&
            sourceNativeDir == (if (phase == "INSTALL") currentNativeDir else
                Path.of(context.getValue("sourceNativeOracleFile").jsonPrimitive.content).parent) &&
            (phase == "INSTALL" || sourceNativeDir.parent != caseDir.parent &&
                sourcePin.spec.name == originalOracle.getValue("sourceGenerationId").jsonPrimitive.content + "-v2"))
        val targetIntent = objectFile(currentNativeDir.resolve("intent.json"))
        val targetResult = objectFile(currentNativeDir.resolve("result.json"))
        require(targetIntent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == phase &&
            targetIntent.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content == generation &&
            targetResult.getValue("invocation") == targetIntent && targetResult.getValue("passed").jsonPrimitive.boolean &&
            targetResult.getValue("finished").jsonPrimitive.boolean && targetResult.getValue("exitCode").jsonPrimitive.int == 0)
        val intent = objectFile(sourceNativeDir.resolve("intent.json"))
        val result = objectFile(sourceNativeDir.resolve("result.json"))
        val observation = objectFile(sourceNativeDir.resolve("native-result.json"))
        val receiptPath = sourceNativeDir.resolve("matrix-original-owner-session.json")
        val receiptBytes = read(receiptPath)
        val receipt = json.parseToJsonElement(receiptBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val observed = objectFile(sourceNativeDir.resolve("matrix-original-observation.json"))
        val nativeContext = objectFile(sourceNativeDir.resolve("context.json"))
        val nativeOracle = objectFile(sourceNativeDir.resolve("oracle.json"))
        val identityState = objectFile(Path.of(nativeContext.getValue("originalIdentityStateFile")
            .jsonPrimitive.content))
        require(intent.getValue("serviceId").jsonPrimitive.content == "element" &&
            intent.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
            intent.getValue("variant").jsonPrimitive.content == "NATIVE" &&
            intent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL" &&
            intent.getValue("binding").jsonObject.getValue("generationId") == originalOracle.getValue("sourceGenerationId") &&
            intent.getValue("contextSha256").jsonPrimitive.content == ReleaseLocks.sha256(
                read(sourceNativeDir.resolve("context.json"), 4194304)) &&
            result.getValue("passed").jsonPrimitive.boolean && result.getValue("finished").jsonPrimitive.boolean &&
            result.getValue("exitCode").jsonPrimitive.int == 0 &&
            result.getValue("invocation") == intent &&
            result.getValue("artifactHashes").jsonObject.getValue("matrix-original-owner-session.json")
                .jsonPrimitive.content == ReleaseLocks.sha256(receiptBytes) &&
            result.getValue("artifactHashes").jsonObject.getValue("matrix-original-observation.json")
                .jsonPrimitive.content == ReleaseLocks.sha256(read(sourceNativeDir.resolve(
                    "matrix-original-observation.json"))) &&
            result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content ==
                ReleaseLocks.sha256(read(sourceNativeDir.resolve("oracle.json"))) &&
            result.getValue("observationSha256").jsonPrimitive.content ==
                ReleaseLocks.sha256(read(sourceNativeDir.resolve("native-result.json"))) &&
            observation.getValue("assertions").jsonObject.values.all { it.jsonPrimitive.boolean } &&
            nativeOracle.getValue("feature").jsonObject.getValue("sender") ==
                originalOracle.getValue("matrixUserId") &&
            nativeOracle.getValue("feature").jsonObject.getValue("event") ==
                originalOracle.getValue("eventId")) {
            "Same-phase Element original PKCE predecessor is not a completed source"
        }
        val invocation = intent.getValue("invocationId").jsonPrimitive.content
        val custody = Path.of(nativeContext.getValue("credentialCustodyDirectory").jsonPrimitive.content)
        val expected = custody.resolve("$invocation-original-owner-session.token")
        val refresh = custody.resolve("$invocation-original-owner-session.token.refresh")
        val attempt = custody.resolve("$invocation-original-owner-session.token.intent.json")
        require(custody.isAbsolute && custody.normalize() == custody &&
            ReleasePrivateFiles.directory(custody).let { true } &&
            expected.parent == custody && refresh.parent == custody &&
            receipt.keys == setOf("schemaVersion", "invocationId", "phase", "sourceGenerationId",
                "targetGenerationId", "targetManifestSha256", "ownerUserId", "ownerMasSubject",
                "ownerUpstreamSubject", "registeredClientId", "privateTokenPath", "privateTokenSha256",
                "privateRefreshPath", "privateRefreshSha256") &&
            receipt.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            receipt.getValue("invocationId").jsonPrimitive.content == invocation &&
            receipt.getValue("phase").jsonPrimitive.content == "INSTALL" &&
            receipt.getValue("targetGenerationId") == originalOracle.getValue("sourceGenerationId") &&
            receipt.getValue("targetManifestSha256").jsonPrimitive.content == sourcePin.manifestSha256 &&
            receipt.getValue("sourceGenerationId") == originalOracle.getValue("sourceGenerationId") &&
            receipt.getValue("ownerUserId") == originalOracle.getValue("matrixUserId") &&
            receipt.getValue("ownerMasSubject") == originalOracle.getValue("masSubject") &&
            receipt.getValue("registeredClientId").jsonPrimitive.content == registered &&
            receipt.getValue("privateTokenPath").jsonPrimitive.content == expected.toString() &&
            receipt.getValue("privateRefreshPath").jsonPrimitive.content == refresh.toString() &&
            receipt.getValue("privateTokenSha256").jsonPrimitive.content.matches(hex) &&
            receipt.getValue("privateRefreshSha256").jsonPrimitive.content.matches(hex) &&
            observed.getValue("ownerSessionSha256") == receipt.getValue("privateTokenSha256") &&
            observed.getValue("ownerSessionRefreshSha256") == receipt.getValue("privateRefreshSha256") &&
            observed.getValue("ownerSessionMasSubject") == receipt.getValue("ownerMasSubject") &&
            observed.getValue("ownerSessionUpstreamSubject") == receipt.getValue("ownerUpstreamSubject") &&
            observed.getValue("ownerSessionClientId") == receipt.getValue("registeredClientId") &&
            receipt.getValue("ownerMasSubject").jsonPrimitive.content ==
                QualificationMatrixActor.ownerMasSubject(pin.spec, pin.runtimeFingerprint) &&
            identityState.getValue("users").jsonObject.getValue("owner").jsonObject
                .getValue("subject") == receipt.getValue("ownerUpstreamSubject"))
        val attemptValue = objectFile(attempt)
        require(attemptValue == buildJsonObject {
            put("invocationId", invocation); put("clientId", registered)
            put("issuer", "https://matrix-auth.datamancy.net/")
            put("ownerUserId", originalOracle.getValue("matrixUserId"))
        })
        val source = read(expected, 8192)
        val renewal = read(refresh, 8192)
        require(source.size in 40..8192 && renewal.size in 40..8192 && !source.contentEquals(renewal) &&
            source.all { it.toInt().toChar() in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~+/=-" } &&
            renewal.all { it.toInt().toChar() in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~+/=-" } &&
            ReleaseLocks.sha256(source) == receipt.getValue("privateTokenSha256").jsonPrimitive.content &&
            ReleaseLocks.sha256(renewal) == receipt.getValue("privateRefreshSha256").jsonPrimitive.content)
        // Rotate the genuine PKCE refresh under a separate one-use owner intent for
        // EACH Android invocation. An unknown response fences the chain permanently.
        val inherited = if (phase == "RESTORE") QualificationMatrixSessionRefresh.inheritedRefresh(
            originalOracle.getValue("sourceGenerationId").jsonPrimitive.content,
            invocation, ReleaseLocks.sha256(source), renewal,sourcePin.manifestSha256) else renewal
        val rotated = QualificationMatrixSessionRefresh.issue(generation, invocation,
            androidInvocationId, source, inherited, roots, bundle, pin, bundleSha)
        val current = rotated.access
        QualificationMatrixSessionRefresh.confirm(generation, invocation, androidInvocationId, 1,
            ReleaseLocks.sha256(current),ReleaseLocks.sha256(source),pin.manifestSha256)
        val staged = caseDir.resolve("owner-proofs/matrix-original-owner-session.token")
        val proof = caseDir.resolve("owner-proofs/matrix-original-owner-session.json")
        require(!Files.exists(staged, NOFOLLOW_LINKS) && !Files.exists(proof, NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(staged, current)
        val tokenSha = ReleaseLocks.sha256(current)
        val output = buildJsonObject {
            put("schemaVersion", 1); put("phase", phase)
            put("sourceGenerationId", originalOracle.getValue("sourceGenerationId"))
            put("targetGenerationId", generation); put("selectedManifestSha256", pin.manifestSha256)
            put("sourceRecipeSha256", originalOracle.getValue("sourceRecipeSha256"))
            put("ownerUserId", originalOracle.getValue("matrixUserId"))
            put("ownerMasSubject", originalOracle.getValue("masSubject"))
            put("registeredClientId", registered); put("privateTokenSha256", tokenSha)
            put("pkceIssuanceSha256", receipt.getValue("privateTokenSha256"))
            put("elementNativeInvocationId", targetIntent.getValue("invocationId"))
            put("elementNativeResultSha256", ReleaseLocks.sha256(read(currentNativeDir.resolve("result.json"),1048576)))
        }
        // Verify target issuer BEFORE making the source receipt available to an Android case.
        val verificationContext = JsonObject(context + mapOf("freshOriginalSessionFile" to JsonPrimitive(staged.toString())))
        require(QualificationMatrixDeviceActor.verifyOwnerToken(verificationContext, roots, bundle,
            GenerationRuntime.BASE.resolve(generation), pin, bundleSha, current) >= 1)
        ReleasePrivateFiles.save(proof, json.encodeToString(output).encodeToByteArray())
        return mapOf("freshOriginalSessionFile" to JsonPrimitive(staged.toString()),
            "freshOriginalSessionReceiptFile" to JsonPrimitive(proof.toString()))
    }

    fun current(caseDir: Path, context: JsonObject): JsonObject {
        val first = caseDir.resolve("owner-proofs/matrix-original-owner-session.json")
        require(context.getValue("freshOriginalSessionReceiptFile").jsonPrimitive.content == first.toString())
        val initial = objectFile(first)
        val count = (2..4).takeWhile { n -> Files.exists(caseDir.resolve(
            "owner-proofs/matrix-original-owner-session-$n.json"),NOFOLLOW_LINKS) }.size
        require((count + 2..4).none { n -> Files.exists(caseDir.resolve(
            "owner-proofs/matrix-original-owner-session-$n.json"),NOFOLLOW_LINKS) ||
            Files.exists(caseDir.resolve("owner-proofs/matrix-original-owner-session-$n.token"),NOFOLLOW_LINKS) })
        val nativeInvocation = if (initial.getValue("phase").jsonPrimitive.content == "RESTORE")
            objectFile(Path.of(context.getValue("sourceNativeOracleFile").jsonPrimitive.content)
                .parent.resolve("intent.json")).getValue("invocationId").jsonPrimitive.content
            else initial.getValue("elementNativeInvocationId").jsonPrimitive.content
        val generation = initial.getValue("targetGenerationId").jsonPrimitive.content
        val invocation = caseDir.resolve("intent.json").let { path ->
            objectFile(path).getValue("invocationId").jsonPrimitive.content }
        if (count == 0) {
            val access = read(caseDir.resolve("owner-proofs/matrix-original-owner-session.token"),8192)
            require(initial.getValue("privateTokenSha256").jsonPrimitive.content == ReleaseLocks.sha256(access))
            QualificationMatrixSessionRefresh.confirm(generation,nativeInvocation,invocation,1,
                ReleaseLocks.sha256(access),initial.getValue("pkceIssuanceSha256").jsonPrimitive.content,
                initial.getValue("selectedManifestSha256").jsonPrimitive.content)
            return context
        }
        val sequence = count + 1
        val receipt = caseDir.resolve("owner-proofs/matrix-original-owner-session-$sequence.json")
        val token = caseDir.resolve("owner-proofs/matrix-original-owner-session-$sequence.token")
        val next = objectFile(receipt)
        val sha = ReleaseLocks.sha256(read(token,8192))
        require(next.keys == initial.keys && next.filterKeys { it != "privateTokenSha256" } ==
            initial.filterKeys { it != "privateTokenSha256" } &&
            next.getValue("privateTokenSha256").jsonPrimitive.content == sha)
        QualificationMatrixSessionRefresh.confirm(generation,nativeInvocation,invocation,sequence,sha,
            initial.getValue("pkceIssuanceSha256").jsonPrimitive.content,
            initial.getValue("selectedManifestSha256").jsonPrimitive.content)
        return JsonObject(context + mapOf("freshOriginalSessionFile" to JsonPrimitive(token.toString()),
            "freshOriginalSessionReceiptFile" to JsonPrimitive(receipt.toString())))
    }

    /** Fixed-action midcase refresh. No token/URL/path is supplied by the Android caller;
     * the prior receipt digest alone selects the exact last acknowledged version. */
    fun renew(caseDir: Path, context: JsonObject, priorSha256: String,
        generation: String, invocation: String, phase: String, pin: GenerationPin,
        roots: ActivationInput, bundle: GenerationBundle, bundleSha: String): JsonObject {
        require(priorSha256.matches(hex) && phase in setOf("INSTALL", "RESTORE") &&
            invocation.matches(Regex("case-[a-f0-9-]{36}")) &&
            caseDir == Path.of(context.getValue("freshOriginalSessionFile").jsonPrimitive.content)
                .parent.parent && pin.spec.name == "$generation-v2")
        // RESTORE's sourceNativeOracleFile intentionally points to the held INSTALL
        // oracle, not the completed target-native PKCE issuer. Resolve the latter
        // from this same-phase artifact root and the initial receipt's invocation.
        val nativeCase = caseDir.parent.resolve("element--workflow--headless--native")
        val originalNative = Path.of(context.getValue("sourceNativeOracleFile").jsonPrimitive.content)
        require(nativeCase.parent == caseDir.parent && nativeCase != caseDir &&
            originalNative.fileName.toString() == "oracle.json" &&
            (if (phase == "INSTALL") originalNative == nativeCase.resolve("oracle.json")
             else originalNative != nativeCase.resolve("oracle.json") &&
                originalNative.parent != caseDir.parent))
        val nativeIntent = objectFile(nativeCase.resolve("intent.json"))
        val nativeResult = objectFile(nativeCase.resolve("result.json"))
        val sourceNativeCase = if (phase == "INSTALL") nativeCase else originalNative.parent
        val sourceIntent = objectFile(sourceNativeCase.resolve("intent.json"))
        val sourceContext = objectFile(sourceNativeCase.resolve("context.json"))
        val nativeReceiptPath = sourceNativeCase.resolve("matrix-original-owner-session.json")
        val nativeReceiptBytes = read(nativeReceiptPath)
        val nativeReceipt = json.parseToJsonElement(nativeReceiptBytes.decodeToString(
            throwOnInvalidSequence = true)).jsonObject
        require(nativeIntent.getValue("serviceId").jsonPrimitive.content == "element" &&
            nativeIntent.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
            nativeIntent.getValue("variant").jsonPrimitive.content == "NATIVE" &&
            nativeIntent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == phase &&
            nativeIntent.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content == generation &&
            nativeResult.getValue("passed").jsonPrimitive.boolean &&
            nativeResult.getValue("finished").jsonPrimitive.boolean &&
            nativeResult.getValue("exitCode").jsonPrimitive.int == 0 &&
            nativeResult.getValue("invocation") == nativeIntent &&
            nativeResult.getValue("artifactHashes").jsonObject.getValue("oracle.json")
                .jsonPrimitive.content == ReleaseLocks.sha256(read(nativeCase.resolve("oracle.json"))) &&
            sourceIntent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL" &&
            sourceIntent.getValue("binding").jsonObject.getValue("generationId") ==
                objectFile(Path.of(context.getValue("originalMatrixOracleFile").jsonPrimitive.content))
                    .getValue("sourceGenerationId") &&
            nativeReceipt.getValue("phase").jsonPrimitive.content == "INSTALL" &&
            nativeReceipt.getValue("invocationId") == sourceIntent.getValue("invocationId") &&
            objectFile(sourceNativeCase.resolve("result.json")).getValue("artifactHashes")
                .jsonObject.getValue("matrix-original-owner-session.json").jsonPrimitive.content ==
                    ReleaseLocks.sha256(nativeReceiptBytes) &&
            objectFile(sourceNativeCase.resolve("result.json")).getValue("invocation") == sourceIntent &&
            objectFile(sourceNativeCase.resolve("result.json")).getValue("passed").jsonPrimitive.boolean)
        val nativeInvocation = sourceIntent.getValue("invocationId").jsonPrimitive.content
        val custody = Path.of(sourceContext.getValue("credentialCustodyDirectory").jsonPrimitive.content)
        ReleasePrivateFiles.directory(custody)
        val sourceAccess = custody.resolve("$nativeInvocation-original-owner-session.token")
        val sourceRefresh = custody.resolve("$nativeInvocation-original-owner-session.token.refresh")
        require(sourceAccess.toString() == nativeReceipt.getValue("privateTokenPath").jsonPrimitive.content &&
            sourceRefresh.toString() == nativeReceipt.getValue("privateRefreshPath").jsonPrimitive.content &&
            ReleaseLocks.sha256(read(sourceAccess,8192)) == nativeReceipt.getValue("privateTokenSha256").jsonPrimitive.content &&
            ReleaseLocks.sha256(read(sourceRefresh,8192)) == nativeReceipt.getValue("privateRefreshSha256").jsonPrimitive.content)
        val first = caseDir.resolve("owner-proofs/matrix-original-owner-session.json")
        val initial = objectFile(first)
        val original = objectFile(Path.of(context.getValue("originalMatrixOracleFile").jsonPrimitive.content))
        require(initial.getValue("elementNativeInvocationId") == nativeIntent.getValue("invocationId") &&
            initial.getValue("elementNativeResultSha256").jsonPrimitive.content ==
                ReleaseLocks.sha256(read(nativeCase.resolve("result.json"),1048576)) &&
            initial.getValue("pkceIssuanceSha256") == nativeReceipt.getValue("privateTokenSha256") &&
            initial.getValue("ownerUserId") == original.getValue("matrixUserId") &&
            initial.getValue("ownerMasSubject") == original.getValue("masSubject") &&
            initial.getValue("targetGenerationId").jsonPrimitive.content == generation &&
            initial.getValue("phase").jsonPrimitive.content == phase &&
            initial.getValue("selectedManifestSha256").jsonPrimitive.content == pin.manifestSha256)
        val count = (2..4).takeWhile { n -> Files.exists(caseDir.resolve(
            "owner-proofs/matrix-original-owner-session-$n.json"), NOFOLLOW_LINKS) }.size
        val sequence = count + 2
        require(sequence in 2..4 && (sequence..4).none { n -> Files.exists(caseDir.resolve(
            "owner-proofs/matrix-original-owner-session-$n.json"), NOFOLLOW_LINKS) ||
            Files.exists(caseDir.resolve("owner-proofs/matrix-original-owner-session-$n.token"), NOFOLLOW_LINKS) })
        val previous = if (sequence == 2) first else caseDir.resolve(
            "owner-proofs/matrix-original-owner-session-${sequence-1}.json")
        val prior = read(previous)
        val priorReceipt = json.parseToJsonElement(prior.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val previousToken = if (sequence == 2) caseDir.resolve(
            "owner-proofs/matrix-original-owner-session.token") else caseDir.resolve(
            "owner-proofs/matrix-original-owner-session-${sequence-1}.token")
        val previousSha = ReleaseLocks.sha256(read(previousToken,8192))
        require(ReleaseLocks.sha256(prior) == priorSha256 &&
            priorReceipt.keys == initial.keys &&
            priorReceipt.filterKeys { it != "privateTokenSha256" } == initial.filterKeys {
                it != "privateTokenSha256" } &&
            priorReceipt.getValue("privateTokenSha256").jsonPrimitive.content == previousSha)
        QualificationMatrixSessionRefresh.confirm(generation,nativeInvocation,invocation,sequence-1,
            previousSha,initial.getValue("pkceIssuanceSha256").jsonPrimitive.content,
            initial.getValue("selectedManifestSha256").jsonPrimitive.content)
        val originalRefresh = read(sourceRefresh,8192)
        val inherited = if (phase == "RESTORE") QualificationMatrixSessionRefresh.inheritedRefresh(
            initial.getValue("sourceGenerationId").jsonPrimitive.content,nativeInvocation,
            ReleaseLocks.sha256(read(sourceAccess,8192)),originalRefresh,
            nativeReceipt.getValue("targetManifestSha256").jsonPrimitive.content) else originalRefresh
        val issued = QualificationMatrixSessionRefresh.issue(generation,nativeInvocation,invocation,
            read(sourceAccess,8192),inherited,roots,bundle,pin,bundleSha,sequence)
        require(issued.sequence == sequence &&
            !issued.access.contentEquals(read(previousToken,8192)))
        val token = caseDir.resolve("owner-proofs/matrix-original-owner-session-$sequence.token")
        val receipt = caseDir.resolve("owner-proofs/matrix-original-owner-session-$sequence.json")
        require(!Files.exists(token,NOFOLLOW_LINKS) && !Files.exists(receipt,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(token,issued.access)
        val next = JsonObject(initial + ("privateTokenSha256" to JsonPrimitive(
            ReleaseLocks.sha256(issued.access))))
        val selectedContext = JsonObject(context + ("freshOriginalSessionFile" to
            JsonPrimitive(token.toString())))
        require(QualificationMatrixDeviceActor.verifyOwnerToken(selectedContext, roots, bundle,
            GenerationRuntime.BASE.resolve(generation),pin,bundleSha,issued.access) >= 1)
        ReleasePrivateFiles.save(receipt,json.encodeToString(next).encodeToByteArray())
        return buildJsonObject {
            put("sequence",sequence); put("priorSessionReceiptSha256",priorSha256)
            put("sessionReceiptSha256",ReleaseLocks.sha256(read(receipt)))
            put("sessionTokenSha256",ReleaseLocks.sha256(issued.access))
        }
    }
}
