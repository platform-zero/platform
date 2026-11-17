package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

/** Synthetic read-only original-byte fixtures; never live receipts or a qualification run. */
class RestoredCaseClosureEvidenceTest {
    private val json = Json { encodeDefaults = true; explicitNulls = true }
    private val source = "q-111111111111"
    private val target = "q-222222222222"
    private val suite = "a".repeat(24)
    private val fp = "f".repeat(64)
    private val h = "d".repeat(64)
    private val targetRoot = GenerationRuntime.BASE.resolve(target)
    private val sourceRoot = GenerationRuntime.BASE.resolve(source)
    private val caseRoot = Path.of("/tmp/synthetic-case-evidence")
    private data class Fixture(val files: MutableMap<Path, ByteArray>, val scope: QualificationControlScope,
        val proof: RestoredAggregateProof, val pin: GenerationPin, val closures: List<OwnerCaseClosure>,
        val paths: Map<String, Path>) {
        fun verify(expected: QualificationControlScope = scope, actual: RestoredAggregateProof = proof) =
            RestoredCaseClosureEvidence.verify(expected, actual, pin) { path, max ->
                val bytes = files[path] ?: error("Absent original synthetic file: $path")
                require(bytes.size <= max)
                bytes
            }
    }
    private fun bytes(value: Any): ByteArray = when (value) {
        is JsonElement -> json.encodeToString(JsonElement.serializer(), value).encodeToByteArray()
        else -> error("Only explicitly serialized fixtures")
    }
    private fun fixture(sameCid: Boolean = false): Fixture {
        val files = mutableMapOf<Path, ByteArray>()
        fun put(path: Path, raw: ByteArray): ActivationInput {
            require(files.put(path, raw) == null)
            return ActivationInput(path.toString(), ReleaseLocks.sha256(raw))
        }
        fun pin(path: Path, value: JsonElement) = put(path, bytes(value))
        val caddy = RuntimeProcess("caddy", "synthetic", h, 1000,
            files = listOf(RuntimeFile("cert.pem", "/run/secrets/cert.pem"),
                RuntimeFile("key.pem", "/run/secrets/key.pem"),
                RuntimeFile("files-cert.pem", "/run/secrets/files-cert.pem"),
                RuntimeFile("files-key.pem", "/run/secrets/files-key.pem")),
            networks = listOf("qualification-web"))
        val rss = RuntimeProcess("rss-jobs", "synthetic", h, 1000, networks = listOf("qualification-web"))
        val seafile = RuntimeProcess("seafile", "synthetic", h, 1000, networks = listOf("app-net"))
        val spec = PrivateDeploymentSpec(name = "$target-v2", volumes = emptyList(),
            processes = listOf(caddy, rss, seafile), networks = listOf("qualification-web", "app-net"),
            store = RuntimeStore.CANONICAL_V2)
        val cert = put(PrivateDeployment.BASE.resolve(spec.name).resolve("cert.pem"),
            "original certificate".encodeToByteArray())
        val key = put(PrivateDeployment.BASE.resolve(spec.name).resolve("key.pem"),
            "original private key".encodeToByteArray())
        val filesCert = put(PrivateDeployment.BASE.resolve(spec.name).resolve("files-cert.pem"),
            "original files certificate".encodeToByteArray())
        val filesKey = put(PrivateDeployment.BASE.resolve(spec.name).resolve("files-key.pem"),
            "original files private key".encodeToByteArray())
        val targetPin = GenerationPin(GenerationMember(spec.name), h,
            mapOf("cert.pem" to cert.sha256, "key.pem" to key.sha256,
                "files-cert.pem" to filesCert.sha256, "files-key.pem" to filesKey.sha256), fp, spec)
        val sourceSpec = spec.copy(name = "$source-v2")
        val sourcePin = targetPin.copy(member = GenerationMember(sourceSpec.name), spec = sourceSpec)
        val sourceBundle = buildJsonObject {
            put("request", buildJsonObject { put("id", source) })
            put("members", buildJsonArray { add(json.encodeToJsonElement(sourcePin)) })
            put("ownership", buildJsonObject {
                put("contract", buildJsonObject {
                    put("site", "synthetic")
                    put("routes", buildJsonArray { add(json.encodeToJsonElement(
                        SiteRouteOwner("files.datamancy.net", "seafile", "$source-v2/seafile", 8080))) })
                })
                put("approvedHosts", buildJsonArray { add("start.datamancy.net"); add("files.datamancy.net") })
            })
        }
        val sourceReceipt = pin(sourceRoot.resolve("bundle.json"), sourceBundle)
        val targetBundle = buildJsonObject {
            put("request", buildJsonObject { put("id", target) })
            put("members", buildJsonArray { add(json.encodeToJsonElement(targetPin)) })
            put("recoverySourceKopia", buildJsonObject {
                put("generation", source); put("bundleSha256", sourceReceipt.sha256)
            })
        }
        val targetReceipt = pin(targetRoot.resolve("bundle.json"), targetBundle)
        val candidate = buildJsonObject {
            for (field in listOf("implementationSha256", "artifactsSha256", "configurationSha256",
                "acceptanceSha256", "sitePolicySha256")) put(field, h)
        }
        val binding = buildJsonObject {
            put("trialId", "trial-one"); put("generationId", target); put("phase", "RESTORE")
            put("candidate", candidate)
        }
        val bindingPin = pin(Path.of("/tmp/synthetic-binding.json"), binding)
        val inventory = pin(Path.of("/tmp/synthetic-products.json"), buildJsonObject { put("schemaVersion", 1) })
        val definitions = listOf(Triple("opensearch", "HEADLESS", "NATIVE"),
            Triple("seafile", "WEB", "BROWSER"), Triple("alloy", "HEADLESS", "NATIVE"),
            Triple("rss-jobs", "HEADLESS", "NATIVE"))
        val manifest = buildJsonObject {
            put("schemaVersion", 2)
            put("cases", buildJsonArray {
                for ((service, surface, variant) in definitions) add(buildJsonObject {
                    put("serviceId", service); put("surface", surface); put("variant", variant)
                    put("journey", "workflow"); put("runner", "scripts/qualified-runner.py")
                    put("adapter", "runners/$service-native.py")
                    put("restoreAssertions", buildJsonArray { add("original"); add("restored") })
                })
            })
        }
        val manifestPin = pin(Path.of("/tmp/synthetic-manifest.json"), manifest)
        val originalContexts = pin(Path.of("/tmp/synthetic-contexts.json"), buildJsonObject {
            for ((service, surface, variant) in definitions) put(
                "$service--workflow--${surface.lowercase()}--${variant.lowercase()}",
                buildJsonObject { put("fixture", "nonsecret") })
        })
        val scope = QualificationControlScope(suiteId = suite, generationId = target,
            bundleSha256 = targetReceipt.sha256, operation = "execute-qualified", controllerSha256 = h,
            products = inventory, manifest = manifestPin, binding = bindingPin,
            journalFile = "/tmp/synthetic-journal.jsonl", journalHeadSha256 = h,
            artifactRoot = caseRoot.toString(), contexts = originalContexts)
        put(targetRoot.resolve("qualification-control/$suite/scope.intent.json"),
            json.encodeToString(scope).encodeToByteArray())
        val quiesceOp = "r-" + "c".repeat(12)
        val stopped = ListenerBridgeQuiesceResult(quiesceOp, h, source, target, "e".repeat(64))
        val quiescence = put(Path.of("/mnt/media/p0-v3/ingress-succession/synthetic")
            .resolve("$quiesceOp.bridge-result.json"), json.encodeToString(stopped).encodeToByteArray())
        val readiness = RuntimeAudit(spec.name, fp, 3, null,
            listOf(RuntimeStatus("caddy", "running", null), RuntimeStatus("rss-jobs", "running", null),
                RuntimeStatus("seafile", "running", null)))
        val ready = put(targetRoot.resolve("qualification-restored/$suite/private-readiness.json"),
            json.encodeToString(readiness).encodeToByteArray())
        val closurePins = mutableListOf<ActivationInput>()
        val closures = mutableListOf<OwnerCaseClosure>()
        val paths = mutableMapOf<String, Path>()
        for ((index, definition) in definitions.withIndex()) {
            val (service, surface, variant) = definition
            val caseId = "case-${(index + 1).toString().padStart(8, '0')}-1111-4111-8111-111111111111"
            val evidence = "$service--workflow--${surface.lowercase()}--${variant.lowercase()}"
            val dir = caseRoot.resolve(evidence)
            paths[service] = dir
            val mode = when (service) {
                "seafile" -> "QCLIENT_RUNNER"
                "alloy" -> "HOST_NATIVE_WITH_DENIAL_PROBE"
                else -> "HOST_NATIVE"
            }
            val hasClient = mode != "HOST_NATIVE"
            val hasIngress = service == "seafile" || service == "rss-jobs"
            val context = pin(dir.resolve("context.json"), buildJsonObject {
                put("fixture", "nonsecret"); put("bundleSha256", targetReceipt.sha256)
                put("caSha256", h)
            })
            val intent = buildJsonObject {
                put("invocationId", caseId); put("binding", binding)
                put("serviceId", service); put("surface", surface); put("variant", variant)
                put("journey", "workflow"); put("inventorySha256", inventory.sha256)
                put("manifestSha256", manifestPin.sha256); put("runnerSha256", h)
                put("contextSha256", context.sha256)
                put("requiredAssertions", buildJsonArray { add("original"); add("restored") })
            }
            val intentPin = pin(dir.resolve("intent.json"), intent)
            val oracle = pin(dir.resolve("oracle.json"), buildJsonObject { put("original", service) })
            val observation = buildJsonObject {
                put("schemaVersion", 2); put("invocationId", caseId); put("serviceId", service)
                put("surface", surface); put("variant", variant); put("journey", "workflow")
                put("phase", "RESTORE"); put("generationId", target)
                put("assertions", buildJsonObject { put("original", true); put("restored", true) })
                put("artifacts", buildJsonObject { put("oracle.json", oracle.sha256) })
            }
            val observationPin = pin(dir.resolve("native-result.json"), observation)
            val log = put(dir.resolve("runner.log"),
                if (index == 0) byteArrayOf() else "runner $service completed\n".encodeToByteArray())
            val result = buildJsonObject {
                put("invocation", intent); put("passed", true); put("finished", true)
                put("exitCode", 0); put("failureType", JsonNull)
                put("logSha256", log.sha256); put("observationSha256", observationPin.sha256)
                put("artifactHashes", observation.getValue("artifacts"))
            }
            val resultPin = pin(dir.resolve("result.json"), result)
            val native = if (hasClient) QualificationClientNative(
                (if (sameCid) "a" else (index + 1).toString(16)).repeat(64), 123 + index,
                456L + index, "10.0.0.${index + 3}", "b".repeat(64)) else null
            val fence = native?.let { client ->
                val nativeBytes = json.encodeToString(client).encodeToByteArray()
                put(targetRoot.resolve("qualification-client/$caseId/native.json"), nativeBytes)
                put(targetRoot.resolve("qualification-client/$caseId/fenced.json"), json.encodeToString(
                    QualificationClientFence(caseId, target, client.containerId, client.netnsInode,
                        h, ReleaseLocks.sha256(nativeBytes))).encodeToByteArray())
            }
            val stoppedCopy = put(dir.resolve("owner-proofs/source-stopped.json"), files.getValue(Path.of(quiescence.path)))
            val readyCopy = put(dir.resolve("owner-proofs/private-readiness.json"), files.getValue(Path.of(ready.path)))
            val ingress: ActivationInput?
            val removal: ActivationInput?
            if (hasIngress) {
                val installOp = qualificationCaseBridgeOperation(suite, caseId, "install")
                val removeOp = qualificationCaseBridgeOperation(suite, caseId, "remove")
                val bridgeRoot = Path.of("/mnt/media/p0-v3/restored-bridges/synthetic").resolve(target)
                val original = buildJsonObject { put("state", "original") }
                val installed = buildJsonObject { put("state", "installed") }
                val bridge = RestoredBridgeBinding(installOp, "synthetic", source, target, fp,
                    "qualification-web", "10.0.0.2", setOf("rss-jobs"), "https", quiesceOp,
                    stopped.sourceStoppedProofSha256, ready.sha256,
                    setOf("start.datamancy.net", "files.datamancy.net"), listOf(CaddyUpstream(
                        "files.datamancy.net", "p0v3-live-$target-v2-seafile:8080")),
                    mapOf("start.datamancy.net" to cert, "files.datamancy.net" to filesCert),
                    mapOf("start.datamancy.net" to key, "files.datamancy.net" to filesKey),
                    mapOf("start.datamancy.net" to "/run/secrets/cert.pem",
                        "files.datamancy.net" to "/run/secrets/files-cert.pem"),
                    mapOf("start.datamancy.net" to "/run/secrets/key.pem",
                        "files.datamancy.net" to "/run/secrets/files-key.pem"),
                    nativeClientCapabilities = if (native == null) setOf("rss-mastodon") else emptySet(),
                    qualifierClientInvocationId = native?.let { caseId },
                    qualifierClientContainerId = native?.containerId, qualifierClientAddress = native?.clientIp)
                val installIntent = put(bridgeRoot.resolve("$installOp.intent.json"),
                    json.encodeToString(RestoredBridgeIntent(bridge, "install", original, installed, "etag")).encodeToByteArray())
                ingress = put(dir.resolve("owner-proofs/ingress-intent.json"),
                    files.getValue(Path.of(installIntent.path)))
                put(bridgeRoot.resolve("$installOp.result.json"), json.encodeToString(
                    RestoredBridgeResult(installOp, installIntent.sha256, "install",
                        TransactionalCaddy.digest(original), TransactionalCaddy.digest(installed))).encodeToByteArray())
                val removeIntent = put(bridgeRoot.resolve("$removeOp.intent.json"),
                    json.encodeToString(RestoredBridgeIntent(bridge, "remove", installed, original, "etag")).encodeToByteArray())
                removal = put(bridgeRoot.resolve("$removeOp.result.json"), json.encodeToString(
                    RestoredBridgeResult(removeOp, removeIntent.sha256, "remove",
                        TransactionalCaddy.digest(installed), TransactionalCaddy.digest(original))).encodeToByteArray())
            } else { ingress = null; removal = null }
            val gate = OwnerCaseGate(invocationId = caseId, mode = mode, caseIntentSha256 = intentPin.sha256,
                contextSha256 = context.sha256, client = native,
                ingress = ingress?.let { ActivationInput("owner-proofs/ingress-intent.json", it.sha256) },
                sourceStopped = ActivationInput("owner-proofs/source-stopped.json", stoppedCopy.sha256),
                privateReadiness = ActivationInput("owner-proofs/private-readiness.json", readyCopy.sha256))
            put(dir.resolve("qualification-case-gate.json"), json.encodeToString(gate).encodeToByteArray())
            put(dir.resolve("case-closure.json"), json.encodeToString(
                OwnerCaseFenced(caseId, fence, removal)).encodeToByteArray())
            val closure = OwnerCaseClosure(invocationId = caseId, caseDirectory = dir.toString(),
                evidenceKey = evidence, mode = mode, phase = "RESTORE", caseIntent = intentPin,
                context = context, result = resultPin, client = native,
                ingress = ingress, clientFence = fence, bridgeRemoval = removal)
            closures += closure
            closurePins += put(targetRoot.resolve("qualification-control/$suite/case-closures/$caseId.json"),
                json.encodeToString(closure).encodeToByteArray())
        }
        val proof = RestoredAggregateProof(operation = scope.operation, suiteId = suite,
            source = ReleaseGeneration(source, sourceReceipt.sha256),
            target = ReleaseGeneration(target, targetReceipt.sha256),
            sourceDisposition = RestoredSourceDisposition.RESUMED, quiescence = quiescence,
            heldCapture = null, ownedUpdate = null, retainedSource = null, sourceResume = null,
            caseClosures = closurePins, finalIsolation = ActivationInput("/tmp/synthetic-isolation", h))
        return Fixture(files, scope, proof, targetPin, closures, paths)
    }

    @Test fun `four exact cases bind real-shaped host public probe and RSS originals without modifying V1 receipts`() {
        val f = fixture()
        val before = f.files.toMap()
        assertEquals(f.closures, f.verify())
        assertEquals(before, f.files) // read-only: original V1 bridge receipt bytes remain untouched.
        assertEquals(setOf("HOST_NATIVE", "QCLIENT_RUNNER", "HOST_NATIVE_WITH_DENIAL_PROBE"),
            f.verify().map { it.mode }.toSet())
    }

    @Test fun `missing duplicate extra and foreign expected trial candidate or scope refuse`() {
        val f = fixture()
        val pins = f.proof.caseClosures
        for (changed in listOf(pins.dropLast(1), pins + pins.first(), pins +
            ActivationInput("/foreign/case-closure.json", h)))
            assertFails { f.verify(actual = f.proof.copy(caseClosures = changed)) }
        assertFails { f.verify(expected = f.scope.copy(suiteId = "b".repeat(24))) }
        assertFails { f.verify(actual = f.proof.copy(suiteId = "b".repeat(24))) }
        val bindingPath = Path.of(f.scope.binding.path)
        val original = f.files.getValue(bindingPath)
        f.files[bindingPath] = original.decodeToString().replace("trial-one", "trial-two").encodeToByteArray()
        assertFails { f.verify() }
        f.files[bindingPath] = original.decodeToString()
            .replaceFirst("\"candidate\":{", "\"candidate\":{\"unapproved\":true,")
            .encodeToByteArray()
        assertFails { f.verify() }
        f.files[bindingPath] = original
        val other = f.scope.copy(controllerSha256 = "e".repeat(64))
        assertFails { f.verify(expected = other) }
    }

    @Test fun `context oracle artifacts client fence and gate identity cannot drift`() {
        val f = fixture(); assertEquals(4, f.verify().size)
        fun altered(path: Path, value: ByteArray) {
            val original = f.files.getValue(path)
            f.files[path] = value
            try { assertFails { f.verify() } } finally { f.files[path] = original }
        }
        val host = f.paths.getValue("opensearch")
        altered(host.resolve("context.json"), "{}".encodeToByteArray())
        altered(host.resolve("oracle.json"), "{\"original\":\"foreign\"}".encodeToByteArray())
        altered(host.resolve("native-result.json"), "{}".encodeToByteArray())
        val web = f.paths.getValue("seafile")
        altered(web.resolve("qualification-case-gate.json"), "{}".encodeToByteArray())
        val cid = f.closures.single { it.evidenceKey.startsWith("seafile--") }.invocationId
        altered(targetRoot.resolve("qualification-client/$cid/native.json"), "{}".encodeToByteArray())
        altered(targetRoot.resolve("qualification-client/$cid/fenced.json"), "{}".encodeToByteArray())
    }

    @Test fun `narrowed but self consistent assertions cannot replace pinned RESTORE requirements`() {
        val f = fixture()
        val closure = f.closures.single { it.evidenceKey.startsWith("opensearch--") }
        val dir = Path.of(closure.caseDirectory)
        val intent = json.parseToJsonElement(f.files.getValue(dir.resolve("intent.json")).decodeToString()).jsonObject
        val narrow = JsonObject(intent + ("requiredAssertions" to buildJsonArray { add("original") }))
        val intentRaw = bytes(narrow)
        f.files[dir.resolve("intent.json")] = intentRaw
        val observation = json.parseToJsonElement(f.files.getValue(dir.resolve("native-result.json")).decodeToString()).jsonObject
        val nativeRaw = bytes(JsonObject(observation +
            ("assertions" to buildJsonObject { put("original", true) })))
        f.files[dir.resolve("native-result.json")] = nativeRaw
        val result = json.parseToJsonElement(f.files.getValue(dir.resolve("result.json")).decodeToString()).jsonObject
        val resultRaw = bytes(JsonObject(result + mapOf("invocation" to narrow,
            "observationSha256" to JsonPrimitive(ReleaseLocks.sha256(nativeRaw)))))
        f.files[dir.resolve("result.json")] = resultRaw
        val gate = json.decodeFromString<OwnerCaseGate>(f.files.getValue(dir.resolve("qualification-case-gate.json")).decodeToString())
        f.files[dir.resolve("qualification-case-gate.json")] = json.encodeToString(
            gate.copy(caseIntentSha256 = ReleaseLocks.sha256(intentRaw))).encodeToByteArray()
        val changed = closure.copy(caseIntent = ActivationInput(closure.caseIntent.path, ReleaseLocks.sha256(intentRaw)),
            result = ActivationInput(closure.result.path, ReleaseLocks.sha256(resultRaw)))
        val prior = f.proof.caseClosures.single { it.path.endsWith("/${closure.invocationId}.json") }
        val closureRaw = json.encodeToString(changed).encodeToByteArray()
        f.files[Path.of(prior.path)] = closureRaw
        assertFails { f.verify(actual = f.proof.copy(caseClosures = f.proof.caseClosures.map { if (it == prior)
            ActivationInput(it.path, ReleaseLocks.sha256(closureRaw)) else it })) }
    }

    @Test fun `one native container cannot count as two distinct client cases`() {
        val f = fixture(sameCid = true)
        assertEquals(2, f.closures.mapNotNull { it.client?.containerId }.size)
        assertFails { f.verify() }
    }

    @Test fun `empty original log is valid but changed or absent logs are not`() {
        val f = fixture(); assertEquals(4, f.verify().size)
        val empty = f.paths.getValue("opensearch").resolve("runner.log")
        assertTrue(f.files.getValue(empty).isEmpty())
        val original = f.files.remove(empty)
        assertFails { f.verify() }
        f.files[empty] = requireNotNull(original)
        f.files[empty] = "later".encodeToByteArray(); assertFails { f.verify() }
        f.files[empty] = original
        val nonempty = f.paths.getValue("seafile").resolve("runner.log")
        val prior = f.files.getValue(nonempty)
        f.files[nonempty] = byteArrayOf(); assertFails { f.verify() }
        f.files[nonempty] = prior
        assertEquals(4, f.verify().size)
    }

    @Test fun `foreign backend port generation or duplicated upstream cannot pass even with paired V1 receipts`() {
        fun wrongUpstream(change: (CaddyUpstream) -> List<CaddyUpstream>) {
            val f = fixture()
            val closure = f.closures.single { it.evidenceKey.startsWith("seafile--") }
            val dir = Path.of(closure.caseDirectory)
            val bridgeRoot = Path.of("/mnt/media/p0-v3/restored-bridges/synthetic").resolve(target)
            val installOp = qualificationCaseBridgeOperation(suite, closure.invocationId, "install")
            val removeOp = qualificationCaseBridgeOperation(suite, closure.invocationId, "remove")
            val installPath = bridgeRoot.resolve("$installOp.intent.json")
            val removePath = bridgeRoot.resolve("$removeOp.intent.json")
            val install = json.decodeFromString<RestoredBridgeIntent>(f.files.getValue(installPath).decodeToString())
            val binding = install.binding.copy(upstreams = change(install.binding.upstreams.single()))
            val installRaw = json.encodeToString(install.copy(binding = binding)).encodeToByteArray()
            val remove = json.decodeFromString<RestoredBridgeIntent>(f.files.getValue(removePath).decodeToString())
            val removeRaw = json.encodeToString(remove.copy(binding = binding)).encodeToByteArray()
            f.files[installPath] = installRaw
            f.files[removePath] = removeRaw
            f.files[dir.resolve("owner-proofs/ingress-intent.json")] = installRaw
            for ((op, raw) in listOf(installOp to installRaw, removeOp to removeRaw)) {
                val result = bridgeRoot.resolve("$op.result.json")
                val old = json.decodeFromString<RestoredBridgeResult>(f.files.getValue(result).decodeToString())
                f.files[result] = json.encodeToString(old.copy(intentSha256 = ReleaseLocks.sha256(raw))).encodeToByteArray()
            }
            val gatePath = dir.resolve("qualification-case-gate.json")
            val gate = json.decodeFromString<OwnerCaseGate>(f.files.getValue(gatePath).decodeToString())
            f.files[gatePath] = json.encodeToString(gate.copy(ingress = ActivationInput(
                "owner-proofs/ingress-intent.json", ReleaseLocks.sha256(installRaw)))).encodeToByteArray()
            val changed = closure.copy(ingress = ActivationInput(closure.ingress!!.path, ReleaseLocks.sha256(installRaw)),
                bridgeRemoval = ActivationInput(closure.bridgeRemoval!!.path,
                    ReleaseLocks.sha256(f.files.getValue(Path.of(closure.bridgeRemoval.path)))))
            f.files[dir.resolve("case-closure.json")] = json.encodeToString(OwnerCaseFenced(
                closure.invocationId, closure.clientFence, changed.bridgeRemoval)).encodeToByteArray()
            val prior = f.proof.caseClosures.single { it.path.endsWith("/${closure.invocationId}.json") }
            val closureRaw = json.encodeToString(changed).encodeToByteArray()
            f.files[Path.of(prior.path)] = closureRaw
            assertFails { f.verify(actual = f.proof.copy(caseClosures = f.proof.caseClosures.map { if (it == prior)
                ActivationInput(it.path, ReleaseLocks.sha256(closureRaw)) else it })) }
        }
        wrongUpstream { listOf(it.copy(dial = it.dial.replace(":8080", ":8081"))) }
        wrongUpstream { listOf(it.copy(dial = it.dial.replace(target, "q-333333333333"))) }
        wrongUpstream { listOf(it, it) }
    }

    @Test fun `foreign remove and install original operations or wrong quiescence readiness refuse`() {
        val f = fixture(); val web = f.closures.single { it.evidenceKey.startsWith("seafile--") }
        val rss = f.closures.single { it.evidenceKey.startsWith("rss-jobs--") }
        val webPin = f.proof.caseClosures.first { it.path.endsWith("/${web.invocationId}.json") }
        val original = f.files.getValue(Path.of(webPin.path))
        val acceptance = f.paths.getValue("seafile").resolve("case-closure.json")
        val acceptanceRaw = f.files.getValue(acceptance)
        val foreign = web.copy(bridgeRemoval = rss.bridgeRemoval)
        f.files[Path.of(webPin.path)] = json.encodeToString(foreign).encodeToByteArray()
        f.files[acceptance] = json.encodeToString(OwnerCaseFenced(web.invocationId,
            web.clientFence, rss.bridgeRemoval)).encodeToByteArray()
        assertFails { f.verify(actual = f.proof.copy(caseClosures = f.proof.caseClosures.map {
            if (it == webPin) ActivationInput(it.path, ReleaseLocks.sha256(f.files.getValue(Path.of(it.path)))) else it
        })) }
        f.files[Path.of(webPin.path)] = original
        f.files[acceptance] = acceptanceRaw
        val siteRoot = Path.of("/mnt/media/p0-v3/restored-bridges/synthetic").resolve(target)
        val install = siteRoot.resolve("${qualificationCaseBridgeOperation(suite, web.invocationId, "install")}.intent.json")
        val intent = f.files.getValue(install)
        f.files[install] = f.files.getValue(siteRoot.resolve(
            "${qualificationCaseBridgeOperation(suite, rss.invocationId, "install")}.intent.json"))
        assertFails { f.verify() }
        f.files[install] = intent
        val stopped = Path.of(f.proof.quiescence.path)
        val stoppedRaw = f.files.getValue(stopped)
        f.files[stopped] = "{}".encodeToByteArray(); assertFails { f.verify() }
        f.files[stopped] = stoppedRaw
        val readiness = targetRoot.resolve("qualification-restored/$suite/private-readiness.json")
        val readyRaw = f.files.getValue(readiness)
        f.files[readiness] = "{}".encodeToByteArray(); assertFails { f.verify() }
        f.files[readiness] = readyRaw
    }

    @Test fun `misplaced or unknown owner proof and reserved adapter evidence cannot substitute originals`() {
        val f = fixture()
        val web = f.paths.getValue("seafile")
        val original = f.files.remove(web.resolve("owner-proofs/ingress-intent.json"))
        assertFails { f.verify() }
        f.files[web.resolve("owner-proofs/ingress-intent.json")] = requireNotNull(original)
        f.files[web.resolve("owner-proofs/unknown.json")] = "forged".encodeToByteArray()
        assertEquals(4, f.verify().size) // Unreferenced file is NOT accepted as evidence.
        val oracle = f.files.remove(web.resolve("oracle.json"))
        assertFails { f.verify() }
        f.files[web.resolve("oracle.json")] = requireNotNull(oracle)

        val host = f.paths.getValue("opensearch")
        val closure = f.closures.single { it.evidenceKey.startsWith("opensearch--") }
        val pin = f.proof.caseClosures.single { it.path.endsWith("/${closure.invocationId}.json") }
        val name = "owner-native/forged.json"
        val witness = "adapter spoof".encodeToByteArray()
        f.files[host.resolve(name)] = witness
        val added = JsonPrimitive(ReleaseLocks.sha256(witness))
        val native = json.parseToJsonElement(f.files.getValue(host.resolve("native-result.json")).decodeToString()).jsonObject
        val nativeUpdated = JsonObject(native + ("artifacts" to JsonObject(
            native.getValue("artifacts").jsonObject + (name to added))))
        f.files[host.resolve("native-result.json")] = bytes(nativeUpdated)
        val result = json.parseToJsonElement(f.files.getValue(host.resolve("result.json")).decodeToString()).jsonObject
        val resultUpdated = JsonObject(result + mapOf(
            "artifactHashes" to nativeUpdated.getValue("artifacts"),
            "observationSha256" to JsonPrimitive(ReleaseLocks.sha256(bytes(nativeUpdated)))))
        f.files[host.resolve("result.json")] = bytes(resultUpdated)
        val revised = closure.copy(result = ActivationInput(closure.result.path,
            ReleaseLocks.sha256(bytes(resultUpdated))))
        f.files[Path.of(pin.path)] = json.encodeToString(revised).encodeToByteArray()
        val revisedPins = f.proof.caseClosures.map { if (it == pin)
            ActivationInput(it.path, ReleaseLocks.sha256(f.files.getValue(Path.of(it.path)))) else it }
        assertFails { f.verify(actual = f.proof.copy(caseClosures = revisedPins)) }
    }
}
