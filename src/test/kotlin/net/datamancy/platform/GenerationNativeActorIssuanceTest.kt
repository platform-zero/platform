package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Test
import kotlin.test.*

/** Injected case artifacts exercise custody checks, never native enrollment proof. */
internal class GenerationNativeActorIssuanceTest {
    private val json = Json { encodeDefaults = true }
    private fun dir(path: Path): Path {
        Files.createDirectory(path, PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        return path
    }
    private fun put(path: Path, value: String): ActivationInput {
        ReleasePrivateFiles.save(path, value.encodeToByteArray())
        return ActivationInput(path.toString(), ReleaseLocks.sha256(ReleasePrivateFiles.read(path)))
    }
    @Test fun `typed issuance requires five completed original native account cases and distinct API bearer readbacks`() {
        val base = Files.createTempDirectory("p0-native-issuance-")
        Files.setPosixFilePermissions(base, PosixFilePermissions.fromString("rwx------"))
        try {
            val generation = "q-123456789abc"
            val source = dir(base.resolve(generation))
            val bundle = put(source.resolve("bundle.json"), "sealed-source-bundle").sha256
            val grants = dir(source.resolve("issued"))
            val artifacts = dir(source.resolve("artifacts"))
            val qualification = dir(source.resolve("qualification-control"))
            val suite = "a".repeat(24)
            val suiteDir = dir(qualification.resolve(suite))
            val closures = dir(suiteDir.resolve("case-closures"))
            val map = linkedMapOf<String, JsonElement>()
            val keys = listOf("bookstack", "erpnext", "firefly-iii", "forgejo", "donetick")
            for (service in keys) {
                val creds = linkedMapOf<String, JsonElement>()
                for (role in listOf("owner", "outsider")) {
                    val username = if (service == "donetick") role else "$role@$service.test"
                    val file = put(grants.resolve("$service-$role.json"),
                        "{\"username\":\"$username\",\"password\":\"${ReleaseLocks.sha256("$service-$role".toByteArray())}\"}")
                    creds["${role}CredentialFile"] = JsonPrimitive(file.path)
                }
                if (service == "donetick") {
                    for ((field, role, user) in listOf(
                        Triple("appNonMemberCredentialFile", "appNonMember", "app-nonmember"),
                        Triple("ownerSsoCredentialFile", "sso-owner", "owner"),
                        Triple("appNonMemberSsoCredentialFile", "sso-appNonMember", "app-nonmember"),
                        Triple("gatewayOutsiderSsoCredentialFile", "sso-outsider", "outsider"))) {
                        val file = put(grants.resolve("donetick-$role.json"),
                            "{\"username\":\"$user\",\"password\":\"${ReleaseLocks.sha256("donetick-$role".toByteArray())}\"}")
                        creds[field] = JsonPrimitive(file.path)
                    }
                    creds["appNonMemberSubject"] = JsonPrimitive("app-nonmember")
                    creds["gatewayOutsiderSubject"] = JsonPrimitive("outsider")
                    creds["ownerIssuerSubjectUuid"] = JsonPrimitive("00000000-0000-4000-8000-000000000001")
                    creds["appNonMemberIssuerSubjectUuid"] = JsonPrimitive("00000000-0000-4000-8000-000000000003")
                    creds["gatewayOutsiderIssuerSubjectUuid"] = JsonPrimitive("00000000-0000-4000-8000-000000000002")
                }
                if (service == "bookstack") for (role in listOf("owner", "outsider")) {
                    val file = put(grants.resolve("bookstack-api-$role.json"),
                        "{\"tokenId\":\"p0v3-${ReleaseLocks.sha256("api-$role".toByteArray()).take(32)}\",\"secret\":\"${ReleaseLocks.sha256("api-secret-$role".toByteArray())}\"}")
                    creds[if (role == "owner") "bookstackApiGrantFile" else "outsiderBookstackApiGrantFile"] = JsonPrimitive(file.path)
                }
                val case = JsonObject(creds)
                map["$service--workflow--headless--native"] = case
                if (service == "bookstack") map["bookstack--workflow--web--browser"] = case
            }
            val context = put(source.resolve("contexts.json"), json.encodeToString(JsonObject(map)))
            var sequence = 0
            fun completed(service: String, surface: String, variant: String, original: JsonObject): Path {
                sequence++
                val key = "$service--workflow--${surface.lowercase()}--${variant.lowercase()}"
                val case = dir(artifacts.resolve(key))
                val invocation = "case-%08x-0000-4000-8000-%012x".format(sequence, sequence)
                val caseContext = put(case.resolve("context.json"), json.encodeToString(original))
                val intent = put(case.resolve("intent.json"), "original intent $service $surface")
                val oracle = buildJsonObject {
                    if (service != "bookstack") put("owner", if (service == "donetick") "owner" else "owner@$service.test")
                    if (service == "bookstack") { put("bookId", 11); put("pageId", 12); put("attachmentId", 13) }
                    if (service == "firefly-iii") {
                        put("accountId", 21); put("transactionId", 22)
                        put("firstUseOwnerName", "Original onboarding owner 0123456789abcdef01234567")
                        put("firstUseOutsiderName", "Original onboarding outsider 0123456789abcdef01234567")
                    }
                }
                val oraclePin = put(case.resolve("oracle.json"), json.encodeToString(oracle))
                val native = put(case.resolve("native-result.json"), buildJsonObject {
                    put("schemaVersion", 2); put("invocationId", invocation); put("generationId", generation)
                    put("phase", "INSTALL"); put("serviceId", service); put("surface", surface)
                    put("variant", variant); put("journey", "workflow")
                    put("assertions", buildJsonObject {
                        put("authorization-denial", true)
                        if (service == "firefly-iii") put("synthetic-import", true)
                    })
                }.toString())
                val gatewayProof = if (service == "donetick") put(case.resolve(
                    "donetick-gateway-denial-proof.json"), buildJsonObject {
                    put("schemaVersion", 1); put("generationId", generation); put("invocationId", invocation)
                    put("phase", "INSTALL"); put("host", "donetick.datamancy.net")
                    put("gatewayOutsiderSubject", "outsider")
                    put("gatewayOutsiderIssuerSubjectUuid", original.getValue("gatewayOutsiderIssuerSubjectUuid"))
                    put("httpStatus", 403)
                }.toString()) else null
                val result = put(case.resolve("result.json"), buildJsonObject {
                    put("passed", true); put("finished", true); put("exitCode", 0)
                    put("observationSha256", native.sha256)
                    put("artifactHashes", buildJsonObject {
                        put("oracle.json", oraclePin.sha256)
                        gatewayProof?.let { put("donetick-gateway-denial-proof.json", it.sha256) }
                    })
                    put("invocation", buildJsonObject {
                        put("invocationId", invocation)
                        put("binding", buildJsonObject { put("phase", "INSTALL"); put("generationId", generation) })
                    })
                }.toString())
                val closure = OwnerCaseClosure(invocationId = invocation, caseDirectory = case.toString(),
                    evidenceKey = key, mode = "QCLIENT_RUNNER", phase = "INSTALL", caseIntent = intent,
                    context = caseContext, result = result, client = null, ingress = null,
                    clientFence = null, bridgeRemoval = null)
                put(closures.resolve("$invocation.json"), json.encodeToString(closure))
                return case
            }
            val locations = keys.associateWith { service ->
                completed(service, "HEADLESS", "NATIVE", map.getValue("$service--workflow--headless--native").jsonObject)
            }
            completed("bookstack", "WEB", "BROWSER", map.getValue("bookstack--workflow--web--browser").jsonObject)
            val scope = QualificationControlScope(suiteId = suite, generationId = generation,
                bundleSha256 = bundle, operation = "execute-staged", controllerSha256 = "f".repeat(64),
                products = context, manifest = context, binding = context,
                journalFile = source.resolve("journal.json").toString(), journalHeadSha256 = "a".repeat(64),
                artifactRoot = artifacts.toString(), contexts = context)
            // A changed original native ID is refused before any custody write.
            val fireflyOracle = locations.getValue("firefly-iii").resolve("oracle.json")
            val originalOracle = ReleasePrivateFiles.read(fireflyOracle)
            Files.writeString(fireflyOracle, "{}")
            assertFails { GenerationNativeActorIssuance.produceAtVerifiedBase(source, base, bundle, scope) }
            assertFalse(Files.exists(source.resolve("qualification-issuance-native")))
            Files.write(fireflyOracle, originalOracle)
            val gatewayProof = locations.getValue("donetick").resolve("donetick-gateway-denial-proof.json")
            val originalGateway = ReleasePrivateFiles.read(gatewayProof)
            Files.writeString(gatewayProof, "{\"httpStatus\":200}")
            assertFails { GenerationNativeActorIssuance.produceAtVerifiedBase(source, base, bundle, scope) }
            assertFalse(Files.exists(source.resolve("qualification-issuance-native")))
            Files.write(gatewayProof, originalGateway)
            val denied = assertFailsWith<IllegalStateException> {
                GenerationNativeActorIssuance.produceAtVerifiedBase(source, base, bundle, scope)
            }
            assertContains(denied.message.orEmpty(), "Original service-native account readbacks")
            assertFalse(Files.exists(source.resolve("qualification-issuance-native")))
            assertFalse(Files.exists(source.resolve("qualification-issuance")))
            assertFails { GenerationNativeActorIssuance.produceAtVerifiedBase(source, base, bundle, scope) {
                service, _ -> buildJsonObject {
                    put("owner", if (service == "donetick") "owner" else "owner@$service.test")
                    put("outsider", if (service == "donetick") "outsider" else "outsider@$service.test")
                    put("nativeResourceId", "1")
                }
            } }
            assertFalse(Files.exists(source.resolve("qualification-issuance-native")))
            assertFalse(Files.exists(source.resolve("qualification-issuance")))
            // Injected service replies test only the typed binding/custody writer.
            // They cannot be supplied to the production produce() path.
            val readbacks = GenerationNativeActorIssuance.produceAtVerifiedBase(source, base, bundle, scope) {
                service, _ ->
                val case = map.getValue("$service--workflow--headless--native").jsonObject
                val owner = Json.parseToJsonElement(Files.readString(Path.of(
                    case.getValue("ownerCredentialFile").jsonPrimitive.content))).jsonObject
                val outsider = Json.parseToJsonElement(Files.readString(Path.of(
                    case.getValue("outsiderCredentialFile").jsonPrimitive.content))).jsonObject
                buildJsonObject {
                    put("owner", owner.getValue("username"))
                    if (service == "donetick") {
                        val app = Json.parseToJsonElement(Files.readString(Path.of(
                            case.getValue("appNonMemberCredentialFile").jsonPrimitive.content))).jsonObject
                        put("appNonMember", app.getValue("username"))
                    } else put("outsider", outsider.getValue("username"))
                    put("ownerNativeId", "original-native-owner-$service")
                    put("outsiderNativeId", "original-native-outsider-$service")
                }
            }
            assertEquals(keys.toSet(), readbacks.keys)
            val staged = RecoveryActorCustody.stage(source, bundle, context, readbacks)
            assertEquals(keys.toSet(), staged.issuanceReadbackSha256.keys)
            assertFails { RecoveryActorCustody.stage(source, bundle, context, readbacks) }
        } finally {
            Files.walk(base).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
