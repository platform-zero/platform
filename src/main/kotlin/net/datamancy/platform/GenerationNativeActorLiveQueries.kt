package net.datamancy.platform

import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** Original INSTALL-only, bounded native account queries. Runs inside the exact
 * systemd-owned original CID; exec is read-only diagnosis, never an alternate
 * application launcher or a substitute for the original START ACK. */
internal class GenerationNativeActorLiveQueries(private val root: Path, private val bundle: GenerationBundle,
    private val expected: String, private val scope: QualificationControlScope,
    private val runtimeBase: Path = PrivateDeployment.BASE) {
    private val json = Json { ignoreUnknownKeys = false }
    init {
        require(root == GenerationRuntime.BASE.resolve(bundle.request.id) && scope.generationId == bundle.request.id &&
            expected == scope.bundleSha256 && bundle.recoverySourceKopia == null && bundle.recoverySourceArchiveSha256 == null &&
            expected == ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)))
    }
    private fun pinInput(pin: GenerationPin, name: String): String {
        val bytes = ReleasePrivateFiles.read(runtimeBase.resolve(pin.spec.name).resolve(name), 65536)
        require(ReleaseLocks.sha256(bytes) == pin.inputHashes.getValue(name))
        return bytes.decodeToString(throwOnInvalidSequence = true)
    }
    private fun originalEnv(pin: GenerationPin, name: String): Map<String, String> {
        val lines = pinInput(pin, name).lines().filter { it.isNotBlank() }
        val pairs = lines.map { line ->
            val key = line.substringBefore('=')
            val value = line.substringAfter('=', missingDelimiterValue = "")
            require(key.matches(Regex("[A-Z][A-Z0-9_]{1,70}")) && value.isNotEmpty() &&
                !value.contains('\r') && !value.contains('\n'))
            key to value
        }
        require(pairs.map { it.first }.distinct().size == pairs.size)
        return pairs.toMap()
    }
    private fun sealedAccount(service: String, pin: GenerationPin, process: String,
        source: String, values: Map<String, String>, executable: String): JsonObject {
        val proc = pin.spec.processes.single { it.id == process && !it.oneShot }
        val status = json.decodeFromString<QuadletMemberStart>(ReleasePrivateFiles.read(root.resolve(
            "quadlet-member-${pin.spec.name}-$process.result.json"), 8192)
            .decodeToString(throwOnInvalidSequence = true))
        require(status.bundleSha256 == expected && status.member == pin.spec.name && status.process == process &&
            status.status.state == "running" && status.containerId.matches(Regex("[a-f0-9]{64}")))
        RuntimeQuadletSystemd.requireServing("${RuntimeQuadlets.unit(pin.spec, proc)}.service",
            status.containerId, pin.spec.store)
        require(values.isNotEmpty() && values.keys.all { it.matches(Regex("[A-Z][A-Z0-9_]{1,70}")) } &&
            values.values.none { it.contains('\r') || it.contains('\n') || it.length > 8192 })
        val query = root.resolve("qualification-account-queries")
        if (!Files.exists(query, NOFOLLOW_LINKS)) {
            Files.createDirectory(query, PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root)
        }
        ReleasePrivateFiles.directory(query)
        val envFile = query.resolve("$service.env")
        val envBytes = values.toSortedMap().entries.joinToString("\n", postfix = "\n") { "${it.key}=${it.value}" }.toByteArray()
        ReleasePrivateFiles.save(envFile, envBytes)
        val command = pin.spec.store.prefix() + listOf("exec", "--env-file", envFile.toString(),
            "--user", "${proc.userId}:${proc.groupId}", "-i", status.containerId, executable)
        val child = ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD).start()
        try {
            child.outputStream.use { it.write(source.toByteArray(Charsets.UTF_8)) }
            val bytes = child.inputStream.readNBytes(8193)
            require(child.waitFor(45, TimeUnit.SECONDS) && child.exitValue() == 0 && bytes.size in 2..8192)
            val result = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(result.isNotEmpty() && result.keys.size <= 16 &&
                result.getValue("owner").jsonPrimitive.content == "owner" &&
                result.getValue("outsider").jsonPrimitive.content == "outsider" &&
                result.getValue("ownerNativeId") != result.getValue("outsiderNativeId"))
            return result
        } finally { if (child.isAlive) child.destroyForcibly() }
    }
    private fun actor(service: String, actor: String) = GenerationOriginalActorInputs.credential(scope, service, actor)
    private fun donetickReadback(owner: JsonObject, appNonMember: JsonObject,
        gatewayOutsider: JsonObject, oracle: JsonObject): JsonObject {
        val service = "donetick"
        val host = "donetick.datamancy.net"
        val manifest = PackagedGraphFragment.pendingV3R9().first
        val artifactRoot = Path.of(scope.artifactRoot)
        val directory = artifactRoot.resolve("donetick--workflow--headless--native")
        require(artifactRoot.isAbsolute && artifactRoot.normalize() == artifactRoot &&
            artifactRoot.toRealPath() == artifactRoot &&
            Files.isDirectory(directory, NOFOLLOW_LINKS) && directory.toRealPath() == directory)
        val result = json.parseToJsonElement(ReleasePrivateFiles.read(directory.resolve("result.json"), 1048576)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val inv = result.getValue("invocation").jsonObject
        require(result.getValue("passed").jsonPrimitive.boolean && result.getValue("finished").jsonPrimitive.boolean &&
            result.getValue("exitCode").jsonPrimitive.int == 0 &&
            inv.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content == scope.generationId &&
            inv.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL")
        val proofPath = directory.resolve("donetick-native-proof.json")
        val proofBytes = ReleasePrivateFiles.read(proofPath, 16384)
        require(ReleaseLocks.sha256(proofBytes) == result.getValue("artifactHashes").jsonObject
            .getValue("donetick-native-proof.json").jsonPrimitive.content)
        val proof = json.parseToJsonElement(proofBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val sessionBytes = ReleasePrivateFiles.read(directory.resolve("donetick-group-sessions.json"), 16384)
        require(ReleaseLocks.sha256(sessionBytes) == proof.getValue("privateGroupSessionsSha256").jsonPrimitive.content &&
            proof.getValue("phase").jsonPrimitive.content == "INSTALL" &&
            proof.getValue("appNonMemberDenied").jsonPrimitive.boolean &&
            proof.getValue("appNonMemberSubject").jsonPrimitive.content ==
                appNonMember.getValue("username").jsonPrimitive.content &&
            proof.getValue("gatewayOutsiderSubject").jsonPrimitive.content ==
                gatewayOutsider.getValue("username").jsonPrimitive.content &&
            proof.getValue("originalChoreId") == oracle.getValue("choreId") &&
            proof.getValue("originalCompletionId") == oracle.getValue("completionId"))
        val session = json.parseToJsonElement(sessionBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val contexts = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(requireNotNull(scope.contexts).path), 4194304)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val original = contexts.getValue("donetick--workflow--headless--native").jsonObject
        val ownerCredential = ReleasePrivateFiles.read(Path.of(original.getValue("ownerCredentialFile").jsonPrimitive.content),16384)
        DonetickTripleActorContext.requireContext(original)
        val outsiderCredential = ReleasePrivateFiles.read(Path.of(original.getValue("outsiderCredentialFile").jsonPrimitive.content),16384)
        val appNonMemberCredential = ReleasePrivateFiles.read(Path.of(
            original.getValue("appNonMemberCredentialFile").jsonPrimitive.content),16384)
        val ownerSsoCredential = ReleasePrivateFiles.read(Path.of(
            original.getValue("ownerSsoCredentialFile").jsonPrimitive.content),16384)
        val appNonMemberSsoCredential = ReleasePrivateFiles.read(Path.of(
            original.getValue("appNonMemberSsoCredentialFile").jsonPrimitive.content),16384)
        val gatewayOutsiderSsoCredential = ReleasePrivateFiles.read(Path.of(
            original.getValue("gatewayOutsiderSsoCredentialFile").jsonPrimitive.content),16384)
        require(appNonMember.getValue("username").jsonPrimitive.content == "app-nonmember" &&
            gatewayOutsider.getValue("username").jsonPrimitive.content == "outsider" &&
            setOf(owner.getValue("username").jsonPrimitive.content,
                appNonMember.getValue("username").jsonPrimitive.content,
                gatewayOutsider.getValue("username").jsonPrimitive.content).size == 3) {
            "Gateway-denied outsider cannot substitute for the GROUP-authorized app non-member"
        }
        val fresh = requireNotNull(bundle.ownership?.assembly?.request?.freshIdentity).also { it.validate() }
        require(original.getValue("ownerIssuerSubjectUuid").jsonPrimitive.content == fresh.ownerUuid &&
            original.getValue("appNonMemberIssuerSubjectUuid").jsonPrimitive.content == fresh.appNonMemberUuid &&
            original.getValue("gatewayOutsiderIssuerSubjectUuid").jsonPrimitive.content == fresh.outsiderUuid &&
            fresh.outsiderGroups.isEmpty() && fresh.appNonMemberGroups == setOf("users")) {
            "Original GROUP app-test issuer subject cannot alias gateway-denied outsider"
        }
        val trust = QualificationPrivateTls.observe(bundle,
            setOf(host, "auth.datamancy.net", "keycloak-auth.datamancy.net"), expected)
        require(session.keys == setOf("schemaVersion", "host", "owner", "appNonMember",
            "ownerCredentialSha256", "appNonMemberCredentialSha256", "gatewayOutsiderCredentialSha256",
            "ownerSsoCredentialSha256", "appNonMemberSsoCredentialSha256", "gatewayOutsiderSsoCredentialSha256",
            "ownerCookie", "appNonMemberCookie", "gatewayOutsiderSubject", "appNonMemberSubject",
            "ownerIssuerSubjectUuid", "appNonMemberIssuerSubjectUuid", "gatewayOutsiderIssuerSubjectUuid",
            "generationId", "bundleSha256", "invocationId", "originalChoreId", "originalChoreName",
            "sourceLeafSha256", "sourceIdentityLeafSha256", "sourceGatewayLeafSha256", "caSha256") &&
            session.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            session.getValue("host").jsonPrimitive.content == host &&
            session.getValue("generationId").jsonPrimitive.content == scope.generationId &&
            session.getValue("bundleSha256").jsonPrimitive.content == expected &&
            session.getValue("invocationId").jsonPrimitive.content == inv.getValue("invocationId").jsonPrimitive.content &&
            session.getValue("originalChoreId") == oracle.getValue("choreId") &&
            session.getValue("originalChoreName") == oracle.getValue("name") &&
            session.getValue("owner").jsonPrimitive.content == owner.getValue("username").jsonPrimitive.content &&
            session.getValue("appNonMember").jsonPrimitive.content == appNonMember.getValue("username").jsonPrimitive.content &&
            session.getValue("appNonMemberSubject").jsonPrimitive.content == appNonMember.getValue("username").jsonPrimitive.content &&
            session.getValue("gatewayOutsiderSubject").jsonPrimitive.content == gatewayOutsider.getValue("username").jsonPrimitive.content &&
            session.getValue("ownerIssuerSubjectUuid").jsonPrimitive.content == fresh.ownerUuid &&
            session.getValue("appNonMemberIssuerSubjectUuid").jsonPrimitive.content == fresh.appNonMemberUuid &&
            session.getValue("gatewayOutsiderIssuerSubjectUuid").jsonPrimitive.content == fresh.outsiderUuid &&
            session.getValue("ownerCredentialSha256").jsonPrimitive.content == ReleaseLocks.sha256(ownerCredential) &&
            session.getValue("appNonMemberCredentialSha256").jsonPrimitive.content == ReleaseLocks.sha256(appNonMemberCredential) &&
            session.getValue("gatewayOutsiderCredentialSha256").jsonPrimitive.content == ReleaseLocks.sha256(outsiderCredential) &&
            session.getValue("ownerSsoCredentialSha256").jsonPrimitive.content == ReleaseLocks.sha256(ownerSsoCredential) &&
            session.getValue("appNonMemberSsoCredentialSha256").jsonPrimitive.content == ReleaseLocks.sha256(appNonMemberSsoCredential) &&
            session.getValue("gatewayOutsiderSsoCredentialSha256").jsonPrimitive.content == ReleaseLocks.sha256(gatewayOutsiderSsoCredential) &&
            session.getValue("sourceLeafSha256").jsonPrimitive.content == trust.leaves.getValue(host) &&
            session.getValue("sourceIdentityLeafSha256").jsonPrimitive.content == trust.leaves.getValue("auth.datamancy.net") &&
            session.getValue("sourceGatewayLeafSha256").jsonPrimitive.content == trust.leaves.getValue("keycloak-auth.datamancy.net") &&
            session.getValue("caSha256").jsonPrimitive.content == ReleaseLocks.sha256(trust.roots))
        val ownerCookie = session.getValue("ownerCookie").jsonPrimitive.content
        val outsiderCookie = session.getValue("appNonMemberCookie").jsonPrimitive.content
        require(ownerCookie != outsiderCookie &&
            listOf(ownerCookie, outsiderCookie).all { it.matches(Regex("_p0v3_edge=[A-Za-z0-9._~-]{24,512}")) })
        val ownerClient = GenerationOriginalActorHttp.client(root,bundle,expected,manifest,host,ownerCookie)
        val outsiderClient = GenerationOriginalActorHttp.client(root,bundle,expected,manifest,host,outsiderCookie)
        val native = DonetickRuntime.nativeIssuanceReadback(ownerClient,outsiderClient,
            java.net.URI("https://$host"), owner.getValue("username").jsonPrimitive.content,
            owner.getValue("password").jsonPrimitive.content, appNonMember.getValue("username").jsonPrimitive.content,
            appNonMember.getValue("password").jsonPrimitive.content,
            oracle.getValue("choreId").jsonPrimitive.long, oracle.getValue("name").jsonPrimitive.content)
        require(native["owner"] == owner.getValue("username").jsonPrimitive.content &&
            native["appNonMember"] == appNonMember.getValue("username").jsonPrimitive.content &&
            native["nativeResourceId"] == oracle.getValue("choreId").jsonPrimitive.content)
        return JsonObject(native.mapValues { JsonPrimitive(it.value) })
    }
    fun read(service: String, oracle: JsonObject): JsonObject {
        val pin = bundle.members.single { member -> member.spec.processes.any { it.id == when (service) {
            "bookstack" -> "bookstack-php"; "erpnext" -> "backend"; "firefly-iii" -> "firefly-php"
            "forgejo" -> "forgejo"; "donetick" -> "donetick"; else -> error("Unknown actor service")
        } } }
        val owner = actor(service, "owner")
        val outsider = actor(service, "outsider")
        val ownerName = owner.getValue("username").jsonPrimitive.content
        val outsiderName = outsider.getValue("username").jsonPrimitive.content
        require(ownerName != outsiderName && owner.getValue("password") != outsider.getValue("password"))
        return when (service) {
            "bookstack" -> {
                val env = originalEnv(pin, "bookstack-migration.env")
                val apiOwner = GenerationOriginalActorInputs.apiGrant(scope, "owner")
                val apiOutsider = GenerationOriginalActorInputs.apiGrant(scope, "outsider")
                require(apiOwner.getValue("tokenId").jsonPrimitive.content == env.getValue("P0V3_BOOKSTACK_API_ID") &&
                    apiOwner.getValue("secret").jsonPrimitive.content == env.getValue("P0V3_BOOKSTACK_API_SECRET") &&
                    apiOutsider.getValue("tokenId").jsonPrimitive.content == env.getValue("P0V3_BOOKSTACK_OUTSIDER_API_ID") &&
                    apiOutsider.getValue("secret").jsonPrimitive.content == env.getValue("P0V3_BOOKSTACK_OUTSIDER_API_SECRET"))
                val vals = mapOf("P0V3_OWNER_SUB" to env.getValue("P0V3_OWNER_SUB"),
                    "P0V3_BOOKSTACK_OUTSIDER_SUB" to env.getValue("P0V3_BOOKSTACK_OUTSIDER_SUB"),
                    "P0V3_OWNER_PASSWORD" to env.getValue("P0V3_INITIAL_ADMIN_PASSWORD"),
                    "P0V3_BOOKSTACK_API_ID" to apiOwner.getValue("tokenId").jsonPrimitive.content,
                    "P0V3_BOOKSTACK_API_SECRET" to apiOwner.getValue("secret").jsonPrimitive.content,
                    "P0V3_BOOKSTACK_OUTSIDER_API_ID" to env.getValue("P0V3_BOOKSTACK_OUTSIDER_API_ID"),
                    "P0V3_BOOKSTACK_OUTSIDER_API_SECRET" to env.getValue("P0V3_BOOKSTACK_OUTSIDER_API_SECRET"))
                val native = sealedAccount(service, pin, "bookstack-php",
                    FreshBookstackApiSource.nativeIssuanceReadbackSource(), vals, "php")
                require(native.getValue("ownerSubjectUuid").jsonPrimitive.content == env.getValue("P0V3_OWNER_SUB") &&
                    native.getValue("outsiderSubjectUuid").jsonPrimitive.content == env.getValue("P0V3_BOOKSTACK_OUTSIDER_SUB"))
                native
            }
            "firefly-iii" -> {
                val env = originalEnv(pin, "firefly-onboarding.env")
                val vals = listOf("P0V3_OWNER_SUB", "P0V3_OUTSIDER_SUB", "P0V3_OWNER_PASSWORD",
                    "P0V3_OUTSIDER_PASSWORD").associateWith(env::getValue)
                val native = sealedAccount(service, pin, "firefly-php",
                    FireflyCanonical.nativeIssuanceReadbackSource(), vals, "php")
                require(native.getValue("ownerSubjectUuid").jsonPrimitive.content == env.getValue("P0V3_OWNER_SUB") &&
                    native.getValue("outsiderSubjectUuid").jsonPrimitive.content == env.getValue("P0V3_OUTSIDER_SUB"))
                native
            }
            "erpnext" -> {
                val env = originalEnv(pin, "erp-site-bootstrap.env")
                sealedAccount(service, pin, "backend", ErpNextRuntime.nativeIssuanceReadbackSource(),
                    listOf("ERP_OWNER_PASSWORD", "ERP_OUTSIDER_PASSWORD").associateWith(env::getValue),
                    "/home/frappe/frappe-bench/env/bin/python")
            }
            "forgejo" -> {
                val journal = root.resolve("qualification-actor-enrollment")
                ReleasePrivateFiles.directory(journal)
                val intent = json.parseToJsonElement(ReleasePrivateFiles.read(journal.resolve(
                    "forgejo-actors-${scope.generationId}.attempted.json"), 8192)
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                val completed = json.parseToJsonElement(ReleasePrivateFiles.read(journal.resolve(
                    "forgejo-actors-${scope.generationId}.completed.json"), 8192)
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                require(intent.getValue("generation").jsonPrimitive.content == scope.generationId &&
                    intent.getValue("ownerPasswordSha256").jsonPrimitive.content == ReleaseLocks.sha256(
                        owner.getValue("password").jsonPrimitive.content.toByteArray()) &&
                    intent.getValue("outsiderPasswordSha256").jsonPrimitive.content == ReleaseLocks.sha256(
                        outsider.getValue("password").jsonPrimitive.content.toByteArray()) &&
                    completed.getValue("generation").jsonPrimitive.content == scope.generationId &&
                    completed.getValue("owner").jsonPrimitive.content == ownerName &&
                    completed.getValue("outsider").jsonPrimitive.content == outsiderName)
                val host = "forgejo.datamancy.net"
                val manifest = PackagedGraphFragment.pendingV3R9().first
                val client = GenerationOriginalActorHttp.client(root, bundle, expected, manifest, host)
                val native = ForgejoRuntime.nativeIssuanceReadback(client, java.net.URI("https://$host"), ownerName,
                    owner.getValue("password").jsonPrimitive.content, outsiderName,
                    outsider.getValue("password").jsonPrimitive.content,
                    oracle.getValue("repository").jsonPrimitive.content)
                require(native["owner"] == ownerName && native["outsider"] == outsiderName &&
                    native["nativeResourceId"]?.toLongOrNull()?.let { it > 0 } == true)
                JsonObject(native.mapValues { JsonPrimitive(it.value) })
            }
            "donetick" -> donetickReadback(owner, actor(service, "appNonMember"), outsider, oracle)
            else -> error("Unknown actor service")
        }
    }
}
