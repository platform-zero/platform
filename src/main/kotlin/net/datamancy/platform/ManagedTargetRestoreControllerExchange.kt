package net.datamancy.platform

import java.net.URLEncoder
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.time.Instant
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Original-issued scoped realm authority. The secret is read only from the
 * sealed ORIGINAL input; an isolated TARGET must actually exchange it against
 * its CID-bound Keycloak. No browser PKCE, provider token or invented bearer. */
@Serializable internal data class ManagedRestoreControllerExchangeIntent(val schemaVersion: Int = 1,
    val sourceGeneration: String, val targetGeneration: String, val sourceBundleSha256: String,
    val targetBundleSha256: String, val sourceRealmSha256: String, val targetRealmSha256: String,
    val clientId: String, val serviceSubject: String, val secretSha256: String,
    val targetKeycloakCid: String)
@Serializable internal data class ManagedRestoreControllerExchangeResult(val schemaVersion: Int = 1,
    val intentSha256: String, val sourceGeneration: String, val targetGeneration: String,
    val targetKeycloakCid: String, val clientId: String, val serviceSubject: String,
    val bearerSha256: String, val nativeIntrospectionSha256: String,
    val expiresAtEpochSeconds: Long, val targetIssuerVerified: Boolean = true)
@Serializable internal data class ManagedRestoreControllerOriginalResult(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val originalRealmSha256: String,
    val originalKeycloakCid: String, val serviceSubject: String, val secretSha256: String,
    val bearerSha256: String, val nativeIntrospectionSha256: String,
    val expiresAtEpochSeconds: Long, val intentSha256: String)
internal data class ManagedRestoreControllerToken(val bearer: String,
    val receipt: ActivationInput, val subject: String)
internal object ManagedTargetRestoreControllerExchange {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val sha = Regex("[a-f0-9]{64}")
    private const val id = "managed-restore-controller"
    private const val issuer = "https://auth.datamancy.net/realms/p0v3"
    private val roles = setOf("view-users", "view-clients", "manage-clients", "manage-realm")
    private fun form(vararg values: Pair<String, String>): ByteArray = values.joinToString("&") { (key, value) ->
        "$key=${URLEncoder.encode(value, UTF_8)}" }.toByteArray(UTF_8)
    internal fun validateIntrospection(payload: JsonObject, source: String, subject: String,
        targetToken: String): Long {
        require(source.matches(Regex("q-[a-f0-9]{12}")) &&
            java.util.UUID.fromString(subject).toString() == subject && targetToken.length in 80..8192)
        val audiences = payload.getValue("aud").let { value -> if (value is JsonArray)
            value.map { it.jsonPrimitive.content }.toSet() else setOf(value.jsonPrimitive.content) }
        val granted = payload.getValue("resource_access").jsonObject
            .getValue("realm-management").jsonObject.getValue("roles").jsonArray
            .map { it.jsonPrimitive.content }.toSet()
        val expiry = payload.getValue("exp").jsonPrimitive.long
        require(payload.getValue("active").jsonPrimitive.boolean &&
            payload.getValue("iss").jsonPrimitive.content == issuer &&
            payload.getValue("azp").jsonPrimitive.content == id &&
            payload.getValue("sub").jsonPrimitive.content == subject &&
            payload.getValue("p0v3_generation").jsonPrimitive.content == source &&
            "realm-management" in audiences && granted == roles &&
            expiry in (Instant.now().epochSecond + 20)..(Instant.now().epochSecond + 900)) {
            "Isolated target did not authenticate the original scoped controller service account" }
        return expiry
    }
    /** Original issuer must issue/read back the scoped service account only
     * AFTER it is native-ready. This is never a source-sealing prerequisite. */
    fun issueOriginal(bundle: GenerationBundle, root: Path, expected: String,
        http: ManagedRevisionHttp): ActivationInput {
        require(bundle.recoverySourceKopia == null && bundle.request.managedLanes != null &&
            root == GenerationRuntime.BASE.resolve(bundle.request.id) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304)) == expected)
        ManagedGraphIssuerHosts.verify(bundle,root,expected)
        val pin=bundle.members.single()
        val realmPath=PrivateDeployment.BASE.resolve(pin.spec.name).resolve("inputs/identity-realm.json")
        val realmBytes=ReleasePrivateFiles.read(realmPath,4194304)
        val realmSha=pin.inputHashes.getValue("identity-realm.json")
        require(ReleaseLocks.sha256(realmBytes)==realmSha)
        val realm=json.parseToJsonElement(realmBytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val client=realm.getValue("clients").jsonArray.map { it.jsonObject }.single {
            it["clientId"]?.jsonPrimitive?.content==id }
        val secret=client.getValue("secret").jsonPrimitive.content
        require(client==IdentityRuntime.canonicalRestoreControllerClient(secret,bundle.request.id))
        val account=realm.getValue("users").jsonArray.map { it.jsonObject }.single {
            it["serviceAccountClientId"]?.jsonPrimitive?.content==id }
        val subject=account.getValue("id").jsonPrimitive.content
        require(account==IdentityRuntime.canonicalRestoreControllerServiceAccount(subject))
        val start=json.decodeFromString<QuadletMemberStart>(ReleasePrivateFiles.read(root.resolve(
            "quadlet-member-${pin.spec.name}-keycloak.result.json"),8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(start.process=="keycloak" && start.bundleSha256==expected &&
            start.status.state=="running" && start.containerId.matches(sha))
        val dir=root.resolve("managed/identity")
        ReleasePrivateFiles.directory(dir)
        val intent=dir.resolve("restore-controller-original.intent.json")
        val result=dir.resolve("restore-controller-original.result.json")
        require(!Files.exists(intent,NOFOLLOW_LINKS) && !Files.exists(result,NOFOLLOW_LINKS)) {
            "Original service token exchange already attempted; never replay" }
        val claim=buildJsonObject {
            put("generation",bundle.request.id);put("bundleSha256",expected)
            put("realmSha256",realmSha);put("keycloakCid",start.containerId)
            put("serviceSubject",subject);put("secretSha256",ReleaseLocks.sha256(secret.toByteArray(UTF_8)))
        }.toString().toByteArray()
        ReleasePrivateFiles.save(intent,claim)
        val (code,raw)=http.request("POST","/realms/p0v3/protocol/openid-connect/token",null,
            form("grant_type" to "client_credentials","client_id" to id,"client_secret" to secret))
        require(code==200 && raw.size in 100..8192)
        val response=json.parseToJsonElement(raw.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val bearer=response.getValue("access_token").jsonPrimitive.content
        require(response.getValue("token_type").jsonPrimitive.content.equals("Bearer",true) &&
            response.getValue("expires_in").jsonPrimitive.int in 20..900 &&
            bearer.length in 80..8192 && bearer.split('.').size==3)
        val (nativeCode,nativeBytes)=http.request("POST","/realms/p0v3/protocol/openid-connect/token/introspect",
            null,form("client_id" to id,"client_secret" to secret,"token" to bearer))
        require(nativeCode==200 && nativeBytes.size in 100..8192)
        val expires=validateIntrospection(json.parseToJsonElement(nativeBytes.decodeToString(
            throwOnInvalidSequence=true)).jsonObject,bundle.request.id,subject,bearer)
        val receipt=ManagedRestoreControllerOriginalResult(generation=bundle.request.id,
            bundleSha256=expected,originalRealmSha256=realmSha,originalKeycloakCid=start.containerId,
            serviceSubject=subject,secretSha256=ReleaseLocks.sha256(secret.toByteArray(UTF_8)),
            bearerSha256=ReleaseLocks.sha256(bearer.toByteArray(UTF_8)),
            nativeIntrospectionSha256=ReleaseLocks.sha256(nativeBytes),
            expiresAtEpochSeconds=expires,intentSha256=ReleaseLocks.sha256(claim))
        val bytes=json.encodeToString(receipt).toByteArray()
        ReleasePrivateFiles.save(result,bytes)
        return ActivationInput(result.toString(),ReleaseLocks.sha256(bytes))
    }
    private fun original(bundle: GenerationBundle): Pair<ManagedRestoreControllerExchangeIntent, String> {
        val target = bundle.request.id
        val snapshot = requireNotNull(bundle.recoverySourceKopia)
        val source = snapshot.generation
        require(source != target && bundle.request.managedLanes != null && bundle.members.size == 1)
        val oldRoot = GenerationRuntime.BASE.resolve(source)
        val sourceBytes = ReleasePrivateFiles.read(oldRoot.resolve("bundle.json"), 4194304)
        require(ReleaseLocks.sha256(sourceBytes) == snapshot.bundleSha256)
        val old = json.decodeFromString<GenerationBundle>(sourceBytes.decodeToString(throwOnInvalidSequence = true))
        require(old.request.id == source && old.recoverySourceKopia == null && old.members.size == 1 &&
            old.request.managedLanes != null && old.request.store == bundle.request.store)
        val pin = old.members.single()
        val sourceRealm = PrivateDeployment.BASE.resolve(pin.spec.name).resolve("inputs/identity-realm.json")
        val realmBytes = ReleasePrivateFiles.read(sourceRealm, 4194304)
        val sourceHash = pin.inputHashes.getValue("identity-realm.json")
        require(ReleaseLocks.sha256(realmBytes) == sourceHash)
        val realm = json.parseToJsonElement(realmBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val client = realm.getValue("clients").jsonArray.map { it.jsonObject }.single {
            it.getValue("clientId").jsonPrimitive.content == id }
        val secret = client.getValue("secret").jsonPrimitive.content
        require(client == IdentityRuntime.canonicalRestoreControllerClient(secret, source))
        val account = realm.getValue("users").jsonArray.map { it.jsonObject }.single {
            it["serviceAccountClientId"]?.jsonPrimitive?.content == id }
        val subject = account.getValue("id").jsonPrimitive.content
        require(account == IdentityRuntime.canonicalRestoreControllerServiceAccount(subject) &&
            subject !in setOf(old.request.managedLanes!!.ownerSubject,
                old.request.managedLanes.readerSubject, old.request.managedLanes.lanes.first().subject))
        val originalIntent = ReleasePrivateFiles.read(oldRoot.resolve(
            "managed/identity/restore-controller-original.intent.json"),8192)
        val originalResult = json.decodeFromString<ManagedRestoreControllerOriginalResult>(ReleasePrivateFiles.read(
            oldRoot.resolve("managed/identity/restore-controller-original.result.json"),8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(originalResult.schemaVersion==1 && originalResult.generation==source &&
            originalResult.bundleSha256==snapshot.bundleSha256 &&
            originalResult.originalRealmSha256==sourceHash && originalResult.serviceSubject==subject &&
            originalResult.secretSha256==ReleaseLocks.sha256(secret.toByteArray(UTF_8)) &&
            originalResult.intentSha256==ReleaseLocks.sha256(originalIntent) &&
            listOf(originalResult.bearerSha256,originalResult.nativeIntrospectionSha256,
                originalResult.originalKeycloakCid).all(sha::matches)) {
            "Original issuer never acknowledged the scoped restore-controller credential" }
        val targetPin = bundle.members.single()
        val targetBytes = ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(targetPin.spec.name)
            .resolve("inputs/identity-realm.json"), 4194304)
        val targetHash = targetPin.inputHashes.getValue("identity-realm.json")
        require(ReleaseLocks.sha256(targetBytes) == targetHash &&
            targetBytes.contentEquals(realmBytes)) {
            "Isolated target did not import the selected original protected realm" }
        val expected = ReleaseLocks.sha256(ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(target)
            .resolve("bundle.json"), 4194304))
        val keycloakBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(target).resolve(
            "quadlet-member-${targetPin.spec.name}-keycloak.result.json"), 8192)
        val keycloak = json.decodeFromString<QuadletMemberStart>(keycloakBytes.decodeToString(throwOnInvalidSequence = true))
        require(keycloak.process == "keycloak" && keycloak.bundleSha256 == expected &&
            keycloak.status.state == "running" && keycloak.containerId.matches(sha))
        val intent = ManagedRestoreControllerExchangeIntent(sourceGeneration = source,
            targetGeneration = target, sourceBundleSha256 = snapshot.bundleSha256,
            targetBundleSha256 = expected, sourceRealmSha256 = sourceHash,
            targetRealmSha256 = targetHash, clientId = id, serviceSubject = subject,
            secretSha256 = ReleaseLocks.sha256(secret.toByteArray(UTF_8)),
            targetKeycloakCid = keycloak.containerId)
        return intent to secret
    }
    /** Caller holds generation + managed owner locks, with verified selected
     * target CID/CA/leaf and exact issuer.hosts. Never call for source sealing. */
    fun exchange(bundle: GenerationBundle, root: Path, expected: String,
        http: ManagedRevisionHttp): ManagedRestoreControllerToken {
        require(root == GenerationRuntime.BASE.resolve(bundle.request.id) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)) == expected)
        ManagedGraphIssuerHosts.verify(bundle, root, expected)
        val (claim, secret) = original(bundle)
        require(claim.targetBundleSha256 == expected)
        val dir = root.resolve("managed/identity/recovery-revision")
        ReleasePrivateFiles.directory(dir)
        val intentPath = dir.resolve("scoped-controller-token.intent.json")
        val resultPath = dir.resolve("scoped-controller-token.result.json")
        val introspectionPath = dir.resolve("scoped-controller-token.introspection.json")
        require(listOf(intentPath, resultPath, introspectionPath).none { Files.exists(it, NOFOLLOW_LINKS) }) {
            "Target scoped controller token already attempted; no second exchange on lost ACK" }
        val intentBytes = json.encodeToString(claim).toByteArray()
        ReleasePrivateFiles.save(intentPath, intentBytes)
        val (code, response) = http.request("POST", "/realms/p0v3/protocol/openid-connect/token", null,
            form("grant_type" to "client_credentials", "client_id" to id, "client_secret" to secret))
        require(code == 200 && response.size in 100..8192)
        val issued = json.parseToJsonElement(response.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val bearer = issued.getValue("access_token").jsonPrimitive.content
        require(issued.getValue("token_type").jsonPrimitive.content.equals("Bearer", true) &&
            bearer.length in 80..8192 && bearer.split('.').size == 3 &&
            issued.getValue("expires_in").jsonPrimitive.int in 20..900)
        val (status, introspection) = http.request("POST", "/realms/p0v3/protocol/openid-connect/token/introspect",
            null, form("client_id" to id, "client_secret" to secret, "token" to bearer))
        require(status == 200 && introspection.size in 100..8192)
        val observed = json.parseToJsonElement(introspection.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val expiry = validateIntrospection(observed, claim.sourceGeneration, claim.serviceSubject, bearer)
        // Exclude the bearer from every persisted result. Introspection can
        // include token material in vendor fields: persist only vetted claims.
        val safe = buildJsonObject {
            put("active", true); put("iss", issuer); put("azp", id)
            put("sub", claim.serviceSubject); put("p0v3_generation", claim.sourceGeneration)
            put("exp", expiry); put("aud", "realm-management")
            put("roles", buildJsonArray { roles.sorted().forEach { add(it) } })
        }.toString().toByteArray()
        ReleasePrivateFiles.save(introspectionPath, safe)
        val result = ManagedRestoreControllerExchangeResult(
            intentSha256 = ReleaseLocks.sha256(intentBytes), sourceGeneration = claim.sourceGeneration,
            targetGeneration = claim.targetGeneration, targetKeycloakCid = claim.targetKeycloakCid,
            clientId = id, serviceSubject = claim.serviceSubject,
            bearerSha256 = ReleaseLocks.sha256(bearer.toByteArray(UTF_8)),
            nativeIntrospectionSha256 = ReleaseLocks.sha256(introspection),
            expiresAtEpochSeconds = expiry)
        val resultBytes = json.encodeToString(result).toByteArray()
        ReleasePrivateFiles.save(resultPath, resultBytes)
        return ManagedRestoreControllerToken(bearer, ActivationInput(resultPath.toString(),
            ReleaseLocks.sha256(resultBytes)), claim.serviceSubject)
    }
}
