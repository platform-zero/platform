package net.datamancy.platform

import java.net.URL
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateFactory
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Only the scoped original confidential service actor may revise imported
 * managed clients on the isolated target; no human session or external bearer. */
@Serializable internal data class ManagedRecoveryIssuerResult(val targetGeneration:String,val targetBundleSha256:String,
    val sourceBundleSha256:String,val keycloakCid:String,val scopedTokenResultSha256:String,
    val scopedControllerSubject:String,val stepHashes:List<String>,val targetAgentSubject:String,
    val targetReaderSubject:String,val scopedRetirementIntentSha256:String,
    val scopedRetirementResultSha256:String,val originalSecretDenied:Boolean,
    val revokedSourceTokens:Boolean,val targetScopedTokenReadback:Boolean)

internal interface ManagedRevisionHttp {
    fun request(method:String,path:String,bearer:String?,body:ByteArray?=null):Pair<Int,ByteArray>
}
/** All traffic is CID-bound Keycloak HTTPS; never use the public issuer's admin route. */
internal class PinnedManagedRevisionHttp(ca:Path,leaf:Path,privateAddress:String):ManagedRevisionHttp {
    private val factory:javax.net.ssl.SSLSocketFactory
    private val leafSha:String
    init {
        val caBytes=ReleasePrivateFiles.read(ca,65536)
        val certificate=CertificateFactory.getInstance("X.509").generateCertificate(
            ReleasePrivateFiles.read(leaf,65536).inputStream())
        leafSha=ReleaseLocks.sha256(certificate.encoded)
        val store=KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null,null);setCertificateEntry("selected-target-identity",CertificateFactory.getInstance("X.509")
                .generateCertificate(caBytes.inputStream()))
        }
        val pkix=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
            .trustManagers.filterIsInstance<X509TrustManager>().single()
        val pinned=object: X509TrustManager {
            override fun getAcceptedIssuers()=pkix.acceptedIssuers
            override fun checkClientTrusted(chain:Array<java.security.cert.X509Certificate>,auth:String)=pkix.checkClientTrusted(chain,auth)
            override fun checkServerTrusted(chain:Array<java.security.cert.X509Certificate>,auth:String) {
                pkix.checkServerTrusted(chain,auth)
                require(chain.isNotEmpty() && ReleaseLocks.sha256(chain[0].encoded)==leafSha)
            }
        }
        val trusted=SSLContext.getInstance("TLS").apply { init(null,arrayOf(pinned),null) }.socketFactory
        factory=PrivatePinnedSocketFactory(trusted,"keycloak",privateAddress)
    }
    override fun request(method:String,path:String,bearer:String?,body:ByteArray?):Pair<Int,ByteArray> {
        require(method in setOf("GET","PUT","POST") && (path.startsWith("/admin/realms/p0v3/") ||
            path in setOf("/realms/p0v3/protocol/openid-connect/token",
                "/realms/p0v3/protocol/openid-connect/token/introspect")) &&
            !path.contains("..") && !path.contains('?') && path.length<=256 && (body?.size?:0)<=65536 &&
            bearer?.let { it.length in 80..8192 && !it.contains('\n') }!=false)
        val connection=URL("https://keycloak:8443$path").openConnection() as HttpsURLConnection
        try {
            connection.sslSocketFactory=factory;connection.instanceFollowRedirects=false
            connection.connectTimeout=4000;connection.readTimeout=6000;connection.requestMethod=method
            connection.setRequestProperty("Accept","application/json")
            bearer?.let { connection.setRequestProperty("Authorization","Bearer $it") }
            if(body!=null) {
                connection.doOutput=true;connection.setRequestProperty("Content-Type",
                    if(path.startsWith("/admin/")) "application/json" else "application/x-www-form-urlencoded")
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val code=connection.responseCode
            require(code !in 300..399) { "Native issuer redirect refused" }
            val stream=if(code>=400) connection.errorStream else connection.inputStream
            val bytes=stream?.use { it.readNBytes(65537) }?:byteArrayOf()
            require(bytes.size<=65536)
            return code to bytes
        } finally { connection.disconnect() }
    }
}

/** Original stage owner keeps its lock; every mutation has an EXCLUSIVE intent and
 * independent native readback result. A partial/uncertain effect is never replayed. */
internal object ManagedRecoveryIdentityRevision {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private val sha=Regex("[a-f0-9]{64}")
    fun preflight(bundle:GenerationBundle,root:Path,expected:String) {
        require(bundle.recoverySourceKopia!=null && bundle.request.managedLanes?.native?.brokerHost!=null &&
            root==GenerationRuntime.BASE.resolve(bundle.request.id) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304))==expected)
        val snapshot=requireNotNull(bundle.recoverySourceKopia)
        val sourceRoot=GenerationRuntime.BASE.resolve(snapshot.generation)
        val originalBytes=ReleasePrivateFiles.read(sourceRoot.resolve("bundle.json"),4194304)
        require(ReleaseLocks.sha256(originalBytes)==snapshot.bundleSha256 &&
            snapshot.generation!=bundle.request.id)
        val original=json.decodeFromString<GenerationBundle>(originalBytes.decodeToString(throwOnInvalidSequence=true))
        val sourcePin=original.members.single();val targetPin=bundle.members.single()
        val sourceRealm=ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(sourcePin.spec.name)
            .resolve("inputs/identity-realm.json"),4194304)
        val targetRealm=ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(targetPin.spec.name)
            .resolve("inputs/identity-realm.json"),4194304)
        require(original.request.id==snapshot.generation &&
            original.request.managedLanes!=null &&
            ReleaseLocks.sha256(sourceRealm)==sourcePin.inputHashes.getValue("identity-realm.json") &&
            ReleaseLocks.sha256(targetRealm)==targetPin.inputHashes.getValue("identity-realm.json") &&
            sourceRealm.contentEquals(targetRealm) &&
            original.request.managedLanes?.ownerSubject==bundle.request.managedLanes?.ownerSubject)
        val realm=json.parseToJsonElement(sourceRealm.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val client=realm.getValue("clients").jsonArray.map { it.jsonObject }.single {
            it["clientId"]?.jsonPrimitive?.content=="managed-restore-controller" }
        require(client==IdentityRuntime.canonicalRestoreControllerClient(
            client.getValue("secret").jsonPrimitive.content,snapshot.generation))
        val actor=realm.getValue("users").jsonArray.map { it.jsonObject }.single {
            it["serviceAccountClientId"]?.jsonPrimitive?.content=="managed-restore-controller" }
        require(actor==IdentityRuntime.canonicalRestoreControllerServiceAccount(
            actor.getValue("id").jsonPrimitive.content))
        val originalResult=json.decodeFromString<ManagedRestoreControllerOriginalResult>(
            ReleasePrivateFiles.read(sourceRoot.resolve("managed/identity/restore-controller-original.result.json"),8192)
                .decodeToString(throwOnInvalidSequence=true))
        require(originalResult.generation==snapshot.generation &&
            originalResult.bundleSha256==snapshot.bundleSha256 &&
            originalResult.originalRealmSha256==ReleaseLocks.sha256(sourceRealm) &&
            originalResult.secretSha256==ReleaseLocks.sha256(
                client.getValue("secret").jsonPrimitive.content.encodeToByteArray()) &&
            originalResult.serviceSubject==actor.getValue("id").jsonPrimitive.content &&
            originalResult.intentSha256==ReleaseLocks.sha256(ReleasePrivateFiles.read(sourceRoot.resolve(
                "managed/identity/restore-controller-original.intent.json"),8192)))
    }
    fun beforeEnrollment(bundle:GenerationBundle,root:Path,expected:String,controller:Path) {
        preflight(bundle,root,expected)
        val dir=root.resolve("managed/identity/recovery-revision")
        require(!Files.exists(dir,NOFOLLOW_LINKS)) { "Target issuer revision already attempted; never replay" }
        val descriptor=requireNotNull(bundle.members.single().spec.fragmentBinding?.controllerSha256)
        require(controller==Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$descriptor/bin/p0-v3-platform"))
        PinnedBackupController.verifyDistribution(controller.parent.parent,descriptor,"p0-v3-platform")
        val child=ProcessBuilder(controller.toString(),"release","generation-recovered-managed-revise",
            bundle.request.id,expected).also {
            it.environment()["JAVA_TOOL_OPTIONS"]="-Djdk.net.hosts.file=${root.resolve("managed/control/issuer.hosts")}" 
            it.redirectOutput(ProcessBuilder.Redirect.DISCARD);it.redirectError(ProcessBuilder.Redirect.DISCARD)
        }.start()
        try { require(child.waitFor(180,TimeUnit.SECONDS) && child.exitValue()==0) {
            "Target Keycloak issuer revision uncertain; preserve original intents, never replay"
        } } finally { if(child.isAlive) child.destroyForcibly() }
        verify(bundle,root,expected)
    }
    fun verify(bundle:GenerationBundle,root:Path,expected:String):ManagedRecoveryIssuerResult {
        val dir=root.resolve("managed/identity/recovery-revision")
        val result=json.decodeFromString<ManagedRecoveryIssuerResult>(ReleasePrivateFiles.read(
            dir.resolve("original.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        preflight(bundle,root,expected)
        val exchangeIntentBytes=ReleasePrivateFiles.read(dir.resolve("scoped-controller-token.intent.json"),8192)
        val exchangeIntent=json.decodeFromString<ManagedRestoreControllerExchangeIntent>(
            exchangeIntentBytes.decodeToString(throwOnInvalidSequence=true))
        val exchangeBytes=ReleasePrivateFiles.read(dir.resolve("scoped-controller-token.result.json"),8192)
        val exchange=json.decodeFromString<ManagedRestoreControllerExchangeResult>(
            exchangeBytes.decodeToString(throwOnInvalidSequence=true))
        val original=json.parseToJsonElement(ReleasePrivateFiles.read(dir.resolve("original.intent.json"),8192)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        val safe=json.parseToJsonElement(ReleasePrivateFiles.read(dir.resolve(
            "scoped-controller-token.introspection.json"),8192)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(safe.getValue("active").jsonPrimitive.boolean &&
            safe.getValue("iss").jsonPrimitive.content=="https://auth.datamancy.net/realms/p0v3" &&
            safe.getValue("azp").jsonPrimitive.content=="managed-restore-controller" &&
            safe.getValue("sub").jsonPrimitive.content==exchange.serviceSubject &&
            safe.getValue("p0v3_generation").jsonPrimitive.content==exchange.sourceGeneration &&
            safe.getValue("aud").jsonPrimitive.content=="realm-management" &&
            safe.getValue("roles").jsonArray.map { it.jsonPrimitive.content }.toSet()==setOf(
                "view-users","view-clients","manage-clients","manage-realm") &&
            safe.getValue("exp").jsonPrimitive.long==exchange.expiresAtEpochSeconds &&
            exchange.nativeIntrospectionSha256.matches(sha) && exchange.bearerSha256.matches(sha) &&
            exchange.intentSha256==ReleaseLocks.sha256(exchangeIntentBytes) &&
            exchange.sourceGeneration==requireNotNull(bundle.recoverySourceKopia).generation &&
            exchange.targetGeneration==bundle.request.id && exchange.targetIssuerVerified &&
            exchange.clientId=="managed-restore-controller" &&
            exchange.serviceSubject==exchangeIntent.serviceSubject &&
            exchange.targetKeycloakCid==exchangeIntent.targetKeycloakCid &&
            original["targetGeneration"]?.jsonPrimitive?.content==bundle.request.id &&
            original["sourceGeneration"]?.jsonPrimitive?.content==exchange.sourceGeneration &&
            original["bundleSha256"]?.jsonPrimitive?.content==expected &&
            original["scopedTokenResultSha256"]?.jsonPrimitive?.content==ReleaseLocks.sha256(exchangeBytes) &&
            original["controllerSubject"]?.jsonPrimitive?.content==exchange.serviceSubject &&
            original["keycloakCid"]?.jsonPrimitive?.content==result.keycloakCid)
        val names=listOf("managed-lane-agent-secret","managed-lane-agent-mapper",
            "managed-lane-reader-secret","managed-lane-reader-mapper","identity-controller-mapper")
        val retireIntent=ReleasePrivateFiles.read(dir.resolve("scoped-controller-retire.intent.json"),8192)
        val retireResult=ReleasePrivateFiles.read(dir.resolve("scoped-controller-retire.result.json"),8192)
        val retired=json.parseToJsonElement(retireResult.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val retirement=json.parseToJsonElement(retireIntent.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(retirement.getValue("sourceGeneration").jsonPrimitive.content==exchange.sourceGeneration &&
            retirement.getValue("targetGeneration").jsonPrimitive.content==bundle.request.id &&
            retirement.getValue("bundleSha256").jsonPrimitive.content==expected &&
            retirement.getValue("keycloakCid").jsonPrimitive.content==exchange.targetKeycloakCid &&
            retirement.getValue("oldSecretSha256").jsonPrimitive.content==exchangeIntent.secretSha256 &&
            retirement.getValue("newSecretSha256").jsonPrimitive.content.matches(sha) &&
            retirement.getValue("newSecretSha256").jsonPrimitive.content!=exchangeIntent.secretSha256 &&
            retirement.getValue("bodySha256").jsonPrimitive.content.matches(sha) &&
            result.scopedRetirementIntentSha256==ReleaseLocks.sha256(retireIntent) &&
            result.scopedRetirementResultSha256==ReleaseLocks.sha256(retireResult) &&
            result.originalSecretDenied && retired.getValue("intentSha256").jsonPrimitive.content==
                result.scopedRetirementIntentSha256 &&
            retired.getValue("newSecretReadback").jsonPrimitive.boolean &&
            retired.getValue("originalSecretDenied").jsonPrimitive.boolean &&
            retired.getValue("keycloakCid").jsonPrimitive.content==result.keycloakCid)
        require(result.stepHashes.size==names.size && names.mapIndexed { i,name ->
            val intent=ReleasePrivateFiles.read(dir.resolve("$name.intent.json"),8192)
            val bytes=ReleasePrivateFiles.read(dir.resolve("$name.result.json"),8192)
            val requested=json.parseToJsonElement(intent.decodeToString(throwOnInvalidSequence=true)).jsonObject
            val record=json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
            require(requested["name"]?.jsonPrimitive?.content==name &&
                requested["targetGeneration"]?.jsonPrimitive?.content==bundle.request.id &&
                requested["bundleSha256"]?.jsonPrimitive?.content==expected &&
                requested["keycloakCid"]?.jsonPrimitive?.content==result.keycloakCid &&
                requested["bodySha256"]?.jsonPrimitive?.content?.matches(sha)==true &&
                record["intentSha256"]?.jsonPrimitive?.content==ReleaseLocks.sha256(intent) &&
                record["readback"]?.jsonPrimitive?.booleanOrNull==true)
            ReleaseLocks.sha256(bytes)==result.stepHashes[i]
        }.all { it } && run {
            val intent=ReleasePrivateFiles.read(dir.resolve("realm-logout-all.intent.json"),8192)
            val record=json.parseToJsonElement(ReleasePrivateFiles.read(
                dir.resolve("realm-logout-all.result.json"),8192).decodeToString(throwOnInvalidSequence=true)).jsonObject
            record["intentSha256"]?.jsonPrimitive?.content==ReleaseLocks.sha256(intent) &&
                record["nativeExitCode"]?.jsonPrimitive?.intOrNull==204
        })
        require(result.targetGeneration==bundle.request.id && result.targetBundleSha256==expected &&
            result.sourceBundleSha256==exchangeIntent.sourceBundleSha256 &&
            result.scopedTokenResultSha256==ReleaseLocks.sha256(exchangeBytes) &&
            result.scopedControllerSubject==exchange.serviceSubject &&
            result.stepHashes.size==5 && result.stepHashes.all(sha::matches) &&
            result.scopedRetirementIntentSha256.matches(sha) &&
            result.scopedRetirementResultSha256.matches(sha) &&
            result.keycloakCid==Json.decodeFromString<QuadletMemberStart>(ReleasePrivateFiles.read(
                root.resolve("quadlet-member-${bundle.members.single().spec.name}-keycloak.result.json"),8192)
                .decodeToString(throwOnInvalidSequence=true)).containerId &&
            result.targetAgentSubject==bundle.request.managedLanes?.lanes?.first()?.subject &&
            result.targetReaderSubject==bundle.request.managedLanes?.readerSubject &&
            result.revokedSourceTokens && result.targetScopedTokenReadback)
        ManagedGraphIssuerHosts.verify(bundle,root,expected)
        return result
    }
    fun issueInChild(generation:String,expected:String) {
        val root=GenerationRuntime.BASE.resolve(generation)
        val bundle=json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304)
            .decodeToString(throwOnInvalidSequence=true))
        ManagedGraphIssuerHosts.verify(bundle,root,expected)
        preflight(bundle,root,expected)
        val sourceId=requireNotNull(bundle.recoverySourceKopia).generation
        val source=json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(
            GenerationRuntime.BASE.resolve(sourceId).resolve("bundle.json"),4194304)
            .decodeToString(throwOnInvalidSequence=true))
        val sourceHost=requireNotNull(source.request.managedLanes?.native?.brokerHost)
        val host=requireNotNull(bundle.request.managedLanes?.native?.brokerHost)
        require(sourceHost.agentSecret.sha256!=host.agentSecret.sha256 &&
            sourceHost.readerSecret.sha256!=host.readerSecret.sha256)
        val member=bundle.members.single()
        val inputs=PrivateDeployment.BASE.resolve(member.spec.name).resolve("inputs")
        val ca=inputs.resolve("identity-ca.pem");val leaf=inputs.resolve("identity-web.pem")
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(ca,65536))==member.inputHashes.getValue("identity-ca.pem") &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(leaf,65536))==member.inputHashes.getValue("identity-web.pem"))
        val hosts=ManagedGraphIssuerHosts.addresses(bundle,root,expected)
        val http=PinnedManagedRevisionHttp(ca,leaf,hosts.getValue("keycloak"))
        val revision=root.resolve("managed/identity/recovery-revision")
        ReleasePrivateFiles.directory(revision.parent)
        require(!Files.exists(revision,NOFOLLOW_LINKS))
        Files.createDirectory(revision,java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(revision.parent)
        val token=ManagedTargetRestoreControllerExchange.exchange(bundle,root,expected,http)
        issue(bundle,root,expected,token,http)
    }
    internal fun issue(bundle:GenerationBundle,root:Path,expected:String,token:ManagedRestoreControllerToken,
        http:ManagedRevisionHttp) {
        val bearer=token.bearer
        val sourceId=requireNotNull(bundle.recoverySourceKopia).generation
        val scoped=json.decodeFromString<ManagedRestoreControllerExchangeResult>(ReleasePrivateFiles.read(
            Path.of(token.receipt.path),8192).decodeToString(throwOnInvalidSequence=true))
        require(token.subject==scoped.serviceSubject && scoped.targetGeneration==bundle.request.id &&
            token.receipt.sha256==ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(token.receipt.path),8192)))
        val plan=requireNotNull(bundle.request.managedLanes);val host=requireNotNull(plan.native.brokerHost)
        val source=json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(
            GenerationRuntime.BASE.resolve(sourceId).resolve("bundle.json"),4194304)
            .decodeToString(throwOnInvalidSequence=true))
        val oldHost=requireNotNull(source.request.managedLanes?.native?.brokerHost)
        val dir=root.resolve("managed/identity/recovery-revision")
        ReleasePrivateFiles.directory(dir)
        require(!Files.exists(dir.resolve("original.intent.json"),NOFOLLOW_LINKS) &&
            !Files.exists(dir.resolve("original.result.json"),NOFOLLOW_LINKS))
        val path="/admin/realms/p0v3/clients"
        fun call(method:String,endpoint:String,body:ByteArray?=null):ByteArray {
            val (status,bytes)=http.request(method,endpoint,bearer,body)
            require(status==if(method=="GET") 200 else 204) { "Target Keycloak native admin operation refused: $status" }
            return bytes
        }
        val all=json.parseToJsonElement(call("GET",path).decodeToString(throwOnInvalidSequence=true)).jsonArray.map { it.jsonObject }
        val ids=listOf("managed-lane-agent","managed-lane-reader","identity-controller")
            .associateWith { id -> all.single { it["clientId"]?.jsonPrimitive?.content==id }
                .getValue("id").jsonPrimitive.content.also { require(runCatching {
                    java.util.UUID.fromString(it).toString()==it }.getOrDefault(false)) } }
        // Target-native admin readback binds the already introspected in-memory
        // bearer to the ORIGINAL scoped service actor, not a human session.
        val controller=all.single { it["clientId"]?.jsonPrimitive?.content=="managed-restore-controller" }
        val controllerId=controller.getValue("id").jsonPrimitive.content
        val account=json.parseToJsonElement(call("GET","$path/$controllerId/service-account-user")
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(controller["serviceAccountsEnabled"]?.jsonPrimitive?.booleanOrNull==true &&
            controller["publicClient"]?.jsonPrimitive?.booleanOrNull==false &&
            account["id"]?.jsonPrimitive?.content==token.subject &&
            account["enabled"]?.jsonPrimitive?.booleanOrNull==true &&
            scoped.clientId=="managed-restore-controller" && scoped.targetIssuerVerified)
        // Verify source-generation mappers and original secrets before first intent.
        val originals=ids.keys.map { id ->
            val uid=ids.getValue(id)
            val client=json.parseToJsonElement(call("GET","$path/$uid").decodeToString(throwOnInvalidSequence=true)).jsonObject
            val mappings=json.parseToJsonElement(call("GET","$path/$uid/protocol-mappers/models").decodeToString(throwOnInvalidSequence=true))
                .jsonArray.map { it.jsonObject }
            val mapper=mappings.single { it["name"]?.jsonPrimitive?.content==
                if(id=="identity-controller") "identity-generation" else "keykeeper-generation" }
            require(mapper.getValue("config").jsonObject.getValue("claim.value").jsonPrimitive.content==sourceId &&
                client.getValue("clientId").jsonPrimitive.content==id)
            if(id!="identity-controller") {
                val present=json.parseToJsonElement(call("GET","$path/$uid/client-secret").decodeToString(throwOnInvalidSequence=true))
                    .jsonObject.getValue("value").jsonPrimitive.content
                val old=oldHost.secret(if(id=="managed-lane-agent") oldHost.agentSecret else oldHost.readerSecret,
                    sourceId)
                require(present==old && present!=host.secret(if(id=="managed-lane-agent") host.agentSecret else host.readerSecret,generation=plan.generation))
            }
            Triple(id,client,mapper)
        }
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(token.receipt.path),8192))==
            token.receipt.sha256 && Path.of(token.receipt.path)==dir.resolve("scoped-controller-token.result.json"))
        val start=Json.decodeFromString<QuadletMemberStart>(ReleasePrivateFiles.read(root.resolve(
            "quadlet-member-${bundle.members.single().spec.name}-keycloak.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        val intent=buildJsonObject { put("sourceGeneration",sourceId);put("targetGeneration",plan.generation)
            put("bundleSha256",expected);put("keycloakCid",start.containerId)
            put("scopedTokenResultSha256",token.receipt.sha256);put("controllerSubject",token.subject) }
        ReleasePrivateFiles.save(dir.resolve("original.intent.json"),intent.toString().toByteArray())
        val sourceTokens=listOf("managed-lane-agent","managed-lane-reader").map { id ->
            ManagedRecoveryIdentityReadback.token(http,id,oldHost.secret(
                if(id=="managed-lane-agent") oldHost.agentSecret else oldHost.readerSecret,sourceId),
                sourceId, if(id=="managed-lane-agent") source.request.managedLanes!!.lanes.first().subject
                    else requireNotNull(source.request.managedLanes!!.readerSubject))
        }
        val stepHashes=mutableListOf<String>()
        fun step(name:String,endpoint:String,body:ByteArray,readback:()->Boolean) {
            val request=buildJsonObject { put("name",name);put("targetGeneration",plan.generation)
                put("bundleSha256",expected);put("bodySha256",ReleaseLocks.sha256(body));put("keycloakCid",start.containerId) }
            val intentBytes=request.toString().toByteArray()
            ReleasePrivateFiles.save(dir.resolve("$name.intent.json"),intentBytes)
            call("PUT",endpoint,body)
            require(readback()) { "Target issuer $name native readback failed; do not replay" }
            val result=buildJsonObject { put("intentSha256",ReleaseLocks.sha256(intentBytes));put("readback",true) }
                .toString().toByteArray()
            ReleasePrivateFiles.save(dir.resolve("$name.result.json"),result)
            stepHashes+=ReleaseLocks.sha256(result)
        }
        for((id,client,mapper) in originals) {
            val uid=ids.getValue(id)
            if(id!="identity-controller") {
                val secret=host.secret(if(id=="managed-lane-agent") host.agentSecret else host.readerSecret,plan.generation)
                val updated=JsonObject(client + ("secret" to JsonPrimitive(secret)))
                step("$id-secret","$path/$uid",updated.toString().toByteArray()) {
                    json.parseToJsonElement(call("GET","$path/$uid/client-secret").decodeToString(throwOnInvalidSequence=true)).jsonObject
                        .getValue("value").jsonPrimitive.content==secret
                }
            }
            val config=mapper.getValue("config").jsonObject
            val replacement=JsonObject(mapper+("config" to JsonObject(config+("claim.value" to JsonPrimitive(plan.generation)))))
            val mid=mapper.getValue("id").jsonPrimitive.content
            require(runCatching { java.util.UUID.fromString(mid).toString()==mid }.getOrDefault(false))
            val endpoint="$path/$uid/protocol-mappers/models/$mid"
            step("$id-mapper",endpoint,replacement.toString().toByteArray()) {
                json.parseToJsonElement(call("GET",endpoint).decodeToString(throwOnInvalidSequence=true)).jsonObject.getValue("config").jsonObject
                    .getValue("claim.value").jsonPrimitive.content==plan.generation
            }
        }
        // Rotate the original scoped controller's target-only secret BEFORE
        // realm logout-all: a disabled service actor could lose the current
        // bearer before that final mutation. Rotation never reissues the
        // original source secret and is independently read back and denied.
        val sourcePin=source.members.single()
        val realmBytes=ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(sourcePin.spec.name)
            .resolve("inputs/identity-realm.json"),4194304)
        require(ReleaseLocks.sha256(realmBytes)==sourcePin.inputHashes.getValue("identity-realm.json"))
        val sourceClient=json.parseToJsonElement(realmBytes.decodeToString(throwOnInvalidSequence=true))
            .jsonObject.getValue("clients").jsonArray.map { it.jsonObject }.single {
                it["clientId"]?.jsonPrimitive?.content=="managed-restore-controller" }
        val originalSecret=sourceClient.getValue("secret").jsonPrimitive.content
        val clientPath="$path/$controllerId"
        val originalLive=json.parseToJsonElement(call("GET","$clientPath/client-secret")
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(originalLive.getValue("value").jsonPrimitive.content==originalSecret &&
            sourceClient==IdentityRuntime.canonicalRestoreControllerClient(originalSecret,sourceId))
        val replacement=ByteArray(32).also { SecureRandom().nextBytes(it) }.joinToString("") {
            "%02x".format(it.toInt() and 255) }
        require(replacement.matches(sha) && replacement!=originalSecret)
        val currentClient=json.parseToJsonElement(call("GET",clientPath)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(currentClient.getValue("clientId").jsonPrimitive.content=="managed-restore-controller" &&
            currentClient.getValue("id").jsonPrimitive.content==controllerId)
        val rotated=JsonObject(currentClient+("secret" to JsonPrimitive(replacement))).toString().toByteArray()
        val retire=buildJsonObject {
            put("sourceGeneration",sourceId);put("targetGeneration",plan.generation)
            put("bundleSha256",expected);put("keycloakCid",start.containerId)
            put("clientId",controllerId);put("oldSecretSha256",ReleaseLocks.sha256(originalSecret.encodeToByteArray()))
            put("newSecretSha256",ReleaseLocks.sha256(replacement.encodeToByteArray()))
            put("bodySha256",ReleaseLocks.sha256(rotated))
        }.toString().toByteArray()
        ReleasePrivateFiles.save(dir.resolve("scoped-controller-retire.intent.json"),retire)
        call("PUT",clientPath,rotated)
        val newValue=json.parseToJsonElement(call("GET","$clientPath/client-secret")
            .decodeToString(throwOnInvalidSequence=true)).jsonObject.getValue("value").jsonPrimitive.content
        require(newValue==replacement)
        val oldForm="grant_type=client_credentials&client_id=managed-restore-controller&client_secret=$originalSecret"
            .encodeToByteArray()
        val (deniedCode,_)=http.request("POST","/realms/p0v3/protocol/openid-connect/token",null,oldForm)
        require(deniedCode in setOf(400,401)) { "Original scoped controller secret still issues target tokens" }
        val retired=buildJsonObject { put("intentSha256",ReleaseLocks.sha256(retire))
            put("newSecretReadback",true);put("originalSecretDenied",true)
            put("keycloakCid",start.containerId) }.toString().toByteArray()
        ReleasePrivateFiles.save(dir.resolve("scoped-controller-retire.result.json"),retired)
        // One final native mutation invalidates old source tokens/sessions. Its
        // original result is never inferred from successful earlier PUTs.
        val last=buildJsonObject { put("name","realm-logout-all");put("targetGeneration",plan.generation)
            put("keycloakCid",start.containerId) }.toString().toByteArray()
        ReleasePrivateFiles.save(dir.resolve("realm-logout-all.intent.json"),last)
        val (logoutCode,_)=http.request("POST","/admin/realms/p0v3/logout-all",bearer)
        require(logoutCode==204)
        val logout=buildJsonObject { put("intentSha256",ReleaseLocks.sha256(last));put("nativeExitCode",logoutCode) }
            .toString().toByteArray()
        ReleasePrivateFiles.save(dir.resolve("realm-logout-all.result.json"),logout)
        // This operation's native readback is intentionally delegated to the
        // already pinned target grant issuer. It checks both new subjects and
        // denial of old secrets before enrollment. Never call issuance on a
        // possibly-revoked old owner token.
        val checked=ManagedRecoveryIdentityReadback.verify(bundle,root,expected,source,http,sourceTokens)
        require(checked)
        val complete=ManagedRecoveryIssuerResult(plan.generation,expected,
            requireNotNull(bundle.recoverySourceKopia).bundleSha256,start.containerId,token.receipt.sha256,
            token.subject,stepHashes,plan.lanes.first().subject,
            requireNotNull(plan.readerSubject),ReleaseLocks.sha256(retire),
            ReleaseLocks.sha256(retired),true,true,true)
        ReleasePrivateFiles.save(dir.resolve("original.result.json"),json.encodeToString(complete).toByteArray())
    }
}
