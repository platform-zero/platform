package net.datamancy.platform

import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpClient
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** Operator-supplied, private and target-scoped offline share handoff. These
 * exact two shares must originate from the independent owner; the controller
 * never silently falls back to source-local original init/root material. */
@Serializable internal data class BaoRestoreOperatorGrant(val generation: String, val originalGeneration: String,
    val originalInitSha256: String, val encryptedOwnerExportSha256: String,
    val offlineOwnerReceipt: ActivationInput, val shares: List<String>)
@Serializable internal data class BaoLocalAgeGrantPlan(val sourceGeneration: String,
    val targetGeneration: String, val snapshotSha256: String, val ciphertext: ActivationInput,
    val originalInitSha256: String, val localAgeIdentitySha256: String,
    val recipientSha256: String, val originalIssuerResultSha256: String)
@Serializable internal data class BaoLocalAgeDecryptResult(val schemaVersion: Int = 1,
    val qualificationScope: String = "LOCAL_ENCRYPTED_BACKUP_ISOLATED_RESTORE",
    val sourceGeneration: String, val targetGeneration: String, val snapshotSha256: String,
    val encryptedArchiveSha256: String, val originalInitSha256: String,
    val decryptedOriginalInitSha256: String, val localAgeIdentitySha256: String,
    val recipientSha256: String, val originalIssuerResultSha256: String,
    val nativeDecryptionVerified: Boolean = true, val independentOffsiteCustodyVerified: Boolean = false)
@Serializable internal data class BaoRestoredUnsealResult(val generation: String,val bundleSha256: String,
    val originalIssuerResultSha256: String,val localAgePlanSha256: String,val originalBaoCid: String,
    val originalBaoStartSha256: String,val effectiveCaSha256: String,val servedLeafDerSha256: String,
    val result: String = "initialized-unsealed-original-raft")
internal object GenerationBaoColdRestore {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private fun data(path: Path,max: Int=65536)=ReleasePrivateFiles.read(path,max)
    private fun scope(bundle:GenerationBundle,expected:String): Triple<GenerationPin,Path,GenerationFreshBaoNativeResult> {
        val root=GenerationRuntime.BASE.resolve(bundle.request.id)
        require(bundle.ownership==null && bundle.recoverySourceKopia!=null &&
            bundle.request.baoBootstrapOperation==null && bundle.members.size==1 &&
            ReleaseLocks.sha256(data(root.resolve("bundle.json"),4194304))==expected)
        val source=requireNotNull(bundle.request.recoveredBaoOriginal)
        val raw=data(Path.of(source.path),8192)
        require(ReleaseLocks.sha256(raw)==source.sha256)
        val issuer=json.decodeFromString<GenerationFreshBaoNativeResult>(raw.decodeToString(throwOnInvalidSequence=true))
        val snapshot=requireNotNull(bundle.recoverySourceKopia)
        val sourceBundle=json.decodeFromString<GenerationBundle>(data(GenerationRuntime.BASE.resolve(
            issuer.generation).resolve("bundle.json"),4194304).decodeToString(throwOnInvalidSequence=true))
        issuer.validate(issuer.generation,sourceBundle)
        require(snapshot.generation==issuer.generation && snapshot.bundleSha256==issuer.bundleSha256 &&
            source.path==GenerationRuntime.BASE.resolve(issuer.generation).resolve("bao-custody")
                .resolve("${issuer.generation}-original-issuer.result.json").toString())
        val pin=bundle.members.single()
        require(pin.spec.processes.single { it.id=="keeper" }.lateEnvironmentFile=="keeper-bao-late.env")
        return Triple(pin,root,issuer)
    }
    /** Owner-locked metadata preflight only; plaintext appears later INSIDE the
     * bounded child after a durable target intent. No manual share or offsite ACK. */
    private fun localPlan(bundle:GenerationBundle,issuer:GenerationFreshBaoNativeResult): BaoLocalAgeGrantPlan {
        val target=bundle.request.id
        val source=issuer.generation
        val exportRoot=GenerationRuntime.BASE.resolve(source).resolve("bao-custody")
        val export=json.decodeFromString<BaoEncryptedExportResult>(data(exportRoot.resolve(
            "$source-original-init-export.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        val recipient=OwnerRecoveryAgeIdentity.verifyLocal(source)
        val localBinding=data(Path.of("/home/gerald/.local/share/p0-v3-recovery/age/$source/binding.json"),8192)
        val localIdentity=json.decodeFromString<OwnerRecoveryIdentityBinding>(localBinding
            .decodeToString(throwOnInvalidSequence=true))
        require(export.originalInitSha256==issuer.originalInit.sha256 &&
            export.originalIssuerResultSha256==bundle.request.recoveredBaoOriginal?.sha256 &&
            export.encryptedArchive.path==exportRoot.resolve("$source-original-init.age").toString() &&
            ReleaseLocks.sha256(data(Path.of(export.encryptedArchive.path),131072))==export.encryptedArchive.sha256 &&
            localIdentity.generation==source && localIdentity.recipientSha256==recipient.sha256 &&
            !export.operatorOfflineHandoffAcknowledged && !export.qualificationEvidence)
        val snapshot=KopiaGenerationStore.receiptHash(requireNotNull(bundle.recoverySourceKopia))
        return BaoLocalAgeGrantPlan(source,target,snapshot,export.encryptedArchive,
            issuer.originalInit.sha256,localIdentity.identitySha256,recipient.sha256,
            requireNotNull(bundle.request.recoveredBaoOriginal).sha256)
    }
    fun startAfterImportedBao(bundle:GenerationBundle,expected:String,controller:Path) {
        val (pin,root,issuer)=scope(bundle,expected)
        val agePlan=localPlan(bundle,issuer)
        val planBytes=json.encodeToString(agePlan).toByteArray()
        val startPath=root.resolve("quadlet-member-${pin.spec.name}-bao.result.json")
        val startBytes=data(startPath,8192)
        val start=json.decodeFromString<QuadletMemberStart>(startBytes.decodeToString(throwOnInvalidSequence=true))
        require(start.process=="bao" && start.bundleSha256==expected && start.status.state=="running")
        val ip=GenerationFreshBaoStage.address(pin,start.containerId)
        val custody=root.resolve("bao-custody")
        val hosts=custody.resolve("${bundle.request.id}-restore-bao.hosts")
        val intent=custody.resolve("${bundle.request.id}-restore-transport.intent.json")
        val result=custody.resolve("${bundle.request.id}-restore-unseal.result.json")
        val localIntent=custody.resolve("${bundle.request.id}-local-age-decrypt.intent.json")
        val localResult=custody.resolve("${bundle.request.id}-local-age-decrypt.result.json")
        require(listOf(hosts,intent,result,localIntent,localResult).none { Files.exists(it,NOFOLLOW_LINKS) })
        val ca=data(PrivateDeployment.BASE.resolve(pin.spec.name).resolve("bao-ca.pem"))
        val leaf=data(PrivateDeployment.BASE.resolve(pin.spec.name).resolve("bao-web.pem"))
        require(ReleaseLocks.sha256(ca)==pin.inputHashes.getValue("bao-ca.pem") &&
            ReleaseLocks.sha256(leaf)==pin.inputHashes.getValue("bao-web.pem"))
        val cert=java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(leaf.inputStream())
        val leafSha=ReleaseLocks.sha256(cert.encoded)
        val planned=BaoRestoredUnsealResult(bundle.request.id,expected,bundle.request.recoveredBaoOriginal!!.sha256,
            ReleaseLocks.sha256(planBytes),start.containerId,ReleaseLocks.sha256(startBytes),
            pin.inputHashes.getValue("bao-ca.pem"),leafSha)
        require(controller==Path.of("/mnt/media/p0-v3/runtime-supervision/releases/"+
            requireNotNull(pin.spec.fragmentBinding?.controllerSha256)+"/bin/p0-v3-platform"))
        PinnedBackupController.verifyDistribution(controller.parent.parent,
            pin.spec.fragmentBinding!!.controllerSha256!!,"p0-v3-platform")
        ReleasePrivateFiles.save(localIntent,planBytes)
        ReleasePrivateFiles.save(intent,json.encodeToString(planned).toByteArray())
        ReleasePrivateFiles.save(hosts,"$ip bao\n".toByteArray())
        val child=ProcessBuilder(controller.toString(),"release","generation-restored-bao-unseal",
            bundle.request.id,expected).also {
                it.environment()["JAVA_TOOL_OPTIONS"]="-Djdk.net.hosts.file=$hosts"
                it.redirectError(ProcessBuilder.Redirect.DISCARD)
                it.redirectOutput(ProcessBuilder.Redirect.DISCARD)
            }.start()
        try { require(child.waitFor(90,TimeUnit.SECONDS) && child.exitValue()==0) {
            "Restored Bao unseal has uncertain original effect; preserve intent and never replay"
        } } finally { if(child.isAlive) child.destroyForcibly() }
        require(data(result,8192).contentEquals(json.encodeToString(planned).toByteArray()) &&
            verifyLocalAge(bundle,expected,agePlan) &&
            GenerationFreshBaoStage.address(pin,start.containerId)==ip)
        val token=data(Path.of(issuer.derivedKeykeeperToken.path),8192)
        require(ReleaseLocks.sha256(token)==issuer.derivedKeykeeperToken.sha256)
        val value=token.decodeToString(throwOnInvalidSequence=true).trimEnd('\n')
        require(value.length in 16..4096 && value.matches(Regex("[A-Za-z0-9._~+/-]+")))
        val env="KEYKEEPER_BAO_TOKEN=$value\n".toByteArray()
        val late=PrivateDeployment.BASE.resolve(pin.spec.name).resolve("keeper-bao-late.env")
        val bound=custody.resolve("${bundle.request.id}-keeper-late.result.json")
        require(!Files.exists(late,NOFOLLOW_LINKS) && !Files.exists(bound,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(late,env)
        ReleasePrivateFiles.save(bound,json.encodeToString(LateKeeperCredentialResult(bundle.request.id,expected,
            bundle.request.recoveredBaoOriginal.sha256,issuer.derivedKeykeeperToken.sha256,
            ReleaseLocks.sha256(env),"isolated-restore")).toByteArray())
        env.fill(0);token.fill(0)
        requireLate(bundle,expected)
    }
    fun unsealInChild(generation:String,expected:String) {
        val root=GenerationRuntime.BASE.resolve(generation)
        val bundle=json.decodeFromString<GenerationBundle>(data(root.resolve("bundle.json"),4194304)
            .decodeToString(throwOnInvalidSequence=true))
        val (pin,_,issuer)=scope(bundle,expected)
        val planned=json.decodeFromString<BaoRestoredUnsealResult>(data(root.resolve("bao-custody")
            .resolve("$generation-restore-transport.intent.json"),8192).decodeToString(throwOnInvalidSequence=true))
        val localPlan=localPlan(bundle,issuer)
        val planBytes=data(root.resolve("bao-custody/$generation-local-age-decrypt.intent.json"),8192)
        require(planBytes.contentEquals(json.encodeToString(localPlan).toByteArray()) &&
            planned.generation==generation && planned.bundleSha256==expected &&
            planned.localAgePlanSha256==ReleaseLocks.sha256(planBytes) &&
            planned.originalIssuerResultSha256==bundle.request.recoveredBaoOriginal!!.sha256 &&
            planned.originalBaoCid==json.decodeFromString<QuadletMemberStart>(data(root.resolve(
                "quadlet-member-${pin.spec.name}-bao.result.json"),8192).decodeToString()).containerId)
        val ip=GenerationFreshBaoStage.address(pin,planned.originalBaoCid)
        require(System.getProperty("jdk.net.hosts.file")==root.resolve("bao-custody")
            .resolve("$generation-restore-bao.hosts").toString() && data(root.resolve("bao-custody")
            .resolve("$generation-restore-bao.hosts"),256).contentEquals("$ip bao\n".toByteArray()))
        val client=GenerationFreshBaoStage.pinnedClient(pin,planned.effectiveCaSha256,
            planned.servedLeafDerSha256,ip)
        fun call(method:String,path:String,payload:String?=null,bearer:String?=null): JsonObject {
            val request=HttpRequest.newBuilder(URI.create("https://bao:8200/v1/$path"))
                .timeout(Duration.ofSeconds(20)).header("Accept","application/json")
            if(payload!=null) request.header("Content-Type","application/json")
            if(bearer!=null) request.header("X-Vault-Token",bearer)
            val reply=client.send(request.method(method,if(payload==null) HttpRequest.BodyPublishers.noBody()
                else HttpRequest.BodyPublishers.ofString(payload)).build(),HttpResponse.BodyHandlers.ofByteArray())
            require(reply.statusCode()==200 && reply.body().size in 1..16384)
            return json.parseToJsonElement(reply.body().decodeToString(throwOnInvalidSequence=true)).jsonObject
        }
        require(call("GET","sys/init").getValue("initialized").jsonPrimitive.boolean &&
            call("GET","sys/seal-status").getValue("sealed").jsonPrimitive.boolean)
        val plaintext=GenerationBaoLocalAgeDecrypt.decryptOriginal(localPlan.sourceGeneration,
            localPlan.ciphertext,localPlan.originalInitSha256,localPlan.originalIssuerResultSha256)
        try {
            val originalInit=json.parseToJsonElement(plaintext.decodeToString(throwOnInvalidSequence=true)).jsonObject
            val shares=originalInit.getValue("keys_base64").jsonArray.map { it.jsonPrimitive.content }
            require(shares.size>=2 && shares.take(2).toSet().size==2 && shares.take(2).all {
                it.matches(Regex("[A-Za-z0-9+/=]{16,1024}")) })
            for ((index,share) in shares.take(2).withIndex()) {
                val shareIntent=root.resolve("bao-custody/$generation-restore-unseal-${index+1}.intent.json")
                ReleasePrivateFiles.save(shareIntent,json.encodeToString(mapOf("generation" to generation,
                    "bundle" to expected,"shareSha256" to ReleaseLocks.sha256(share.toByteArray()),
                    "step" to (index+1).toString())).toByteArray())
                val reply=call("PUT","sys/unseal",buildJsonObject { put("key",share) }.toString())
                require(reply.getValue("sealed").jsonPrimitive.boolean==(index==0))
            }
            require(!call("GET","sys/seal-status").getValue("sealed").jsonPrimitive.boolean)
            val original=data(Path.of(issuer.derivedKeykeeperToken.path),8192)
            try {
                require(ReleaseLocks.sha256(original)==issuer.derivedKeykeeperToken.sha256)
                val token=original.decodeToString(throwOnInvalidSequence=true).trimEnd('\n')
                val readback=call("GET","auth/token/lookup-self",bearer=token).getValue("data").jsonObject
                require(readback.getValue("policies").jsonArray.map { it.jsonPrimitive.content }==
                    listOf("p0v3-keykeeper") && readback.getValue("orphan").jsonPrimitive.boolean)
            } finally { original.fill(0) }
            val evidence=BaoLocalAgeDecryptResult(sourceGeneration=localPlan.sourceGeneration,
                targetGeneration=localPlan.targetGeneration,snapshotSha256=localPlan.snapshotSha256,
                encryptedArchiveSha256=localPlan.ciphertext.sha256,originalInitSha256=localPlan.originalInitSha256,
                decryptedOriginalInitSha256=ReleaseLocks.sha256(plaintext),
                localAgeIdentitySha256=localPlan.localAgeIdentitySha256,
                recipientSha256=localPlan.recipientSha256,
                originalIssuerResultSha256=localPlan.originalIssuerResultSha256)
            require(evidence.originalInitSha256==evidence.decryptedOriginalInitSha256)
            ReleasePrivateFiles.save(root.resolve("bao-custody/$generation-local-age-decrypt.result.json"),
                json.encodeToString(evidence).toByteArray())
            ReleasePrivateFiles.save(root.resolve("bao-custody/$generation-restore-unseal.result.json"),
                json.encodeToString(planned).toByteArray())
        } finally { plaintext.fill(0) }
    }
    private fun verifyLocalAge(bundle:GenerationBundle,expected:String,plan:BaoLocalAgeGrantPlan):Boolean {
        val root=GenerationRuntime.BASE.resolve(bundle.request.id).resolve("bao-custody")
        val intent=data(root.resolve("${bundle.request.id}-local-age-decrypt.intent.json"),8192)
        require(intent.contentEquals(json.encodeToString(plan).toByteArray()) &&
            plan.snapshotSha256==KopiaGenerationStore.receiptHash(requireNotNull(bundle.recoverySourceKopia)) &&
            plan.originalIssuerResultSha256==bundle.request.recoveredBaoOriginal?.sha256)
        val evidence=json.decodeFromString<BaoLocalAgeDecryptResult>(data(root.resolve(
            "${bundle.request.id}-local-age-decrypt.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        require(evidence==BaoLocalAgeDecryptResult(sourceGeneration=plan.sourceGeneration,
            targetGeneration=plan.targetGeneration,snapshotSha256=plan.snapshotSha256,
            encryptedArchiveSha256=plan.ciphertext.sha256,originalInitSha256=plan.originalInitSha256,
            decryptedOriginalInitSha256=plan.originalInitSha256,
            localAgeIdentitySha256=plan.localAgeIdentitySha256,recipientSha256=plan.recipientSha256,
            originalIssuerResultSha256=plan.originalIssuerResultSha256) &&
            expected==ReleaseLocks.sha256(data(GenerationRuntime.BASE.resolve(bundle.request.id)
                .resolve("bundle.json"),4194304))) {
            "Local original age decryption was not authenticated by the target native result"
        }
        return true
    }
    fun requireLate(bundle:GenerationBundle,expected:String) {
        val (pin,root,issuer)=scope(bundle,expected)
        val result=json.decodeFromString<BaoRestoredUnsealResult>(data(root.resolve("bao-custody")
            .resolve("${bundle.request.id}-restore-unseal.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        require(result.bundleSha256==expected && result.originalIssuerResultSha256==bundle.request.recoveredBaoOriginal!!.sha256 &&
            result.localAgePlanSha256==ReleaseLocks.sha256(data(root.resolve("bao-custody")
                .resolve("${bundle.request.id}-local-age-decrypt.intent.json"),8192)) &&
            verifyLocalAge(bundle,expected,localPlan(bundle,issuer)))
        val late=json.decodeFromString<LateKeeperCredentialResult>(data(root.resolve("bao-custody")
            .resolve("${bundle.request.id}-keeper-late.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        val env=data(PrivateDeployment.BASE.resolve(pin.spec.name).resolve("keeper-bao-late.env"),8192)
        val original=data(Path.of(issuer.derivedKeykeeperToken.path),8192)
        require(late.generation==bundle.request.id && late.bundleSha256==expected &&
            late.phase=="isolated-restore" && late.issuerResultSha256==result.originalIssuerResultSha256 &&
            late.tokenSha256==issuer.derivedKeykeeperToken.sha256 && late.envSha256==ReleaseLocks.sha256(env) &&
            env.contentEquals("KEYKEEPER_BAO_TOKEN=${original.decodeToString(throwOnInvalidSequence=true).trimEnd('\n')}\n".toByteArray()))
        env.fill(0);original.fill(0)
    }
}
