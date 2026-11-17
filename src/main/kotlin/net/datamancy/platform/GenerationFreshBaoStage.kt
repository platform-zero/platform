package net.datamancy.platform

import java.net.InetAddress
import java.net.ProxySelector
import java.net.URI
import java.net.http.HttpClient
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.*
import java.net.Socket
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

@Serializable internal data class OriginalBaoTransportIntent(val generation: String, val bundleSha256: String,
    val member: String, val cid: String, val originalStartResultSha256: String,
    val baoWebIPv4: String, val issuerCaSha256: String, val selectedLeafDerSha256: String,
    val ownerPid: Long)
@Serializable internal data class LateKeeperCredentialResult(val generation: String,val bundleSha256: String,
    val issuerResultSha256: String,val tokenSha256: String,val envSha256: String,
    val phase: String = "original-install")
/** Native dependency effect, called by the SAME foreground Quadlet owner after
 * acknowledged Bao readiness and BEFORE any Keeper StartUnit. The isolated JVM
 * has a bounded hosts file for `bao` only; no global DNS, /etc/hosts mutation,
 * proxy, public listener, second generation or Podman application launch.
 */
internal object GenerationFreshBaoStage {
    private val json=Json { encodeDefaults=true; ignoreUnknownKeys=false }
    private val sha=Regex("[a-f0-9]{64}")
    private fun bytes(path: Path,max: Int=65536)=ReleasePrivateFiles.read(path,max)
    private fun checked(bundle: GenerationBundle,expected: String): Pair<GenerationPin,Path> {
        val gen=bundle.request.id; val root=GenerationRuntime.BASE.resolve(gen)
        require(gen.matches(Regex("q-[a-f0-9]{12}")) &&
            ReleaseLocks.sha256(bytes(root.resolve("bundle.json"),4194304))==expected &&
            bundle.request.baoBootstrapOperation?.also { it.validate(gen) }!=null &&
            bundle.ownership!=null &&
            bundle.recoverySourceKopia==null && bundle.members.size==1)
        val pin=bundle.members.single();require(pin.spec.processes.any { it.id=="bao" && !it.oneShot } &&
            pin.spec.processes.single { it.id=="keeper" }.lateEnvironmentFile=="keeper-bao-late.env")
        return pin to root
    }
    fun address(pin: GenerationPin,cid: String): String {
        val observed=PrivateRootfulCommands(30,pin.spec.store).run(listOf("container","inspect",cid))
        require(observed.exitCode==0 && observed.output.length in 128..65536)
        val obj=json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
        require(obj.getValue("Id").jsonPrimitive.content==cid &&
            obj.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean &&
            obj.getValue("Name").jsonPrimitive.content=="p0v3-live-${pin.spec.name}-bao")
        val net=obj.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
        val selected="p0v3-live-${pin.spec.name}-bao-web"
        require(net.keys==pin.spec.processes.single { it.id=="bao" }.networks.map {
            "p0v3-live-${pin.spec.name}-$it" }.toSet() && selected in net)
        val ip=net.getValue(selected).jsonObject.getValue("IPAddress").jsonPrimitive.content
        require(ip.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            InetAddress.getByName(ip).let { it.hostAddress==ip && it.isSiteLocalAddress &&
                !it.isLoopbackAddress && !it.isAnyLocalAddress })
        return ip
    }
    fun issueBeforeKeeper(bundle: GenerationBundle,expected: String,controller: Path) {
        val (pin,root)=checked(bundle,expected)
        val start=root.resolve("quadlet-member-${pin.spec.name}-bao.result.json")
        val startBytes=bytes(start,8192)
        val original=json.decodeFromString<QuadletMemberStart>(startBytes.decodeToString(throwOnInvalidSequence=true))
        require(original.bundleSha256==expected && original.member==pin.spec.name &&
            original.process=="bao" && original.status.state=="running" &&
            sha.matches(original.containerId))
        val ip=address(pin,original.containerId)
        val member=PrivateDeployment.BASE.resolve(pin.spec.name)
        val ca=bytes(member.resolve("bao-ca.pem"));val leaf=bytes(member.resolve("bao-web.pem"))
        require(ReleaseLocks.sha256(ca)==pin.inputHashes.getValue("bao-ca.pem") &&
            ReleaseLocks.sha256(leaf)==pin.inputHashes.getValue("bao-web.pem"))
        val cert=CertificateFactory.getInstance("X.509").generateCertificate(leaf.inputStream()) as X509Certificate
        cert.checkValidity()
        require(cert.subjectAlternativeNames.orEmpty().any { it[0]==2 && it[1]=="bao" })
        val leafSha=ReleaseLocks.sha256(cert.encoded)
        val custody=root.resolve("bao-custody")
        ReleasePrivateFiles.directory(custody)
        val nested=custody.resolve(bundle.request.id)
        ReleasePrivateFiles.directory(nested)
        val intent=OriginalBaoTransportIntent(bundle.request.id,expected,pin.spec.name,original.containerId,
            ReleaseLocks.sha256(startBytes),ip,pin.inputHashes.getValue("bao-ca.pem"),leafSha,
            ProcessHandle.current().pid())
        val marker=custody.resolve("${bundle.request.id}-original-transport.intent.json")
        val hosts=custody.resolve("${bundle.request.id}-original-bao.hosts")
        require(!Files.exists(marker,NOFOLLOW_LINKS) && !Files.exists(hosts,NOFOLLOW_LINKS) &&
            !Files.exists(custody.resolve("${bundle.request.id}-original-issuer.result.json"),NOFOLLOW_LINKS)) {
            "Original Bao dependency attempt already exists; never replay an uncertain init"
        }
        ReleasePrivateFiles.save(marker,json.encodeToString(intent).toByteArray())
        ReleasePrivateFiles.save(hosts,"$ip bao\n".toByteArray())
        val descriptor=requireNotNull(pin.spec.fragmentBinding?.controllerSha256)
        require(controller==Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$descriptor/bin/p0-v3-platform"))
        PinnedBackupController.verifyDistribution(controller.parent.parent,descriptor,"p0-v3-platform")
        val command=ProcessBuilder(controller.toString(),"release","generation-original-bao-issue",
            bundle.request.id,expected)
        command.environment()["JAVA_TOOL_OPTIONS"]="-Djdk.net.hosts.file=$hosts"
        command.redirectError(ProcessBuilder.Redirect.DISCARD)
        command.redirectOutput(ProcessBuilder.Redirect.DISCARD)
        val child=command.start()
        try { require(child.waitFor(180,TimeUnit.SECONDS) && child.exitValue()==0) {
            "Fresh Bao issuer child has no original result; preserve all intents, never retry"
        } } finally { if (child.isAlive) child.destroyForcibly() }
        val native=verifyNative(bundle,expected)
        require(native.originalCid==original.containerId && native.issuerCaSha256==intent.issuerCaSha256 &&
            native.servedLeafDerSha256==leafSha)
        // The local-scope backup must contain an ORIGINAL encrypted init export,
        // not a later reconstructed share, before any Keeper or capture is admitted.
        // This runs ONCE under the same owner lock after a true native Bao issuer
        // result. Its own intent fences an uncertain age encryption permanently.
        val issued=FreshOpenBaoBootstrap.Issued(Path.of(native.derivedKeykeeperToken.path),
            native.derivedKeykeeperToken.sha256,Path.of(native.originalInit.path),native.originalInit.sha256)
        val recipient=OwnerRecoveryAgeIdentity.verifyLocal(bundle.request.id)
        val encrypted=GenerationBaoOfflineCustody.encryptOriginal(bundle.request.id,issued,recipient)
        require(encrypted.originalInitSha256==native.originalInit.sha256 &&
            encrypted.originalIssuerResultSha256==ReleaseLocks.sha256(bytes(
                custody.resolve("${bundle.request.id}-original-issuer.result.json"),8192)) &&
            !encrypted.operatorOfflineHandoffAcknowledged && !encrypted.qualificationEvidence)
        val token=bytes(Path.of(native.derivedKeykeeperToken.path),8192)
        require(ReleaseLocks.sha256(token)==native.derivedKeykeeperToken.sha256)
        val value=token.decodeToString(throwOnInvalidSequence=true).trimEnd('\n')
        require(value.length in 16..4096 && value.matches(Regex("[A-Za-z0-9._~+/-]+")))
        val env=("KEYKEEPER_BAO_TOKEN=$value\n").toByteArray()
        val late=member.resolve("keeper-bao-late.env")
        val result=custody.resolve("${bundle.request.id}-keeper-late.result.json")
        require(!Files.exists(late,NOFOLLOW_LINKS) && !Files.exists(result,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(late,env)
        ReleasePrivateFiles.save(result,json.encodeToString(LateKeeperCredentialResult(bundle.request.id,
            expected,ReleaseLocks.sha256(bytes(custody.resolve("${bundle.request.id}-original-issuer.result.json"),8192)),
            native.derivedKeykeeperToken.sha256,ReleaseLocks.sha256(env))).toByteArray())
        token.fill(0);env.fill(0)
        requireLate(bundle,expected)
    }
    fun verifyNative(bundle: GenerationBundle,expected: String): GenerationFreshBaoNativeResult {
        val (pin,root)=checked(bundle,expected)
        val custody=root.resolve("bao-custody")
        val raw=bytes(custody.resolve("${bundle.request.id}-original-issuer.result.json"),8192)
        val result=json.decodeFromString<GenerationFreshBaoNativeResult>(raw.decodeToString(throwOnInvalidSequence=true))
        result.validate(bundle.request.id,bundle)
        require(result.bundleSha256==expected && result.selectedMember==pin.spec.name &&
            result.originalNativeStageResultSha256==ReleaseLocks.sha256(bytes(root.resolve(
                "quadlet-member-${pin.spec.name}-bao.result.json"),8192)))
        for (source in listOf(result.originalInit,result.derivedKeykeeperToken)) {
            val path=Path.of(source.path)
            require(path.parent==custody.resolve(bundle.request.id) &&
                ReleaseLocks.sha256(bytes(path,65536))==source.sha256)
        }
        return result
    }
    fun requireLate(bundle: GenerationBundle,expected: String) {
        val (pin,root)=checked(bundle,expected)
        val native=verifyNative(bundle,expected)
        val sourceRoot=root.resolve("bao-custody")
        val encrypted=json.decodeFromString<BaoEncryptedExportResult>(bytes(sourceRoot.resolve(
            "${bundle.request.id}-original-init-export.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        require(encrypted.originalInitSha256==native.originalInit.sha256 &&
            encrypted.originalIssuerResultSha256==ReleaseLocks.sha256(bytes(sourceRoot.resolve(
                "${bundle.request.id}-original-issuer.result.json"),8192)) &&
            encrypted.encryptedArchive.path==sourceRoot.resolve("${bundle.request.id}-original-init.age").toString() &&
            ReleaseLocks.sha256(bytes(Path.of(encrypted.encryptedArchive.path),131072))==encrypted.encryptedArchive.sha256 &&
            !encrypted.operatorOfflineHandoffAcknowledged && !encrypted.qualificationEvidence)
        val result=json.decodeFromString<LateKeeperCredentialResult>(bytes(root.resolve("bao-custody")
            .resolve("${bundle.request.id}-keeper-late.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        val env=bytes(PrivateDeployment.BASE.resolve(pin.spec.name).resolve("keeper-bao-late.env"),8192)
        val token=bytes(Path.of(native.derivedKeykeeperToken.path),8192)
        require(result.generation==bundle.request.id && result.bundleSha256==expected &&
            result.phase=="original-install" && result.envSha256==ReleaseLocks.sha256(env) &&
            result.tokenSha256==native.derivedKeykeeperToken.sha256 &&
            result.issuerResultSha256==ReleaseLocks.sha256(bytes(root.resolve("bao-custody")
                .resolve("${bundle.request.id}-original-issuer.result.json"),8192)) &&
            env.contentEquals("KEYKEEPER_BAO_TOKEN=${token.decodeToString(throwOnInvalidSequence=true).trimEnd('\n')}\n".toByteArray()))
        token.fill(0);env.fill(0)
    }
    /** Exact graph CA and leaf, PKIX/hostname/SNI, direct network transport.
     * Child JVM's dedicated hosts file must bind `bao` to its CID's private IP. */
    fun pinnedClient(pin: GenerationPin,issuerSha: String,leafSha: String,ip: String): HttpClient {
        val member=PrivateDeployment.BASE.resolve(pin.spec.name)
        val ca=bytes(member.resolve("bao-ca.pem"),65536)
        val cert=CertificateFactory.getInstance("X.509").generateCertificate(bytes(member.resolve(
            "bao-web.pem"),65536).inputStream()) as X509Certificate
        cert.checkValidity()
        require(cert.subjectAlternativeNames.orEmpty().any { it[0]==2 && it[1]=="bao" } &&
            cert.basicConstraints<0 && cert.issuerX500Principal!=null)
        require(ReleaseLocks.sha256(ca)==issuerSha &&
            pin.inputHashes.getValue("bao-ca.pem")==issuerSha &&
            ReleaseLocks.sha256(cert.encoded)==leafSha &&
            pin.inputHashes.getValue("bao-web.pem")==ReleaseLocks.sha256(bytes(member.resolve("bao-web.pem"),65536)))
        val store=KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null,null); setCertificateEntry("generation-bao-issuer",CertificateFactory.getInstance("X.509")
                .generateCertificate(ca.inputStream()))
        }
        val factory=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val pkix=factory.trustManagers.filterIsInstance<X509TrustManager>().single()
        val trusted=object : X509ExtendedTrustManager() {
            private fun check(chain: Array<X509Certificate>,auth: String) {
                require(chain.isNotEmpty() && ReleaseLocks.sha256(chain[0].encoded)==leafSha)
                pkix.checkServerTrusted(chain,auth)
            }
            override fun checkServerTrusted(c:Array<X509Certificate>,a:String)=check(c,a)
            override fun checkServerTrusted(c:Array<X509Certificate>,a:String,s:Socket) {
                require(s.inetAddress.hostAddress==ip && s.port==8200)
                check(c,a)
            }
            override fun checkServerTrusted(c:Array<X509Certificate>,a:String,e:SSLEngine) {
                require(e.peerHost=="bao" && e.peerPort==8200)
                check(c,a)
            }
            override fun checkClientTrusted(c:Array<X509Certificate>,a:String)=pkix.checkClientTrusted(c,a)
            override fun checkClientTrusted(c:Array<X509Certificate>,a:String,s:Socket)=pkix.checkClientTrusted(c,a)
            override fun checkClientTrusted(c:Array<X509Certificate>,a:String,e:SSLEngine)=pkix.checkClientTrusted(c,a)
            override fun getAcceptedIssuers():Array<X509Certificate> = pkix.acceptedIssuers
        }
        require(InetAddress.getByName("bao").hostAddress==ip &&
            ProxySelector.getDefault()?.select(URI.create("https://bao:8200"))
                ?.all { it==java.net.Proxy.NO_PROXY } != false)
        val ssl=SSLContext.getInstance("TLS").apply { init(null,arrayOf(trusted),null) }
        return HttpClient.newBuilder().sslContext(ssl).followRedirects(HttpClient.Redirect.NEVER).build()
            .also { require(it.proxy().isEmpty) }
    }
    /** Invoked only inside a bounded child JVM with jdk.net.hosts.file pinned to
     * the exact original CID's one-use private `bao` IPv4 by the owner process. */
    fun issueInChild(generation: String, expected: String) {
        val root=GenerationRuntime.BASE.resolve(generation)
        val bundle=json.decodeFromString<GenerationBundle>(bytes(root.resolve("bundle.json"),4194304)
            .decodeToString(throwOnInvalidSequence=true))
        val (pin,_) = checked(bundle,expected)
        val custody=root.resolve("bao-custody")
        val intentBytes=bytes(custody.resolve("$generation-original-transport.intent.json"),8192)
        val intent=json.decodeFromString<OriginalBaoTransportIntent>(intentBytes.decodeToString(throwOnInvalidSequence=true))
        require(intent.generation==generation && intent.bundleSha256==expected &&
            intent.member==pin.spec.name && intent.ownerPid!=ProcessHandle.current().pid() &&
            ProcessHandle.of(intent.ownerPid).orElseThrow().isAlive &&
            intent.cid==json.decodeFromString<QuadletMemberStart>(bytes(root.resolve(
                "quadlet-member-${pin.spec.name}-bao.result.json"),8192).decodeToString()).containerId &&
            intent.baoWebIPv4==address(pin,intent.cid) &&
            System.getProperty("jdk.net.hosts.file")==custody.resolve("$generation-original-bao.hosts").toString() &&
            bytes(custody.resolve("$generation-original-bao.hosts"),256)
                .contentEquals("${intent.baoWebIPv4} bao\n".toByteArray()))
        val expectedLeaf=intent.selectedLeafDerSha256
        val client=pinnedClient(pin,intent.issuerCaSha256,expectedLeaf,intent.baoWebIPv4)
        val issued=FreshOpenBaoBootstrap.issueOriginal(client,URI.create("https://bao:8200"),
            generation,custody.resolve(generation))
        val response=GenerationFreshBaoNativeResult(generation,expected,ReleaseLocks.sha256(
            json.encodeToString(bundle.request.baoBootstrapOperation!!).toByteArray()),pin.spec.name,"bao",
            intent.cid,intent.originalStartResultSha256,intent.issuerCaSha256,expectedLeaf,
            ActivationInput(issued.originalInitFile.toString(),issued.originalInitSha256),
            ActivationInput(issued.keykeeperTokenFile.toString(),issued.keykeeperTokenSha256),true)
        response.validate(generation,bundle)
        ReleasePrivateFiles.save(custody.resolve("$generation-original-issuer.result.json"),
            json.encodeToString(response).toByteArray())
    }
}
