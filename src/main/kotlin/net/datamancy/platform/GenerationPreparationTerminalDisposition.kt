package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

/** Pre-bundle terminal reconciliation. Unlike the staged Quadlet terminal
 * disposition, no bundle, installed unit, CID or stop receipt may exist. A
 * failed preparation's bytes stay frozen; this never repairs any failed ACK. */
@Serializable internal data class PreparationTerminalDisposition(
    val schemaVersion:Int=1,val generation:String,val member:String,
    val originalCensusSha256:String,val failedOutcomes:Map<String,String>,
    val rootFileSha256:Map<String,String>,val ciFileSha256:Map<String,String>,
    val memberFileSha256:Map<String,String>,val manifestSha256:String,
    val otherSourceFileSha256:Map<String,String>,
    val nativeNamespaceSha256:Map<String,String>,val nativeSystemdSha256:String,
    val nativeManagedUnitSha256:String,val nativeCiUserAbsenceSha256:String,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val nativeNamespaceRawReadbackSha256:Map<String,String> = emptyMap(),
    val nativeUnitCount:Int,val bundlePresent:Boolean=false,val originalPreparationPassed:Boolean=false,
    val unitOrCidEffectObserved:Boolean=false,val publicActivation:Boolean=false,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val predecessorFailedTerminalResultSha256:String?=null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val predecessorV2PreEffectDispositionSha256:String?=null)

@Serializable internal data class PreparationTerminalIntent(val generation:String,val member:String,
    val censusSha256:String,val manifestSha256:String,val failedOutcomes:Map<String,String>,
    val action:String="terminal-readback-only")
@Serializable internal data class PreparationTerminalResult(val intentSha256:String,val passed:Boolean,
    val dispositionSha256:String?=null,val failureType:String?=null)
@Serializable internal data class PreparationTerminalReconciliationIntent(val generation:String,val member:String,
    val originalCensusSha256:String,val failedOriginalTerminalIntentSha256:String,
    val failedOriginalTerminalResultSha256:String,val action:String="separate-failed-terminal-readback")
@Serializable internal data class PreparationTerminalV2PreEffectRefusal(val schemaVersion:Int=1,
    val generation:String,val member:String,val censusSha256:String,
    val originalTerminalIntentSha256:String,val originalTerminalFalseResultSha256:String,
    val refusedV2LogPath:String,val refusedV2LogSha256:String,
    val originalFailedOutcomes:Map<String,String>,
    val memberManifestSha256:String,val nativeAbsenceSha256:Map<String,String>,
    val nativeSystemdSha256:String,val nativeManagedUnitSha256:String,
    val nativeCiUserAbsenceSha256:String,
    val firstRawReadbackSha256:Map<String,String>,val secondRawReadbackSha256:Map<String,String>,
    val v2IntentPresent:Boolean=false,val v2ResultPresent:Boolean=false,
    val terminalDispositionPassed:Boolean=false)
@Serializable internal data class PreparationTerminalV3Intent(val generation:String,val member:String,
    val censusSha256:String,val originalTerminalIntentSha256:String,
    val originalTerminalFalseResultSha256:String,val v2PreEffectRefusalSha256:String,
    val action:String="versioned-terminal-after-v2-pre-effect-refusal")

internal object GenerationPreparationTerminalDisposition {
    const val NAME="preparation-terminal-disposition.json"
    const val V2_NAME="preparation-terminal-v2-disposition.json"
    const val V2_PRE_EFFECT="preparation-terminal-v2-pre-effect.disposition.json"
    const val V3_NAME="preparation-terminal-v3-disposition.json"
    private const val V3_INTENT="preparation-terminal-v3.intent.json"
    private const val V3_RESULT="preparation-terminal-v3.result.json"
    private const val INTENT="preparation-terminal.intent.json"
    private const val RESULT="preparation-terminal.result.json"
    private const val V2_INTENT="preparation-terminal-v2.intent.json"
    private const val V2_RESULT="preparation-terminal-v2.result.json"
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private val hash=Regex("[a-f0-9]{64}")
    private val slug=Regex("q-[a-f0-9]{12}")
    /** Source-only gate; live native absence is independently required at the
     * first new effect. Old failed outcomes may not be silently renamed. */
    fun requireClosedForNewSource(generation:String) {
        require(slug.matches(generation))
        val roots=GenerationRuntime.BASE
        if(!Files.exists(roots,NOFOLLOW_LINKS)) return
        ReleasePrivateFiles.directory(roots)
        Files.list(roots).use { entries -> entries.filter { old ->
            old.fileName.toString().matches(slug) && old.fileName.toString()!=generation &&
                Files.isDirectory(old,NOFOLLOW_LINKS) && !Files.exists(old.resolve("bundle.json"),NOFOLLOW_LINKS) &&
                Files.isRegularFile(old.resolve("assembly.result.json"),NOFOLLOW_LINKS)
        }.forEach { old ->
            val result=json.decodeFromString<AssemblyPreparationOutcome>(ReleasePrivateFiles.read(
                old.resolve("assembly.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
            if(!result.passed) {
                val v3=Files.exists(old.resolve(V3_INTENT),NOFOLLOW_LINKS)
                val v2=Files.exists(old.resolve(V2_INTENT),NOFOLLOW_LINKS)
                val file=old.resolve(if(v3) V3_NAME else if(v2) V2_NAME else NAME)
                require(Files.isRegularFile(file,NOFOLLOW_LINKS)) {
                    "An original failed preparation is not terminal; fresh source issuance is refused"
                }
                val saved=json.decodeFromString<PreparationTerminalDisposition>(ReleasePrivateFiles.read(file,1048576)
                    .decodeToString(throwOnInvalidSequence=true))
                require(saved.generation==old.fileName.toString() &&
                    saved.member=="${saved.generation}-v2" && saved.failedOutcomes.size==3 &&
                    saved.failedOutcomes.keys==setOf("assembly.result.json",
                        "assembly-ci-pre-effect-v2.result.json","assembly-ci-member-v3.result.json") &&
                    saved.rootFileSha256.size>=saved.failedOutcomes.size &&
                    saved.rootFileSha256.all { (name,pin) ->
                        !name.contains('/') && pin==sha(old.resolve(name),4194304) } &&
                    saved.failedOutcomes.all { (name,pin) ->
                        saved.rootFileSha256[name]==pin &&
                        !json.parseToJsonElement(ReleasePrivateFiles.read(old.resolve(name),8192)
                            .decodeToString(throwOnInvalidSequence=true)).jsonObject.getValue("passed").jsonPrimitive.boolean } &&
                    saved.ciFileSha256.all { (name,pin) ->
                        !name.contains('/') && pin==sha(old.resolve("ci/$name"),1048576) } &&
                    saved.manifestSha256==sha(PrivateDeployment.BASE.resolve("${saved.member}.json"),4194304) &&
                    !saved.bundlePresent && !saved.originalPreparationPassed && !saved.unitOrCidEffectObserved &&
                    !saved.publicActivation)
                // The journal must have succeeded, not merely have a candidate
                // disposition or an uncertain/failed observation intent.
                val outcome=json.decodeFromString<PreparationTerminalResult>(ReleasePrivateFiles.read(
                    old.resolve(if(v3) V3_RESULT else if(v2) V2_RESULT else RESULT),8192)
                        .decodeToString(throwOnInvalidSequence=true))
                require(outcome.passed && outcome.dispositionSha256==sha(file,1048576) &&
                    (if(v3) saved.predecessorV2PreEffectDispositionSha256==sha(old.resolve(V2_PRE_EFFECT),16384) &&
                        saved.predecessorFailedTerminalResultSha256==sha(old.resolve(RESULT),8192) &&
                        !Files.exists(old.resolve(V2_INTENT),NOFOLLOW_LINKS) &&
                        !json.decodeFromString<PreparationTerminalResult>(ReleasePrivateFiles.read(old.resolve(RESULT),8192)
                            .decodeToString(throwOnInvalidSequence=true)).passed
                    else if(v2) saved.predecessorV2PreEffectDispositionSha256==null &&
                        saved.predecessorFailedTerminalResultSha256==sha(old.resolve(RESULT),8192) &&
                        !json.decodeFromString<PreparationTerminalResult>(ReleasePrivateFiles.read(old.resolve(RESULT),8192)
                            .decodeToString(throwOnInvalidSequence=true)).passed
                    else saved.predecessorFailedTerminalResultSha256==null &&
                        saved.predecessorV2PreEffectDispositionSha256==null))
            }
        } }
    }
    private fun names(dir:Path):Set<String> = Files.list(dir).use { entries ->
        entries.map { it.fileName.toString() }.toList().toSet()
    }
    private fun sha(path:Path,max:Int):String {
        ReleasePrivateFiles.directory(path.parent)
        require(Files.isRegularFile(path,NOFOLLOW_LINKS) && !Files.isSymbolicLink(path) &&
            Files.getPosixFilePermissions(path)==PosixFilePermissions.fromString("rw-------") &&
            (Files.getAttribute(path,"unix:uid",NOFOLLOW_LINKS) as Number).toLong()==UnixSystem().uid &&
            (Files.getAttribute(path,"unix:nlink",NOFOLLOW_LINKS) as Number).toInt()==1 &&
            Files.size(path) in 0L..max.toLong())
        val bytes=Files.newInputStream(path,NOFOLLOW_LINKS).use { it.readNBytes(max+1) }
        require(bytes.size<=max)
        return ReleaseLocks.sha256(bytes)
    }
    private fun metadata(path:Path,meta:JsonObject,max:Int) {
        require(Files.isRegularFile(path,NOFOLLOW_LINKS) && !Files.isSymbolicLink(path) &&
            Files.size(path)==meta.getValue("bytes").jsonPrimitive.long && Files.size(path) in 0L..max.toLong() &&
            (Files.getAttribute(path,"unix:nlink",NOFOLLOW_LINKS) as Number).toInt()==meta.getValue("nlink").jsonPrimitive.int &&
            "0o"+Integer.toOctalString(PosixFilePermissions.toString(Files.getPosixFilePermissions(path)).let { bits ->
                bits.fold(0) { value,c -> value*2 + if(c=='-') 0 else 1 }
            })==meta.getValue("mode").jsonPrimitive.content &&
            sha(path,max)==meta.getValue("sha256").jsonPrimitive.content)
    }
    private fun source(root:Path,census:ActivationInput):PreparationTerminalDisposition {
        require(root.parent==GenerationRuntime.BASE && slug.matches(root.fileName.toString()) &&
            census.sha256.matches(hash) && !Files.exists(root.resolve("bundle.json"),NOFOLLOW_LINKS))
        val censusPath=Path.of(census.path)
        require(censusPath.isAbsolute && Files.isRegularFile(censusPath,NOFOLLOW_LINKS) &&
            !Files.isSymbolicLink(censusPath) && Files.size(censusPath) in 1..1048576 &&
            Files.getPosixFilePermissions(censusPath)==PosixFilePermissions.fromString("rw-------"))
        val bytes=Files.readAllBytes(censusPath)
        require(ReleaseLocks.sha256(bytes)==census.sha256)
        val record=json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(record.getValue("generation").jsonPrimitive.content==root.fileName.toString() &&
            record.getValue("memberPrepared").jsonPrimitive.boolean &&
            !record.getValue("bundlePresent").jsonPrimitive.boolean &&
            !record.getValue("thirdResultPassed").jsonPrimitive.boolean)
        val observedRoot=record.getValue("rootFiles").jsonObject
        val memberFile=observedRoot.keys.single { it.endsWith(".prepare-ci-member-v3.result.json") }
        val member=memberFile.removeSuffix(".prepare-ci-member-v3.result.json")
        require(member.startsWith("${root.fileName}-") && names(root)==observedRoot.keys+
            setOf("ci","managed","rss") + (if(Files.exists(root.resolve(NAME),NOFOLLOW_LINKS)) setOf(NAME) else emptySet()) +
            (if(Files.exists(root.resolve(INTENT),NOFOLLOW_LINKS)) setOf(INTENT) else emptySet()) +
            (if(Files.exists(root.resolve(RESULT),NOFOLLOW_LINKS)) setOf(RESULT) else emptySet()) +
            (if(Files.exists(root.resolve(V2_NAME),NOFOLLOW_LINKS)) setOf(V2_NAME) else emptySet()) +
            (if(Files.exists(root.resolve(V2_INTENT),NOFOLLOW_LINKS)) setOf(V2_INTENT) else emptySet()) +
            (if(Files.exists(root.resolve(V2_RESULT),NOFOLLOW_LINKS)) setOf(V2_RESULT) else emptySet()) +
            (if(Files.exists(root.resolve(V2_PRE_EFFECT),NOFOLLOW_LINKS)) setOf(V2_PRE_EFFECT) else emptySet()) +
            (if(Files.exists(root.resolve(V3_INTENT),NOFOLLOW_LINKS)) setOf(V3_INTENT) else emptySet()) +
            (if(Files.exists(root.resolve(V3_RESULT),NOFOLLOW_LINKS)) setOf(V3_RESULT) else emptySet()) +
            (if(Files.exists(root.resolve(V3_NAME),NOFOLLOW_LINKS)) setOf(V3_NAME) else emptySet()))
        val roots=observedRoot.mapValues { (name,meta) ->
            metadata(root.resolve(name),meta.jsonObject,4194304); meta.jsonObject.getValue("sha256").jsonPrimitive.content
        }
        val failed=roots.filterKeys { it.startsWith("assembly") && it.endsWith(".result.json") }
        require(failed.size==3 && failed.values.toSet().size==3 && failed.keys.all { result ->
            val item=json.parseToJsonElement(ReleasePrivateFiles.read(root.resolve(result),8192)
                .decodeToString(throwOnInvalidSequence=true)).jsonObject
            !item.getValue("passed").jsonPrimitive.boolean &&
                item["bundleSha256"]?.jsonPrimitive?.contentOrNull==null &&
                item["failureType"]?.jsonPrimitive?.content?.isNotBlank()==true &&
                roots.containsKey(result.removeSuffix(".result.json")+".intent.json")
        }) { "Exact three false original preparation outcomes required" }
        val ci=record.getValue("ciFiles").jsonObject.mapValues { it.value.jsonPrimitive.content }
        require(names(root.resolve("ci"))==ci.keys && ci.all { (name,pin)->sha(root.resolve("ci/$name"),1048576)==pin })
        val manifest=record.getValue("memberManifest").jsonObject
        val manifestPath=Path.of(manifest.getValue("path").jsonPrimitive.content)
        require(manifestPath==PrivateDeployment.BASE.resolve("$member.json") &&
            Files.size(manifestPath)==manifest.getValue("bytes").jsonPrimitive.long &&
            Files.getPosixFilePermissions(manifestPath)==PosixFilePermissions.fromString("rw-------") &&
            (Files.getAttribute(manifestPath,"unix:nlink",NOFOLLOW_LINKS) as Number).toInt()==1 &&
            sha(manifestPath,4194304)==manifest.getValue("sha256").jsonPrimitive.content)
        val spec=json.decodeFromString<PrivateDeploymentSpec>(ReleasePrivateFiles.read(manifestPath,4194304)
            .decodeToString(throwOnInvalidSequence=true))
        require(spec.name==member && spec.store==RuntimeStore.CANONICAL_V2 &&
            spec.processes.size in 1..256 && spec.processes.map { it.id }.distinct().size==spec.processes.size)
        val memberRoot=PrivateDeployment.BASE.resolve(member)
        val originals=record.getValue("memberFiles").jsonObject
        require(names(memberRoot)==originals.keys && originals.keys==PrivateDeployment.inputNames(spec).toSet()+"runtime.lock")
        val inputs=originals.mapValues { (name,meta) ->
            metadata(memberRoot.resolve(name),meta.jsonObject,4194304);meta.jsonObject.getValue("sha256").jsonPrimitive.content
        }
        val pin=json.decodeFromString<GenerationPin>(ReleasePrivateFiles.read(root.resolve(memberFile),4194304)
            .decodeToString(throwOnInvalidSequence=true))
        require(pin.member.name==member && pin.spec==spec &&
            pin.manifestSha256==manifest.getValue("sha256").jsonPrimitive.content &&
            pin.inputHashes==inputs.filterKeys { it!="runtime.lock" } &&
            pin.runtimeFingerprint==PrivateDeployment.expectedFingerprint(spec,pin.inputHashes)) {
            "Prepared member result no longer binds the immutable manifest and all inputs"
        }
        val other=linkedMapOf<String,String>()
        for(folder in listOf("managed","rss")) {
            val dir=root.resolve(folder)
            require(Files.isDirectory(dir,NOFOLLOW_LINKS))
            Files.walk(dir,5).use { paths ->
                paths.forEach { p ->
                    require(!Files.isSymbolicLink(p) && p.normalize()==p &&
                        (Files.isDirectory(p,NOFOLLOW_LINKS) || Files.isRegularFile(p,NOFOLLOW_LINKS)))
                    if(Files.isRegularFile(p,NOFOLLOW_LINKS)) other[root.relativize(p).toString()]=sha(p,4194304)
                }
            }
        }
        val expectedOther=json.parseToJsonElement(ReleasePrivateFiles.read(root.resolve(
            "assembly-ci-pre-effect.disposition.json"),8192).decodeToString(throwOnInvalidSequence=true))
            .jsonObject.getValue("adoptedInputSha256").jsonObject.mapValues { it.value.jsonPrimitive.content }
        require(other==expectedOther && names(root.resolve("rss/tokens")).isEmpty()) {
            "Original managed or RSS source changed after failed preparation"
        }
        val issuer=json.parseToJsonElement(ReleasePrivateFiles.read(root.resolve(
            "assembly-ci-member-pre-effect.disposition.json"),8192).decodeToString(throwOnInvalidSequence=true))
            .jsonObject.getValue("freshIssuerSha256").jsonObject
        require(issuer.isNotEmpty() && issuer.all { (file,pin) ->
            val path=Path.of(file)
            path.isAbsolute && path.normalize()==path && path.startsWith(
                Path.of("/mnt/media/p0-v3/release-bootstrap-anchors")) &&
                path.fileName.toString().contains(root.fileName.toString()) &&
                sha(path,8192)==pin.jsonPrimitive.content
        }) { "Original fresh issuer grants changed after partial preparation" }
        val priorIntent=root.resolve(INTENT)
        if(Files.exists(priorIntent,NOFOLLOW_LINKS)) {
            val attempt=json.decodeFromString<PreparationTerminalIntent>(ReleasePrivateFiles.read(priorIntent,8192)
                .decodeToString(throwOnInvalidSequence=true))
            require(attempt.generation==root.fileName.toString() && attempt.member==member &&
                attempt.censusSha256==census.sha256 &&
                attempt.manifestSha256==manifest.getValue("sha256").jsonPrimitive.content &&
                attempt.failedOutcomes==failed && attempt.action=="terminal-readback-only")
            val priorResult=root.resolve(RESULT)
            if(Files.exists(priorResult,NOFOLLOW_LINKS)) {
                val outcome=json.decodeFromString<PreparationTerminalResult>(ReleasePrivateFiles.read(priorResult,8192)
                    .decodeToString(throwOnInvalidSequence=true))
                require(outcome.intentSha256==sha(priorIntent,8192) &&
                    (if(outcome.passed) outcome.dispositionSha256==sha(root.resolve(NAME),1048576) &&
                        outcome.failureType==null else outcome.dispositionSha256==null &&
                        !Files.exists(root.resolve(NAME),NOFOLLOW_LINKS) && !outcome.failureType.isNullOrBlank()))
            }
        } else require(!Files.exists(root.resolve(RESULT),NOFOLLOW_LINKS))
        val second=root.resolve(V2_INTENT)
        if(Files.exists(second,NOFOLLOW_LINKS)) {
            require(Files.exists(root.resolve(INTENT),NOFOLLOW_LINKS) &&
                Files.exists(root.resolve(RESULT),NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve(NAME),NOFOLLOW_LINKS))
            val previous=json.decodeFromString<PreparationTerminalResult>(ReleasePrivateFiles.read(root.resolve(RESULT),8192)
                .decodeToString(throwOnInvalidSequence=true))
            val next=json.decodeFromString<PreparationTerminalReconciliationIntent>(ReleasePrivateFiles.read(second,8192)
                .decodeToString(throwOnInvalidSequence=true))
            require(!previous.passed && previous.dispositionSha256==null &&
                previous.failureType=="java.lang.IllegalArgumentException" &&
                next.generation==root.fileName.toString() && next.member==member &&
                next.originalCensusSha256==census.sha256 &&
                next.failedOriginalTerminalIntentSha256==sha(root.resolve(INTENT),8192) &&
                next.failedOriginalTerminalResultSha256==sha(root.resolve(RESULT),8192) &&
                next.action=="separate-failed-terminal-readback")
            if(Files.exists(root.resolve(V2_RESULT),NOFOLLOW_LINKS)) {
                val outcome=json.decodeFromString<PreparationTerminalResult>(ReleasePrivateFiles.read(root.resolve(V2_RESULT),8192)
                    .decodeToString(throwOnInvalidSequence=true))
                require(outcome.intentSha256==sha(second,8192) &&
                    (if(outcome.passed) outcome.dispositionSha256==sha(root.resolve(V2_NAME),1048576) &&
                        outcome.failureType==null else outcome.dispositionSha256==null &&
                        !Files.exists(root.resolve(V2_NAME),NOFOLLOW_LINKS) && !outcome.failureType.isNullOrBlank()))
            }
        } else require(!Files.exists(root.resolve(V2_RESULT),NOFOLLOW_LINKS))
        if(Files.exists(root.resolve(V2_PRE_EFFECT),NOFOLLOW_LINKS)) {
            val refusal=json.decodeFromString<PreparationTerminalV2PreEffectRefusal>(
                ReleasePrivateFiles.read(root.resolve(V2_PRE_EFFECT),16384)
                    .decodeToString(throwOnInvalidSequence=true))
            val logPath=Path.of(refusal.refusedV2LogPath)
            require(refusal.schemaVersion==1 && refusal.generation==root.fileName.toString() &&
                refusal.member==member && refusal.censusSha256==census.sha256 &&
                refusal.originalTerminalIntentSha256==sha(root.resolve(INTENT),8192) &&
                refusal.originalTerminalFalseResultSha256==sha(root.resolve(RESULT),8192) &&
                refusal.originalFailedOutcomes==failed &&
                refusal.memberManifestSha256==manifest.getValue("sha256").jsonPrimitive.content &&
                refusal.nativeAbsenceSha256.keys==setOf("container","network","volume","secret") &&
                refusal.nativeAbsenceSha256.all { (kind,pin) ->
                    pin==ReleaseLocks.sha256("$kind:$member:absent-v1".toByteArray()) } &&
                listOf(refusal.nativeSystemdSha256,refusal.nativeManagedUnitSha256,
                    refusal.nativeCiUserAbsenceSha256).all(hash::matches) &&
                refusal.firstRawReadbackSha256.keys==refusal.nativeAbsenceSha256.keys &&
                refusal.secondRawReadbackSha256.keys==refusal.nativeAbsenceSha256.keys &&
                (refusal.firstRawReadbackSha256.values+refusal.secondRawReadbackSha256.values).all(hash::matches) &&
                !refusal.v2IntentPresent && !refusal.v2ResultPresent && !refusal.terminalDispositionPassed &&
                !Files.exists(second,NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve(V2_RESULT),NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve(V2_NAME),NOFOLLOW_LINKS) &&
                logPath.isAbsolute && logPath.normalize()==logPath &&
                logPath.startsWith(Path.of("/home/gerald/p0_v3/.coord/rapid-completion")) &&
                Files.isRegularFile(logPath,NOFOLLOW_LINKS) && !Files.isSymbolicLink(logPath) &&
                Files.size(logPath) in 1..4096 &&
                ReleaseLocks.sha256(Files.readAllBytes(logPath))==refusal.refusedV2LogSha256)
        }
        if(Files.exists(root.resolve(V3_INTENT),NOFOLLOW_LINKS)) {
            require(Files.exists(root.resolve(V2_PRE_EFFECT),NOFOLLOW_LINKS))
            val next=json.decodeFromString<PreparationTerminalV3Intent>(
                ReleasePrivateFiles.read(root.resolve(V3_INTENT),8192)
                    .decodeToString(throwOnInvalidSequence=true))
            require(next.generation==root.fileName.toString() && next.member==member &&
                next.censusSha256==census.sha256 &&
                next.originalTerminalIntentSha256==sha(root.resolve(INTENT),8192) &&
                next.originalTerminalFalseResultSha256==sha(root.resolve(RESULT),8192) &&
                next.v2PreEffectRefusalSha256==sha(root.resolve(V2_PRE_EFFECT),16384) &&
                next.action=="versioned-terminal-after-v2-pre-effect-refusal")
            if(Files.exists(root.resolve(V3_RESULT),NOFOLLOW_LINKS)) {
                val result=json.decodeFromString<PreparationTerminalResult>(
                    ReleasePrivateFiles.read(root.resolve(V3_RESULT),8192)
                        .decodeToString(throwOnInvalidSequence=true))
                require(result.intentSha256==sha(root.resolve(V3_INTENT),8192) &&
                    (if(result.passed) result.dispositionSha256==sha(root.resolve(V3_NAME),1048576) &&
                        result.failureType==null else result.dispositionSha256==null &&
                        !Files.exists(root.resolve(V3_NAME),NOFOLLOW_LINKS) && !result.failureType.isNullOrBlank()))
            }
        } else require(!Files.exists(root.resolve(V3_RESULT),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(V3_NAME),NOFOLLOW_LINKS))
        return PreparationTerminalDisposition(generation=root.fileName.toString(),member=member,
            originalCensusSha256=census.sha256,failedOutcomes=failed,
            rootFileSha256=roots,ciFileSha256=ci,memberFileSha256=inputs,
            manifestSha256=manifest.getValue("sha256").jsonPrimitive.content,
            otherSourceFileSha256=other.toSortedMap(),nativeNamespaceSha256=emptyMap(),nativeSystemdSha256="",
            nativeManagedUnitSha256="",nativeCiUserAbsenceSha256="",nativeUnitCount=spec.processes.size+2)
    }
    private fun native(base:PreparationTerminalDisposition,commands:RuntimeCommands,
        units:(List<String>)->ByteArray):PreparationTerminalDisposition {
        val member=base.member
        val inventories=linkedMapOf<String,String>()
        val rawReadbacks=linkedMapOf<String,String>()
        for((kind,args) in listOf("container" to listOf("container","ls","--all","--format","{{.Names}}"),
            "network" to listOf("network","ls","--format","{{.Name}}"),
            "volume" to listOf("volume","ls","--format","{{.Name}}"),
            "secret" to listOf("secret","ls","--format","{{.Name}}"))) {
            val result=commands.run(args)
            require(result.exitCode==0 && result.output.toByteArray().size<=2000000 &&
                result.output.lineSequence().map(String::trim).filter(String::isNotEmpty).none {
                    it.startsWith("p0v3-live-$member-") }) { "Native preparation namespace not terminal" }
            rawReadbacks[kind]=ReleaseLocks.sha256(result.output.toByteArray())
            // The whole canonical store includes unrelated old/other workers;
            // its raw listing may change between two locked absence checks.
            // Every listing is audited above, but ONLY generation-scoped
            // absence is the stable terminal claim and comparison key.
            inventories[kind]=ReleaseLocks.sha256("$kind:$member:absent-v1".toByteArray())
        }
        val spec=json.decodeFromString<PrivateDeploymentSpec>(ReleasePrivateFiles.read(
            PrivateDeployment.BASE.resolve("$member.json"),4194304).decodeToString(throwOnInvalidSequence=true))
        val generation=base.generation
        val names=spec.processes.map { "p0v3-live-$member-${it.id}.service" } +
            listOf("p0v3-rss-$generation.service","p0v3-rss-$generation.timer")
        val readback=units(names)
        require(readback.size in 1..1048576)
        val blocks=readback.decodeToString(throwOnInvalidSequence=true).trim().split(Regex("\\n\\s*\\n"))
        require(blocks.size==names.size && blocks.map { raw ->
            raw.lineSequence().filter { '=' in it }.associate { it.substringBefore('=') to it.substringAfter('=') }
        }.mapIndexed { index,unit ->
            val timer=names[index].endsWith(".timer")
            require(unit["Id"]==names[index] && unit["LoadState"]=="not-found" &&
                unit["ActiveState"]=="inactive" &&
                (if(timer) unit["MainPID"] in setOf(null,"0") else unit["MainPID"]=="0") &&
                (if(timer) unit["ControlPID"] in setOf(null,"0") else unit["ControlPID"]=="0") &&
                unit["Job"] in setOf("0", "") && unit["ControlGroup"].orEmpty().isEmpty()) {
                "Generation unit has native effect"
            }
            unit["Id"]
        }.toSet().size==names.size)
        // The broker belongs to the owner's user manager, not systemd --system.
        val broker="p0v3-managed-lanes-$generation.service"
        require(!Files.exists(Path.of("/home/gerald/.config/systemd/user/$broker"),NOFOLLOW_LINKS)) {
            "Managed broker unit source was installed despite absent generation bundle"
        }
        val ownerUnit=systemctl(listOf(broker),user=true)
        require(ownerUnit.decodeToString(throwOnInvalidSequence=true).let { raw ->
            val values=raw.lineSequence().filter { '=' in it }
                .associate { it.substringBefore('=') to it.substringAfter('=') }
            values["Id"]==broker && values["LoadState"]=="not-found" &&
                values["ActiveState"]=="inactive" && values["MainPID"]=="0" &&
                values["ControlPID"]=="0" && values["Job"] in setOf("0","") &&
                values["ControlGroup"].orEmpty().isEmpty()
        }) { "Managed user broker unit was installed or started" }
        // Dedicated CI UID 784 has no user manager at this early source-only
        // stage. If a bus, UID process, container storage or installed source
        // exists, refuse: do NOT infer absence from an unavailable user bus.
        val ciUser=Path.of("/home/webservices-lab-ci-runner")
        val ciSource=ciUser.resolve(".local/share/p0v3-ci/$generation")
        val generated=listOf(ciUser.resolve(".config/systemd/user/p0v3-ci-$generation-guard.service")) +
            listOf("internal","egress","runner","transport").map { role ->
                ciUser.resolve(".config/containers/systemd/p0v3-ci-$generation-$role.${if(role in setOf("internal","egress")) "network" else "container"}") }
        val proc=Path.of("/proc")
        val hasUid=Files.list(proc).use { entries -> entries.filter { it.fileName.toString().all(Char::isDigit) }
            .anyMatch { pid -> runCatching {
                (Files.getAttribute(pid,"unix:uid",NOFOLLOW_LINKS) as Number).toInt()==784
            }.getOrElse {
                // /proc is volatile: a PID vanishing between list and stat is
                // not evidence of a still-running CI manager. An existing but
                // unreadable entry remains an explicit refusal, never absence.
                Files.exists(pid,NOFOLLOW_LINKS)
            } } }
        require(!hasUid && !Files.exists(Path.of("/run/user/784"),NOFOLLOW_LINKS) &&
            !Files.exists(ciUser.resolve(".local/share/containers/storage"),NOFOLLOW_LINKS) &&
            !Files.exists(ciSource,NOFOLLOW_LINKS) && generated.none { Files.exists(it,NOFOLLOW_LINKS) }) {
            "Dedicated rootless CI manager or native unit/container state cannot be excluded"
        }
        val ciAbsence="ci-uid784-user-manager-process-storage-installed-units-all-absent-v1:$generation"
        return base.copy(nativeNamespaceSha256=inventories,nativeNamespaceRawReadbackSha256=rawReadbacks,
            nativeSystemdSha256=ReleaseLocks.sha256(readback),
            nativeManagedUnitSha256=ReleaseLocks.sha256(ownerUnit),
            nativeCiUserAbsenceSha256=ReleaseLocks.sha256(ciAbsence.toByteArray()))
    }
    internal fun systemd(names:List<String>):ByteArray = systemctl(names,user=false)
    private fun systemctl(names:List<String>,user:Boolean):ByteArray {
        require(names.isNotEmpty() && names.size<=256 && names.all { it.matches(
            Regex("p0v3-(?:live-q-[a-f0-9]{12}-[a-z0-9-]+|rss-q-[a-f0-9]{12}|managed-lanes-q-[a-f0-9]{12})\\.(?:service|timer)")) })
        val process=ProcessBuilder(listOf("/usr/bin/systemctl")+(if(user) listOf("--user") else emptyList())+
            listOf("show","--no-pager",
            "--property=Id,LoadState,ActiveState,MainPID,ControlPID,Job,ControlGroup")+names)
            .redirectErrorStream(true).apply {
                environment().clear()
                if(user) {
                    val uid=UnixSystem().uid
                    environment()["XDG_RUNTIME_DIR"]="/run/user/$uid"
                    environment()["DBUS_SESSION_BUS_ADDRESS"]="unix:path=/run/user/$uid/bus"
                }
            }.start()
        try {
            require(process.waitFor(35,TimeUnit.SECONDS) && process.exitValue()==0)
            val bytes=process.inputStream.use { it.readNBytes(1048577) }
            require(bytes.size in 1..1048576);return bytes
        } finally { if(process.isAlive) process.destroyForcibly() }
    }
    /** Source-only forensic check. This is NOT a native terminal disposition. */
    internal fun inspectSource(root:Path,census:ActivationInput):PreparationTerminalDisposition=source(root,census)
    /** Read-only native preflight under the SAME ordered member locks as the
     * eventual journal. No intent, result or terminal success is written. */
    fun observe(root:Path,census:ActivationInput,
        commands:RuntimeCommands=PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
        units:(List<String>)->ByteArray=::systemd):PreparationTerminalDisposition {
        val base=source(root,census)
        return PrivateDeployment.withOrderedNativeLocks(listOf(base.member)) {
            val before=source(root,census)
            native(before,commands,units).also { require(source(root,census)==before) }
        }
    }

    /** Exact read-only differential for refused pre-effect reconciliation.
     * Unlike a terminal disposition, no result/intent can be produced here. */
    fun observePair(root:Path,census:ActivationInput,
        commands:RuntimeCommands=PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
        units:(List<String>)->ByteArray=::systemd):Pair<PreparationTerminalDisposition,PreparationTerminalDisposition> {
        val base=source(root,census)
        return PrivateDeployment.withOrderedNativeLocks(listOf(base.member)) {
            val before=source(root,census)
            val first=native(before,commands,units)
            val second=native(source(root,census),commands,units)
            require(source(root,census)==before)
            first to second
        }
    }

    /** Caller holds generation/RSS lock; ordered native member locks span the readbacks and write. */
    fun record(root:Path,census:ActivationInput,
        commands:RuntimeCommands=PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
        units:(List<String>)->ByteArray=::systemd):PreparationTerminalDisposition {
        require(!Files.exists(root.resolve(NAME),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(INTENT),NOFOLLOW_LINKS) && !Files.exists(root.resolve(RESULT),NOFOLLOW_LINKS))
        val base=source(root,census)
        return PrivateDeployment.withOrderedNativeLocks(listOf(base.member)) {
            val before=source(root,census)
            val attempt=PreparationTerminalIntent(before.generation,before.member,census.sha256,
                before.manifestSha256,before.failedOutcomes)
            val intentBytes=json.encodeToString(PreparationTerminalIntent.serializer(),attempt).toByteArray()
            ReleasePrivateFiles.save(root.resolve(INTENT),intentBytes)
            try {
                require(source(root,census)==before)
                val sealed=native(before,commands,units)
                require(source(root,census)==before && !Files.exists(root.resolve(NAME),NOFOLLOW_LINKS))
                val bytes=json.encodeToString(PreparationTerminalDisposition.serializer(),sealed).toByteArray()
                ReleasePrivateFiles.save(root.resolve(NAME),bytes)
                ReleasePrivateFiles.save(root.resolve(RESULT),json.encodeToString(
                    PreparationTerminalResult(ReleaseLocks.sha256(intentBytes),true,ReleaseLocks.sha256(bytes))).toByteArray())
                sealed
            } catch (failure:Exception) {
                if(!Files.exists(root.resolve(RESULT),NOFOLLOW_LINKS)) runCatching {
                    ReleasePrivateFiles.save(root.resolve(RESULT),json.encodeToString(
                        PreparationTerminalResult(ReleaseLocks.sha256(intentBytes),false,
                            failureType=failure.javaClass.name)).toByteArray())
                }.onFailure { failure.addSuppressed(it) }
                throw failure
            }
        }
    }
    /** A distinct, one-use disposition of an attempted v2 operation that
     * refused BEFORE its intent. This is NOT terminal success and cannot
     * release a fresh generation. Records exact failed-v1 journal, attempted
     * v2 refusal log, immutable member and two live locked absence readbacks. */
    fun recordV2PreEffectRefusal(root:Path,census:ActivationInput,refusalLog:ActivationInput,
        commands:RuntimeCommands=PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
        units:(List<String>)->ByteArray=::systemd):PreparationTerminalV2PreEffectRefusal {
        val logFile=Path.of(refusalLog.path)
        require(logFile.isAbsolute && logFile.normalize()==logFile &&
            logFile.startsWith(Path.of("/home/gerald/p0_v3/.coord/rapid-completion")) &&
            Files.isRegularFile(logFile,NOFOLLOW_LINKS) && !Files.isSymbolicLink(logFile) &&
            Files.size(logFile) in 1..4096 &&
            refusalLog.sha256==ReleaseLocks.sha256(Files.readAllBytes(logFile)) &&
            Files.readString(logFile).trim()==
                "Separate pre-bundle terminal operation refused (IllegalArgumentException); retain both original and terminal intents/results")
        require(!Files.exists(root.resolve(V2_PRE_EFFECT),NOFOLLOW_LINKS) &&
            listOf(V2_INTENT,V2_RESULT,V2_NAME,V3_INTENT,V3_RESULT,V3_NAME).none {
                Files.exists(root.resolve(it),NOFOLLOW_LINKS) })
        val baseline=source(root,census)
        val firstResult=json.decodeFromString<PreparationTerminalResult>(ReleasePrivateFiles.read(
            root.resolve(RESULT),8192).decodeToString(throwOnInvalidSequence=true))
        require(!firstResult.passed && firstResult.dispositionSha256==null &&
            firstResult.failureType=="java.lang.IllegalArgumentException" &&
            firstResult.intentSha256==sha(root.resolve(INTENT),8192) &&
            !Files.exists(root.resolve(NAME),NOFOLLOW_LINKS))
        return PrivateDeployment.withOrderedNativeLocks(listOf(baseline.member)) {
            val before=source(root,census)
            val first=native(before,commands,units)
            val second=native(source(root,census),commands,units)
            require(first.copy(nativeNamespaceRawReadbackSha256=emptyMap())==
                second.copy(nativeNamespaceRawReadbackSha256=emptyMap()) && source(root,census)==before &&
                !Files.exists(root.resolve(V2_PRE_EFFECT),NOFOLLOW_LINKS)) {
                "Independent generation-scoped v2 pre-effect absence is not stable"
            }
            val record=PreparationTerminalV2PreEffectRefusal(generation=before.generation,
                member=before.member,censusSha256=census.sha256,
                originalTerminalIntentSha256=sha(root.resolve(INTENT),8192),
                originalTerminalFalseResultSha256=sha(root.resolve(RESULT),8192),
                refusedV2LogPath=logFile.toString(),refusedV2LogSha256=refusalLog.sha256,
                originalFailedOutcomes=before.failedOutcomes,memberManifestSha256=before.manifestSha256,
                nativeAbsenceSha256=first.nativeNamespaceSha256,
                nativeSystemdSha256=first.nativeSystemdSha256,
                nativeManagedUnitSha256=first.nativeManagedUnitSha256,
                nativeCiUserAbsenceSha256=first.nativeCiUserAbsenceSha256,
                firstRawReadbackSha256=first.nativeNamespaceRawReadbackSha256,
                secondRawReadbackSha256=second.nativeNamespaceRawReadbackSha256)
            ReleasePrivateFiles.save(root.resolve(V2_PRE_EFFECT),
                json.encodeToString(PreparationTerminalV2PreEffectRefusal.serializer(),record).toByteArray())
            require(source(root,census)==before)
            record // Pre-effect refusal recorded ONLY; no terminal ACK or new source issuance.
        }
    }
    /** NEW one-use terminal journal only after the independently recorded v2
     * pre-effect refusal. Never replays v1 or the v2 attempted operation. */
    fun terminalizeAfterV2Refusal(root:Path,census:ActivationInput,refusal:ActivationInput,
        commands:RuntimeCommands=PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
        units:(List<String>)->ByteArray=::systemd):PreparationTerminalDisposition {
        require(refusal.path==root.resolve(V2_PRE_EFFECT).toString() &&
            refusal.sha256==sha(root.resolve(V2_PRE_EFFECT),16384) &&
            !Files.exists(root.resolve(V3_INTENT),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(V3_RESULT),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(V3_NAME),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(V2_INTENT),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(V2_RESULT),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(V2_NAME),NOFOLLOW_LINKS))
        val initial=source(root,census)
        return PrivateDeployment.withOrderedNativeLocks(listOf(initial.member)) {
            val before=source(root,census)
            val first=native(before,commands,units)
            val second=native(source(root,census),commands,units)
            require(first.copy(nativeNamespaceRawReadbackSha256=emptyMap())==
                second.copy(nativeNamespaceRawReadbackSha256=emptyMap()) && source(root,census)==before) {
                "Generation-scoped native terminal observations differ; no v3 intent"
            }
            val attempt=PreparationTerminalV3Intent(before.generation,before.member,census.sha256,
                sha(root.resolve(INTENT),8192),sha(root.resolve(RESULT),8192),refusal.sha256)
            val intentBytes=json.encodeToString(PreparationTerminalV3Intent.serializer(),attempt).toByteArray()
            ReleasePrivateFiles.save(root.resolve(V3_INTENT),intentBytes)
            try {
                require(source(root,census)==before)
                val sealed=native(source(root,census),commands,units)
                require(sealed.copy(nativeNamespaceRawReadbackSha256=emptyMap())==
                    first.copy(nativeNamespaceRawReadbackSha256=emptyMap()) && source(root,census)==before &&
                    !Files.exists(root.resolve(V3_NAME),NOFOLLOW_LINKS)) {
                    "Post-intent generation-scoped native absence differs; retain v3 failure"
                }
                val bound=sealed.copy(predecessorFailedTerminalResultSha256=attempt.originalTerminalFalseResultSha256,
                    predecessorV2PreEffectDispositionSha256=refusal.sha256)
                val bytes=json.encodeToString(PreparationTerminalDisposition.serializer(),bound).toByteArray()
                ReleasePrivateFiles.save(root.resolve(V3_NAME),bytes)
                ReleasePrivateFiles.save(root.resolve(V3_RESULT),json.encodeToString(
                    PreparationTerminalResult(ReleaseLocks.sha256(intentBytes),true,ReleaseLocks.sha256(bytes))).toByteArray())
                bound
            } catch(failure:Exception) {
                if(!Files.exists(root.resolve(V3_RESULT),NOFOLLOW_LINKS)) runCatching {
                    ReleasePrivateFiles.save(root.resolve(V3_RESULT),json.encodeToString(
                        PreparationTerminalResult(ReleaseLocks.sha256(intentBytes),false,
                            failureType=failure.javaClass.name)).toByteArray())
                }.onFailure { failure.addSuppressed(it) }
                throw failure
            }
        }
    }

    /** Separate one-use response to a *failed* first terminal journal. Recheck
     * the first exact false result and independently observe twice under locks
     * BEFORE committing the new intent; never replay that first intent. */
    fun reconcileFailed(root:Path,census:ActivationInput,priorIntent:ActivationInput,priorResult:ActivationInput,
        commands:RuntimeCommands=PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
        units:(List<String>)->ByteArray=::systemd):PreparationTerminalDisposition {
        require(priorIntent.path==root.resolve(INTENT).toString() &&
            priorResult.path==root.resolve(RESULT).toString() &&
            priorIntent.sha256==sha(root.resolve(INTENT),8192) &&
            priorResult.sha256==sha(root.resolve(RESULT),8192) &&
            !Files.exists(root.resolve(NAME),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(V2_INTENT),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(V2_RESULT),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(V2_NAME),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve(V2_PRE_EFFECT),NOFOLLOW_LINKS))
        val old=json.decodeFromString<PreparationTerminalResult>(ReleasePrivateFiles.read(root.resolve(RESULT),8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(!old.passed && old.dispositionSha256==null &&
            old.failureType=="java.lang.IllegalArgumentException" && old.intentSha256==priorIntent.sha256)
        val initial=source(root,census)
        return PrivateDeployment.withOrderedNativeLocks(listOf(initial.member)) {
            val before=source(root,census)
            val first=native(before,commands,units)
            val second=native(source(root,census),commands,units)
            require(first.copy(nativeNamespaceRawReadbackSha256=emptyMap())==
                second.copy(nativeNamespaceRawReadbackSha256=emptyMap()) && source(root,census)==before) {
                "Independent native terminal observations differ; no new intent"
            }
            val attempt=PreparationTerminalReconciliationIntent(before.generation,before.member,census.sha256,
                priorIntent.sha256,priorResult.sha256)
            val intentBytes=json.encodeToString(PreparationTerminalReconciliationIntent.serializer(),attempt).toByteArray()
            ReleasePrivateFiles.save(root.resolve(V2_INTENT),intentBytes)
            try {
                require(source(root,census)==before)
                val sealed=native(source(root,census),commands,units)
                require(sealed.copy(nativeNamespaceRawReadbackSha256=emptyMap())==
                    first.copy(nativeNamespaceRawReadbackSha256=emptyMap()) && source(root,census)==before &&
                    !Files.exists(root.resolve(V2_NAME),NOFOLLOW_LINKS)) {
                    "Post-intent native absence differs; retain separate v2 failure"
                }
                val bound=sealed.copy(predecessorFailedTerminalResultSha256=priorResult.sha256)
                val bytes=json.encodeToString(PreparationTerminalDisposition.serializer(),bound).toByteArray()
                ReleasePrivateFiles.save(root.resolve(V2_NAME),bytes)
                ReleasePrivateFiles.save(root.resolve(V2_RESULT),json.encodeToString(
                    PreparationTerminalResult(ReleaseLocks.sha256(intentBytes),true,ReleaseLocks.sha256(bytes))).toByteArray())
                bound
            } catch(failure:Exception) {
                if(!Files.exists(root.resolve(V2_RESULT),NOFOLLOW_LINKS)) runCatching {
                    ReleasePrivateFiles.save(root.resolve(V2_RESULT),json.encodeToString(
                        PreparationTerminalResult(ReleaseLocks.sha256(intentBytes),false,
                            failureType=failure.javaClass.name)).toByteArray())
                }.onFailure { failure.addSuppressed(it) }
                throw failure
            }
        }
    }

    /** Immutable-source revalidation for request planning; actual new effects
     * MUST call verify under owner/native locks again for live unit/CID absence. */
    fun readStored(root:Path,census:ActivationInput,terminal:ActivationInput):PreparationTerminalDisposition {
        val second=terminal.path==root.resolve(V2_NAME).toString()
        val third=terminal.path==root.resolve(V3_NAME).toString()
        require((third || second || terminal.path==root.resolve(NAME).toString()) &&
            terminal.sha256==sha(Path.of(terminal.path),1048576))
        val baseline=source(root,census)
        val saved=json.decodeFromString<PreparationTerminalDisposition>(ReleasePrivateFiles.read(Path.of(terminal.path),1048576)
            .decodeToString(throwOnInvalidSequence=true))
        val result=json.decodeFromString<PreparationTerminalResult>(ReleasePrivateFiles.read(
            root.resolve(if(third) V3_RESULT else if(second) V2_RESULT else RESULT),8192)
                .decodeToString(throwOnInvalidSequence=true))
        val priorHash=if(second || third) sha(root.resolve(RESULT),8192) else null
        val refusalHash=if(third) sha(root.resolve(V2_PRE_EFFECT),16384) else null
        require(result.passed && result.dispositionSha256==terminal.sha256 &&
            saved.predecessorFailedTerminalResultSha256==priorHash &&
            saved.predecessorV2PreEffectDispositionSha256==refusalHash &&
            (if(third) !Files.exists(root.resolve(V2_INTENT),NOFOLLOW_LINKS) else true) &&
            saved.copy(nativeNamespaceSha256=emptyMap(),nativeSystemdSha256="",
                nativeManagedUnitSha256="",nativeCiUserAbsenceSha256="",
                nativeNamespaceRawReadbackSha256=emptyMap(),predecessorFailedTerminalResultSha256=null,
                predecessorV2PreEffectDispositionSha256=null)==baseline &&
            saved.nativeNamespaceSha256.keys==setOf("container","network","volume","secret") &&
            saved.nativeNamespaceRawReadbackSha256.keys==saved.nativeNamespaceSha256.keys &&
            saved.nativeNamespaceRawReadbackSha256.values.all(hash::matches) &&
            saved.nativeNamespaceSha256.all { (kind,value) ->
                value==ReleaseLocks.sha256("$kind:${saved.member}:absent-v1".toByteArray()) } &&
            listOf(saved.nativeSystemdSha256,saved.nativeManagedUnitSha256,saved.nativeCiUserAbsenceSha256).all(hash::matches) &&
            !saved.bundlePresent && !saved.originalPreparationPassed && !saved.unitOrCidEffectObserved &&
            !saved.publicActivation) { "Unrecognized or incomplete terminal preparation disposition" }
        return saved
    }
    fun verify(root:Path,census:ActivationInput,terminal:ActivationInput,
        commands:RuntimeCommands=PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
        units:(List<String>)->ByteArray=::systemd):PreparationTerminalDisposition {
        val base=readStored(root,census,terminal)
        return PrivateDeployment.withOrderedNativeLocks(listOf(base.member)) {
            val current=readStored(root,census,terminal)
            val observed=native(source(root,census),commands,units).copy(
                predecessorFailedTerminalResultSha256=current.predecessorFailedTerminalResultSha256,
                predecessorV2PreEffectDispositionSha256=current.predecessorV2PreEffectDispositionSha256)
            require(current.copy(nativeNamespaceRawReadbackSha256=emptyMap())==
                observed.copy(nativeNamespaceRawReadbackSha256=emptyMap()) && !current.bundlePresent &&
                !current.originalPreparationPassed && !current.unitOrCidEffectObserved && !current.publicActivation) {
                "Abandoned preparation disposition changed; retain original fences"
            }
            current
        }
    }
}
