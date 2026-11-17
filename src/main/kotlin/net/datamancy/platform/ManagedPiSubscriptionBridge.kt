package net.datamancy.platform

import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Process-isolated Pi 1.4.0 native provider, never a generic OAuth bearer proxy.
 * One in-flight model request per broker, no retry after an uncertain native effect.
 * Child stderr is discarded and its stdout contains only a bounded model response.
 */
internal class ManagedPiSubscriptionBridge(private val generation: String, private val laneId: String) {
    private val lock = java.util.concurrent.Semaphore(1)
    private val script = Path.of("/home/gerald/.local/share/p0-v3-subscription/openai-only/pi_subscription_broker_v3.mjs")
    private val auth = Path.of("/home/gerald/.local/share/p0-v3-subscription/openai-only/auth.json")
    fun execute(request: ByteArray, authorized: () -> Boolean): ByteArray {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            laneId.matches(Regex("[a-f0-9-]{36}")) && request.size in 2..1048576 && authorized())
        require(lock.tryAcquire()) { "Managed subscription model request already in flight" }
        try {
            require(authorized())
            val root=script.parent
            ReleasePrivateFiles.directory(root)
            val expected=ManagedPiSubscriptionCustody.scriptSha256()
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(script,65536))==expected)
            val authBytes=ReleasePrivateFiles.read(auth,65536)
            try {
                val record=Json.parseToJsonElement(authBytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
                require(record.keys==setOf("openai") && record.getValue("openai").jsonObject["type"]?.jsonPrimitive?.content=="oauth")
            } finally { authBytes.fill(0) }
            val node=Path.of("/opt/node-v24.21.0/bin/node")
            require(Files.isRegularFile(node,NOFOLLOW_LINKS) &&
                RecoveryCapsule.fileHash(node)=="7fde7b8afa198da66257f42ee2001d874c7355631e6d1579a5fb5ef1f246df4c")
            val pi=Path.of("/home/gerald/.local/share/pi/lib/node_modules/@earendil-works/pi-coding-agent")
            require(RecoveryCapsule.fileHash(pi.resolve("package.json"))=="df6883685382d6a914e5797232744c26579fe7db5576ea0e9c859d018ca2d54e" &&
                RecoveryCapsule.fileHash(pi.resolve("dist/core/model-runtime.js"))=="44d8017928eff6721d5a56b4e71f98bcafb124f5aa6e7d3f016491e11fcf6461" &&
                RecoveryCapsule.fileHash(pi.resolve("node_modules/@earendil-works/pi-ai/dist/api/openai-responses.js"))=="002f15414b7c7b62a32610a8a915bdf1a01eed930b8b45d7691e8a5c475fa9b5" &&
                RecoveryCapsule.fileHash(pi.resolve("node_modules/@earendil-works/pi-ai/dist/api/openai-responses-shared.js"))=="eed025a4821b1e017dd024b930caf8fa11c7fe053a81efe11bd7d846fdc641d3")
            val process=ProcessBuilder(node.toString(),script.toString())
                .redirectError(ProcessBuilder.Redirect.DISCARD)
                .apply { environment().clear(); environment().putAll(mapOf("PATH" to "/usr/bin:/bin",
                    "HOME" to "/home/gerald/.local/share/p0-v3-subscription/openai-only", "LANG" to "C")) }
                .start()
            try {
                process.outputStream.use { it.write(request) }
                val output=ByteArrayOutputStream()
                val buffer=ByteArray(16384)
                val deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(90)
                val reader=java.util.concurrent.Executors.newSingleThreadExecutor { runnable ->
                    Thread(runnable,"pi-subscription-output").apply { isDaemon=true }
                }
                try {
                    val pending=reader.submit {
                        process.inputStream.use { input ->
                            while (true) {
                                val count=input.read(buffer)
                                if (count<0) break
                                require(output.size()+count<=4194304)
                                output.write(buffer,0,count)
                            }
                        }
                    }
                    while (!pending.isDone) {
                        require(authorized() && System.nanoTime()<deadline) { "Managed grant revoked or model deadline" }
                        try { pending.get(250,TimeUnit.MILLISECONDS) }
                        catch (_: java.util.concurrent.TimeoutException) { /* cancellation and revocation poll */ }
                    }
                    pending.get()
                } finally { reader.shutdownNow() }
                require(process.waitFor(1,TimeUnit.SECONDS) && process.exitValue()==0 && authorized())
                val bytes=output.toByteArray()
                val response=Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
                require(response["model"]?.jsonPrimitive?.content=="gpt-6-sol" &&
                    response["status"]?.jsonPrimitive?.content=="completed" && bytes.size in 2..4194304)
                return bytes
            } finally { if(process.isAlive) { process.destroyForcibly();process.waitFor(5,TimeUnit.SECONDS) } }
        } finally { lock.release() }
    }
}

/** Curate exactly one provider, never mount the main host Pi auth into Worklane.
 * This is owner-local custody, not a sealed credential or an offline recovery key.
 */
internal object ManagedPiSubscriptionCustody {
    private val root=Path.of("/home/gerald/.local/share/p0-v3-subscription/openai-only")
    private val source=Path.of("/home/gerald/.pi/agent/auth.json")
    private val resource="/runtime/pi_subscription_broker.mjs"
    fun scriptSha256():String = ReleaseLocks.sha256(requireNotNull(javaClass.getResourceAsStream(resource)).use { it.readBytes() })
    fun issue():String {
        require(!Files.exists(root.resolve("auth.json"),NOFOLLOW_LINKS))
        ReleasePrivateFiles.directory(source.parent)
        val original=ReleasePrivateFiles.read(source,65536)
        val selected=try {
            val parsed=Json.parseToJsonElement(original.decodeToString(throwOnInvalidSequence=true)).jsonObject
            val record=requireNotNull(parsed["openai"]).jsonObject
            require(record["type"]?.jsonPrimitive?.content=="oauth" &&
                record["access"]?.jsonPrimitive?.content?.isNotBlank()==true &&
                record["refresh"]?.jsonPrimitive?.content?.isNotBlank()==true)
            Json.encodeToString(kotlinx.serialization.json.JsonObject(mapOf("openai" to record))).toByteArray()
        } finally { original.fill(0) }
        if (!Files.exists(root.parent,NOFOLLOW_LINKS)) {
            val parent=root.parent.parent
            ReleasePrivateFiles.directory(parent)
            Files.createDirectory(root.parent,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(parent)
        }
        ReleasePrivateFiles.directory(root.parent)
        if (!Files.exists(root,NOFOLLOW_LINKS)) {
            Files.createDirectory(root,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root.parent)
        }
        ReleasePrivateFiles.directory(root)
        val intent=root.resolve("issue.intent.json")
        require(!Files.exists(intent,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(intent,"pi-openai-oauth-v2 owner-local provider-only custody\n".toByteArray())
        try {
            ReleasePrivateFiles.save(root.resolve("auth.json"),selected)
            val script=requireNotNull(javaClass.getResourceAsStream(resource)).use { it.readBytes() }
            ReleasePrivateFiles.save(root.resolve("pi_subscription_broker.mjs"),script)
            val result=root.resolve("issue.result.json")
            val bytes=Json.encodeToString(mapOf("provider" to "openai","mode" to "pi-openai-oauth-v2",
                "scriptSha256" to ReleaseLocks.sha256(script),"localCustodyOnly" to "true")).toByteArray()
            ReleasePrivateFiles.save(result,bytes)
            return ReleaseLocks.sha256(bytes)
        } finally { selected.fill(0) }
    }
    fun verify():String {
        ReleasePrivateFiles.directory(root)
        val intent=ReleasePrivateFiles.read(root.resolve("issue.intent.json"),1024)
        require(intent.contentEquals("pi-openai-oauth-v2 owner-local provider-only custody\n".toByteArray()))
        val result=ReleasePrivateFiles.read(root.resolve("issue.result.json"),8192)
        val record=Json.parseToJsonElement(result.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(record["provider"]?.jsonPrimitive?.content=="openai" &&
            record["mode"]?.jsonPrimitive?.content=="pi-openai-oauth-v2" &&
            record["scriptSha256"]?.jsonPrimitive?.content==
                ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("pi_subscription_broker.mjs"),65536)))
        val revision=ReleasePrivateFiles.read(root.resolve("script-v3.result.json"),8192)
        val scriptRecord=Json.parseToJsonElement(revision.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(scriptRecord["precedingCustodySha256"]?.jsonPrimitive?.content==ReleaseLocks.sha256(result) &&
            scriptRecord["scriptSha256"]?.jsonPrimitive?.content==scriptSha256() &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("pi_subscription_broker_v3.mjs"),65536))==scriptSha256())
        val auth=ReleasePrivateFiles.read(root.resolve("auth.json"),65536)
        try {
            val parsed=Json.parseToJsonElement(auth.decodeToString(throwOnInvalidSequence=true)).jsonObject
            require(parsed.keys==setOf("openai") && parsed.getValue("openai").jsonObject["type"]?.jsonPrimitive?.content=="oauth")
        } finally { auth.fill(0) }
        return ReleaseLocks.sha256(revision)
    }
    /** An original v2 script was already issued. Its bytes and result remain
     * immutable; v3 is a separate one-use journaled revision, never an ACK repair. */
    fun issueScriptRevision():String {
        ReleasePrivateFiles.directory(root)
        val previous=ReleasePrivateFiles.read(root.resolve("issue.result.json"),8192)
        require(!Files.exists(root.resolve("script-v3.intent.json"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("script-v3.result.json"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("pi_subscription_broker_v3.mjs"),NOFOLLOW_LINKS))
        val prior=Json.parseToJsonElement(previous.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(prior["scriptSha256"]?.jsonPrimitive?.content==
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("pi_subscription_broker.mjs"),65536)))
        val script=requireNotNull(javaClass.getResourceAsStream(resource)).use { it.readBytes() }
        val bytes=Json.encodeToString(mapOf("precedingCustodySha256" to ReleaseLocks.sha256(previous),
            "scriptSha256" to ReleaseLocks.sha256(script))).toByteArray()
        ReleasePrivateFiles.save(root.resolve("script-v3.intent.json"),bytes)
        ReleasePrivateFiles.save(root.resolve("pi_subscription_broker_v3.mjs"),script)
        ReleasePrivateFiles.save(root.resolve("script-v3.result.json"),bytes)
        return verify()
    }
}
