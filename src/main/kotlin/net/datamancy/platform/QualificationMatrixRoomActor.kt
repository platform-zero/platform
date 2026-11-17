package net.datamancy.platform

import java.nio.file.Path
import java.time.Instant
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.util.concurrent.TimeUnit
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** One-use owner effect: a local QClient intent is not authority to create an RTC room.
 * The native intent is durable before any POST; missing ACK never retries CreateRoom. */
internal object QualificationMatrixRoomActor {
    private val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
    private val roomPattern = Regex("![A-Za-z0-9_-]{8,80}:matrix\\.datamancy\\.net")
    private val hex = Regex("[a-f0-9]{64}")
    private val keyPattern = Regex("(?m)^  \"([a-f0-9]{64})\": \"([a-f0-9]{64})\"$")
    // A fixed no-shell nsenter child. Bearers are stdin-only, response bounded; no caller URL.
    private val child = """import http.client,json,sys
x=json.loads(sys.stdin.buffer.read(8193))
assert set(x)=={'method','token','body'} and x['method'] in ('ListRooms','CreateRoom')
c=http.client.HTTPConnection('127.0.0.1',7880,timeout=12)
try:
 c.request('POST','/twirp/livekit.RoomService/'+x['method'],body=json.dumps(x['body'],separators=(',',':')),headers={'Authorization':'Bearer '+x['token'],'Content-Type':'application/json'})
 r=c.getresponse(); b=r.read(65537)
 assert len(b)<=65536
 sys.stdout.write(json.dumps({'status':r.status,'body':json.loads(b) if b else {}},separators=(',',':')))
finally: c.close()
"""
    private fun token(key: String, secret: String, room: String, grant: JsonObject): String {
        val now = Instant.now().epochSecond
        val encoder = Base64.getUrlEncoder().withoutPadding()
        fun base(raw: String) = encoder.encodeToString(raw.encodeToByteArray())
        val body = base("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + base(buildJsonObject {
            put("iss", key); put("sub", "p0v3-scoped-room-admin")
            put("nbf", now - 5); put("exp", now + 180); put("video", grant)
        }.toString())
        val hmac = Mac.getInstance("HmacSHA256")
        hmac.init(SecretKeySpec(secret.encodeToByteArray(), "HmacSHA256"))
        return body + "." + encoder.encodeToString(hmac.doFinal(body.encodeToByteArray()))
    }
    private fun call(pid: Int, method: String, bearer: String, body: JsonObject): JsonObject {
        require(pid > 1 && method in setOf("ListRooms", "CreateRoom") && bearer.length in 64..8192)
        val args = listOf("/usr/bin/sudo", "-n", "/usr/bin/nsenter", "--target=$pid", "--net",
            "--setuid=1000", "--setgid=1000", "/usr/bin/python3", "-c", child)
        val process = ProcessBuilder(args).redirectErrorStream(false).start()
        val request = buildJsonObject { put("method", method); put("token", bearer); put("body", body) }
        process.outputStream.use { it.write(json.encodeToString(request).encodeToByteArray()) }
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.toHandle().descendants().use { it.toList().asReversed().forEach { child -> child.destroyForcibly() } }
            process.destroyForcibly().waitFor()
            error("Native RoomService response uncertain; original intent retained")
        }
        val bytes = process.inputStream.readNBytes(65537)
        require(bytes.size in 1..65536 && process.exitValue() == 0) {
            "Native RoomService response uncertain; original intent retained"
        }
        return json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject.also {
            require(it.keys == setOf("status", "body"))
        }
    }
    internal fun verifyLocalIntent(proposed: JsonObject, generation: String, room: String,
        sourceGeneration: String, device: String) {
        require(proposed.keys == setOf("generation", "room", "sourceGeneration", "ownerDeviceId") &&
            proposed.getValue("generation").jsonPrimitive.content == generation &&
            proposed.getValue("room").jsonPrimitive.content == room &&
            proposed.getValue("sourceGeneration").jsonPrimitive.content == sourceGeneration &&
            proposed.getValue("ownerDeviceId").jsonPrimitive.content == device)
    }
    /** Teardown reconciliation observes the pending owner intent, never retries CreateRoom
     * or infers success from a room currently present on a potentially foreign actor. */
    fun pending(caseDir: Path): Boolean {
        val intent = caseDir.resolve("owner-proofs/matrix-room.intent.json")
        if (!java.nio.file.Files.exists(intent, java.nio.file.LinkOption.NOFOLLOW_LINKS)) return false
        val raw = ReleasePrivateFiles.read(intent, 65536)
        val result = caseDir.resolve("owner-proofs/matrix-room.result.json")
        if (java.nio.file.Files.exists(result, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.read(result, 65536)
            return false
        }
        val uncertain = buildJsonObject { put("schemaVersion", 1)
            put("ownerIntentSha256", ReleaseLocks.sha256(raw))
            put("status", "ROOM_EFFECT_OR_ACK_UNCERTAIN"); put("success", false) }
        ReleasePrivateFiles.save(caseDir.resolve("owner-proofs/matrix-room.uncertain.json"),
            json.encodeToString(uncertain).encodeToByteArray())
        return true
    }
    fun execute(action: JsonObject, caseDir: Path, context: JsonObject,
        spec: PrivateDeploymentSpec, pin: GenerationPin, phase: String): JsonObject {
        require(action.keys == setOf("action", "roomId", "sourceGenerationId", "ownerDeviceId", "intentSha256") &&
            action.getValue("action").jsonPrimitive.content == "ENSURE_ROOM" && phase in setOf("INSTALL", "RESTORE"))
        val room = action.getValue("roomId").jsonPrimitive.content
        val sourceGeneration = action.getValue("sourceGenerationId").jsonPrimitive.content
        val device = action.getValue("ownerDeviceId").jsonPrimitive.content
        val intentSha = action.getValue("intentSha256").jsonPrimitive.content
        require(room.matches(roomPattern) && sourceGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            device.matches(Regex("[A-Z0-9]{8,80}")) && intentSha.matches(hex) &&
            spec == pin.spec && spec.store == RuntimeStore.CANONICAL_V2)
        val original = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(context.getValue(
            "originalMatrixOracleFile").jsonPrimitive.content), 1048576).decodeToString()).jsonObject
        require(original.getValue("roomId").jsonPrimitive.content == room &&
            original.getValue("sourceGenerationId").jsonPrimitive.content == sourceGeneration &&
            (phase == "INSTALL") == (sourceGeneration == spec.name.removeSuffix("-v2")))
        // The genuine native original observation, not the QClient's self-asserted device ID.
        val observation = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(context.getValue(
            "nativeObservationFile").jsonPrimitive.content), 1048576).decodeToString()).jsonObject
        require(observation.getValue("deviceId").jsonPrimitive.content == device &&
            observation.getValue("roomId").jsonPrimitive.content == room &&
            observation.getValue("generationId").jsonPrimitive.content == spec.name.removeSuffix("-v2"))
        val local = ReleasePrivateFiles.read(caseDir.resolve("livekit-android-create.intent.json"), 8192)
        require(ReleaseLocks.sha256(local) == intentSha)
        val proposed = json.parseToJsonElement(local.decodeToString(throwOnInvalidSequence = true)).jsonObject
        verifyLocalIntent(proposed, spec.name.removeSuffix("-v2"), room, sourceGeneration, device)
        val input = PrivateDeployment.BASE.resolve(spec.name).resolve("livekit.yaml")
        val yaml = ReleasePrivateFiles.read(input, 65536).decodeToString(throwOnInvalidSequence = true)
        require(ReleaseLocks.sha256(yaml.encodeToByteArray()) == pin.inputHashes.getValue("livekit.yaml"))
        val keys = keyPattern.findAll(yaml).toList()
        require(keys.size == 1)
        val (key, secret) = keys.single().destructured
        val livekit = QualificationMatrixActor.selectedProcess(spec, pin.runtimeFingerprint, "livekit")
        val pid = livekit.getValue("pid").jsonPrimitive.int
        val cid = livekit.getValue("containerId").jsonPrimitive.content
        // Save BEFORE the denial/list/create sequence. There is intentionally no adopt/retry
        // path after a pending or lost ACK, including if the room is found existing.
        val ownerIntent = buildJsonObject {
            put("schemaVersion", 1); put("invocationId", caseDir.resolve("intent.json").let { path ->
                json.parseToJsonElement(ReleasePrivateFiles.read(path, 65536).decodeToString()).jsonObject
                    .getValue("invocationId").jsonPrimitive.content })
            put("roomId", room); put("sourceGenerationId", sourceGeneration)
            put("ownerDeviceId", device); put("localIntentSha256", intentSha)
            put("selectedLivekitContainerId", cid); put("selectedManifestSha256", pin.manifestSha256)
        }
        val bytes = json.encodeToString(ownerIntent).encodeToByteArray()
        ReleasePrivateFiles.save(caseDir.resolve("owner-proofs/matrix-room.intent.json"), bytes)
        val invalid = token(key, if (secret == "0".repeat(64)) "1".repeat(64) else "0".repeat(64), room,
            buildJsonObject { put("roomList", true); put("room", room) })
        val admin = token(key, secret, room, buildJsonObject {
            put("roomList", true); put("roomCreate", true); put("roomAdmin", true); put("room", room)
        })
        require(call(pid, "ListRooms", invalid, buildJsonObject { putJsonArray("names") { add(room) } })
            .getValue("status").jsonPrimitive.int == 401) { "Invalid native RoomService signer accepted" }
        val list = call(pid, "ListRooms", admin, buildJsonObject { putJsonArray("names") { add(room) } })
        require(list.getValue("status").jsonPrimitive.int == 200)
        val rooms = list.getValue("body").jsonObject.getValue("rooms").jsonArray
        require(rooms.size <= 1 && rooms.all { it.jsonObject.getValue("name").jsonPrimitive.content == room })
        if (rooms.isEmpty()) {
            val created = call(pid, "CreateRoom", admin, buildJsonObject { put("name", room); put("max_participants", 4) })
            require(created.getValue("status").jsonPrimitive.int == 200 &&
                created.getValue("body").jsonObject.getValue("name").jsonPrimitive.content == room)
        }
        val readback = call(pid, "ListRooms", admin, buildJsonObject { putJsonArray("names") { add(room) } })
        require(readback.getValue("status").jsonPrimitive.int == 200 &&
            readback.getValue("body").jsonObject.getValue("rooms").jsonArray.single().jsonObject
                .getValue("name").jsonPrimitive.content == room)
        val result = buildJsonObject { put("containerId", cid); put("roomId", room)
            put("sourceGenerationId", sourceGeneration); put("invalidTokenDenied", true)
            put("nativeRoomReadback", true); put("ownerIntentSha256", intentSha)
            put("ownerEffectFenced", true) }
        ReleasePrivateFiles.save(caseDir.resolve("owner-proofs/matrix-room.result.json"),
            json.encodeToString(result).encodeToByteArray())
        return result
    }
}
