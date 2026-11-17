package net.datamancy.platform

import java.nio.file.Files
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

/** Exact, quiesced CE recipe. Restore schemas/files externally; never rerun schema/user seeding. */
internal object SeafileRecovery {
    fun spec(source: PrivateDeploymentSpec, inventory: AcquiredInventory, name: String, sourceHash: String): PrivateDeploymentSpec {
        require(source == SeafileRuntime.spec(inventory, source.name)) { "Unsupported file recovery recipe" }
        require(source.name != name && sourceHash.matches(Regex("[a-f0-9]{64}")))
        fun marker(path: String) = "test ! -L $path; test -f $path; grep -qx '$sourceHash' $path"
        val guard = "test ! -e /state/.restore-in-progress; test ! -L /state/.restore-in-progress; " +
            marker("/state/.p0v3-restore-complete") + "; " + marker("/state/.p0v3-database-import-complete") + "; " +
            "test -d /state/seafile-data; test ! -L /state/seafile-data; " +
            "test -f /state/conf/seahub_settings.py; test ! -L /state/conf/seahub_settings.py"
        val databaseCheck = """
            import os,pymysql
            for name in ('ccnet_db','seafile_db','seahub_db'):
                conn=pymysql.connect(host='mariadb',user='seafile',password=os.environ['SEAFILE_MYSQL_DB_PASSWORD'],database=name)
                with conn.cursor() as cursor:
                    cursor.execute('SHOW TABLES')
                    if not cursor.fetchall(): raise SystemExit('Recovered database missing tables')
                conn.close()
        """.trimIndent()
        val usersCheck = """
            from seaserv import ccnet_api
            for role in ('owner','reader','outsider'):
                if ccnet_api.get_emailuser(role+'@localhost.invalid') is None:
                    raise SystemExit('Recovered identity missing; refusing to regenerate')
        """.trimIndent()
        return source.copy(name = name, processes = source.processes.map { p -> when (p.id) {
            "schema-init" -> p.copy(entrypoint = "/bin/sh", command = listOf("-ec", guard + "; exec /usr/bin/python3 -c \"\${1}\"", "restore-check", databaseCheck))
            "users-init" -> p.copy(entrypoint = "/usr/bin/python3", command = listOf("-c", usersCheck))
            else -> p
        } }).also { PrivateDeployment.validate(it) }
    }

    fun prepare(inventory: AcquiredInventory, recovered: Path, name: String, base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val sourcePath = recovered.resolve("source-spec.json")
        val bytes = ReleaseLocks.privateBytes(sourcePath)
        val source = PrivateDeployment.read(sourcePath)
        val target = spec(source, inventory, name, ReleaseLocks.sha256(bytes))
        val inputs = SingleUserRestore.inputNames(source).associateWith { ReleaseLocks.privateBytes(recovered.resolve(it)).decodeToString(throwOnInvalidSequence = true) }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) inputs.forEach { (file, content) ->
            require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(content.toByteArray())) { "Recovered file inputs changed; refusing replacement" }
        }
        return RuntimePreparation.prepare(target, base) { inputs }
    }
}

/** Source/target immutable spec + native Seafile backend identity before AND after a fixed ro query. */
@Serializable internal data class OfficeCallbackNativeReadback(
    val schemaVersion: Int, val generation: String, val deploymentName: String,
    val runtimeFingerprint: String, val backendContainerId: String, val backendImageId: String,
    val stateVolume: String, val operationKey: String, val completedCount: Int,
    val callbackState: String?, val replayAdmission: String, val nativeCollectorSha256: String)

internal interface OfficeCallbackNativeTransport {
    fun inspect(exactContainer: String): String
    fun readonly(exactContainer: String, key: String): String
}

/** Canonical V2 only; fixed namespace, fixed image-native script and fixed SQLite path. */
internal object OfficeCallbackNativeCollector {
    private const val GUARD = "/run/secrets/office_callback_guard.py"
    private val digest = Regex("[a-f0-9]{64}")
    private val keyPattern = Regex("office-callback-v2:[a-f0-9]{64}")
    private fun sha(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }
    /** No caller-supplied executable, script, local ledger path or SQL. */
    private object Native : OfficeCallbackNativeTransport {
        private fun command(args: List<String>, maximum: Int): String {
            RuntimeStore.CANONICAL_V2.verifyConfiguration()
            val store = RuntimeStore.CANONICAL_V2
            val fixed = listOf("sudo", "-n", "podman", "--remote=false", "--module=${store.module}",
                "--root=${store.graph}", "--runroot=${store.run}", "--network-config-dir=${store.network}")
            val deadline = RecoveryDeadline.remainingSecondsIfBound()?.let { minOf(it, 20L) } ?: 20L
            require(deadline in 1..20)
            val process = ProcessBuilder(fixed + args).apply {
                environment().clear(); environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LC_ALL" to "C"))
                redirectError(ProcessBuilder.Redirect.DISCARD)
            }.start()
            try {
                val output = java.util.concurrent.CompletableFuture.supplyAsync { process.inputStream.readNBytes(maximum + 1) }
                require(process.waitFor(deadline, TimeUnit.SECONDS) && process.exitValue() == 0) {
                    "Native Office ledger collector refused; source must remain held"
                }
                val data = output.get(2, TimeUnit.SECONDS)
                require(data.size <= maximum) { "Unbounded native Office callback evidence" }
                return data.decodeToString(throwOnInvalidSequence = true)
            } finally { if (process.isAlive) process.destroyForcibly() }
        }
        override fun inspect(exactContainer: String): String = command(listOf("inspect", exactContainer), 262144)
        override fun readonly(exactContainer: String, key: String): String = command(
            listOf("exec", exactContainer, "/usr/bin/python3", "-B",
                GUARD, "--readonly-collector", key), 4096)
    }
    fun collect(spec: PrivateDeploymentSpec, generation: String, expectedFingerprint: String,
        operationKey: String, native: OfficeCallbackNativeTransport = Native): OfficeCallbackNativeReadback {
        require(spec.store == RuntimeStore.CANONICAL_V2 && generation.matches(Regex("q-[a-f0-9]{12}")) &&
            expectedFingerprint.matches(digest) && operationKey.matches(keyPattern))
        val backend = spec.processes.single { it.id == "seafile-backend" }
        require(!backend.oneShot && backend.imageId.matches(digest) &&
            backend.volumes == listOf(RuntimeMount("seafile-state", "/state"), RuntimeMount("seafile-rpc", "/rpc")) &&
            backend.files.any { it.file == "seafile-office-callback-guard.py" && it.target == GUARD } &&
            spec.volumes.single { it.id == "seafile-state" }.userId == backend.userId)
        val container = "p0v3-live-${spec.name}-seafile-backend"
        require(container.matches(Regex("p0v3-live-[a-z0-9-]{1,125}-seafile-backend")))
        fun nativeId(): String {
            val parsed = Json.parseToJsonElement(native.inspect(container)).jsonArray.single().jsonObject
            val labels = parsed.getValue("Config").jsonObject.getValue("Labels").jsonObject
            val mounts = parsed.getValue("Mounts").jsonArray.map { it.jsonObject }
            val cid = parsed.getValue("Id").jsonPrimitive.content
            require(cid.matches(digest) &&
                parsed.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == backend.imageId &&
                parsed.getValue("State").jsonObject.getValue("Running").jsonPrimitive.content == "true" &&
                labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == expectedFingerprint &&
                mounts.single { it.getValue("Destination").jsonPrimitive.content == "/state" }
                    .getValue("Name").jsonPrimitive.content == "p0v3-live-${spec.name}-volume-seafile-state") {
                "Native Seafile backend image/CID/fingerprint/state volume drift; preserve original"
            }
            return cid
        }
        val before = nativeId()
        val collectorBytes = native.readonly(container, operationKey).toByteArray(Charsets.UTF_8)
        require(collectorBytes.size in 32..4096)
        val result = Json.parseToJsonElement(collectorBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(result.keys == setOf("schemaVersion", "completedCount", "operationKey", "state", "replayAdmission") &&
            result.getValue("schemaVersion").jsonPrimitive.content == "1" &&
            result.getValue("operationKey").jsonPrimitive.content == operationKey)
        val done = result.getValue("completedCount").jsonPrimitive.content.toIntOrNull()
        val state = result.getValue("state").let { if (it.toString() == "null") null else it.jsonPrimitive.content }
        val admission = result.getValue("replayAdmission").jsonPrimitive.content
        require(done != null && done in 2..100000 && state in setOf(null, "pending", "done") &&
            admission == (if (state == null) "new-only" else "deny")) {
            "Office native callback ledger/admission does not establish source two-editor replay fence"
        }
        require(nativeId() == before) { "Native Seafile backend swapped during read-only callback query" }
        return OfficeCallbackNativeReadback(1, generation, spec.name, expectedFingerprint, before,
            backend.imageId, "p0v3-live-${spec.name}-volume-seafile-state", operationKey,
            done, state, admission, sha(collectorBytes))
    }
}
