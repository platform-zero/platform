package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class PlankaVersionTransition(val from: String, val to: String) {
    fun validate() {
        require(from == "2.2.0" && to == "2.2.1") {
            "Unsupported Planka transition; restore the pre-update snapshot into a fresh isolated generation instead of downgrading a database"
        }
    }
}
@Serializable internal data class PlankaMigrationRequest(val schemaVersion: Int = 1, val operation: String,
    val transition: PlankaVersionTransition, val generation: String, val bundleSha256: String,
    val snapshotId: String, val manifest: ActivationInput, val migrationEnvironment: ActivationInput,
    val image: ActivationImagePin, val fenceId: String)
@Serializable internal data class PlankaMigrationResult(val operation: String, val requestSha256: String,
    val passed: Boolean, val migrationRoleRetired: Boolean, val failureType: String? = null)

/** Versioned, forward-only Knex migration. Never invokes db/init.js (which also seeds administrators).
 * The sole supported patch upgrade has identical upstream migration files; latest() still verifies the
 * complete applied migration set. No claim of native compatibility evidence is made by this source recipe.
 */
internal class PlankaMigration(private val root: Path, private val commands: RuntimeCommands,
    private val observe: (PrivateDeploymentSpec, String) -> Unit) {
    companion object {
        internal val SCRIPT = """
            const fs = require('fs');
            if (require('/app/package.json').version !== '2.2.1') throw new Error('Wrong Planka image version');
            const cfg = require('/app/db/knexfile');
            cfg.connection.ssl = {rejectUnauthorized:true, ca:fs.readFileSync('/run/secrets/postgres-ca.pem')};
            const knex = require('/app/node_modules/knex')(cfg);
            (async () => { try {
              const before = await knex.migrate.list();
              if (before[1].length !== 0) throw new Error('Unsupported source schema: 2.2.0 and 2.2.1 have the same migration set');
              await knex.migrate.latest();
              const after = await knex.migrate.list();
              if (after[1].length !== 0) throw new Error('Pending migrations');
            } finally { await knex.destroy(); } })().catch(() => { process.exitCode = 1; });
        """.trimIndent()
        /** Extract ONLY the original retired migration principal's DB URL, never its bootstrap
         * administrator credential or PostgreSQL root env. The source bytes must match the
         * immutable original bundle and the synthesized file is CREATE_NEW under a private intent.
         */
        fun prepareEnvironment(original: GenerationBundle, runtimeBase: Path, destination: Path): ActivationInput {
            require(original.request.store == RuntimeStore.CANONICAL_V2 && original.ownedUpdate == null &&
                original.recoverySourceKopia == null && original.recoverySourceArchiveSha256 == null)
            val owner = original.members.single { pin -> pin.spec.processes.any { it.id == "planka" } }
            val initializer = owner.spec.processes.single { it.id == "planka-init" }
            require(initializer.oneShot && initializer.environmentFile == "planka-bootstrap.env" &&
                owner.spec.processes.single { it.id == "planka" }.environmentFile == "planka.env")
            val source = runtimeBase.resolve(owner.spec.name).resolve("planka-bootstrap.env")
            val bytes = ReleasePrivateFiles.read(source)
            require(ReleaseLocks.sha256(bytes) == owner.inputHashes.getValue("planka-bootstrap.env")) {
                "Original migration principal cannot be replaced or regenerated"
            }
            val env = bytes.decodeToString(throwOnInvalidSequence = true)
            val urls = env.lineSequence().filter { it.startsWith("DATABASE_URL=") }.toList()
            require(urls.size == 1 && urls.single().matches(Regex(
                "DATABASE_URL=postgresql://planka_migrate:[a-f0-9]{64}@postgres:5432/planka\\?sslmode=verify-full")) &&
                env.lineSequence().count { it == "NODE_EXTRA_CA_CERTS=/run/secrets/postgres-ca.pem" } == 1 &&
                env.lineSequence().count { it.startsWith("DEFAULT_ADMIN_PASSWORD=") } == 1)
            val ca = ReleasePrivateFiles.read(runtimeBase.resolve(owner.spec.name).resolve("postgres-ca.pem"))
            require(ReleaseLocks.sha256(ca) == owner.inputHashes.getValue("postgres-ca.pem"))
            val sanitized = urls.single() + "\nNODE_EXTRA_CA_CERTS=/run/secrets/postgres-ca.pem\n"
            ReleasePrivateFiles.save(destination, sanitized.toByteArray())
            return ActivationInput(destination.toString(), ReleaseLocks.sha256(sanitized.toByteArray()))
        }
        fun real(root: Path, store: RuntimeStore) = PlankaMigration(root, PrivateRootfulCommands(120, store = store)) { spec, fence ->
            val runtime = PrivateDeployment.real()
            val observed = runtime.audit(spec, false)
            require(observed.maintenanceId == fence && observed.statuses.all {
                if (it.id == "postgres") it.state == "running" else it.state in setOf("absent", "exited", "completed", "configured", "created")
            }) { "Migration requires an isolated staged database, no application writers" }
        }
        fun requireRollbackSafe(phase: Phase, from: String, to: String) {
            require(phase !in setOf(Phase.ACTIVATION_STARTED, Phase.COMMITTED, Phase.RECOVERY_REQUIRED)) {
                "Possible escaped writes: rollback requires authoritative reconciliation, never stale snapshot replacement"
            }
            require(from == to) { "Binary downgrade is not rollback; import the original verified snapshot into a fresh target" }
        }
    }
    fun migrate(request: PlankaMigrationRequest): PlankaMigrationResult = ReleasePrivateFiles.locked(root) {
        request.transition.validate()
        require(request.schemaVersion == 1 && request.operation.matches(Regex("r-[a-f0-9]{12}")) &&
            request.generation.matches(Regex("q-[a-f0-9]{12}")) && request.bundleSha256.matches(Regex("[a-f0-9]{64}")) &&
            request.snapshotId.matches(Regex("cap-[a-f0-9]{12}")) && java.util.UUID.fromString(request.fenceId).toString() == request.fenceId)
        fun pinned(pin: ActivationInput): ByteArray = ReleasePrivateFiles.read(Path.of(pin.path)).also {
            require(ReleaseLocks.sha256(it) == pin.sha256) { "Migration input changed" }
        }
        val spec = Json.decodeFromString<PrivateDeploymentSpec>(pinned(request.manifest).decodeToString())
        PrivateDeployment.validate(spec)
        require(spec.name.startsWith(request.generation + "-") && spec.store == RuntimeStore.CANONICAL_V2 &&
            spec.processes.none { it.oneShot } && spec.processes.any { it.id == "postgres" } &&
            spec.databaseAccess.any { it.consumer == "planka" && it.provider == "postgres" }) {
            "Only a recovered canonical Planka target with retired initializers may migrate"
        }
        val app = spec.processes.single { it.id == "planka" }
        require(request.image.reference == app.image && request.image.imageId == app.imageId)
        val env = pinned(request.migrationEnvironment).decodeToString()
        require(env.lineSequence().filter { it.isNotEmpty() }.all { it.startsWith("DATABASE_URL=") || it.startsWith("NODE_EXTRA_CA_CERTS=") } &&
            env.lineSequence().count { it.startsWith("DATABASE_URL=postgresql://planka_migrate:") } == 1 &&
            "DEFAULT_ADMIN" !in env && "KNEX_REJECT_UNAUTHORIZED_SSL_CERTIFICATE" !in env)
        val ca = app.files.single { it.target == "/run/secrets/postgres-ca.pem" }
        val network = spec.databaseAccess.single { it.consumer == "planka" }.network
        val pg = "p0v3-live-${spec.name}-postgres"
        val worker = "p0v3-migration-${request.operation}"
        val bytes = Json.encodeToString(request).toByteArray()
        val digest = ReleaseLocks.sha256(bytes)
        // One pending slot per target. Failure and interruption never unlock migration replay.
        require(!java.nio.file.Files.exists(root.resolve("pending.json"))) { "Uncertain or completed migration cannot be replayed" }
        observe(spec, request.fenceId)
        ReleasePrivateFiles.save(root.resolve("pending.json"), bytes)
        fun call(args: List<String>): String {
            val result = commands.run(args)
            check(result.exitCode == 0) { "Planka migration command failed; retained worker and intent require reconciliation" }
            return result.output.trim()
        }
        fun role(sql: String) = call(listOf("exec", pg, "psql", "-X", "-U", "postgres", "-d", "planka", "-v", "ON_ERROR_STOP=1", "-Atc", sql))
        var failure: Exception? = null
        var retired = false
        var interrupted = false
        try {
            role("ALTER ROLE planka_migrate LOGIN;")
            call(listOf("run", "--name", worker, "--pull=never", "--read-only", "--user", "1000:1000",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", "--security-opt=apparmor=p0v3-private-v1",
                "--memory=512m", "--pids-limit=128", "--network", "p0v3-live-${spec.name}-$network",
                "--env-file", request.migrationEnvironment.path, "--volume",
                "${Path.of(request.manifest.path).parent.resolve(spec.name).resolve(ca.file)}:/run/secrets/postgres-ca.pem:ro",
                "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m", "--entrypoint", "/usr/local/bin/node", app.image, "-e", SCRIPT))
        } catch (error: Exception) { failure = error; interrupted = Thread.interrupted() || error is InterruptedException }
        finally {
            interrupted = Thread.interrupted() || interrupted
            try {
                role("ALTER ROLE planka_migrate NOLOGIN;")
                require(role("SELECT rolcanlogin FROM pg_roles WHERE rolname='planka_migrate';") == "f")
                retired = true
            } catch (error: Exception) {
                interrupted = Thread.interrupted() || error is InterruptedException || interrupted
                if (failure == null) failure = error else failure!!.addSuppressed(error)
            }
        }
        // Retain the role-retirement observation before restoring cancellation: otherwise the
        // interrupted thread closes the result channel and hides the original migration failure.
        interrupted = Thread.interrupted() || interrupted
        val result = PlankaMigrationResult(request.operation, digest, failure == null && !interrupted, retired, failure?.javaClass?.name)
        try {
            ReleasePrivateFiles.save(root.resolve("${request.operation}.result.json"), Json.encodeToString(result).toByteArray())
            if (interrupted) throw InterruptedException("Migration interrupted; retain isolation and original attempt").also {
                failure?.let(it::initCause)
            }
            result
        } catch (recording: Exception) {
            interrupted = Thread.interrupted() || recording is InterruptedException || interrupted
            if (interrupted && recording !is InterruptedException)
                throw InterruptedException("Migration interrupted while retaining outcome").also { it.initCause(recording); failure?.let(it::addSuppressed) }
            throw recording
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }
}
