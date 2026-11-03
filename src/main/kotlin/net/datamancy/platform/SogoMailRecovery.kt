package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

/** Cold three-volume restore only. Original provisioning commands are never replayed. */
internal object SogoMailRecovery {
    fun spec(source: PrivateDeploymentSpec, inventory: AcquiredInventory, name: String, sourceHash: String): PrivateDeploymentSpec {
        require(source == SogoMailRuntime.spec(inventory, source.name)) { "Unsupported groupware/mail recovery recipe" }
        require(source.name != name && name.startsWith("smrestore-") && sourceHash.matches(Regex("[a-f0-9]{64}")))
        fun marker(root: String) = "test ! -e $root/.restore-in-progress; test ! -L $root/.restore-in-progress; " +
            "test -f $root/.p0v3-restore-complete; test ! -L $root/.p0v3-restore-complete; " +
            "test \"${'$'}(stat -c %s $root/.p0v3-restore-complete)\" = 65; grep -qx '$sourceHash' $root/.p0v3-restore-complete"
        val app = source.processes.single { it.id == "sogod" }
        val home = RuntimeProcess("home-restore-check", app.image, app.imageId, 994, entrypoint = "/bin/sh",
            command = listOf("-ec", marker("/home/sogo") + "; test -d /home/sogo/spool; test ! -L /home/sogo/spool"),
            volumes = listOf(RuntimeMount("home", "/home/sogo")), oneShot = true, apparmorProfile = "p0v3-private-v1")
        val database = "/var/lib/postgresql/data"
        val processes = source.processes.map { p -> when (p.id) {
            "database-init" -> p.copy(entrypoint = "/bin/sh", command = listOf("-ec", marker(database) + "; test ! -e $database/postmaster.pid; test ! -L $database/postmaster.pid; test -f $database/global/pg_control; test ! -L $database/global/pg_control; grep -qx 17 $database/PG_VERSION"))
            "accounts-init" -> p.copy(entrypoint = "/bin/sh", command = listOf("-ec", """
                export PGUSER=sogo PGDATABASE=sogo PGPASSWORD="${'$'}SOGO_PASSWORD"
                result=${'$'}(/usr/lib/postgresql/17/bin/psql -X -At -v ON_ERROR_STOP=1 -c "SELECT (SELECT count(*) FROM users WHERE c_uid IN ('alice','bob','outsider')) = 3 AND NOT (SELECT rolcanlogin FROM pg_roles WHERE rolname='initializer') AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user)")
                test "${'$'}result" = t
            """.trimIndent()))
            "mail-init" -> p.copy(entrypoint = "/bin/sh", command = listOf("-ec", marker("/data") + "; test -f /data/store/CURRENT; test ! -L /data/store/CURRENT; cmp /data/ready /run/secrets/generation"))
            "sogod" -> p.copy(dependencies = p.dependencies + "home-restore-check")
            else -> p
        } } + home
        return source.copy(name = name, processes = processes).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, recovered: Path, name: String, base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val sourcePath = recovered.resolve("source-spec.json")
        val bytes = ReleaseLocks.privateBytes(sourcePath)
        val source = PrivateDeployment.read(sourcePath)
        val target = spec(source, inventory, name, ReleaseLocks.sha256(bytes))
        val inputs = SingleUserRestore.inputNames(source).associateWith { ReleaseLocks.privateBytes(recovered.resolve(it)).decodeToString(throwOnInvalidSequence = true) }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) inputs.forEach { (file, content) ->
            require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(content.toByteArray())) { "Recovered groupware inputs changed; refusing replacement" }
        }
        return RuntimePreparation.prepare(target, base) { inputs }
    }
}
