package net.datamancy.platform

import java.nio.file.Files
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
