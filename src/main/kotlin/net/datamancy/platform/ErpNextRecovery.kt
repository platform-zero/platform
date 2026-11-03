package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

/** Cold ERP restore preparation only. Never installs a site, runs migrations or recreates accounts. */
internal object ErpNextRecovery {
    fun spec(source: PrivateDeploymentSpec, inventory: AcquiredInventory, name: String, sourceHash: String): PrivateDeploymentSpec {
        require(source == ErpNextRuntime.spec(inventory, source.name).copy(store = source.store)) {
            "Unsupported ERP recovery recipe"
        }
        require(name != source.name && name.startsWith("erprestore-") && sourceHash.matches(Regex("[a-f0-9]{64}")))
        fun guard(root: String) = BusinessRestoreGuards.marker(root, sourceHash)
        val processes = source.processes.map { p -> when (p.id) {
            "mariadb-init" -> p.copy(environmentFile = null, command = listOf("-ec",
                guard("/var/lib/mysql") + "; test -d /var/lib/mysql/mysql; test ! -L /var/lib/mysql/mysql; " +
                    "test -d /var/lib/mysql/p0_erp; test ! -L /var/lib/mysql/p0_erp; " +
                    "test -f /var/lib/mysql/ibdata1; test ! -L /var/lib/mysql/ibdata1"))
            "mariadb" -> p.copy(environmentFile = null, readiness = listOf("/bin/sh", "-ec",
                "mariadb-admin --no-defaults --socket=/tmp/mysql.sock ping >/dev/null 2>&1"))
            "cache", "queue" -> p.copy(entrypoint = "/bin/sh", command = listOf("-ec",
                guard("/data") + "; exec /usr/local/bin/valkey-server /run/secrets/${p.id}.conf"))
            "site-config-init" -> p.copy(command = listOf("/run/secrets/erp-restore-check.py", sourceHash),
                volumes = listOf(RuntimeMount("sites", "/site-state"), RuntimeMount("config", "/bench-config"), RuntimeMount("logs", "/bench-logs")),
                files = listOf(RuntimeFile("erp-restore-check.py", "/run/secrets/erp-restore-check.py")))
            "site-init" -> p.copy(environmentFile = "erp.env", files = emptyList(), command = listOf("-c", """
                import json, pymysql
                from pathlib import Path
                config = json.loads(Path('/home/frappe/frappe-bench/sites/${ErpNextRuntime.SITE}/site_config.json').read_text())
                connection = pymysql.connect(host='mariadb', port=3306, user=config.get('db_user', config['db_name']), password=config['db_password'], database=config['db_name'], connect_timeout=10, read_timeout=10, write_timeout=10)
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT COUNT(*) FROM tabUser WHERE name='Administrator' AND enabled=1")
                        if cursor.fetchone()[0] != 1:
                            raise RuntimeError('Recovered ERP administrator missing or disabled')
                        cursor.execute("SELECT COUNT(*) FROM tabDocType WHERE name IN ('Quotation','Sales Invoice','GL Entry')")
                        if cursor.fetchone()[0] != 3:
                            raise RuntimeError('Recovered ERP schema incomplete')
                finally:
                    connection.close()
            """.trimIndent()))
            "installer-retire" -> source.processes.single { it.id == "site-init" }.copy(
                id = "installer-retire", dependencies = listOf("site-init"), environmentFile = "installer.env", files = emptyList(),
                command = listOf("-c", """
                import json, os, pymysql
                from pathlib import Path
                config = json.loads(Path('/home/frappe/frappe-bench/sites/${ErpNextRuntime.SITE}/site_config.json').read_text())
                connection = pymysql.connect(host='mariadb', port=3306, user=config.get('db_user', config['db_name']), password=config['db_password'], database=config['db_name'], connect_timeout=10, read_timeout=10, write_timeout=10)
                try:
                    with connection.cursor() as cursor:
                        cursor.execute('SHOW GRANTS FOR CURRENT_USER')
                        grants = [row[0] for row in cursor.fetchall()]
                        if not grants or any('GRANT OPTION' in grant.upper() or (' ON *.* ' in grant.upper() and not grant.upper().startswith('GRANT USAGE ON *.* ')) for grant in grants):
                            raise RuntimeError('Recovered ERP database role is privileged')
                finally:
                    connection.close()
                try:
                    installer = pymysql.connect(host='mariadb', port=3306, user='frappe_installer', password=os.environ['INSTALLER_PASSWORD'], connect_timeout=10, read_timeout=10, write_timeout=10)
                except pymysql.err.OperationalError as error:
                    if error.args[0] != 1045:
                        raise
                else:
                    installer.close()
                    raise RuntimeError('Recovered ERP installer still authenticates')
            """.trimIndent()))
            else -> p
        } }
        return source.copy(name = name, processes = processes).also { PrivateDeployment.validate(it) }
    }

    fun prepare(inventory: AcquiredInventory, recovered: Path, name: String, base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val sourcePath = recovered.resolve("source-spec.json")
        val sourceBytes = ReleaseLocks.privateBytes(sourcePath)
        val source = PrivateDeployment.read(sourcePath)
        val target = spec(source, inventory, name, ReleaseLocks.sha256(sourceBytes))
        val required = PrivateDeployment.inputNames(target).toSet()
        val inputs = required.associateWith { file ->
            if (file == "erp-restore-check.py") ErpNextRecovery::class.java.getResource("/runtime/erp-restore-check.py")!!.readText()
            else ReleaseLocks.privateBytes(recovered.resolve(file)).decodeToString(throwOnInvalidSequence = true)
        }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) inputs.forEach { (file, content) ->
            require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(content.toByteArray())) {
                "Recovered ERP inputs changed; refusing replacement"
            }
        }
        return RuntimePreparation.prepare(target, base) { inputs }
    }
}
