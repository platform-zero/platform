package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

/** Firefly-specific recovery: fresh PostgreSQL role/database, externally restored dump/files, no migration/seed replay. */
internal object FireflyRecovery {
    fun spec(source: PrivateDeploymentSpec, inventory: AcquiredInventory, name: String, sourceHash: String): PrivateDeploymentSpec {
        require(source == FireflyRuntime.spec(inventory, source.name)) { "Unsupported financial source recipe" }
        require(name != source.name && sourceHash.matches(Regex("[a-f0-9]{64}")))
        fun checks(process: RuntimeProcess) = process.volumes.joinToString("; ") {
            BusinessRestoreGuards.marker(it.target, sourceHash)
        }
        return source.copy(name = name, processes = source.processes.map { p ->
            when (p.id) {
                "firefly-files-init" -> p.copy(command = listOf("-ec", checks(p)))
                "firefly-migrate" -> p.copy(command = listOf("-ec", checks(p) + "\n" + """
                    test -s /var/www/html/storage/oauth-private.key
                    test -s /var/www/html/storage/oauth-public.key
                    php -r '${'$'}db=new PDO("pgsql:host=postgres;dbname=firefly", "firefly", getenv("DB_PASSWORD")); if((int)${'$'}db->query("SELECT count(*) FROM users")->fetchColumn()<1)exit(1);'
                """.trimIndent()))
                else -> p
            }
        }).also { PrivateDeployment.validate(it) }
    }

    fun prepare(inventory: AcquiredInventory, recovered: Path, name: String, base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val sourcePath = recovered.resolve("source-spec.json")
        val bytes = ReleaseLocks.privateBytes(sourcePath)
        val source = PrivateDeployment.read(sourcePath)
        val target = spec(source, inventory, name, ReleaseLocks.sha256(bytes))
        val inputs = SingleUserRestore.inputNames(source).associateWith {
            ReleaseLocks.privateBytes(recovered.resolve(it)).decodeToString(throwOnInvalidSequence = true)
        }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) {
            inputs.forEach { (file, content) -> require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(content.toByteArray())) {
                "Recovered financial inputs changed; refusing replacement"
            } }
        }
        return RuntimePreparation.prepare(target, base) { inputs }
    }
}
