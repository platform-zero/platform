package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.MessageDigest
import java.util.HexFormat

/** Exact offline SearXNG recipe only. Restored corpus is never seeded or migrated. */
internal object SearxngRecovery {
    fun spec(source: PrivateDeploymentSpec, inventory: AcquiredInventory, name: String, sourceHash: String): PrivateDeploymentSpec {
        require(source == SearxngRuntime.spec(inventory, source.name)) { "Unsupported search recovery recipe" }
        require(source.name != name && sourceHash.matches(Regex("[a-f0-9]{64}")))
        val initializer = source.processes.single { it.oneShot }
        val check = initializer.copy(id = "restore-check", command = listOf("-ec",
            "test ! -e /corpus/.restore-in-progress; test ! -L /corpus/.restore-in-progress; " +
                "test ! -L /corpus/.p0v3-restore-complete; test -f /corpus/.p0v3-restore-complete; " +
                "test ! -L /corpus/documents.db; test -f /corpus/documents.db; " +
                "grep -qx '$sourceHash' /corpus/.p0v3-restore-complete; " +
                "exec /usr/local/searxng/.venv/bin/python -c \"import sqlite3; c=sqlite3.connect('file:/corpus/documents.db?mode=ro',uri=True); " +
                "r=c.execute('PRAGMA integrity_check').fetchone(); " +
                "c.execute('SELECT title,url,content FROM documents LIMIT 1').fetchall(); " +
                "raise SystemExit(0 if r==('ok',) else 1)\""),
            files = SingleUserRestore.inputNames(source).sorted().map { RuntimeFile(it, "/run/secrets/source-$it") })
        return source.copy(name = name, processes = listOf(check) + source.processes.filterNot { it.oneShot }.map { p ->
            p.copy(dependencies = p.dependencies.map { if (it == initializer.id) check.id else it })
        }).also { PrivateDeployment.validate(it) }
    }

    fun prepare(inventory: AcquiredInventory, recovered: Path, name: String, base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val sourcePath = recovered.resolve("source-spec.json")
        val bytes = ReleaseLocks.privateBytes(sourcePath)
        val source = PrivateDeployment.read(sourcePath)
        val hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))
        val target = spec(source, inventory, name, hash)
        val inputs = SingleUserRestore.inputNames(source).associateWith {
            ReleaseLocks.privateBytes(recovered.resolve(it)).decodeToString(throwOnInvalidSequence = true)
        }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) inputs.forEach { (file, content) ->
            require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(content.toByteArray())) {
                "Recovered search inputs changed; refusing replacement"
            }
        }
        return RuntimePreparation.prepare(target, base) { inputs }
    }
}
