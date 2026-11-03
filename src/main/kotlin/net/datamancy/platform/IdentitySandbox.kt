package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** Fake, explicit Keycloak + disposable PostgreSQL only. No production SSO policy or existing PostgreSQL store. */
internal class IdentitySandbox(private val base: Path, private val backups: Path, private val commands: (Path) -> ProbeCommands,
    private val settle: () -> Unit = { Thread.sleep(2000) }) {
    companion object {
        const val KEYCLOAK = "quay.io/keycloak/keycloak@sha256:3e1ac632e743660017b1e6bb4c3ffc800fd02c82cdd0db858cd03456a98a8dfc"
        const val POSTGRES = PostgresSandbox.IMAGE
        const val REALM = "p0v3-sandbox"
        const val CLIENT = "p0v3-test-cli"
        const val HUMAN_SUB = "11111111-1111-4111-8111-111111111111"
        const val AGENT_SUB = "22222222-2222-4222-8222-222222222222"
        fun real() = IdentitySandbox(ProbeLifecycle.PRODUCTION_BASE, Path.of("/mnt/media/p0-v3/backup"),
            { root -> RootlessPodman(root, root.resolve("network-config")) })
    }
    private val dirPerms = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE)
    private val filePerms = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
    private val marker = "identity-fixture\n$KEYCLOAK\n$POSTGRES\n"
    private val root get() = base.resolve("identity-fixture")
    private val archive get() = backups.resolve("identity-fixture")
    private val pg = "p0v3-identity-pg"
    private val kc = "p0v3-identity-kc"
    private val network = "p0v3-identity-net"
    private val files = listOf("realm.json", "keycloak.env", "pg-password", "backup.dump")

    private fun checkParent(path: Path, expected: Path) {
        require(path == expected || path.toRealPath().startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath())) { "Outside private v3 sandbox" }
        require(path.parent.toRealPath() == Path.of("/mnt/media/p0-v3") ||
            (path != expected && path.parent.toRealPath().startsWith(Path.of(System.getProperty("java.io.tmpdir")).toRealPath()))) { "Unsafe parent" }
        require(Files.isDirectory(path, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(path) == dirPerms &&
            Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) == com.sun.security.auth.module.UnixSystem().uid.toInt()) { "Unowned sandbox root" }
    }
    private fun owned(path: Path, allowed: (String) -> Boolean) {
        val owner = path.resolve(".identity-owner")
        require(Files.isDirectory(path, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(path) == dirPerms &&
            Files.isRegularFile(owner, NOFOLLOW_LINKS) && Files.readString(owner) == marker) { "Unowned identity scope" }
        Files.list(path).use { entries -> require(entries.allMatch { allowed(it.fileName.toString()) }) { "Unexpected identity entry" } }
    }
    private fun createDir(path: Path) { Files.createDirectory(path); Files.setPosixFilePermissions(path, dirPerms) }
    private fun privateFile(path: Path, text: String) {
        Files.writeString(path, text, CREATE_NEW)
        Files.setPosixFilePermissions(path, filePerms)
    }
    private fun random(): String = ByteArray(24).also(SecureRandom()::nextBytes).let { bytes ->
        try { bytes.joinToString("") { "%02x".format(it) } } finally { bytes.fill(0) }
    }
    private fun realm(human: String, agent: String): String {
        fun user(id: String, name: String, secret: String) = buildJsonObject {
            put("id", id); put("username", name); put("enabled", true)
            put("firstName", "Sandbox"); put("lastName", if (id == HUMAN_SUB) "Human" else "Agent")
            put("email", "$name@example.invalid"); put("emailVerified", true)
            put("credentials", buildJsonArray { add(buildJsonObject {
                put("type", "password"); put("value", secret); put("temporary", false)
            }) })
        }
        return buildJsonObject {
            put("realm", REALM); put("enabled", true)
            put("clients", buildJsonArray { add(buildJsonObject {
                put("clientId", CLIENT); put("protocol", "openid-connect"); put("enabled", true)
                put("publicClient", true); put("directAccessGrantsEnabled", true); put("standardFlowEnabled", false)
                put("fullScopeAllowed", false)
            }) })
            put("users", buildJsonArray { add(user(HUMAN_SUB, "sandbox-human", human)); add(user(AGENT_SUB, "sandbox-agent", agent)) })
        }.toString()
    }

    fun prepare() {
        checkParent(base, ProbeLifecycle.PRODUCTION_BASE)
        checkParent(backups, Path.of("/mnt/media/p0-v3/backup"))
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            createDir(root)
            privateFile(root.resolve(".identity-owner"), marker)
            createDir(root.resolve("secrets")); createDir(root.resolve("data")); createDir(root.resolve("restores"))
            createDir(root.resolve("network-config"))
            privateFile(root.resolve("containers.conf"), "[network]\ndefault_rootless_network_cmd = \"slirp4netns\"\n")
            val db = random(); val admin = random(); val human = random(); val agent = random()
            privateFile(root.resolve("secrets/pg-password"), db)
            privateFile(root.resolve("secrets/keycloak.env"), "KC_DB=postgres\nKC_DB_URL=jdbc:postgresql://p0v3-identity-db:5432/keycloak\nKC_DB_USERNAME=postgres\nKC_DB_PASSWORD=$db\nKC_BOOTSTRAP_ADMIN_USERNAME=sandbox-admin\nKC_BOOTSTRAP_ADMIN_PASSWORD=$admin\n")
            privateFile(root.resolve("secrets/realm.json"), realm(human, agent))
        }
        if (!Files.exists(archive, NOFOLLOW_LINKS)) { createDir(archive); privateFile(archive.resolve(".identity-owner"), marker) }
        guard()
    }
    private fun guard(): Path {
        checkParent(base, ProbeLifecycle.PRODUCTION_BASE)
        checkParent(backups, Path.of("/mnt/media/p0-v3/backup"))
        owned(root) { it in setOf(".identity-owner", "secrets", "data", "restores", "network-config", "containers.conf", "podman-root", "podman-run") }
        owned(archive) { it == ".identity-owner" || Regex("[a-z][a-z0-9-]{0,23}").matches(it) || it.startsWith(".pending-") }
        val networkConfig = root.resolve("network-config")
        val config = root.resolve("containers.conf")
        require(Files.isRegularFile(config, NOFOLLOW_LINKS) &&
            Files.readString(config) == "[network]\ndefault_rootless_network_cmd = \"slirp4netns\"\n" &&
            Files.getPosixFilePermissions(config) == filePerms) { "Invalid private Podman network helper configuration" }
        require(Files.isDirectory(networkConfig, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(networkConfig) == dirPerms &&
            Files.getAttribute(networkConfig, "unix:uid", NOFOLLOW_LINKS) == com.sun.security.auth.module.UnixSystem().uid.toInt()) {
            "Missing private network config directory"
        }
        Files.list(networkConfig).use { entries -> require(entries.allMatch {
            (Regex("p0v3-identity-net(?:-[a-z][a-z0-9-]{0,23})?\\.json").matches(it.fileName.toString()) ||
                it.fileName.toString() == "netavark.lock") &&
                Files.isRegularFile(it, NOFOLLOW_LINKS) && Files.size(it) <= 65536
        }) { "Unexpected private network definition" } }
        require(listOf("secrets", "data", "restores").all { Files.isDirectory(root.resolve(it), NOFOLLOW_LINKS) } &&
            listOf("realm.json", "keycloak.env", "pg-password").all {
                val path = root.resolve("secrets/$it")
                Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(path) == filePerms && Files.size(path) in 1..16384
            }) { "Missing or unsafe fake identity input" }
        return root
    }
    private fun cmd(args: List<String>) = commands(guard()).invoke(args)
    private fun present(name: String, running: Boolean = false) =
        cmd(listOf("ps") + (if (running) emptyList() else listOf("-a")) + listOf("--filter", "name=^$name$", "--format", "{{.Names}}")).trim() == name
    private fun awaitDb(name: String) {
        val query = listOf("exec", name, "psql", "-U", "postgres", "-d", "keycloak", "-tA", "-c", "SELECT 1")
        repeat(40) {
            if (runCatching { cmd(query).trim() == "1" }.getOrDefault(false)) {
                settle()
                if (runCatching { cmd(query).trim() == "1" }.getOrDefault(false)) return
            }
            Thread.sleep(500)
        }
        error("Private identity database not ready")
    }
    private fun startDb(name: String, network: String, data: Path, password: Path) {
        require(!present(name)) { "Database container already exists" }
        cmd(listOf("image", "exists", POSTGRES))
        cmd(listOf("create", "--name", name, "--network=$network", "--network-alias=p0v3-identity-db", "--pull=never",
            "--read-only", "--tmpfs=/tmp:rw,mode=1777,size=64m", "--tmpfs=/var/run/postgresql:rw,mode=1777,size=16m",
            "--pids-limit=128", "--memory=512m", "--security-opt=no-new-privileges",
            "--env=POSTGRES_PASSWORD_FILE=/run/secrets/fake-password", "--env=POSTGRES_DB=keycloak",
            "--volume=$password:/run/secrets/fake-password:ro", "--volume=$data:/var/lib/postgresql/data:rw", POSTGRES))
        cmd(listOf("start", name)); require(present(name, true)) { "Private database exited" }
        awaitDb(name)
    }
    private fun startKeycloak(name: String, network: String, port: Int, env: Path, realmFile: Path) {
        require(!present(name)) { "Keycloak container already exists" }
        cmd(listOf("image", "exists", KEYCLOAK))
        cmd(listOf("create", "--name", name, "--network=$network", "--pull=never",
            "--publish=127.0.0.1:$port:8080/tcp", "--user=0", "--pids-limit=256", "--memory=1g",
            "--security-opt=no-new-privileges", "--env-file=$env",
            "--volume=$realmFile:/opt/keycloak/data/import/$REALM-realm.json:ro",
            KEYCLOAK, "start-dev", "--hostname=http://127.0.0.1:$port", "--import-realm"))
        cmd(listOf("start", name)); require(present(name, true)) { "Private Keycloak exited" }
    }
    fun install() {
        guard(); cmd(listOf("network", "create", network))
        startDb(pg, network, root.resolve("data"), root.resolve("secrets/pg-password"))
        startKeycloak(kc, network, 18580, root.resolve("secrets/keycloak.env"), root.resolve("secrets/realm.json"))
    }
    fun stop() {
        require(present(kc) && present(pg)) { "Identity containers absent" }
        cmd(listOf("stop", "--time=20", kc)); cmd(listOf("stop", "--time=10", pg))
    }
    private fun removeTarget(service: String, db: String, net: String) {
        for (name in listOf(service, db)) {
            if (present(name)) {
                if (present(name, true)) cmd(listOf("stop", "--time=20", name))
                cmd(listOf("rm", name))
            }
        }
        if (net in cmd(listOf("network", "ls", "--format", "{{.Name}}")).lines()) cmd(listOf("network", "rm", net))
    }
    fun remove() { removeTarget(kc, pg, network) }
    private fun sha(file: Path) = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)).joinToString("") { "%02x".format(it) }
    private fun id(value: String): String { require(Regex("[a-z][a-z0-9-]{0,23}").matches(value)) { "Invalid identity backup ID" }; return value }
    private fun manifest(dir: Path): String = files.joinToString("") { "${sha(dir.resolve(it))}  $it\n" }
    fun backup(value: String) {
        id(value); guard(); require(present(kc, true) && present(pg, true)) { "Stop-safe backup requires both servers" }
        val target = archive.resolve(value)
        require(!Files.exists(target, NOFOLLOW_LINKS)) { "Identity backup already exists" }
        val pending = Files.createTempDirectory(archive, ".pending-")
        cmd(listOf("stop", "--time=20", kc))
        try {
            cmd(listOf("exec", pg, "pg_dump", "-U", "postgres", "-d", "keycloak", "-Fc",
                "--no-owner", "--no-acl", "--file=/tmp/identity.dump"))
            cmd(listOf("cp", "$pg:/tmp/identity.dump", pending.resolve("backup.dump").toString()))
            Files.setPosixFilePermissions(pending.resolve("backup.dump"), filePerms)
            listOf("realm.json", "keycloak.env", "pg-password").forEach {
                Files.copy(root.resolve("secrets/$it"), pending.resolve(it)); Files.setPosixFilePermissions(pending.resolve(it), filePerms)
            }
            require(Files.size(pending.resolve("backup.dump")) in 1..67108864) { "Invalid identity pg_dump" }
            privateFile(pending.resolve(".sha256"), manifest(pending))
            Files.move(pending, target, ATOMIC_MOVE)
        } finally {
            // Never delete a partial backup here; retain for manual review if anything failed.
            cmd(listOf("start", kc))
        }
    }
    fun restore(value: String) {
        id(value); guard()
        val source = archive.resolve(value)
        require(Files.isDirectory(source, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(source) == dirPerms &&
            Files.getAttribute(source, "unix:uid", NOFOLLOW_LINKS) == com.sun.security.auth.module.UnixSystem().uid.toInt() && files.all {
            Files.isRegularFile(source.resolve(it), NOFOLLOW_LINKS) &&
                Files.getPosixFilePermissions(source.resolve(it)) == filePerms && Files.size(source.resolve(it)) in 1..67108864
        } && Files.isRegularFile(source.resolve(".sha256"), NOFOLLOW_LINKS) &&
            Files.getPosixFilePermissions(source.resolve(".sha256")) == filePerms &&
            Files.size(source.resolve(".sha256")) <= 1024 &&
            Files.readString(source.resolve(".sha256")) == manifest(source)) { "Identity backup hash mismatch" }
        val restored = root.resolve("restores/$value")
        require(!Files.exists(restored, NOFOLLOW_LINKS)) { "Isolated identity target exists" }
        createDir(restored); createDir(restored.resolve("data"))
        val net = "$network-$value"; val db = "$pg-$value"; val service = "$kc-$value"
        cmd(listOf("network", "create", net))
        startDb(db, net, restored.resolve("data"), source.resolve("pg-password"))
        cmd(listOf("cp", source.resolve("backup.dump").toString(), "$db:/tmp/identity.dump"))
        cmd(listOf("exec", db, "pg_restore", "-U", "postgres", "-d", "keycloak", "--exit-on-error",
            "--no-owner", "--no-acl", "/tmp/identity.dump"))
        startKeycloak(service, net, 18581, source.resolve("keycloak.env"), source.resolve("realm.json"))
    }
    fun removeRestore(value: String) {
        id(value); removeTarget("$kc-$value", "$pg-$value", "$network-$value")
    }
    fun fakePassword(user: String): String {
        require(user == "sandbox-human" || user == "sandbox-agent") { "Only fake identities permitted" }
        val json = Json.parseToJsonElement(Files.readString(guard().resolve("secrets/realm.json"))).jsonObject
        val subject = json["users"]!!.jsonArray.first { it.jsonObject["username"]!!.jsonPrimitive.content == user }.jsonObject
        return subject["credentials"]!!.jsonArray.first().jsonObject["value"]!!.jsonPrimitive.content
    }
}
