package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class ForgejoCiAccountAdoptionGrant(val schemaVersion: Int = 1,
    val account: String, val uid: Int, val gid: Int, val identitySha256: String,
    val authorizesLingerOnly: Boolean)
@Serializable internal data class ForgejoCiAccountEffect(val schemaVersion: Int = 1,
    val account: String, val uid: Int = 784, val gid: Int = 784,
    val action: String, val priorResultSha256: String? = null)
@Serializable internal data class ForgejoCiAccountEffectResult(val intentSha256: String,
    val observedSha256: String)

/** One global account identity shared by generations; never recreate a
 * pre-existing UID, group, subordinate range, home or linger without the
 * original owner ACK. No engine socket is transferred to the job.
 */
internal object ForgejoCiNativeAccountOwner {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val root = Path.of("/mnt/media/p0-v3/rootless-ci-account-owner")
    private const val name = "webservices-lab-ci-runner"
    private const val home = "/home/webservices-lab-ci-runner"
    private const val subordinateStart = 2949120L
    private const val subordinateEnd = 3014655L
    private val actions = listOf("group", "user", "home", "subuid", "subgid", "linger")
    private fun lines(path: String): List<String> = Files.readAllLines(Path.of(path)).filter { it.isNotBlank() }
    private fun account(): String {
        val pwd = lines("/etc/passwd").singleOrNull { it.substringBefore(':') == name }
            ?: error("Dedicated CI account is absent")
        require(pwd.split(':').let { it.size == 7 && it[2] == "784" && it[3] == "784" &&
            it[5] == home && it[6] == "/usr/sbin/nologin" })
        require(lines("/etc/passwd").count { it.split(':').getOrNull(2) == "784" } == 1)
        val group = lines("/etc/group").singleOrNull { it.substringBefore(':') == name }
        require(group?.split(':')?.getOrNull(2) == "784" &&
            lines("/etc/group").count { it.split(':').getOrNull(2) == "784" } == 1)
        require(Files.isDirectory(Path.of(home), NOFOLLOW_LINKS) &&
            (Files.getAttribute(Path.of(home), "unix:uid", NOFOLLOW_LINKS) as Number).toInt() == 784 &&
            (Files.getAttribute(Path.of(home), "unix:gid", NOFOLLOW_LINKS) as Number).toInt() == 784 &&
            Files.getPosixFilePermissions(Path.of(home)) ==
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        for (file in listOf("/etc/subuid", "/etc/subgid")) {
            require(lines(file).count { it == "$name:$subordinateStart:65536" } == 1)
            require(lines(file).filterNot { it.startsWith("$name:") }.none { line ->
                val fields = line.split(':')
                if (fields.size != 3) true else {
                    val first = fields[1].toLongOrNull()
                    val size = fields[2].toLongOrNull()
                    first == null || size == null || size <= 0 ||
                        first <= subordinateEnd && Math.addExact(first, size - 1) >= subordinateStart
                }
            }) { "Dedicated rootless subordinate UID/GID range overlaps" }
        }
        return ReleaseLocks.sha256((pwd + "\n" + group + "\n" +
            lines("/etc/subuid").single { it.startsWith("$name:") } + "\n" +
            lines("/etc/subgid").single { it.startsWith("$name:") }).toByteArray())
    }
    private fun sudo(vararg command: String): String {
        val child = ProcessBuilder(listOf("/usr/bin/sudo", "-n", "--") + command.toList())
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        try {
            require(child.waitFor(45, TimeUnit.SECONDS) && child.exitValue() == 0) {
                "Dedicated account native effect uncertain; preserve original intent"
            }
            val output = child.inputStream.readNBytes(4097)
            require(output.size <= 4096)
            return output.decodeToString(throwOnInvalidSequence = true)
        } finally { if (child.isAlive) child.destroyForcibly() }
    }
    private fun effect(action: String, previous: String?, native: () -> Unit, check: () -> String): String {
        val intent = ForgejoCiAccountEffect(account = name, action = action, priorResultSha256 = previous)
        val bytes = json.encodeToString(intent).toByteArray()
        val i = root.resolve("$action.intent.json"); val r = root.resolve("$action.result.json")
        require(!Files.exists(i, NOFOLLOW_LINKS) && !Files.exists(r, NOFOLLOW_LINKS)) {
            "Dedicated account owner has prior or uncertain $action effect"
        }
        ReleasePrivateFiles.save(i, bytes)
        native()
        val observed = check()
        require(observed.isNotBlank())
        val result = ForgejoCiAccountEffectResult(ReleaseLocks.sha256(bytes),
            ReleaseLocks.sha256(observed.toByteArray()))
        ReleasePrivateFiles.save(r, json.encodeToString(result).toByteArray())
        return ReleaseLocks.sha256(ReleasePrivateFiles.read(r, 8192))
    }
    /** Read-only admission before the first whole-stack member starts. A
     * pre-existing UID needs an explicit adoption grant, never an invented
     * original provisioning result. No linger or account is changed here. */
    fun preflight() {
        if (Files.exists(root, NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("linger.result.json"), NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(root)
            require((actions + "adopt").none { Files.exists(root.resolve("$it.intent.json"), NOFOLLOW_LINKS) ||
                Files.exists(root.resolve("$it.result.json"), NOFOLLOW_LINKS) }) {
                "Uncertain global CI account effect needs original-owner reconciliation before full cohort"
            }
        }
        if (Files.exists(root.resolve("linger.result.json"), NOFOLLOW_LINKS)) {
            attest()
            return
        }
        if (lines("/etc/passwd").any { it.substringBefore(':') == name }) {
            val identity = account()
            val bytes = ReleasePrivateFiles.read(Path.of(
                "/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/account-adoption.json"), 8192)
            val grant = json.decodeFromString<ForgejoCiAccountAdoptionGrant>(bytes.decodeToString())
            require(grant.schemaVersion == 1 && grant.account == name && grant.uid == 784 && grant.gid == 784 &&
                grant.identitySha256 == identity && grant.authorizesLingerOnly)
        } else {
            require(lines("/etc/passwd").none { it.split(':').getOrNull(2) == "784" } &&
                lines("/etc/group").none { it.substringBefore(':') == name || it.split(':').getOrNull(2) == "784" })
        }
    }
    fun provision(): String {
        require(root.parent.toRealPath() == root.parent &&
            (Files.getAttribute(root.parent, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() ==
                com.sun.security.auth.module.UnixSystem().uid &&
            Files.getPosixFilePermissions(root.parent).none { it.name in setOf("GROUP_WRITE", "OTHERS_WRITE") })
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            Files.createDirectory(root, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root.parent)
        }
        ReleasePrivateFiles.directory(root)
        if (Files.exists(root.resolve("linger.result.json"), NOFOLLOW_LINKS)) return attest()
        if (lines("/etc/passwd").any { it.substringBefore(':') == name }) {
            require(actions.none { Files.exists(root.resolve("$it.intent.json"), NOFOLLOW_LINKS) } &&
                !Files.exists(root.resolve("adopt.intent.json"), NOFOLLOW_LINKS)) {
                "Existing account adoption or provisioning is uncertain"
            }
            val identity = account()
            val source = ReleasePrivateFiles.read(Path.of(
                "/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/account-adoption.json"), 8192)
            val grant = json.decodeFromString<ForgejoCiAccountAdoptionGrant>(source.decodeToString())
            require(grant.schemaVersion == 1 && grant.account == name && grant.uid == 784 && grant.gid == 784 &&
                grant.identitySha256 == identity && grant.authorizesLingerOnly) {
                "Pre-existing UID 784 cannot be relabelled as a provisioned Platform account"
            }
            ReleasePrivateFiles.save(root.resolve("adopt.intent.json"), ReleaseLocks.sha256(source).toByteArray())
            ReleasePrivateFiles.save(root.resolve("adopt.result.json"), identity.toByteArray())
            effect("linger", ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("adopt.result.json"), 8192)),
                { sudo("/usr/bin/loginctl", "enable-linger", name) }) {
                sudo("/usr/bin/loginctl", "show-user", name, "-p", "Linger").trim().also {
                    require(it == "Linger=yes")
                }
            }
            return attest()
        }
        require(actions.none { Files.exists(root.resolve("$it.intent.json"), NOFOLLOW_LINKS) } &&
            listOf("/etc/subuid", "/etc/subgid").all { file -> lines(file).none { line ->
                val parts = line.split(':')
                val first = parts.getOrNull(1)?.toLongOrNull()
                val count = parts.getOrNull(2)?.toLongOrNull()
                first == null || count == null || count <= 0 ||
                    first <= subordinateEnd && Math.addExact(first, count - 1) >= subordinateStart
            } } &&
            !Files.exists(Path.of(home), NOFOLLOW_LINKS) &&
            lines("/etc/passwd").none { it.substringBefore(':') == name || it.split(':').getOrNull(2) == "784" } &&
            lines("/etc/group").none { it.substringBefore(':') == name || it.split(':').getOrNull(2) == "784" }) {
            "Foreign dedicated account or uncertain original provisioning"
        }
        var prior: String? = null
        prior = effect("group", prior, { sudo("/usr/sbin/groupadd", "--gid", "784", name) }) {
            lines("/etc/group").single { it.substringBefore(':') == name }
        }
        prior = effect("user", prior, { sudo("/usr/sbin/useradd", "--system", "--uid", "784", "--gid", "784",
            "--home-dir", home, "--create-home", "--shell", "/usr/sbin/nologin", name) }) {
            lines("/etc/passwd").single { it.substringBefore(':') == name }
        }
        prior = effect("home", prior, { sudo("/usr/bin/chmod", "0700", home) }) {
            require(Files.getPosixFilePermissions(Path.of(home)) ==
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
            "784:784:0700"
        }
        for ((label, file, option) in listOf(Triple("subuid", "/etc/subuid", "--add-subuids"),
            Triple("subgid", "/etc/subgid", "--add-subgids"))) {
            require(lines(file).none { it.startsWith("$name:") })
            prior = effect(label, prior, { sudo("/usr/sbin/usermod", option,
                "$subordinateStart-$subordinateEnd", name) }) {
                lines(file).single { it.startsWith("$name:") }.also {
                    require(it == "$name:$subordinateStart:65536")
                }
            }
        }
        effect("linger", prior, { sudo("/usr/bin/loginctl", "enable-linger", name) }) {
            sudo("/usr/bin/loginctl", "show-user", name, "-p", "Linger").trim().also {
                require(it == "Linger=yes")
            }
        }
        return attest()
    }
    fun attest(): String {
        ReleasePrivateFiles.directory(root)
        val adopted = Files.exists(root.resolve("adopt.intent.json"), NOFOLLOW_LINKS)
        var prior: String? = if (adopted) {
            val grantBytes = ReleasePrivateFiles.read(Path.of(
                "/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/account-adoption.json"), 8192)
            val grant = json.decodeFromString<ForgejoCiAccountAdoptionGrant>(grantBytes.decodeToString())
            require(grant.schemaVersion == 1 && grant.account == name && grant.uid == 784 && grant.gid == 784 &&
                grant.identitySha256 == account() && grant.authorizesLingerOnly &&
                ReleasePrivateFiles.read(root.resolve("adopt.intent.json"), 8192).decodeToString() ==
                    ReleaseLocks.sha256(grantBytes) &&
                ReleasePrivateFiles.read(root.resolve("adopt.result.json"), 8192).decodeToString() == grant.identitySha256)
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("adopt.result.json"), 8192))
        } else null
        for (action in if (adopted) listOf("linger") else actions) {
            val bytes = ReleasePrivateFiles.read(root.resolve("$action.intent.json"), 8192)
            val intent = json.decodeFromString<ForgejoCiAccountEffect>(bytes.decodeToString())
            val result = json.decodeFromString<ForgejoCiAccountEffectResult>(ReleasePrivateFiles.read(
                root.resolve("$action.result.json"), 8192).decodeToString())
            require(intent.account == name && intent.uid == 784 && intent.gid == 784 &&
                intent.action == action && intent.priorResultSha256 == prior &&
                result.intentSha256 == ReleaseLocks.sha256(bytes))
            prior = ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("$action.result.json"), 8192))
        }
        require(sudo("/usr/bin/loginctl", "show-user", name, "-p", "Linger").trim() == "Linger=yes")
        return account()
    }
}
