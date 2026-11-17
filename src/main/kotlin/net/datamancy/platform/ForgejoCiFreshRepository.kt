package net.datamancy.platform

import java.net.URI
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Fresh, repository-scoped issuer dependency. Import an independently pinned
 * offline Git bundle first; create only the requested private org/repository;
 * push over authenticated private IP with TLS/SNI pinning and no DNS fallback.
 * Each remote effect has its own original intent/result. Never recreate an org,
 * a repo, or a Git push after a missing ACK under another operation ID.
 */
internal object ForgejoCiFreshRepository {
    private val json = Json { encodeDefaults = true }
    private fun git(working: Path, vararg args: String, network: Boolean = false,
        environment: Map<String, String> = emptyMap()): ByteArray {
        val command = ProcessBuilder(listOf("/usr/bin/git") + args.toList())
            .directory(working.toFile()).redirectError(ProcessBuilder.Redirect.DISCARD)
        command.environment().apply {
            listOf("GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_TRACE", "GIT_CURL_VERBOSE",
                "GIT_SSL_NO_VERIFY", "GIT_PROXY_COMMAND", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                "http_proxy", "https_proxy", "all_proxy").forEach { remove(it) }
            put("GIT_CONFIG_GLOBAL", "/dev/null"); put("GIT_CONFIG_SYSTEM", "/dev/null")
            put("GIT_TERMINAL_PROMPT", "0"); put("GIT_ALLOW_PROTOCOL", if (network) "https" else "file")
            putAll(environment)
        }
        val child = command.start()
        return try {
            val output = child.inputStream.readNBytes(1048577)
            require(output.size <= 1048576 && child.waitFor(120, TimeUnit.SECONDS) && child.exitValue() == 0) {
                "Offline Git source or original private Git push failed; never replay an uncertain effect"
            }
            output
        } finally { if (child.isAlive) child.destroyForcibly() }
    }
    fun initialize(plan: ForgejoCiSourcePlan, bundle: GenerationBundle, root: Path, owner: ByteArray) {
        require(plan.freshIssuerBootstrap && bundle.request.forgejoCi == plan &&
            root == GenerationRuntime.BASE.resolve(plan.generation))
        val pin = requireNotNull(plan.trustedRepositoryBundle)
        val archive = Path.of(pin.path)
        require(Files.isRegularFile(archive, NOFOLLOW_LINKS) && RecoveryCapsule.fileHash(archive) == pin.sha256)
        val repo = plan.enrollment.repository.split('/')
        require(repo.size == 2 && repo.all { it.matches(Regex("[a-zA-Z0-9_.-]{1,64}")) })
        val ci = root.resolve("ci"); ReleasePrivateFiles.directory(ci)
        val proof = ci.resolve("fresh-repository.result.json")
        require(!Files.exists(ci.resolve("fresh-repository.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(proof, NOFOLLOW_LINKS)) { "Uncertain fresh Forgejo repository operation; no replay" }
        val work = ci.resolve("trusted-repository.git")
        Files.createDirectory(work, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(ci)
        git(work, "init", "--bare", "--quiet")
        git(work, "fetch", "--quiet", "--no-tags", archive.toString(),
            "refs/heads/main:refs/heads/main")
        val commit = git(work, "rev-parse", "refs/heads/main").decodeToString().trim()
        require(commit == plan.enrollment.trustedCommit)
        val paths = git(work, "ls-tree", "-r", "--name-only", commit, ".forgejo/workflows/")
            .decodeToString().lineSequence().filter { it.isNotBlank() }.toList()
        require(paths.size == 1 && paths.single().matches(Regex("\\.forgejo/workflows/[a-z0-9_-]+\\.ya?ml")))
        val workflow = git(work, "show", "$commit:${paths.single()}")
        require(ReleaseLocks.sha256(workflow) == plan.workflow.sha256 &&
            workflow.contentEquals(GenerationRuntime.privateInput(Path.of(plan.workflow.path))))
        ForgejoWorkflowSource.inspect(plan.enrollment, commit, workflow)
        val (endpoint, currentCa) = if (plan.graphOwnedLateUpstream)
            ForgejoCiGraphUpstreamAdoption.current(plan)
        else requireNotNull(plan.privateUpstream) to requireNotNull(plan.upstreamCa)
        val privateIp = URI(endpoint)
        require(privateIp.port == 443 && ForgejoCiTransportSource.validUpstream(privateIp.toString()))
        val claim = buildJsonObject {
            put("generation", plan.generation); put("bundleSha256", ReleaseLocks.sha256(
                ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)))
            put("sourcePlanSha256", ReleaseLocks.sha256(json.encodeToString(plan).toByteArray()))
            put("repositoryBundleSha256", pin.sha256); put("commit", commit)
            put("workflowSha256", plan.workflow.sha256)
        }
        ReleasePrivateFiles.save(ci.resolve("fresh-repository.intent.json"), claim.toString().toByteArray())
        val orgBody = buildJsonObject { put("username", repo[0]); put("visibility", "private") }.toString().toByteArray()
        val org = ForgejoCiPrivateApi.freshCreate(plan, owner, "/api/v1/orgs", orgBody)
        require(org.status == 201 && org.body.size in 1..65536)
        val orgJson = json.parseToJsonElement(org.body.decodeToString()).jsonObject
        require(orgJson.getValue("username").jsonPrimitive.content == repo[0])
        ReleasePrivateFiles.save(ci.resolve("fresh-org.result.json"), ReleaseLocks.sha256(org.body).toByteArray())
        val body = buildJsonObject { put("name", repo[1]); put("private", true); put("auto_init", false) }
            .toString().toByteArray()
        ReleasePrivateFiles.save(ci.resolve("fresh-repo.intent.json"), ReleaseLocks.sha256(body).toByteArray())
        val created = ForgejoCiPrivateApi.freshCreate(plan, owner,
            "/api/v1/orgs/${repo[0]}/repos", body)
        require(created.status == 201 && created.body.size in 1..65536)
        val entity = json.parseToJsonElement(created.body.decodeToString()).jsonObject
        require(entity.getValue("full_name").jsonPrimitive.content == plan.enrollment.repository &&
            entity.getValue("private").jsonPrimitive.boolean)
        ReleasePrivateFiles.save(ci.resolve("fresh-repo.result.json"), ReleaseLocks.sha256(created.body).toByteArray())
        val ca = currentCa
        val secret = ci.resolve("fresh-repository-admin.password")
        ReleasePrivateFiles.save(secret, owner)
        val askpass = ci.resolve("fresh-repository-askpass")
        val helper = """#!/bin/sh
case "$1" in
  *sername*) printf '%s\n' 'p0v3-bootstrap' ;;
  *) /usr/bin/python3 -c 'import os,sys; p=sys.argv[1]; f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW); sys.stdout.buffer.write(os.read(f,257)); os.close(f)' '${secret}' ;;
esac
"""
        ReleasePrivateFiles.save(askpass, helper.toByteArray())
        Files.setPosixFilePermissions(askpass, PosixFilePermissions.fromString("rwx------"))
        val env = mapOf("GIT_ASKPASS" to askpass.toString(), "GIT_ASKPASS_REQUIRE" to "force")
        ReleasePrivateFiles.save(ci.resolve("fresh-push.intent.json"), commit.toByteArray())
        try {
            git(work, "-c", "http.curloptResolve=forgejo.datamancy.net:443:${privateIp.host}",
                "-c", "http.sslCAInfo=${ca.path}", "-c", "http.followRedirects=false",
                "-c", "http.proxy=", "-c", "credential.helper=", "push", "--porcelain",
                "https://forgejo.datamancy.net/${repo[0]}/${repo[1]}.git", "refs/heads/main:refs/heads/main",
                network = true, environment = env)
            val readback = ForgejoCiPrivateApi.freshRepository(plan, owner,
                "/api/v1/repos/${plan.enrollment.repository}/git/commits/$commit")
            require(readback.status == 200 && readback.body.size in 1..65536 &&
                json.parseToJsonElement(readback.body.decodeToString()).jsonObject.getValue("sha").jsonPrimitive.content == commit)
            ReleasePrivateFiles.save(ci.resolve("fresh-push.result.json"), commit.toByteArray())
            ReleasePrivateFiles.save(proof, claim.toString().toByteArray())
        } finally {
            Files.deleteIfExists(secret)
            Files.deleteIfExists(askpass)
        }
    }
}
