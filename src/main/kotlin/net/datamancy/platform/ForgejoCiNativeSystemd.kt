package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Exclusive rootless systemd/Quadlet owner. Every native start/stop has its
 * own sealed intent and result. Caller must own the whole generation lock and
 * must not invoke this outside the complete dependency-ordered INSTALL path.
 * No direct Podman *container start* and no fallback after an uncertain unit.
 */
@Serializable internal data class ForgejoCiUnitIntent(val generation: String,
    val bundleSha256: String, val action: String, val unit: String, val sourceSha256: String)
@Serializable internal data class ForgejoCiUnitResult(val intentSha256: String,
    val unit: String, val activeState: String, val mainPid: Long,
    val nativeReadbackSha256: String)
@Serializable internal data class ForgejoCiNativeStartResult(val generation: String,
    val bundleSha256: String, val registrationSha256: String,
    val stages: Map<String, ForgejoCiUnitResult>, val promotable: Boolean = false)

@Serializable internal data class ForgejoCiOriginalCustody(val sourceGeneration: String,
    val sourceBundleSha256: String, val registrationResultSha256: String,
    val nativeStartSha256: String, val stopResultSha256: Map<String, String>,
    val jobStateSha256: Map<String, String>)

internal object ForgejoCiNativeSystemd {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private const val uid = 784
    private fun systemctl(plan: ForgejoCiSourcePlan, vararg args: String): ProcessBuilder = ProcessBuilder(
        listOf("/usr/bin/sudo", "-n", "-u", plan.dedicatedAccount, "--", "/usr/bin/env",
            "XDG_RUNTIME_DIR=/run/user/784", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/784/bus",
            "/usr/bin/systemctl", "--user", "--no-pager") + args.toList())
    private fun account(plan: ForgejoCiSourcePlan, vararg args: String): ProcessBuilder = ProcessBuilder(
        listOf("/usr/bin/sudo", "-n", "-u", plan.dedicatedAccount, "--") + args.toList()).apply {
        environment()["XDG_RUNTIME_DIR"] = "/run/user/784"
        environment()["HOME"] = "/home/webservices-lab-ci-runner"
    }
    private fun run(command: ProcessBuilder, limit: Int = 32768, deadlineSeconds: Long = 120): String {
        val child = command.redirectError(ProcessBuilder.Redirect.DISCARD).start()
        val reader = java.util.concurrent.Executors.newSingleThreadExecutor { task ->
            Thread(task, "p0v3-ci-native-readback").apply { isDaemon = true }
        }
        val output = reader.submit<ByteArray> { child.inputStream.readNBytes(limit + 1) }
        try {
            require(child.waitFor(deadlineSeconds, TimeUnit.SECONDS) && child.exitValue() == 0) {
                "Native rootless CI unit action lacks its original result"
            }
            val bytes = output.get(5, TimeUnit.SECONDS)
            require(bytes.size <= limit) { "Unbounded CI native readback" }
            return bytes.decodeToString(throwOnInvalidSequence = true)
        } finally {
            if (child.isAlive) child.destroyForcibly()
            reader.shutdownNow()
        }
    }
    private fun fields(text: String): Map<String, String> = buildMap {
        for (line in text.lineSequence().filter { it.isNotBlank() }) {
            val (name, value) = line.split('=', limit = 2).also { require(it.size == 2) }
            require(put(name, value) == null) { "Duplicate systemd property" }
        }
    }
    private fun status(plan: ForgejoCiSourcePlan, unit: String): Map<String, String> = fields(run(
        systemctl(plan, "show", "-p", "Id", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState",
            "-p", "MainPID", "-p", "DropInPaths", unit), 8192, 20))
    private fun sourcePath(plan: ForgejoCiSourcePlan, unit: String): Path {
        val name = "p0v3-ci-${plan.generation}"
        val root = Path.of("/home/webservices-lab-ci-runner/.config")
        return if (unit == "$name-guard.service") root.resolve("systemd/user/$unit")
            else root.resolve("containers/systemd/${unit.removeSuffix(".service")}.container")
    }
    private fun unitNames(plan: ForgejoCiSourcePlan): Map<String, String> {
        val name = "p0v3-ci-${plan.generation}"
        return linkedMapOf("internal" to "$name-internal-network.service",
            "egress" to "$name-egress-network.service", "transport" to "$name-transport.service",
            "guard" to "$name-guard.service", "runner" to "$name-runner.service")
    }
    private fun verifyStaged(plan: ForgejoCiSourcePlan, root: Path) {
        val ci = root.resolve("ci")
        val bytes = ReleasePrivateFiles.read(ci.resolve("account-stage.intent.json"), 8192)
        val intended = json.decodeFromString<ForgejoCiAccountStageIntent>(bytes.decodeToString(throwOnInvalidSequence = true))
        val stage = json.decodeFromString<ForgejoCiAccountStageResult>(ReleasePrivateFiles.read(
            ci.resolve("account-stage.result.json"), 8192).decodeToString(throwOnInvalidSequence = true))
        require(stage.intentSha256 == ReleaseLocks.sha256(bytes) && stage.files == intended.files &&
            stage.accountUid == uid && intended.generation == plan.generation)
        val names = unitNames(plan)
        val render = ForgejoCiNativeUnits.render(plan)
        for ((stageName, unit) in names) {
            val source = if (stageName in setOf("internal", "egress"))
                unit.removeSuffix("-network.service") + ".network"
                else if (stageName == "guard") unit else unit.removeSuffix(".service") + ".container"
            val expected = intended.files.getValue("unit-$source")
            require(expected == ReleaseLocks.sha256(render.getValue(source).toByteArray()) &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(ci.resolve("unit-$source"), 131072)) == expected)
            val installed = if (stageName in setOf("internal", "egress"))
                Path.of("/home/webservices-lab-ci-runner/.config/containers/systemd/$source")
                else sourcePath(plan, unit)
            require(run(account(plan, "/usr/bin/sha256sum", installed.toString()), 1024, 15)
                .substringBefore(' ') == expected) { "Installed rootless CI unit differs from sealed source" }
        }
    }
    private fun installed(plan: ForgejoCiSourcePlan, unit: String): Map<String, String> = status(plan, unit).also {
        require(it["Id"] == unit && it["LoadState"] == "loaded" && it["DropInPaths"].isNullOrEmpty()) {
            "Unreviewed generated CI unit or drop-in"
        }
    }
    private fun native(plan: ForgejoCiSourcePlan, stage: String): String {
        val name = "p0v3-ci-${plan.generation}"
        return when (stage) {
            "internal", "egress" -> {
                val network = "$name-$stage"
                val data = run(account(plan, plan.rootlessPodman.path, "network", "inspect", network,
                    "--format", "json"), 32768)
                val parsed = json.parseToJsonElement(data).jsonArray.single().jsonObject
                require(parsed.getValue("name").jsonPrimitive.content == network &&
                    parsed.getValue("internal").jsonPrimitive.content == (stage == "internal").toString() &&
                    parsed.getValue("driver").jsonPrimitive.content == "bridge") {
                    "Actual rootless CI network is not the approved isolated bridge"
                }
                data
            }
            "transport", "runner" -> {
                val data = run(account(plan, plan.rootlessPodman.path, "container", "inspect",
                    "$name-$stage", "--format", "json"), 65536)
                val parsed = json.parseToJsonElement(data).jsonArray.single().jsonObject
                val expected = if (stage == "transport") requireNotNull(plan.transportImage).expectedImageId
                    else requireNotNull(plan.runnerImage).expectedImageId
                val networks = parsed.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject.keys
                require(parsed.getValue("Image").jsonPrimitive.content == expected &&
                    parsed.getValue("State").jsonObject.getValue("Running").jsonPrimitive.content == "true" &&
                    networks == if (stage == "runner") setOf("$name-internal")
                        else setOf("$name-internal", "$name-egress")) {
                    "Rootless CI worker or transport image/network differs from source"
                }
                val host = parsed.getValue("HostConfig").jsonObject
                val capDrop = host.getValue("CapDrop").jsonArray.map { it.jsonPrimitive.content.uppercase() }.toSet()
                val capAdd = host.getValue("CapAdd").jsonArray.map { it.jsonPrimitive.content.uppercase() }.toSet()
                val opts = host.getValue("SecurityOpt").jsonArray.map { it.jsonPrimitive.content.lowercase() }
                require(capDrop == setOf("ALL") &&
                    capAdd == (if (stage == "transport") setOf("NET_BIND_SERVICE") else emptySet()) &&
                    opts.any { it in setOf("no-new-privileges", "no-new-privileges:true") } &&
                    host.getValue("Privileged").jsonPrimitive.content == "false" &&
                    host.getValue("PidsLimit").jsonPrimitive.content.toLong() ==
                        (if (stage == "transport") 64L else 128L) &&
                    host.getValue("Memory").jsonPrimitive.content.toLong() ==
                        (if (stage == "transport") 128L * 1048576 else 256L * 1048576) &&
                    parsed.getValue("Config").jsonObject.getValue("User").jsonPrimitive.content == "0:0") {
                    "Rootless CI systemd source did not install exact container authority"
                }
                if (stage == "transport") {
                    val internal = parsed.getValue("NetworkSettings").jsonObject.getValue("Networks")
                        .jsonObject.getValue("$name-internal").jsonObject
                    require("forgejo.datamancy.net" in internal.getValue("Aliases").jsonArray
                        .map { it.jsonPrimitive.content }) { "No approved internal DNS alias for private CI transport" }
                }
                if (stage == "runner") {
                    val values = parsed.getValue("Config").jsonObject.getValue("Env").jsonArray
                        .map { it.jsonPrimitive.content }
                    val env = values.associate { value ->
                        require('=' in value); value.substringBefore('=') to value.substringAfter('=')
                    }
                    require(env.size == values.size) { "Duplicate effective runner environment" }
                    val trust = "/etc/ssl/certs/p0v3-ci-forgejo-ca.pem"
                    require(env["DOCKER_HOST"] == "unix:///run/p0v3-ci/guard.sock" &&
                        setOf("SSL_CERT_FILE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE")
                            .all { env[it] == trust }) {
                        "Runner has no guarded engine endpoint and pinned private checkout CA"
                    }
                }
                val mounts = parsed.getValue("Mounts").jsonArray
                val allowed = if (stage == "transport") setOf("transport-Caddyfile", "transport-leaf.pem",
                    "transport-leaf-key.pem", "transport-upstream-ca.pem") else setOf(".runner", "runner-config.yaml", "guard.sock", "transport-ca.pem")
                require(mounts.size == allowed.size && mounts.map { it.jsonObject.getValue("Source").jsonPrimitive.content
                    .substringAfterLast('/') }.toSet() == allowed && mounts.all {
                    it.jsonObject.getValue("RW").jsonPrimitive.content == "false"
                }) { "Unexpected CI host mount or writable worker socket" }
                data
            }
            "guard" -> {
                val limits = fields(run(systemctl(plan, "show", "-p", "MemoryMax", "-p", "MemorySwapMax",
                    "-p", "TasksMax", "$name-guard.service"), 2048, 20))
                require(limits["MemoryMax"] == (256L * 1048576L).toString() &&
                    limits["MemorySwapMax"] == (256L * 1048576L).toString() &&
                    limits["TasksMax"] == "128") {
                    "Rootless CI guard lacks effective bounded memory/swap/task policy"
                }
                val socket = "/home/webservices-lab-ci-runner/.local/share/p0v3-ci/${plan.generation}/guard.sock"
                val data = run(account(plan, "/usr/bin/stat", "-Lc", "%u:%a:%i:%F", socket), 1024, 15).trim()
                require(data.matches(Regex("784:600:[1-9][0-9]*:socket"))) { "Missing exact owned guard socket" }
                data
            }
            else -> error("Unknown CI native stage")
        }
    }
    private fun step(plan: ForgejoCiSourcePlan, root: Path, bundleHash: String, stage: String,
        action: String, unit: String, sourceSha256: String, op: () -> String): ForgejoCiUnitResult {
        val ci = root.resolve("ci")
        val intent = ForgejoCiUnitIntent(plan.generation, bundleHash, action, unit, sourceSha256)
        val stem = "$action-$stage"
        require(!Files.exists(ci.resolve("$stem.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(ci.resolve("$stem.result.json"), NOFOLLOW_LINKS)) {
            "Uncertain original CI unit operation cannot be replayed: $stem"
        }
        val bytes = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(ci.resolve("$stem.intent.json"), bytes)
        val result = op()
        val shown = installed(plan, unit)
        require(shown["ActiveState"] == if (action == "start") "active" else "inactive") {
            "CI systemd unit lacks native $action result"
        }
        val main = shown.getValue("MainPID").toLong()
        require(if (action == "start") main > 1 || stage in setOf("internal", "egress")
                else main == 0L) { "CI native unit has an unexpected PID" }
        val evidence = ForgejoCiUnitResult(ReleaseLocks.sha256(bytes), unit,
            shown.getValue("ActiveState"), main, ReleaseLocks.sha256(result.toByteArray()))
        ReleasePrivateFiles.save(ci.resolve("$stem.result.json"), json.encodeToString(evidence).toByteArray())
        return evidence
    }
    fun start(bundle: GenerationBundle, root: Path, recovered: Boolean = false): ForgejoCiNativeStartResult {
        val plan = if (recovered) requireNotNull(bundle.request.recoveredForgejoCiTarget)
            else requireNotNull(bundle.request.forgejoCi)
        plan.validate(bundle.request.id)
        require(bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            root == GenerationRuntime.BASE.resolve(plan.generation) &&
            if (recovered) bundle.request.forgejoCi == null && bundle.recoverySourceKopia != null &&
                ForgejoCiNativeRecovery.authenticatedResult(bundle, root) != null
            else bundle.request.recoveredForgejoCi == null && bundle.recoverySourceKopia == null)
        SiteOwnerships.checkSealed(bundle)
        val hash = ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray())
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)) == hash)
        // Member stages precede CI in the one complete release, not a CI-only
        // cohort. A missing native member ACK cannot be replaced by a CI start.
        for (member in bundle.members) {
            val spec = member.spec
            val stem = if (recovered) "restore-start" else "stage"
            val intent = json.decodeFromString<GenerationIntent>(ReleasePrivateFiles.read(root.resolve(
                "${spec.name}.$stem.intent.json"), 8192).decodeToString(throwOnInvalidSequence = true))
            val result = json.decodeFromString<List<RuntimeStatus>>(ReleasePrivateFiles.read(root.resolve(
                "${spec.name}.$stem.result.json"), 131072).decodeToString(throwOnInvalidSequence = true))
            require(intent.bundleSha256 == hash && intent.action ==
                (if (recovered) "start-imported-member" else "stage-member") &&
                result.size == spec.processes.size && spec.processes.all { process ->
                    result.singleOrNull { it.id == process.id }?.let { status ->
                        if (process.oneShot) status.state in setOf("completed", "exited") && status.exitCode == 0
                        else status.state == "running"
                    } == true
                }) { "Whole dependency-ordered native cohort is not ready for CI" }
        }
        val ci = root.resolve("ci")
        ReleasePrivateFiles.directory(ci)
        require(!Files.exists(ci.resolve("native-start.result.json"), NOFOLLOW_LINKS))
        if (plan.graphOwnedLateUpstream)
            ForgejoCiGraphUpstreamAdoption.adopt(plan,bundle,root,hash,recovered)
        ForgejoCiNativeAccountOwner.provision()
        val liveBus = Path.of("/run/user/784/bus")
        require(Files.exists(liveBus, NOFOLLOW_LINKS) &&
            (Files.getAttribute(liveBus, "unix:uid", NOFOLLOW_LINKS) as Number).toInt() == uid &&
            UnixSystem().uid != uid.toLong()) { "Dedicated rootless systemd manager is not owned and reachable" }
        ForgejoCiNativeAccountStage.stage(plan, root, hash)
        ForgejoCiNativeBinaryStage.stage(plan, root, hash)
        ForgejoCiNativeImages.import(plan, root, hash)
        verifyStaged(plan, root)
        val names = unitNames(plan)
        val source = ForgejoCiNativeUnits.render(plan)
        val reload = ForgejoCiUnitIntent(plan.generation, hash, "daemon-reload", "--user",
            ReleaseLocks.sha256(source.toString().toByteArray()))
        val reloadBytes = json.encodeToString(reload).toByteArray()
        require(!Files.exists(ci.resolve("daemon-reload.intent.json"), NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(ci.resolve("daemon-reload.intent.json"), reloadBytes)
        run(systemctl(plan, "daemon-reload"), 1024, 60)
        names.values.forEach { installed(plan, it) }
        ReleasePrivateFiles.save(ci.resolve("daemon-reload.result.json"),
            ReleaseLocks.sha256(reloadBytes).toByteArray())
        val stages = linkedMapOf<String, ForgejoCiUnitResult>()
        for (stage in listOf("internal", "egress", "transport", "guard")) {
            val unit = names.getValue(stage)
            stages[stage] = step(plan, root, hash, stage, "start", unit,
                ReleaseLocks.sha256(source.toString().toByteArray())) {
                run(systemctl(plan, "start", unit), 8192, 180)
                native(plan, stage)
            }
        }
        val registrationPlan = if (recovered || !plan.freshIssuerBootstrap) plan
            else {
                val owner = ForgejoCiFreshIssuer.credential(bundle, root)
                try { ForgejoCiFreshRepository.initialize(plan, bundle, root, owner) }
                finally { owner.fill(0) }
                ForgejoCiFreshIssuer.issue(plan, bundle, root)
            }
        val registered = ForgejoCiNativeRegistration.register(registrationPlan, root, hash)
        if (recovered) ForgejoCiNativeRecovery.verifyFresh(bundle, root, registered)
        val unit = names.getValue("runner")
        stages["runner"] = step(plan, root, hash, "runner", "start", unit,
            ReleaseLocks.sha256(source.getValue("p0v3-ci-${plan.generation}-runner.container").toByteArray())) {
            run(systemctl(plan, "start", unit), 8192, 180)
            native(plan, "runner")
        }
        val result = ForgejoCiNativeStartResult(plan.generation, hash,
            ReleaseLocks.sha256(json.encodeToString(registered).toByteArray()), stages)
        ReleasePrivateFiles.save(ci.resolve("native-start.result.json"), json.encodeToString(result).toByteArray())
        return result
    }

    /** No cleanup on a missing original CI ACK. A job that merely appears
     * exited cannot replace its original wait/stop receipt. */
    fun stopIfOwned(bundle: GenerationBundle, root: Path): Boolean {
        val plan = bundle.request.forgejoCi ?: bundle.request.recoveredForgejoCiTarget ?: return true
        val ci = root.resolve("ci")
        if (!Files.exists(ci.resolve("start-internal.intent.json"), NOFOLLOW_LINKS)) return true
        val original = json.decodeFromString<ForgejoCiNativeStartResult>(ReleasePrivateFiles.read(
            ci.resolve("native-start.result.json"), 16384).decodeToString(throwOnInvalidSequence = true))
        val hash = ReleaseLocks.sha256(json.encodeToString(bundle).toByteArray())
        val names = unitNames(plan)
        require(original.generation == plan.generation && original.bundleSha256 == hash &&
            original.registrationSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                ci.resolve("registration.result.json"), 8192)) && original.stages.keys == names.keys &&
            original.stages.all { (name, result) ->
                result.unit == names.getValue(name) && result.activeState == "active" &&
                    json.decodeFromString<ForgejoCiUnitResult>(ReleasePrivateFiles.read(
                        ci.resolve("start-$name.result.json"), 8192).decodeToString(throwOnInvalidSequence = true)) == result
            }) { "Uncertain rootless CI start: preserve native fence" }
        // The guard journals terminal waits and stops inside UID 784's private
        // state. Count neither an exited-CID observation nor a new stop ID as
        // an original terminal ACK.
        val state = "/home/webservices-lab-ci-runner/.local/share/p0v3-ci/${plan.generation}/guard-state"
        val audit = """import json,os,sys
p=sys.argv[1]
n=set(os.listdir(p))
if not n: print('empty'); sys.exit(0)
if 'create.intent.json' not in n or 'create.result.json' not in n: sys.exit(11)
a=json.load(open(p+'/create.result.json'))['id']
if 'start.intent.json' in n and 'start.result.json' not in n: sys.exit(12)
if 'wait.intent.json' in n and 'wait.result.json' not in n: sys.exit(17)
if 'stop.intent.json' in n and 'stop.result.json' not in n: sys.exit(18)
if 'start.result.json' in n and not ({'wait.result.json','stop.result.json'} & n): sys.exit(13)
for x in n:
 if x.startswith(('exec-create-','exec-start-')) and x.endswith('.intent.json') and x.replace('.intent.json','.result.json') not in n: sys.exit(19)
for x in ('wait.result.json','stop.result.json'):
 if x in n and json.load(open(p+'/'+x))['id'] != a: sys.exit(14)
print('terminal:'+a)
""".trimIndent()
        val stopJob = """import http.client,json,os,socket,sys
p,guard=sys.argv[1:]
n=set(os.listdir(p))
if not n or 'wait.result.json' in n or 'stop.result.json' in n: sys.exit(0)
if 'create.result.json' not in n or 'start.result.json' not in n or 'stop.intent.json' in n: sys.exit(21)
cid=json.load(open(p+'/create.result.json'))['id']
if not isinstance(cid,str) or len(cid)!=64 or any(c not in '0123456789abcdef' for c in cid): sys.exit(22)
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM); s.settimeout(45); s.connect(guard)
end=bytes([13,10])
s.sendall(end.join([('POST /v1.41/containers/'+cid+'/stop HTTP/1.1').encode(),b'Host: ci-guard',b'Content-Length: 0',b'Connection: close',b'',b'']))
first=b''
while not first.endswith(end) and len(first)<256:
 x=s.recv(1)
 if not x: sys.exit(23)
 first+=x
s.close()
if not (first.startswith(b'HTTP/1.1 204 ') or first.startswith(b'HTTP/1.1 304 ')): sys.exit(24)
if not os.path.isfile(p+'/stop.result.json') or json.load(open(p+'/stop.result.json'))['id']!=cid: sys.exit(25)
""".trimIndent()
        val socket = "/home/webservices-lab-ci-runner/.local/share/p0v3-ci/${plan.generation}/guard.sock"
        run(account(plan, "/usr/bin/python3", "-c", stopJob, state, socket), 1024, 90)
        val terminal = run(account(plan, "/usr/bin/python3", "-c", audit, state), 1024, 15).trim()
        require(terminal == "empty" || terminal.matches(Regex("terminal:[a-f0-9]{64}"))) {
            "CI job terminal custody is incomplete"
        }
        val stopped = linkedMapOf<String, ForgejoCiUnitResult>()
        for (stage in listOf("runner", "guard", "transport", "egress", "internal")) {
            val unit = names.getValue(stage)
            stopped[stage] = step(plan, root, hash, stage, "stop", unit,
                original.stages.getValue(stage).intentSha256) {
                run(systemctl(plan, "stop", unit), 8192, 180)
                // No optimistic capacity release; the original systemd stop
                // result is read back per unit and kept with the stop receipt.
                status(plan, unit).toString()
            }
        }
        require(stopped.size == names.size)
        // This is an inert, non-secret snapshot of ORIGINAL effects. It is
        // captured by Kopia but never imported as a live worker credential.
        val digestSource = """import hashlib,json,os,sys
p=sys.argv[1]
out={}
for n in sorted(os.listdir(p)):
 if not (n.endswith('.intent.json') or n.endswith('.result.json')): sys.exit(15)
 q=p+'/'+n
 if not os.path.isfile(q) or os.path.islink(q) or os.stat(q).st_uid!=784 or os.stat(q).st_size>65536: sys.exit(16)
 with open(q,'rb') as f: out[n]=hashlib.sha256(f.read()).hexdigest()
print(json.dumps(out,sort_keys=True,separators=(',',':')))
""".trimIndent()
        val stateHashes = json.parseToJsonElement(run(account(plan, "/usr/bin/python3", "-c",
            digestSource, state), 32768, 15)).jsonObject.mapValues { it.value.jsonPrimitive.content }
        require(stateHashes.isEmpty() == (terminal == "empty") &&
            stateHashes.values.all { it.matches(Regex("[a-f0-9]{64}")) })
        val custody = ForgejoCiOriginalCustody(plan.generation, hash,
            ReleaseLocks.sha256(ReleasePrivateFiles.read(ci.resolve("registration.result.json"), 8192)),
            ReleaseLocks.sha256(ReleasePrivateFiles.read(ci.resolve("native-start.result.json"), 16384)),
            stopped.mapValues { (stage, _) -> ReleaseLocks.sha256(ReleasePrivateFiles.read(
                ci.resolve("stop-$stage.result.json"), 8192)) }, stateHashes)
        ReleasePrivateFiles.save(ci.resolve("cold-custody.json"), json.encodeToString(custody).toByteArray())
        return true
    }
}
