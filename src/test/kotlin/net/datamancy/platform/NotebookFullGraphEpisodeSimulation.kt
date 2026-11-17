package net.datamancy.platform

import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

/** Injected systemd/native-ACK transport, never a production Podman run.
 * The selected 132-process canonical spec, not a standalone Hub recipe, drives
 * the same parent actuator and two successive container episodes per user.
 */
internal fun runNotebookEpisodeSimulation(spec: PrivateDeploymentSpec) {
    val generation = spec.name.take(14)
    val base = Files.createTempDirectory("p0v3-full-notebook-",
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    val root = Files.createDirectory(base.resolve(generation),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    val runtime = Files.createDirectory(base.resolve("runtime"),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    Files.createDirectory(runtime.resolve(spec.name),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    val json = Json { encodeDefaults=true }
    fun save(path: Path, bytes: ByteArray) = ReleasePrivateFiles.save(path,bytes)
    fun save(path: Path, value: String) = save(path,value.toByteArray())
    fun hash(path: Path) = ReleaseLocks.sha256(ReleasePrivateFiles.read(path,8192))
    val pin = GenerationPin(GenerationMember(spec.name),"a".repeat(64),emptyMap(),"b".repeat(64),spec)
    val bundle = GenerationBundle(GenerationRequest(id=generation,candidateSha256="c".repeat(64),
        members=listOf(pin.member),diskReservationMiB=10240,store=RuntimeStore.CANONICAL_V2),
        listOf(pin),12288)
    val bundleBytes = json.encodeToString(bundle).toByteArray()
    save(root.resolve("bundle.json"),bundleBytes)
    val expected = ReleaseLocks.sha256(bundleBytes)
    val socketKeys = mapOf("alice" to "a".repeat(64),"bob" to "b".repeat(64))
    val settings = """{"notebookGeneration":"$generation","servers":{"alice":{"parentControlKey":"${socketKeys.getValue("alice")}"},"bob":{"parentControlKey":"${socketKeys.getValue("bob")}"}}}"""
    save(runtime.resolve(spec.name).resolve("jupyterhub-hub-settings.json"),settings)
    val originalCids = mapOf("alice" to "1".repeat(64),"bob" to "2".repeat(64))
    for (user in originalCids.keys) {
        val intent = root.resolve("quadlet-launch-${spec.name}-$user.intent.json")
        save(intent,"original-injected-stage-$user")
        save(root.resolve("quadlet-launch-${spec.name}-$user.result.json"),json.encodeToString(
            QuadletLaunchResult(intentSha256=hash(intent),containerId=originalCids.getValue(user),
                imageId=spec.processes.single { it.id == user }.imageId,nativeAcknowledged=true)))
        save(root.resolve("quadlet-member-${spec.name}-$user.result.json"),json.encodeToString(
            QuadletMemberStart(bundleSha256=expected,member=spec.name,process=user,
                installedAuditSha256="e".repeat(64),containerId=originalCids.getValue(user),
                status=RuntimeStatus(user,"running",null))))
    }
    val nextOrdinal = mutableMapOf("alice" to 1,"bob" to 1)
    val running = mutableMapOf<String,String>()
    val present = originalCids.toMutableMap()
    var loseNextStop = false
    val injectedNative = RuntimeCommands { argv ->
        when {
            argv.size == 3 && argv.take(2) == listOf("container","inspect") -> {
                val user = present.entries.singleOrNull { it.value == argv[2] }?.key
                if (user == null) RuntimeCommandResult(1,"") else RuntimeCommandResult(0,
                    """[{"Id":"${argv[2]}","Name":"p0v3-live-${spec.name}-$user","Image":"sha256:${spec.processes.single { it.id == user }.imageId}","Config":{"Labels":{"io.p0v3.private-deployment":"${spec.name}"}},"State":{"Running":false,"Pid":0}}]""")
            }
            argv.size == 3 && argv.take(2) == listOf("container","rm") -> {
                val user = present.entries.singleOrNull { it.value == argv[2] }?.key
                requireNotNull(user); present.remove(user); running.remove(user)
                RuntimeCommandResult(0,argv[2])
            }
            argv == listOf("container","ls","--all","--format","{{.Names}}") ->
                RuntimeCommandResult(0,present.keys.joinToString("\n") { "p0v3-live-${spec.name}-$it" })
            else -> error("Unexpected injected native effect $argv")
        }
    }
    val manager = QuadletUnitManager { action, unit ->
        val user = listOf("alice","bob").single { unit.endsWith("-$it.service") }
        val ordinal = nextOrdinal.getValue(user)
        val suffix = NotebookEpisodePaths.suffix(root,spec.name,user)
        assertEquals(".episode-%04d".format(ordinal),suffix)
        if (action == "start") {
            val path = NotebookEpisodePaths.path(root,"quadlet-launch-${spec.name}-$user.intent",spec.name,user)
            save(path,"injected-generated-quadlet-start-$user-$ordinal")
            val cid = (if (user == "alice") "3" else "4").repeat(63) + ordinal.toString()
            save(NotebookEpisodePaths.path(root,"quadlet-launch-${spec.name}-$user.result",spec.name,user),
                json.encodeToString(QuadletLaunchResult(intentSha256=hash(path),containerId=cid,
                    imageId=spec.processes.single { it.id == user }.imageId,nativeAcknowledged=true)))
            running[user]=cid
            present[user]=cid
        } else {
            if (loseNextStop) { loseNextStop=false; return@QuadletUnitManager }
            val path = NotebookEpisodePaths.path(root,"quadlet-stop-${spec.name}-$user.intent",spec.name,user)
            save(path,"injected-systemd-stop-$user-$ordinal")
            save(NotebookEpisodePaths.path(root,"quadlet-stop-${spec.name}-$user.result",spec.name,user),
                json.encodeToString(QuadletStopResult(intentSha256=hash(path),
                    containerId=running.getValue(user),stopped=true,nativeStopAcknowledged=true)))
        }
    }
    val owner = RuntimeQuadletOwnerStage(root,runtime,base,manager=manager)
    val actor = NotebookParentActuator(bundle,pin,root,expected,owner,manager,runtime,
        injectedNative,generationBase=base,
        originalStop={ user ->
            val path = root.resolve("quadlet-stop-${spec.name}-$user.intent.json")
            save(path,"injected-original-systemd-stop-$user")
            QuadletStopResult(intentSha256=hash(path),containerId=originalCids.getValue(user),
                stopped=true,nativeStopAcknowledged=true).also {
                save(root.resolve("quadlet-stop-${spec.name}-$user.result.json"),json.encodeToString(it))
            }
        },
        delegateEffect={ process,action ->
            val path = NotebookEpisodePaths.path(root,
                "quadlet-delegate-${spec.name}-${process.id}-$action.intent",spec.name,process.id)
            save(path,"injected-owner-held-systemd-delegation-$action-${process.id}-${nextOrdinal.getValue(process.id)}")
        },
        verifyStart={ process ->
            assertTrue(Files.exists(NotebookEpisodePaths.path(root,
                "quadlet-delegate-${spec.name}-${process.id}-start.intent",spec.name,process.id)))
        },
        unitTerminalReadback={ "ActiveState=inactive\nMainPID=0\nControlPID=0\nJob=0\n".toByteArray() },
        readiness={ p,cid -> assertEquals(running[p.id],cid); RuntimeStatus(p.id,"running",null) },
        serving={ p,cid ->
            // The original stage's two CIDs are already running when the actor
            // records its first native serving observation.
            assertEquals(running[p.id] ?: originalCids[p.id],cid)
            "{\"unit\":\"${RuntimeQuadlets.unit(spec,p)}.service\",\"cid\":\"$cid\",\"native\":\"injected\"}"
        })
    val control = NotebookParentControlSocket(root,spec.name,
        ReleaseLocks.sha256(settings.toByteArray()),actor,runtime,base,ownerAuthorized={true})
    fun request(user: String, action: String, intent: String? = null, key: String = socketKeys.getValue(user)): String {
        SocketChannel.open(StandardProtocolFamily.UNIX).use { channel ->
            channel.connect(UnixDomainSocketAddress.of(root.resolve("notebooks/control.sock")))
            val method = if (intent == null) "GET" else "POST"
            val message = "$method /v1/notebooks/$user/$action HTTP/1.1\r\nHost: p0-notebook-parent\r\n" +
                "Authorization: Bearer $key\r\nX-P0-Generation: $generation\r\nX-P0-Notebook-User: $user\r\n" +
                (if (intent == null) "" else "X-P0-Intent: $intent\r\nContent-Length: 0\r\n") + "\r\n"
            channel.write(ByteBuffer.wrap(message.toByteArray()))
            val reply = ByteBuffer.allocate(2048)
            while (channel.read(reply) > 0) {}
            return reply.array().copyOf(reply.position()).decodeToString()
        }
    }
    try {
        assertTrue(NotebookSelectedGraph.selected(root,spec))
        actor.retireOriginals()
        control.start() // Bind before Hub controller starts, but POST waits for whole stage.
        assertContains(request("alice","state"),"stopped")
        assertTrue(request("alice","start","9".repeat(32)).startsWith("HTTP/1.1 503"))
        save(root.resolve("stage.result.json"),json.encodeToString(GenerationOutcome("stage",expected,true)))
        assertTrue(running.isEmpty())
        assertTrue(request("alice","state",key=socketKeys.getValue("bob")).startsWith("HTTP/1.1 503"))
        for (ordinal in 2..3) {
            for (user in listOf("alice","bob")) {
                nextOrdinal[user]=ordinal
                assertTrue(request(user,"start",(if (user == "alice") "a" else "b")
                    .repeat(31)+ordinal.toString()).startsWith("HTTP/1.1 201"))
                assertContains(request(user,"state"),"running")
                assertTrue(request(user,"stop",(if (user == "alice") "c" else "d")
                    .repeat(31)+ordinal.toString()).startsWith("HTTP/1.1 204"))
                assertContains(request(user,"state"),"stopped")
            }
        }
        assertTrue(running.isEmpty())
        assertEquals(3,NotebookLifecycleEpisodes(root,spec.name,"alice",
            RuntimeQuadlets.render(spec).specSha256).completed().size)
        nextOrdinal["alice"]=4
        actor.apply("alice",NotebookParentAction.START,"5".repeat(32))
        loseNextStop=true
        assertFails { actor.apply("alice",NotebookParentAction.STOP,"6".repeat(32)) }
        assertFails { actor.apply("alice",NotebookParentAction.STOP,"7".repeat(32)) }
        assertFails { actor.apply("alice",NotebookParentAction.START,"8".repeat(32)) }
        assertTrue(Files.exists(root.resolve("notebooks/stop-requests/alice/0004.intent.json")))
    } finally {
        control.close()
        Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
    }
}
