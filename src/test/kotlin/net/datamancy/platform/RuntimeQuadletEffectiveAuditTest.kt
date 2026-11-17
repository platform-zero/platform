package net.datamancy.platform

import kotlin.test.*

class RuntimeQuadletEffectiveAuditTest {
    private fun fixture(): Triple<PrivateDeploymentSpec, RuntimeQuadletBundle, RuntimeProcess> {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        return Triple(spec, RuntimeQuadlets.render(spec), spec.processes.single { it.id == "forgejo" })
    }
    internal fun show(spec: PrivateDeploymentSpec, p: RuntimeProcess, start: String): String {
        val unit = RuntimeQuadlets.unit(spec, p)
        val binding = spec.fragmentBinding!!
        fun helper(action: String) = "/usr/bin/setpriv --reuid=${binding.controllerUid} --regid=${binding.controllerGid} --init-groups " +
            "/mnt/media/p0-v3/runtime-supervision/releases/${binding.controllerSha256}/bin/p0-v3-platform runtime $action ${spec.name} ${p.id}"
        fun entry(path: String, args: String, ignored: Boolean = false) = "{ path=$path ; argv[]=$args ; ignore_errors=${if (ignored) "yes" else "no"} ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"
        return mapOf(
            "LoadState" to "loaded", "FragmentPath" to "/run/systemd/generator/$unit.service",
            "SourcePath" to "/etc/containers/systemd/p0-v3/$unit.container",
            "DropInPaths" to "/etc/systemd/system/$unit.service.d/50-p0-lifecycle.conf",
            "Type" to "notify", "Restart" to "no", "User" to "",
            "Delegate" to "yes", "DelegateSubgroup" to "p0v3-supervisor",
            "DelegateControllers" to "cpu cpuset io memory pids",
            "ExecStart" to entry("/usr/bin/setpriv", helper("unit-run")),
            "ExecStartPre" to entry("/usr/bin/setpriv", helper("unit-admit")),
            "ExecStop" to entry("/usr/bin/setpriv", helper("unit-stop")),
            "ExecStopPost" to entry("/usr/bin/setpriv", helper("unit-stop"), ignored = true),
        ).entries.joinToString("\n", postfix = "\n") { "${it.key}=${it.value}" } +
            "ExecStopPost=${entry("/usr/bin/setpriv", helper("unit-guard"))}\n"
    }

    @Test fun `effective unit validator rejects destructive stop and missing dropin`() {
        val (spec, bundle, p) = fixture()
        val unit = RuntimeQuadlets.unit(spec, p)
        // Synthetic systemctl properties test parser policy, NOT installed-unit evidence.
        val start = "/usr/bin/podman --remote=false --module=${spec.store.module} " +
            "--root=${spec.store.graph} --runroot=${spec.store.run} --network-config-dir=${spec.store.network} " +
            "run --name p0v3-live-${spec.name}-${p.id} --replace --rm --pull never --read-only " +
            "--security-opt=no-new-privileges --user ${p.userId}:${p.groupId} --replace=false --rm=false " +
            "--memory=${p.memoryMiB}m --pids-limit=512 ${p.image} web"
        val source = bundle.files.getValue("$unit.container").toByteArray()
        val dropIn = bundle.files.getValue("$unit.service.d/50-p0-lifecycle.conf").toByteArray()
        val effective = show(spec, p, start)
        val command = RuntimeQuadletGeneratedStart.parse(spec, p, start)
        val digest = RuntimeQuadletEffectiveAudit.audit(spec, bundle, p, source, dropIn, effective, command)
        assertTrue(digest.matches(Regex("[a-f0-9]{64}")))
        val observedDuringStart = effective.replace("start_time=[n/a]", "start_time=[Tue 2026-11-10 18:20:00 UTC]")
            .replace("pid=0 ; code=(null) ; status=0/0", "pid=321 ; code=exited ; status=0")
        val observedAfterStop = observedDuringStart.replace("stop_time=[n/a]", "stop_time=[Tue 2026-11-10 18:21:00 UTC]")
            .replace("pid=321 ; code=exited ; status=0", "pid=812 ; code=exited ; status=1")
        assertEquals(digest, RuntimeQuadletEffectiveAudit.audit(spec, bundle, p, source, dropIn, observedDuringStart, command))
        assertEquals(digest, RuntimeQuadletEffectiveAudit.audit(spec, bundle, p, source, dropIn, observedAfterStop, command))
        val posts = effective.lineSequence().filter { it.startsWith("ExecStopPost=") }.toList()
        assertEquals(2, posts.size)
        for (changed in listOf(
            effective.replace("ExecStopPost={ path=/usr/bin/setpriv", "ExecStopPost={ path=/usr/bin/podman"),
            effective.replace(posts.joinToString("\n"), posts.reversed().joinToString("\n")),
            effective.replace(posts[1] + "\n", ""),
            effective.replace("ExecStopPost=${posts[0].substringAfter('=')}",
                "ExecStopPost=${posts[0].substringAfter('=').replace("ignore_errors=yes", "ignore_errors=no")}"),
            observedDuringStart.replace("code=exited ; status=0", "code=(exited) ; status=0/EXTERNAL"),
            effective.replace("runtime unit-run ${spec.name} ${p.id} ;", "runtime unit-run ${spec.name} ${p.id} --rm=true ;"),
            effective.replace("Restart=no", "Restart=always"),
            effective.replace("Delegate=yes", "Delegate=no"),
            effective.replace("DelegateSubgroup=p0v3-supervisor", "DelegateSubgroup="),
            effective.replace("DelegateControllers=cpu cpuset io memory pids", "DelegateControllers=cpu io"),
            effective.replace("/etc/systemd/system/$unit.service.d/50-p0-lifecycle.conf", "/tmp/foreign.conf"),
            effective.replace("ExecStartPre={ path=/usr/bin/setpriv", "ExecStartPre={ path=/bin/sh"),
            effective.replace("runtime unit-admit ${spec.name} ${p.id} ;", "runtime unit-admit ${spec.name} ${p.id} --override ;"),
            effective.replace("runtime unit-stop ${spec.name} ${p.id} ;", "runtime unit-stop ${spec.name} ${p.id} ; /bin/sh ;"),
            effective.replace("SourcePath=/etc/containers/systemd/p0-v3/", "SourcePath=/etc/containers/systemd/foreign/"),
            effective + "ExecStop=duplicate\n",
        )) assertFails { RuntimeQuadletEffectiveAudit.audit(spec, bundle, p, source, dropIn, changed, command) }
        assertFails { RuntimeQuadletEffectiveAudit.audit(spec, bundle, p, source, byteArrayOf(0), effective, command) }
        assertFails { RuntimeQuadletEffectiveAudit.audit(spec, bundle, p, source, dropIn, effective,
            RuntimeQuadletGeneratedStart.parse(spec, p, start.replace("--rm=false", "--rm=true"))) }
    }
}
