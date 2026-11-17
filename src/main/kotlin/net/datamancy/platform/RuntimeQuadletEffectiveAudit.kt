package net.datamancy.platform

/** Separate installed-systemd admission boundary. A generator dry run cannot substitute
 * for systemd's final ExecStart/Stop after drop-ins are merged. The installer must feed this
 * the exact root-owned source/drop-in bytes AND `systemctl show` for the installed service.
 * This validator does not install, start, stop or assert a release qualification result.
 */
internal object RuntimeQuadletEffectiveAudit {
    private val keys = setOf("LoadState", "FragmentPath", "SourcePath", "DropInPaths", "Type", "Restart",
        "User", "Delegate", "DelegateSubgroup", "DelegateControllers",
        "ExecStart", "ExecStartPre", "ExecStop", "ExecStopPost")

    fun audit(spec: PrivateDeploymentSpec, bundle: RuntimeQuadletBundle, process: RuntimeProcess,
        source: ByteArray, dropIn: ByteArray, show: String, generated: List<String>? = null): String {
        require(bundle == RuntimeQuadlets.render(spec) && process in spec.processes)
        val unit = RuntimeQuadlets.unit(spec, process)
        require(source.contentEquals(bundle.files.getValue("$unit.container").toByteArray()) &&
            dropIn.contentEquals(bundle.files.getValue("$unit.service.d/50-p0-lifecycle.conf").toByteArray())) {
            "Installed Quadlet source or mandatory drop-in changed"
        }
        require(show.toByteArray().size in 1..65536 && !show.contains('\u0000'))
        val entries = show.lineSequence().filter { it.isNotEmpty() }.map { line ->
            require('=' in line) { "Invalid effective systemd unit" }
            line.substringBefore('=') to line.substringAfter('=')
        }.toList()
        // systemctl show emits one ExecStopPost= line per command, not a single
        // combined value. Accept EXACTLY two in order and no other duplicate key.
        val grouped = entries.groupBy({ it.first }, { it.second })
        require(grouped.keys == keys && grouped.all { (key, list) ->
            list.size == (if (key == "ExecStopPost") 2 else 1)
        }) { "Incomplete effective systemd unit" }
        val values = grouped.mapValues { (key, list) ->
            if (key == "ExecStopPost") list.joinToString(" ") else list.single()
        }
        require(values.getValue("LoadState") == "loaded" && values.getValue("Restart") == "no" &&
            values.getValue("Type") == (if (process.oneShot) "oneshot" else "notify")) {
            "Foreign or unsafe effective systemd unit"
        }
        require(values.getValue("User") in setOf("", "root") &&
            values.getValue("Delegate") == "yes" &&
            values.getValue("DelegateSubgroup") == "p0v3-supervisor" &&
            values.getValue("DelegateControllers").split(' ').toSet().containsAll(setOf("memory", "pids")) &&
            values.getValue("SourcePath") == "/etc/containers/systemd/p0-v3/$unit.container" &&
            values.getValue("FragmentPath") == "/run/systemd/generator/$unit.service" &&
            values.getValue("DropInPaths") == "/etc/systemd/system/$unit.service.d/50-p0-lifecycle.conf") {
            "Installed unit domain, generator source or drop-in differs"
        }
        // The effective start is the gated helper. The original generated Podman argv is
        // checked separately against the root-owned generated fragment AND a fresh pinned
        // 5.4.2 translation of the same exact source by RuntimeQuadletInstalledAudit.
        generated?.let { words ->
            val command = " ${words.joinToString(" ")} "
            require(words.firstOrNull() == "/usr/bin/podman" && words.contains(process.image) &&
                command.contains(" --name p0v3-live-${spec.name}-${process.id} ") &&
                command.contains(" --pull never ") && command.contains(" --root=${spec.store.graph} ") &&
                command.contains(" --runroot=${spec.store.run} ") &&
                command.contains(" --module=${spec.store.module} ") &&
                command.contains(" --network-config-dir=${spec.store.network} ") &&
                command.indexOf(" --replace=false ") > command.indexOf(" --replace ") &&
                command.indexOf(" --rm=false ") > command.indexOf(" --rm ") &&
                command.contains(" --memory=${process.memoryMiB}m ") &&
                command.contains(" --pids-limit=512 ") && command.contains(" --read-only ") &&
                command.contains(" --security-opt=no-new-privileges ") &&
                command.contains(" --user ${process.userId}:${process.groupId} ") &&
                (!process.oneShot || command.contains(" --label io.p0v3.initializer-intent=\u0001P0_INITIALIZER_INTENT\u0001 ")) &&
                !command.contains(" --privileged ")) { "Unsafe generated Quadlet Podman command" }
        }
        val binding = requireNotNull(spec.fragmentBinding)
        val helper = "/mnt/media/p0-v3/runtime-supervision/releases/${binding.controllerSha256}/bin/p0-v3-platform"
        fun fixed(value: String, action: String, ignoreErrors: Boolean = false): Boolean {
            val expected = "/usr/bin/setpriv --reuid=${binding.controllerUid} --regid=${binding.controllerGid} --init-groups $helper runtime $action ${spec.name} ${process.id}"
            // A prefix comparison would admit extra helper arguments or a second command
            // after the expected process/member. Match the complete systemd show entry.
            val entry = Regex("^\\{ path=/usr/bin/setpriv ; argv\\[\\]=${Regex.escape(expected)} ; " +
                "ignore_errors=${if (ignoreErrors) "yes" else "no"} ; start_time=\\[[^]\\r\\n]*] ; stop_time=\\[[^]\\r\\n]*] ; " +
                "pid=[0-9]+ ; (?:code=\\(null\\) ; status=0/0|" +
                "code=(?:exited|killed|dumped) ; status=(?:0|[1-9][0-9]{0,2})) }$")
            return entry.matches(value)
        }
        require(fixed(values.getValue("ExecStart"), "unit-run") &&
            fixed(values.getValue("ExecStartPre"), "unit-admit") &&
            fixed(values.getValue("ExecStop"), "unit-stop") &&
            values.getValue("ExecStopPost").split(" } { ").let { entries ->
                entries.size == 2 && fixed(entries[0] + " }", "unit-stop", ignoreErrors = true) &&
                    fixed("{ " + entries[1], "unit-guard")
            }) {
            "Generated destructive stop or unauthorized admission command is effective"
        }
        // systemctl show includes volatile timestamps/PIDs/exit status in every Exec*
        // entry. Validate their shape above, then bind the *static effective policy*.
        // Hashing the raw show output would revoke a valid lease when ExecStartPre runs.
        val dynamic = Regex(" ; start_time=\\[[^]\\r\\n]*] ; stop_time=\\[[^]\\r\\n]*] ; " +
            "pid=[0-9]+ ; (?:code=\\(null\\) ; status=0/0|" +
            "code=(?:exited|killed|dumped) ; status=(?:0|[1-9][0-9]{0,2})) }")
        val normalized = values.toSortedMap().map { (key, value) ->
            if (key.startsWith("Exec")) {
                require(dynamic.findAll(value).count() == if (key == "ExecStopPost") 2 else 1) {
                    "Unrecognized systemd execution evidence"
                }
                "$key=${dynamic.replace(value, " ; start_time=[observed] ; stop_time=[observed] ; pid=observed ; code=(observed) ; status=observed/observed }")}"
            } else "$key=$value"
        }.joinToString("\n", postfix = "\n")
        return ReleaseLocks.sha256("quadlet-effective-policy-v1\n".toByteArray() + source + dropIn + normalized.toByteArray())
    }
}
