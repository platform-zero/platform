package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions

/** Parse exactly the pinned generator's ExecStart, not a shell command. The parsed argv is
 * usable only by the systemd unit's owner-gated ExecStart replacement. Never execute a
 * caller-supplied command, a different generator version or a foreign generated source.
 */
internal object RuntimeQuadletGeneratedStart {
    fun fromPinnedGenerator(spec: PrivateDeploymentSpec, process: RuntimeProcess,
        invoke: (List<String>, Path?) -> RuntimeCommandResult = RuntimeQuadletDiagnostics::invoke): List<String> {
        val bundle = RuntimeQuadlets.render(spec)
        require(process in spec.processes && invoke(listOf("--version"), null).let {
            it.exitCode == 0 && it.output.trim() == "5.4.2"
        }) { "Pinned Quadlet generator unavailable" }
        val root = Files.createTempDirectory("p0v3-gated-exec-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            bundle.files.filterKeys { it.endsWith(".container") }.forEach { (name, bytes) ->
                Files.writeString(root.resolve(name), bytes)
            }
            val result = invoke(listOf("--dryrun"), root)
            require(result.exitCode == 0)
            RuntimeQuadletDiagnostics.audit(spec, result.output)
            val unit = RuntimeQuadlets.unit(spec, process)
            val section = result.output.substringAfter("---$unit.service---").substringBefore("\n---")
            val line = section.lineSequence().single { it.startsWith("ExecStart=/usr/bin/podman ") }
            return parse(spec, process, line.substringAfter('=')).also { argv ->
                require(argv.first() == "/usr/bin/podman" && argv.contains(process.image))
            }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    /** Values come from a validated generated command and the *verified* original private
     * environment, never from the caller's ambient shell environment. */
    fun expand(argv: List<String>, spec: PrivateDeploymentSpec, p: RuntimeProcess,
        fingerprint: String, initializerIntent: String? = null): List<String> {
        require(p in spec.processes && fingerprint.matches(Regex("[a-f0-9]{64}")) &&
            (initializerIntent == null || initializerIntent.matches(Regex("[a-f0-9]{64}"))) &&
            (p.oneShot == (initializerIntent != null)))
        val unit = RuntimeQuadlets.unit(spec, p)
        return argv.map { word ->
            require(!word.contains('\u0000'))
            var value = word.replace("%t/%N.cid", "/run/$unit.cid")
                .replace("\u0001P0_RUNTIME_FINGERPRINT\u0001", fingerprint)
            if (initializerIntent != null) value = value.replace("\u0001P0_INITIALIZER_INTENT\u0001", initializerIntent)
            require(!value.contains('\u0001')) { "Unbound generated environment placeholder" }
            value
        }
    }

    /** Tokenizer for the generator's systemd ExecStart grammar, not shlex or /bin/sh. */
    internal fun parse(spec: PrivateDeploymentSpec, p: RuntimeProcess, value: String): List<String> {
        require(p in spec.processes && value.length in 32..65536 && !value.contains('\r') && !value.contains('\u0000'))
        val parts = mutableListOf<String>()
        var word = StringBuilder()
        var quoted = false
        var started = false
        var index = 0
        while (index < value.length) {
            val char = value[index]
            if (!quoted && char == ' ') {
                if (started) { parts += word.toString(); word = StringBuilder(); started = false }
                index++; continue
            }
            if (char == '"') { quoted = !quoted; started = true; index++; continue }
            if (char == '\\') {
                require(index + 1 < value.length)
                val next = value[++index]
                word.append(when (next) { 'n' -> '\n'; 't' -> '\t'; '\\' -> '\\'; '"' -> '"'; else ->
                    error("Unsupported generated systemd escape") })
                started = true; index++; continue
            }
            if (char == '$') {
                if (index + 1 < value.length && value[index + 1] == '$') {
                    word.append('$'); index += 2; started = true; continue
                }
                val names = listOf("P0_RUNTIME_FINGERPRINT", "P0_INITIALIZER_INTENT")
                val match = names.firstOrNull { value.startsWith("\${$it}", index) }
                require(match != null && (match != "P0_INITIALIZER_INTENT" || p.oneShot)) {
                    "Unrecognized generated environment expansion"
                }
                word.append("\u0001$match\u0001"); index += match.length + 3; started = true; continue
            }
            if (char == '%') {
                if (index + 1 < value.length && value[index + 1] == '%') {
                    word.append('%'); index += 2; started = true; continue
                }
                require(value.startsWith("%t/%N.cid", index)) { "Unsupported generated systemd specifier" }
                word.append("%t/%N.cid"); index += "%t/%N.cid".length; started = true; continue
            }
            require(char.code in 0x20..0x7e || (quoted && char == '\n')) {
                "Unsupported character in generated start"
            }
            word.append(char); started = true; index++
        }
        require(!quoted && started)
        parts += word.toString()
        require(parts.size in 20..256 && parts[0] == "/usr/bin/podman" && parts.contains("run") &&
            parts.contains("--name") && parts.contains("p0v3-live-${spec.name}-${p.id}") &&
            parts.contains("--replace=false") && parts.contains("--rm=false") && parts.contains(p.image)) {
            "Generated command differs from sealed Quadlet lifecycle"
        }
        return parts
    }
}
