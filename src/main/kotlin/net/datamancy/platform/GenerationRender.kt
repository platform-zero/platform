package net.datamancy.platform

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class GenerationRenderManifest(val schemaVersion: Int = 1,
    val assemblySha256: String, val files: Map<String, String>, val runtimeAdmitted: Boolean = false,
    val privateInputsIncluded: Boolean = false, val qualificationEvidence: Boolean = false)

/** Deterministic graph/unit export. No credential generation, generator invocation or native actuator. */
internal object GenerationRender {
    private val json = Json { encodeDefaults = true }
    fun export(plan: AssemblyPlan, output: Path): GenerationRenderManifest {
        require(plan.specs.isNotEmpty() && plan.specs.all { it.executionBackend == RuntimeExecutionBackend.QUADLET_V2 }) {
            "Operational export requires explicit Quadlet recipes; no direct backend conversion"
        }
        require(output.isAbsolute && output.normalize() == output)
        ReleasePrivateFiles.directory(output.parent)
        require(!Files.exists(output, NOFOLLOW_LINKS)) { "Export requires a new directory; retain partial exports" }
        val topology = CanonicalTopology.compile(plan, false).topology
        val files = sortedMapOf<String, ByteArray>()
        fun add(path: String, value: String) { require(files.put(path, value.toByteArray()) == null) }
        add("assembly.json", json.encodeToString(plan.summary))
        add("topology.json", json.encodeToString(topology))
        add("artifact-inventory.json", json.encodeToString(plan.inventory))
        FragmentRecipes.fragments(if (plan.summary.members.any { it.recipe == CanonicalSharedYamlGraph.RECIPE } &&
            CanonicalSharedYamlGraph.manifest().scope == "full-private") 5 else 4).forEach { fragment ->
            fragment.exportResources().forEach { (name, bytes) ->
            require(ReleaseLocks.sha256(bytes) == fragment.resourceHashes.getValue(name))
            val existing = files.putIfAbsent("sources/fragments/v2/$name", bytes)
            require(existing == null || existing.contentEquals(bytes)) { "Conflicting packaged resource" }
        } }
        if (plan.summary.members.any { it.recipe == CanonicalSharedYamlGraph.RECIPE }) {
            val references = CanonicalSharedYamlGraph.manifest().fragments.drop(2)
            val resources = PackagedGraphFragment.exportV3AssemblyResources() + references.flatMap { ref ->
                PackagedGraphFragment.loadV3(ref.id, ref.revision).exportResources().entries.map { it.key to it.value }
            }.associate { it }
            resources.forEach { (path, bytes) ->
                val existing = files.putIfAbsent("sources/fragments/v3/$path", bytes)
                require(existing == null || existing.contentEquals(bytes))
            }
        }
        plan.specs.forEach { spec ->
            val summary = plan.summary.members.single { it.name == spec.name }
            require(summary.specSha256 == ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()))
            val binding = requireNotNull(spec.fragmentBinding)
            val compiled = when (binding.recipe) {
                CanonicalSharedYamlGraph.RECIPE -> CanonicalSharedYamlGraph.spec(plan.inventory, spec.name,
                    FragmentPhase.valueOf(binding.phase), binding.controllerSha256, binding.controllerUid, binding.controllerGid)
                FragmentRecipes.FORGEJO_POSTGRES -> FragmentRecipes.spec(plan.inventory, spec.name,
                    FragmentPhase.valueOf(binding.phase), binding.controllerSha256, binding.controllerUid, binding.controllerGid)
                else -> error("Unrecognized packaged Quadlet graph")
            }
            require(spec == compiled) { "Export graph differs from packaged recipe" }
            add("${spec.name}/runtime.json", Json.encodeToString(spec))
            val bundle = RuntimeQuadlets.render(spec)
            add("${spec.name}/quadlet-bundle.json", json.encodeToString(bundle))
            bundle.files.forEach { (name, text) -> add("${spec.name}/quadlets/$name", text) }
        }
        val manifest = GenerationRenderManifest(assemblySha256 = SiteOwnerships.assemblyDigest(plan),
            files = files.mapValues { ReleaseLocks.sha256(it.value) })
        Files.createDirectory(output, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        sync(output.parent)
        // Preserve partial output on all failures. A missing result never authorizes use or replacement.
        save(output.resolve("export.intent.json"), json.encodeToString(manifest).toByteArray())
        sync(output)
        files.forEach { (relative, bytes) ->
            val target = output.resolve(relative)
            var parent = output
            for (component in output.relativize(target.parent)) {
                if (component.toString().isEmpty()) continue
                val child = parent.resolve(component)
                if (!Files.exists(child, NOFOLLOW_LINKS)) {
                    Files.createDirectory(child, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                    sync(parent)
                }
                ReleasePrivateFiles.directory(child)
                parent = child
            }
            save(target, bytes); sync(target.parent)
        }
        save(output.resolve("export.result.json"), json.encodeToString(manifest).toByteArray())
        sync(output)
        return manifest
    }
    private fun sync(path: Path) = FileChannel.open(path, READ).use { it.force(true) }
    private fun save(path: Path, bytes: ByteArray) {
        FileChannel.open(path, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel ->
            val buffer = java.nio.ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
    }
}
