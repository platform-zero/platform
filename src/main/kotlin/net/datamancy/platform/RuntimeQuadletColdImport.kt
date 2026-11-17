package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class QuadletColdImportVolumeResult(val schemaVersion: Int = 1,
    val member: String, val fingerprint: String, val volume: String, val intentSha256: String,
    val originalArchiveSha256: String, val nativeReadbackSha256: String, val entries: Int)

/** Imports authenticated stopped volume archives into freshly provisioned Quadlet
 * resources. This never launches a product process, invokes a direct-backend
 * deployment or translates an original initializer into a new operation.
 */
internal class RuntimeQuadletColdImport(private val generationRoot: Path,
    private val commands: RuntimeCommands = PrivateRootfulCommands(120, RuntimeStore.CANONICAL_V2)) {
    private val json = Json { encodeDefaults = true }
    fun importVolumes(spec: PrivateDeploymentSpec, fingerprint: String,
        archives: Map<String, Path>, expectedHashes: Map<String, String>, verificationRoot: Path): List<QuadletColdImportVolumeResult> {
        require(spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            spec.store == RuntimeStore.CANONICAL_V2 && spec.processes.none { it.oneShot } &&
            spec.ingress == null && spec.nativeIngress == null &&
            spec.volumes.map { it.id }.toSet() == archives.keys && archives.keys == expectedHashes.keys &&
            expectedHashes.values.all { it.matches(Regex("[a-f0-9]{64}")) })
        ReleasePrivateFiles.directory(generationRoot)
        ReleasePrivateFiles.directory(verificationRoot)
        // Inspect ALL source archives before the first volume import. No partial
        // tar, foreign hardlink, owner or ACL may be admitted mid-operation.
        val trees = spec.volumes.associate { volume ->
            val archive = archives.getValue(volume.id)
            RecoveryCapsule.guard(archive, RecoveryCapsule.MAX_TOTAL)
            require(RecoveryCapsule.fileHash(archive) == expectedHashes.getValue(volume.id)) {
                "Original Quadlet volume differs from authenticated Kopia payload"
            }
            volume.id to VolumeTar.inspect(archive, volume.userId,
                volume.mappedOwners.map { it.userId to it.groupId }.toSet())
        }
        return spec.volumes.map { volume ->
            val id = volume.id
            val archive = archives.getValue(id)
            val name = "p0v3-live-${spec.name}-volume-$id"
            val resultPath = generationRoot.resolve("quadlet-import-$id.result.json")
            val intentPath = generationRoot.resolve("quadlet-import-$id.intent.json")
            require(!Files.exists(resultPath, NOFOLLOW_LINKS) && !Files.exists(intentPath, NOFOLLOW_LINKS)) {
                "Original volume import already attempted; no replay"
            }
            val resource = generationRoot.resolve("quadlet-resource-volume-volume-$id.result.json")
            val admitted = json.decodeFromString<QuadletResourceResult>(ReleasePrivateFiles.read(resource, 8192).decodeToString())
            require(admitted.schemaVersion == 1 && admitted.observedId == name)
            val sourceHash = expectedHashes.getValue(id)
            val bytes = json.encodeToString(mapOf("member" to spec.name, "fingerprint" to fingerprint,
                "volume" to name, "originalArchiveSha256" to sourceHash,
                "resourceResultSha256" to ReleaseLocks.sha256(ReleasePrivateFiles.read(resource, 8192)))).toByteArray()
            ReleasePrivateFiles.save(intentPath, bytes)
            require(RecoveryCapsule.fileHash(archive) == sourceHash) {
                "Original volume archive changed before native import"
            }
            var phase = "native-volume-import"
            try {
                val imported = commands.run(listOf("volume", "import", name, archive.toString()))
                require(imported.exitCode == 0 && imported.output.toByteArray().size <= 4096) {
                    "Quadlet volume import lacks original native ACK; retain intent and isolation"
                }
                phase = "metadata-restore"
                ColdVolumeImport.restoreTree(spec, volume, trees.getValue(id))
                phase = "native-volume-export"
                val readback = verificationRoot.resolve("$id.tar")
                ColdVolumeExport.export(spec, volume, readback, maximumBytes = minOf(RecoveryCapsule.MAX_TOTAL,
                    Math.addExact(Files.size(archive), VolumeTar.MAX_METADATA_PREFIX)))
                phase = "independent-descriptor-readback"
                val entries = ColdVolumeImport.verifyImported(archive, readback, volume.userId,
                    volume.mappedOwners.map { it.userId to it.groupId }.toSet())
                require(RecoveryCapsule.fileHash(archive) == sourceHash) {
                    "Kopia volume payload changed after independent native readback"
                }
                QuadletColdImportVolumeResult(member = spec.name, fingerprint = fingerprint, volume = id,
                    intentSha256 = ReleaseLocks.sha256(bytes), originalArchiveSha256 = sourceHash,
                    nativeReadbackSha256 = RecoveryCapsule.fileHash(readback), entries = entries.size).also {
                    ReleasePrivateFiles.save(resultPath, json.encodeToString(it).toByteArray())
                }
            } catch (failure: Exception) {
                // A failure is an immutable ORIGINAL observation, not a new
                // permission to resume this volume import or metadata write.
                val diagnostic = failure.message?.takeIf { it.length in 1..160 &&
                    it.matches(Regex("[A-Za-z0-9 .,:;()_/-]+")) } ?: "unspecified"
                ReleasePrivateFiles.save(generationRoot.resolve("quadlet-import-$id.failure.json"),
                    json.encodeToString(mapOf("member" to spec.name, "volume" to id,
                        "phase" to phase, "failureClass" to failure.javaClass.name,
                        "diagnostic" to diagnostic, "intentSha256" to ReleaseLocks.sha256(bytes))).toByteArray())
                throw failure
            }
        }
    }
}
