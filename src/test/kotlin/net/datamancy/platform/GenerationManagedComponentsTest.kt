package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions

/** Pure framing/admission tests only; these are not native capture or restore evidence. */
class GenerationManagedComponentsTest {
    private val hash = "a".repeat(64)
    private val metadata = listOf("managed/index.json", "managed/oracle.json", "managed/source-manifest.toml")
    private val archives = listOf("home", "workspace", "manifests", "transcripts").map { "managed/$it/tree.tar" }
    private fun manifest(): CapsuleManifest {
        val files = metadata.map { CapsuleFile(it, 32, hash) } + archives.map { CapsuleFile(it, 1024, hash) }
        return CapsuleManifest(id = "cap-0123456789ab", generation = "q-0123456789ab",
            bundleSha256 = hash, members = emptyList(), files = files, managedFiles = files.map { it.name })
    }

    @Test fun historicalManifestHasNoManagedPartition(): Unit {
        GenerationManagedComponents.validate(manifest().copy(files = emptyList(), managedFiles = emptyList()))
    }

    @Test fun exactFourArchivesRequireOriginalManifestAndOracle(): Unit {
        GenerationManagedComponents.validate(manifest())
        for (name in metadata + archives) {
            val original = manifest()
            assertFailsWith<IllegalArgumentException> {
                GenerationManagedComponents.validate(original.copy(files = original.files.filterNot { it.name == name },
                    managedFiles = original.managedFiles - name))
            }
        }
    }

    @Test fun undeclaredOrDuplicatePhysicalPayloadCannotHideBehindIndex(): Unit {
        val original = manifest()
        assertFailsWith<IllegalArgumentException> {
            GenerationManagedComponents.validate(original.copy(files = original.files + original.files.first()))
        }
        assertFailsWith<IllegalArgumentException> {
            GenerationManagedComponents.validate(original.copy(managedFiles = original.managedFiles.dropLast(1)))
        }
        val foreign = CapsuleFile("managed/control/runtime.json", 32, hash)
        assertFailsWith<IllegalArgumentException> {
            GenerationManagedComponents.validate(original.copy(files = original.files + foreign,
                managedFiles = original.managedFiles + foreign.name))
        }
    }

    @Test fun controllerAndManagedPartitionsCannotAlias(): Unit {
        assertFailsWith<IllegalArgumentException> {
            GenerationManagedComponents.validate(manifest().copy(controllerFiles = listOf(metadata.first())))
        }
    }

    @Test fun managedMetadataAndTarBoundsAreExplicit(): Unit {
        for (invalid in listOf(CapsuleFile(metadata.first(), 0, hash),
            CapsuleFile(metadata.first(), 1048577, hash), CapsuleFile(metadata.first(), 32, "not-a-digest"),
            CapsuleFile(archives.first(), 1025, hash), CapsuleFile(archives.first(), 512, hash))) {
            val original = manifest()
            assertFailsWith<IllegalArgumentException> {
                GenerationManagedComponents.validate(original.copy(files = original.files.map {
                    if (it.name == invalid.name) invalid else it
                }))
            }
        }
    }

    @Test fun sharedOrderedPartFramingIsTheOnlySegmentedForm(): Unit {
        val original = manifest()
        val name = archives.first()
        val parts = listOf("$name.part-0000", "$name.part-0001")
        val files = original.files.filterNot { it.name == name } + parts.map { CapsuleFile(it, 1024, hash) }
        val segmented = original.copy(files = files, managedFiles = files.map { it.name },
            volumes = listOf(RecoveryVolume(name, 2048, hash, parts)))
        GenerationManagedComponents.validate(segmented)
        assertFailsWith<IllegalArgumentException> {
            GenerationManagedComponents.validate(segmented.copy(volumes = listOf(RecoveryVolume(name, 2048, hash, parts.reversed()))))
        }
        assertFailsWith<IllegalArgumentException> {
            GenerationManagedComponents.validate(segmented.copy(volumes = listOf(RecoveryVolume(name, 2048, hash, parts.take(1)))))
        }
    }

    @Test fun unmanagedImportCannotInventPayloadOrInvokeNativeBackend(): Unit {
        val mode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
        val base = Files.createTempDirectory("managed-import-admission", mode)
        try {
            val recovered = Files.createDirectory(base.resolve("recovered"), mode)
            val targetRoot = Files.createDirectory(base.resolve("q-fedcba987654"), mode)
            val request = GenerationRequest(id = "q-0123456789ab", candidateSha256 = hash,
                members = emptyList(), diskReservationMiB = 1024)
            val source = GenerationBundle(request, emptyList(), 0)
            val target = source.copy(request = request.copy(id = targetRoot.fileName.toString()))
            val empty = manifest().copy(files = emptyList(), managedFiles = emptyList())
            GenerationManagedComponents.importOwned(source, target, empty, recovered, targetRoot) { _, _ ->
                error("Unmanaged import must not instantiate a native backend")
            }
            assertFalse(Files.exists(targetRoot.resolve("managed-import.intent.json")))
            assertFailsWith<IllegalArgumentException> {
                GenerationManagedComponents.importOwned(source, target, manifest(), recovered, targetRoot) { _, _ ->
                    error("Forged managed payload must fail before native effects")
                }
            }
            assertFalse(Files.exists(targetRoot.resolve("managed")))
            assertFalse(Files.exists(targetRoot.resolve("managed-import.intent.json")))
        } finally {
            Files.walk(base).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { Files.delete(it) } }
        }
    }

    @Test fun omittedManagedPlansDoNotInventResourcesOrCapabilities(): Unit {
        val request = GenerationRequest(id = "q-0123456789ab", candidateSha256 = hash,
            members = emptyList(), diskReservationMiB = 1024)
        GenerationManagedComponents.validate(request)
        assertEquals(0L, GenerationManagedComponents.memoryReservationMiB(request))
        assertEquals(0L, GenerationManagedComponents.diskReservationMiB(request))
        assertEquals(emptySet(), GenerationManagedComponents.capabilities(request))
        assertEquals(emptyList(), GenerationManagedComponents.ownership(request))
        assertFailsWith<IllegalArgumentException> {
            GenerationManagedComponents.ownership(request.copy(recoveryStateReservationMiB = 1024))
        }
    }
}
