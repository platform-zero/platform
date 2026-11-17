package net.datamancy.platform

import java.nio.file.Path

/** Podman imports children but omits mount-root attributes. Only used inside the pristine target's runtime lock. */
internal object ColdVolumeImport {
    fun restoreRoot(spec: PrivateDeploymentSpec, volume: RuntimeVolume, entry: VolumeTarEntry) =
        ColdVolumeMetadata().restore(spec, volume, entry)

    /** Applies every original entry's owner/mode/ACL/user.* attribute/mtime after native import.
     * The caller must keep target isolation locks held and independently re-export/compare all
     * entry descriptors before recording import success or resuming the source.
     */
    fun restoreTree(spec: PrivateDeploymentSpec, volume: RuntimeVolume, entries: List<VolumeTarEntry>) =
        ColdVolumeMetadata().restoreTree(spec, volume, entries)

    /** Compare independently observed native target export, not just import exit status. A changed
     * ACL, approved xattr, inode link descriptor, target, timestamp or content retains isolation.
     */
    fun verifyImported(sourceArchive: Path, targetArchive: Path, owner: Int,
        mappedOwners: Set<Pair<Int, Int>> = emptySet()): List<VolumeTarEntry> {
        require(sourceArchive != targetArchive && sourceArchive.isAbsolute && targetArchive.isAbsolute)
        val source = VolumeTar.inspect(sourceArchive, owner, mappedOwners)
        val target = VolumeTar.inspect(targetArchive, owner, mappedOwners)
        require(source == target) { "Native imported volume differs from original metadata or content" }
        return target
    }
}
