package net.datamancy.platform

/** Podman imports children but omits mount-root attributes. Only used inside the pristine target's runtime lock. */
internal object ColdVolumeImport {
    fun restoreRoot(spec: PrivateDeploymentSpec, volume: RuntimeVolume, entry: VolumeTarEntry) =
        ColdVolumeMetadata().restore(spec, volume, entry)
}
