package net.datamancy.platform

import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlin.test.Test

/** Read-only diagnostic for fenced scratch r1: do NOT call operate or load. */
class WorklaneFullPreparePreflightDiagnosticTest {
    @Test fun snapshotIsolatedProbeBeforeAnyNativePrepareIntent() {
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/native-probes/q-186d9a43b739/managed")
        val plan=Json.decodeFromString<ManagedLanePlan>(ReleasePrivateFiles.read(
            root.resolve("isolated-managed-plan.json"),65536).decodeToString(throwOnInvalidSequence=true))
        val native=plan.native
        val control=root.resolve("control")
        val image=requireNotNull(native.imageArchive)
        val backend=NativeManagedLaneBackend(Path.of(native.worklane.path),Path.of(native.podman.path),
            Path.of(native.storageConfig.path),Path.of(native.manifest.path),
            control.resolve("home"),control.resolve("config"),control.resolve("data"),control.resolve("run"),
            image,mapOf("worklane" to native.worklane.sha256,"podman" to native.podman.sha256,
                "storageConfig" to native.storageConfig.sha256,"manifest" to native.manifest.sha256,
                "imageArchive" to image.archive.sha256))
        backend.preflight(plan.lanes.single { it.kind==ManagedLaneKind.WORKLANE },root.resolve("worklane"),
            ManagedLaneOperation.PREPARE,null,null,System.currentTimeMillis()+TimeUnit.MINUTES.toMillis(30))
    }
}
