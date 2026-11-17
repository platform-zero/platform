package net.datamancy.platform

import java.nio.file.Path

/** Exact selected r9 canonical process owner. Never infer a standalone
 * jupyterhub member from the module name: the full graph is one assembled member.
 */
internal object NotebookSelectedGraph {
    fun selected(root: Path, spec: PrivateDeploymentSpec): Boolean {
        val generation = root.fileName.toString()
        if (!generation.matches(Regex("q-[a-f0-9]{12}")) ||
            !spec.name.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39}")) ||
            !spec.name.startsWith("$generation-") ||
            spec.store != RuntimeStore.CANONICAL_V2 ||
            spec.executionBackend != RuntimeExecutionBackend.QUADLET_V2 ||
            spec.fragmentBinding?.recipe != CanonicalSharedYamlGraph.RECIPE) return false
        val hub = spec.processes.singleOrNull { it.id == "hub-controller" } ?: return false
        if (hub.controlSocketMount != RuntimeControlSocketMount(
            GenerationRuntime.BASE.resolve(generation).resolve("notebooks/control.sock").toString(),
            "/run/p0-notebooks/control.sock") ||
            hub.files.none { it.file == "jupyterhub-hub-settings.json" &&
                it.target == "/run/secrets/hub-settings.json" } ||
            hub.files.none { it.file == "jupyterhub-hub-config.py" &&
                it.target == "/run/secrets/hub-config.py" }) return false
        return listOf("alice","bob").all { user ->
            spec.processes.singleOrNull { it.id == user }?.let { p ->
                !p.oneShot && p.memoryMiB == 2048 && p.userId == 1000 &&
                    p.volumes.singleOrNull() == RuntimeMount(user,"/home/jovyan") &&
                    p.files.any { it.file == "jupyterhub-$user-control" }
            } == true
        }
    }
}
