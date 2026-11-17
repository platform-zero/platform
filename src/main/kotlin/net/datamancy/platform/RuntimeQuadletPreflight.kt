package net.datamancy.platform

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Native read-only prerequisites for installing disabled units. The direct-Podman backend
 * intentionally refuses QUADLET_V2 even for observation; do not route installation through
 * its apply/audit methods or pretend a generator dry-run checked the native image/store.
 */
internal object RuntimeQuadletPreflight {
    fun verify(spec: PrivateDeploymentSpec, commands: RuntimeCommands = PrivateRootfulCommands(30, spec.store)) {
        RuntimeQuadlets.render(spec)
        require(spec.store == RuntimeStore.CANONICAL_V2)
        fun read(args: List<String>, bound: Int = 2_000_000): String {
            val answer = commands.run(args)
            require(answer.exitCode == 0 && answer.output.toByteArray().size in 1..bound) {
                "Cannot establish native Quadlet installation prerequisites"
            }
            return answer.output
        }
        val info = Json.parseToJsonElement(read(listOf("info", "--format", "json"))).jsonObject
        val store = info.getValue("store").jsonObject
        val security = info.getValue("host").jsonObject.getValue("security").jsonObject
        require(store.getValue("graphRoot").jsonPrimitive.content == spec.store.graph &&
            store.getValue("runRoot").jsonPrimitive.content == spec.store.run &&
            security.getValue("rootless").jsonPrimitive.content == "false" &&
            security.getValue("apparmorEnabled").jsonPrimitive.content == "true" &&
            security.getValue("seccompEnabled").jsonPrimitive.content == "true") {
            "Quadlet native store or confinement differs"
        }
        spec.processes.forEach { p ->
            val image = Json.parseToJsonElement(read(listOf("image", "inspect", p.image), 65536)).jsonArray.single().jsonObject
            require(image.getValue("Id").jsonPrimitive.content.removePrefix("sha256:") == p.imageId &&
                image.getValue("Digest").jsonPrimitive.content == p.image.substringAfter('@')) {
                "Quadlet image differs from the sealed graph"
            }
        }
        for (args in listOf(listOf("container", "ls", "--all", "--format", "{{.Names}}"),
            listOf("network", "ls", "--format", "{{.Name}}"),
            listOf("volume", "ls", "--format", "{{.Name}}"),
            listOf("secret", "ls", "--format", "{{.Name}}"))) {
            val answer = commands.run(args)
            require(answer.exitCode == 0 && answer.output.toByteArray().size <= 2_000_000 &&
                answer.output.lineSequence().none { it.trim().startsWith("p0v3-live-${spec.name}-") }) {
                "Existing Quadlet namespace resource or incomplete native census"
            }
        }
    }
}
