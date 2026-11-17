package net.datamancy.platform

import java.nio.file.Path

/** Private durable secrets backend. Startup readiness means TLS API available, never automatic unseal. */
internal object OpenBaoRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "openbao"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "openbao" }
        require(image.os == "linux" && image.architecture == "amd64")
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("data", 1000)), processes = listOf(
            RuntimeProcess("bao", image.pinnedImage, image.imageId, 1000, entrypoint = "/usr/bin/bao",
                command = listOf("server", "-config=/run/secrets/bao.hcl"),
                environmentFile = "bao.env", files = listOf("bao.hcl", "ca.pem", "web.pem", "web-key.pem").map {
                    RuntimeFile(it, "/run/secrets/$it")
                }, volumes = listOf(RuntimeMount("data", "/bao/data")), apparmorProfile = "p0v3-private-v1", memoryMiB = 1024,
                readiness = listOf("/bin/sh", "-ec", "set +e; status=${'$'}(/usr/bin/bao status -format=json 2>/dev/null); code=${'$'}?; " +
                    "test ${'$'}code -eq 0 || test ${'$'}code -eq 2 || " +
                    "{ test ${'$'}code -eq 1 && printf '%s' \"${'$'}status\" | grep -Eq '\"initialized\"[[:space:]]*:[[:space:]]*false' && " +
                    "printf '%s' \"${'$'}status\" | grep -Eq '\"sealed\"[[:space:]]*:[[:space:]]*true'; }"))
        )).also { PrivateDeployment.validate(it) }
    }
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        require(compiled.processes.map { it.id } == listOf("bao") && compiled.processes.none { it.oneShot })
        val bao = compiled.processes.single()
        require(bao.entrypoint == "/usr/bin/bao" && bao.command == listOf("server", "-config=/run/secrets/bao.hcl") &&
            bao.environmentFile == "bao.env" && bao.files.map { it.file }.toSet() == setOf("bao.hcl", "ca.pem", "web.pem", "web-key.pem"))
        return compiled.also { PrivateDeployment.validate(it) } // Ordinary restore boot is sealed, too.
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "openbao", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("bao") }): Map<String, String> = pki() + mapOf(
        "bao.env" to "BAO_ADDR=https://bao:8200\nBAO_CACERT=/run/secrets/ca.pem\nHOME=/tmp\n",
        "bao.hcl" to """
            ui = false
            api_addr = "https://bao:8200"
            cluster_addr = "https://bao:8201"
            log_level = "warn"
            storage "raft" {
              path = "/bao/data"
              node_id = "bao"
            }
            audit "file" "private" {
              options {
                file_path = "/bao/data/audit.log"
                log_raw = "false"
              }
            }
            listener "tcp" {
              address = "0.0.0.0:8200"
              tls_cert_file = "/run/secrets/web.pem"
              tls_key_file = "/run/secrets/web-key.pem"
              tls_min_version = "tls12"
            }
        """.trimIndent() + "\n")
}
