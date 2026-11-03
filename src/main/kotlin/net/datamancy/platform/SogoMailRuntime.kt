package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.*

/** Fresh composite only: never rewrites either standalone fixture's inputs or credentials. */
internal object SogoMailRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "sogo-mail"): PrivateDeploymentSpec {
        val sogo = SogoRuntime.spec(inventory, name, mailEnabled = true)
        val mail = MailRuntime.spec(name)
        val processes = sogo.processes.map { if (it.id == "sogod") it.copy(dependencies = it.dependencies + "mail") else it } +
            mail.processes.map { process -> process.copy(
                environmentFile = if (process.id == "mail-init") "mail-bootstrap.env" else process.environmentFile,
                files = process.files.map { if (it.file == "ca.pem") it.copy(file = "mail-ca.pem") else it }
            ) }
        return sogo.copy(volumes = sogo.volumes + mail.volumes, processes = processes).also { PrivateDeployment.validate(it) }
    }
    fun inputs(pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) }): Map<String, String> {
        val mail = MailRuntime.inputs { pki("mail") }.mapKeys { (name, _) -> when (name) {
            "ca.pem" -> "mail-ca.pem"
            "bootstrap.env" -> "mail-bootstrap.env"
            else -> name
        } }
        val users = Json.parseToJsonElement(mail.getValue("users.json")).jsonObject.mapValues { it.value.jsonPrimitive.content }
        val sogo = SogoRuntime.inputs(users = users, mailEnabled = true, pki = pki)
        require((sogo.keys intersect mail.keys).isEmpty()) { "Composite inputs must not shadow each other" }
        return sogo + mail
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "sogo-mail", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
}
