package net.datamancy.platform

import java.net.InetAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Bounded, non-sensitive terminal HTTP probe detail for a failed original start. */
internal class QuadletReadinessTimeout(val lastProbe: String) :
    IllegalStateException("Quadlet daemon readiness timed out; keep generation fenced")

/** Controller-side native barrier; systemd dependencies alone never imply readiness. */
internal object RuntimeQuadletReadiness {
    // Sails/Planka serves HTTP/1.1 and may close an h2c upgrade request without
    // a response. Do not treat a Python/curl 200 as proof that Java's default
    // HTTP/2-upgrade transport can complete the owned controller's probe.
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2))
        .version(HttpClient.Version.HTTP_1_1).followRedirects(HttpClient.Redirect.NEVER).build()
    fun waitFor(spec: PrivateDeploymentSpec, process: RuntimeProcess,
        expectedCid: String? = null,
        commands: RuntimeCommands = PrivateRootfulCommands(15, spec.store),
        pause: () -> Unit = { Thread.sleep(500) },
        durationSeconds: Long = 90): RuntimeStatus {
        require(process in spec.processes && !process.oneShot && durationSeconds in 1..300 &&
            (expectedCid == null || expectedCid.matches(Regex("[a-f0-9]{64}"))))
        val name = "p0v3-live-${spec.name}-${process.id}"
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(durationSeconds)
        var lastProbe = "not-attempted"
        do {
            val inspected = commands.run(listOf("container", "inspect", name))
            require(inspected.exitCode == 0 && inspected.output.toByteArray().size in 1..65536)
            val item = Json.parseToJsonElement(inspected.output).jsonArray.single().jsonObject
            val labels = item.getValue("Config").jsonObject.getValue("Labels").jsonObject
            val state = item.getValue("State").jsonObject
            require((expectedCid == null || item.getValue("Id").jsonPrimitive.content == expectedCid) &&
                item.getValue("Name").jsonPrimitive.content == name &&
                item.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == process.imageId &&
                labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                state.getValue("Status").jsonPrimitive.content == "running" &&
                state.getValue("Running").jsonPrimitive.content == "true") {
                "Quadlet daemon exited or changed during readiness"
            }
            val ready = if (process.readinessHttpPort != null) {
                val addresses = item.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
                val ip = addresses.getValue("p0v3-live-${spec.name}-${process.networks.first()}")
                    .jsonObject.getValue("IPAddress").jsonPrimitive.content
                require(runCatching { InetAddress.getByName(ip).isSiteLocalAddress }.getOrDefault(false)) {
                    "No exact private Quadlet readiness address"
                }
                val url = URI("http", null, ip, process.readinessHttpPort, process.readinessHttpPath, null, null)
                runCatching { client.send(HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(3)).GET().build(),
                    HttpResponse.BodyHandlers.discarding()).statusCode() }.fold(
                    onSuccess = { status -> lastProbe = "http-status-$status"; status == 200 },
                    onFailure = { failure ->
                        // Never serialize exception text: it can include an address or
                        // transport configuration. The class is enough to diagnose the
                        // original failed readiness without leaking credentials.
                        var terminal: Throwable = failure
                        repeat(4) { terminal = terminal.cause ?: terminal }
                        lastProbe = "http-exception-${failure.javaClass.simpleName}-${terminal.javaClass.simpleName}"
                        false
                    })
            } else {
                require(process.readiness.isNotEmpty())
                commands.run(listOf("exec", name) + process.readiness).also {
                    lastProbe = "exec-exit-${it.exitCode}"
                }.exitCode == 0
            }
            if (ready) return RuntimeStatus(process.id, "running", null)
            if (System.nanoTime() < deadline) pause()
        } while (System.nanoTime() < deadline)
        throw QuadletReadinessTimeout(lastProbe)
    }
}
