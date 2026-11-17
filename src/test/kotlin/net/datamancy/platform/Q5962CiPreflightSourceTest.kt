package net.datamancy.platform

import java.nio.file.Path
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.junit.jupiter.api.Test
import kotlin.test.*

class Q5962CiPreflightSourceTest {
    @Test fun `original failed preparation CI preflight is diagnosed read only`() {
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5962a9fda75b")
        val request=GenerationAssembly.readRequest(root.resolve("assembly-request.pi-subscription-v3.budgeted.json"))
        val ci=requireNotNull(request.forgejoCi)
        ci.validate(request.id)
        val workflow=GenerationRuntime.privateInput(Path.of(ci.workflow.path))
        assertEquals(ci.workflow.sha256,ReleaseLocks.sha256(workflow))
        val review=ForgejoWorkflowSource.inspect(ci.enrollment,ci.enrollment.trustedCommit,workflow)
        val config=ForgejoRunnerConfigSource.config(ci.enrollment,review,
            "/home/webservices-lab-ci-runner/.local/share/p0v3-ci/${ci.generation}/.runner")
        println("CI read-only stage preflight validated: configBytes=${config.toByteArray().size}, sourceHash=${ci.workflow.sha256}")
        val tls=PrivateWebPki.generate("forgejo-ci",listOf("forgejo-ci","forgejo.datamancy.net"))
        assertEquals(setOf("ca.pem","web.pem","web-key.pem"),tls.keys)
        val leaf = CertificateFactory.getInstance("X.509")
            .generateCertificate(tls.getValue("web.pem").byteInputStream()) as X509Certificate
        assertEquals(setOf("forgejo-ci", "forgejo.datamancy.net"),
            leaf.subjectAlternativeNames.filter { it[0] == 2 }.map { it[1] as String }.toSet())
    }
}
