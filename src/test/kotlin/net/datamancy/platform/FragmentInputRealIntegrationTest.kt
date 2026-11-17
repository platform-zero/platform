package net.datamancy.platform

import java.security.KeyFactory
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import kotlin.test.*

/** Native OpenSSL/input generation only; no database, container or deployment admission. */
class FragmentInputRealIntegrationTest {
    @Test fun `real producer creates matching private database TLS and separated credentials`() {
        val plan = FragmentAssemblyFixture.plan()
        val inputs = FragmentRecipes.inputs(plan.specs.single(), plan.inventory)
        fun certificate(name: String) = CertificateFactory.getInstance("X.509").generateCertificate(
            inputs.getValue(name).byteInputStream()) as X509Certificate
        val ca = certificate("postgres-ca.pem"); val leaf = certificate("postgres.pem")
        ca.checkValidity(); leaf.checkValidity(); ca.verify(ca.publicKey); leaf.verify(ca.publicKey)
        assertTrue(ca.basicConstraints >= 0); assertEquals(-1, leaf.basicConstraints)
        assertTrue(leaf.subjectAlternativeNames.any { it[0] == 2 && it[1] == "postgres" })
        assertTrue("1.3.6.1.5.5.7.3.1" in leaf.extendedKeyUsage)
        val key = inputs.getValue("postgres-key.pem").lineSequence().filterNot { it.startsWith("---") }.joinToString("")
        val privateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(Base64.getDecoder().decode(key)))
        val challenge = "unit-native-key-correspondence-not-a-runtime-credential".toByteArray()
        val signature = Signature.getInstance("SHA256withRSA").run { initSign(privateKey); update(challenge); sign() }
        assertTrue(Signature.getInstance("SHA256withRSA").run { initVerify(leaf.publicKey); update(challenge); verify(signature) })
        val admin = inputs.getValue("postgres-bootstrap.env").substringAfter("POSTGRES_PASSWORD=").trim()
        val runtime = inputs.getValue("forgejo-runtime.env")
        assertTrue(admin.matches(Regex("[a-f0-9]{64}")))
        assertFalse(admin in runtime)
        assertEquals(setOf("postgres-key.pem"), inputs.filterValues { "BEGIN PRIVATE KEY" in it }.keys)
        val cold = FragmentRecipes.coldInputs(plan.inventory, plan.specs.single().name, inputs)
        assertTrue(cold.all { (name, value) -> value == inputs[name] })
    }
}
