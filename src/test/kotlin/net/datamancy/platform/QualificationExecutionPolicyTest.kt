package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class QualificationExecutionPolicyTest {
    private fun manifest(vararg cases: String) = """{"schemaVersion":2,"cases":[${cases.joinToString(",")}] }""".encodeToByteArray()
    private fun definition(service: String, surface: String, variant: String) =
        """{"serviceId":"$service","surface":"$surface","variant":"$variant","journey":"workflow","runner":"scripts/qualified-runner.py","adapter":"runners/$service-native.py"}"""
    @Test fun `exact original case mode never comes from context or client assertion`(): Unit {
        val bytes = manifest(definition("opensearch", "HEADLESS", "NATIVE"),
            definition("mastodon", "HEADLESS", "NATIVE"), definition("alloy", "HEADLESS", "NATIVE"),
            definition("grafana", "WEB", "BROWSER"), definition("grafana", "HEADLESS", "NATIVE"),
            definition("prometheus", "HEADLESS", "NATIVE"), definition("alertmanager", "HEADLESS", "NATIVE"),
            definition("node-exporter", "HEADLESS", "NATIVE"))
        assertEquals(QualificationExecutionMode.HOST_NATIVE,
            QualificationExecutionPolicy.select(bytes, "opensearch", "HEADLESS", "NATIVE", "workflow"))
        assertEquals(QualificationExecutionMode.HOST_NATIVE,
            QualificationExecutionPolicy.select(bytes, "node-exporter", "HEADLESS", "NATIVE", "workflow"))
        assertEquals(QualificationExecutionMode.QCLIENT_RUNNER,
            QualificationExecutionPolicy.select(bytes, "mastodon", "HEADLESS", "NATIVE", "workflow"))
        assertEquals(QualificationExecutionMode.HOST_NATIVE_WITH_DENIAL_PROBE,
            QualificationExecutionPolicy.select(bytes, "alloy", "HEADLESS", "NATIVE", "workflow"))
        assertEquals(QualificationExecutionMode.QCLIENT_RUNNER,
            QualificationExecutionPolicy.select(bytes, "grafana", "WEB", "BROWSER", "workflow"))
        for (service in listOf("grafana", "prometheus", "alertmanager")) assertEquals(
            QualificationExecutionMode.QCLIENT_RUNNER,
            QualificationExecutionPolicy.select(bytes, service, "HEADLESS", "NATIVE", "workflow"))
        assertFails { QualificationExecutionPolicy.select(bytes, "opensearch", "WEB", "BROWSER", "workflow") }
        assertFails { QualificationExecutionPolicy.select(bytes, "invented", "HEADLESS", "NATIVE", "workflow") }
        assertFails { QualificationExecutionPolicy.select(bytes, "mastodon", "HEADLESS", "PRIVATE_NATIVE", "workflow") }
        assertFails { QualificationExecutionPolicy.select(manifest(definition("node-exporter", "WEB", "BROWSER")),
            "node-exporter", "WEB", "BROWSER", "workflow") }
    }
    @Test fun `original identity first-use browser supplies native predecessor`() {
        for (service in listOf("keycloak", "identity-onboarding")) {
            val source = requireNotNull(QualificationExecutionPolicy.predecessor(service,"HEADLESS","NATIVE"))
            assertEquals("WEB",source.surface)
            assertEquals("BROWSER",source.variant)
            assertEquals(setOf("browserSourceOracleFile","browserSourceOracleSha256",
                "browserSourceObservationFile","browserSourceObservationSha256"),source.fields)
            assertEquals(source.fields,source.restoreOriginalFields)
            val browser = QualificationExecutionPolicy.predecessor(service,"WEB","BROWSER")
            if (service == "keycloak") assertEquals(null,browser)
            else {
                val firstUse = requireNotNull(browser)
                assertEquals("keycloak",firstUse.service)
                assertEquals("WEB",firstUse.surface)
                assertEquals("BROWSER",firstUse.variant)
                assertEquals(source.fields,firstUse.fields)
                assertEquals(source.fields,firstUse.restoreOriginalFields)
            }
        }
    }
    @Test fun `ntfy WEB needs completed Keycloak owner but never future GROUP session fields`() {
        val prior = requireNotNull(QualificationExecutionPolicy.predecessor("ntfy","WEB","BROWSER"))
        assertEquals(Triple("keycloak","WEB","BROWSER"),
            Triple(prior.service,prior.surface,prior.variant))
        assertEquals(emptySet(),prior.fields)
        assertEquals(emptySet(),prior.restoreOriginalFields)
        assertEquals(null,QualificationExecutionPolicy.predecessor("ntfy","HEADLESS","NATIVE"))
    }
    @Test fun `Hub browser is the exact held four-field predecessor for both Notebook surfaces`() {
        val four = setOf("hubBrowserSourceOracleFile","hubBrowserSourceOracleSha256",
            "hubBrowserSourceObservationFile","hubBrowserSourceObservationSha256")
        for ((service,surface,variant) in listOf(Triple("jupyterhub","HEADLESS","NATIVE"),
            Triple("jupyter-notebook","HEADLESS","NATIVE"),
            Triple("jupyter-notebook","WEB","BROWSER"))) {
            val edge = requireNotNull(QualificationExecutionPolicy.predecessor(service,surface,variant))
            assertEquals(Triple("jupyterhub","WEB","BROWSER"),Triple(edge.service,edge.surface,edge.variant))
            assertEquals(four,edge.fields)
            assertEquals(four,edge.restoreOriginalFields)
        }
    }
    @Test fun `Firefly browser first use must follow the original native importer source`(): Unit {
        assertEquals(QualificationExecutionPolicy.Predecessor("firefly-iii", "HEADLESS", "NATIVE",
            setOf("sourceNativeOracleFile")),
            QualificationExecutionPolicy.predecessor("firefly-iii", "WEB", "BROWSER"))
        assertEquals(null, QualificationExecutionPolicy.predecessor("firefly-iii", "HEADLESS", "NATIVE"))
        assertEquals(QualificationExecutionPolicy.Predecessor("seafile", "HEADLESS", "NATIVE",
            setOf("sourceNativeOracleFile", "sourceNativeOracleSha256", "sourceNativeObservationFile",
                "sourceNativeObservationSha256")),
            QualificationExecutionPolicy.predecessor("seafile", "WEB", "BROWSER"))
        for (api in listOf("API34", "API36")) assertEquals(
            QualificationExecutionPolicy.predecessor("seafile", "WEB", "BROWSER"),
            QualificationExecutionPolicy.predecessor("seafile", "ANDROID", api))
        val office = QualificationExecutionPolicy.predecessor("onlyoffice", "HEADLESS", "NATIVE")!!
        assertEquals(setOf("browserSourceOracleFile", "browserSourceOracleSha256",
            "browserSourceObservationFile", "browserSourceObservationSha256"), office.fields)
        for (api in listOf("API34", "API36")) assertEquals(office,
            QualificationExecutionPolicy.predecessor("onlyoffice", "ANDROID", api))
        for (service in listOf("alertmanager", "prometheus", "qbittorrent")) {
            val source = requireNotNull(QualificationExecutionPolicy.predecessor(service,"WEB","BROWSER"))
            assertEquals("HEADLESS", source.surface)
            assertEquals("NATIVE", source.variant)
            assertEquals(setOf("sourceNativeOracleFile","sourceNativeOracleSha256",
                "sourceNativeObservationFile","sourceNativeObservationSha256"),source.fields)
            assertEquals(source.fields,source.restoreOriginalFields)
        }
        for (service in listOf("homeassistant", "jellyfin")) for (surface in listOf("WEB", "ANDROID")) {
            val source = QualificationExecutionPolicy.predecessor(service, surface,
                if (surface == "WEB") "BROWSER" else "API34")!!
            assertEquals(source.fields, source.restoreOriginalFields)
            assertEquals("HEADLESS", source.surface)
        }
        assertEquals(setOf("originalSocialOracleFile"),
            QualificationExecutionPolicy.predecessor("mastodon", "WEB", "BROWSER")!!.restoreOriginalFields)
    }
    @Test fun `ambiguous declaration and unknown surface refuse before effect`(): Unit {
        val d = definition("crowdsec", "HEADLESS", "NATIVE")
        assertFails { QualificationExecutionPolicy.select(manifest(d, d), "crowdsec", "HEADLESS", "NATIVE", "workflow") }
        val unknown = manifest(definition("crowdsec", "SHELL", "NATIVE"))
        assertFails { QualificationExecutionPolicy.select(unknown, "crowdsec", "SHELL", "NATIVE", "workflow") }
        assertFails { QualificationExecutionPolicy.select(manifest(d), "crowdsec", "HEADLESS", "NATIVE", "different") }
    }
}
