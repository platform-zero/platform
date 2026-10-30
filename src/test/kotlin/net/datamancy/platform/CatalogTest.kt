package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CatalogTest {
    @Test fun `inventory is complete but claims no deployment`() {
        val catalog = ServiceCatalog.bundled()
        assertEquals(89, catalog.serviceIds.size)
        assertEquals(46, catalog.modules.size) // Only 46 module names were supplied with the 89 IDs.
        assertEquals(listOf("android-test-runner-api34", "android-test-runner-api36", "test-runner", "test-runner-managed"),
            catalog.modules.single { it.id == "test-runners" }.services)
        assertTrue("firefly-native-api" in catalog.serviceIds)
        assertTrue("volume-init" in catalog.serviceIds)
    }

    @Test fun `duplicate service IDs are refused`() {
        val catalog = ServiceCatalog(1, listOf(ServiceModule("app", List(89) { "same" })))
        assertFailsWith<IllegalArgumentException> { catalog.validate() }
    }

    @Test fun `missing IDs are refused`() {
        assertFailsWith<IllegalArgumentException> {
            ServiceCatalog(1, listOf(ServiceModule("app", listOf("app")))).validate()
        }
    }
}
