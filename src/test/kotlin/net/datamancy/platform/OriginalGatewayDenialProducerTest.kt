package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertFails

/** Contract is a future post-start producer, never an observed 403. */
class OriginalGatewayDenialProducerTest {
    @Test fun `declaration is exact and cannot alias the app denial or a native bypass`() {
        OriginalGatewayDenialProducer().validate()
        assertFails { OriginalGatewayDenialProducer(host = "donetick-native.datamancy.net").validate() }
        assertFails { OriginalGatewayDenialProducer(subject = "app-nonmember").validate() }
        assertFails { OriginalGatewayDenialProducer(artifact = "donetick-native-proof.json").validate() }
        assertFails { OriginalGatewayDenialProducer(phase = "RESTORE").validate() }
    }
}
