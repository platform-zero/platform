package net.datamancy.platform

import kotlin.test.*

class QbittorrentRuntimeTest {
    private val image = "example.org/qbittorrent@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf(AcquiredImage("qbittorrent", "upstream",
        "example.org/qbittorrent:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")))

    @Test fun `native qBittorrent suppresses external discovery trackers and unrestricted host header`(): Unit {
        val original = QbittorrentRuntime.spec(inventory)
        val config = QbittorrentRuntime.inputs().getValue("qbittorrent.conf")
        assertTrue(original.processes.all { it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        for (disabled in listOf("Session\\DHTEnabled=false", "Session\\PeXEnabled=false",
            "Session\\LSDEnabled=false", "Connection\\UPnP=false", "WebUI\\HostHeaderValidation=true"))
            assertContains(config, disabled)
        assertContains(config, "WebUI\\ServerDomains=qbittorrent")
        assertFalse("torrents.datamancy.net" in config) // Legacy historical bytes remain unchanged.
        assertFails { QbittorrentRuntime.spec(inventory.copy(images = emptyList())) }
    }

    @Test fun `canonical torrent retains original download and session histories and exact public Host`(): Unit {
        val source = QbittorrentRuntime.canonicalFragment(inventory, "q-111111111111-qbittorrent")
        val inputs = QbittorrentRuntime.canonicalInputs()
        assertEquals(PrivateDeployment.inputNames(source.spec).toSet(), inputs.keys)
        assertContains(inputs.getValue("qbittorrent-qbittorrent.conf"),
            "WebUI\\ServerDomains=qbittorrent;torrents.datamancy.net")
        assertEquals(setOf("transfer-data", "transfer-web"), source.spec.networks.toSet())
        val cold = QbittorrentRuntime.coldRestoreFragment(source)
        assertEquals(source.spec.volumes, cold.spec.volumes)
        assertEquals(listOf("qbittorrent"), cold.spec.processes.map { it.id })
        assertEquals(listOf(RuntimeMount("config", "/config"), RuntimeMount("downloads", "/downloads")),
            cold.spec.processes.single().volumes)
        assertFalse(cold.spec.processes.any { it.oneShot })
        assertFails { QbittorrentRuntime.coldRestoreFragment(source.copy(spec = source.spec.copy(
            processes = source.spec.processes.filterNot { it.oneShot }))) }
    }
}
