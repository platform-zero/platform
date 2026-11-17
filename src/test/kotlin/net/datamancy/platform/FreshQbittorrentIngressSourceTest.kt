package net.datamancy.platform

import kotlin.test.*

class FreshQbittorrentIngressSourceTest {
    @Test fun `fresh native ingress and app config share exactly one password without daemon env exposure`() {
        val password = "a".repeat(64)
        val source = QbittorrentRuntime.freshCanonicalInputs(password, ByteArray(16) { it.toByte() })
        val config = source.getValue("qbittorrent-qbittorrent.conf")
        assertEquals("HOME=/config\nXDG_CONFIG_HOME=/config\nXDG_DATA_HOME=/config\n",
            source.getValue("qbittorrent-qbittorrent.env"))
        assertContains(config, "WebUI\\Username=p0v3-fixture")
        assertContains(config, "WebUI\\ServerDomains=qbittorrent;torrents.datamancy.net;qbittorrent-native.datamancy.net")
        assertContains(config, "WebUI\\Password_PBKDF2=\"${QbittorrentRuntime.passwordSetting(password, ByteArray(16) { it.toByte() })}\"")
        assertFalse(password in config || source.values.any { password in it })
        assertFailsWith<IllegalArgumentException> { QbittorrentRuntime.freshCanonicalInputs("bad") }
    }
}
