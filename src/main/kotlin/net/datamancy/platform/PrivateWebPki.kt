package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions

/** Ephemeral private TLS. For renewable identities use managed(); neither path modifies host trust. */
internal object PrivateWebPki {
    fun generate(host: String, dnsNames: List<String> = listOf(host), run: (Path, List<String>) -> Unit = ::openssl): Map<String, String> {
        require(host.matches(Regex("[a-z][a-z0-9-]{0,39}")))
        require(dnsNames.size in 1..8 && dnsNames.distinct() == dnsNames && host in dnsNames)
        require(dnsNames.all { it.length <= 128 && it.split('.').all { label -> label.matches(Regex("[a-z][a-z0-9-]{0,39}")) } })
        val root = Files.createTempDirectory("p0v3-web-pki-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            run(root, listOf("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "365",
                "-subj", "/CN=p0v3-private-$host-ca", "-keyout", "ca-key.pem", "-out", "ca.pem",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"))
            Files.writeString(root.resolve("web.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=${dnsNames.joinToString(",") { "DNS:$it" }}\n")
            run(root, listOf("req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256", "-subj", "/CN=$host",
                "-keyout", "web-key.pem", "-out", "web.csr"))
            run(root, listOf("x509", "-req", "-sha256", "-days", "365", "-in", "web.csr", "-CA", "ca.pem",
                "-CAkey", "ca-key.pem", "-CAcreateserial", "-extfile", "web.ext", "-out", "web.pem"))
            return listOf("ca.pem", "web.pem", "web-key.pem").associateWith { Files.readString(root.resolve(it)) }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    fun managed(authority: ManagedPrivatePki, operation: String, host: String, dnsNames: List<String> = listOf(host)): Map<String, String> =
        authority.issue(operation, PrivatePkiProfile(PrivatePkiKind.WEB, host, dnsNames)).material

    private fun openssl(root: Path, args: List<String>) = privatePkiOpenSsl(root, args)
}
