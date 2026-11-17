package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions

/** Per-deployment test PKI. No shared trust installation; the temporary issuing key is not retained. */
internal object PrivateSearchPki {
    fun generate(host: String = "opensearch", nodeSubject: String = host, clientSubject: String = "p0v3-admin",
                 freshReader: Boolean = false, run: (Path, List<String>) -> Unit = ::openssl): Map<String, String> {
        require(listOf(host, nodeSubject, clientSubject).all { it.matches(Regex("[a-z][a-z0-9-]{0,39}")) })
        val root = Files.createTempDirectory("p0v3-search-pki-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            run(root, listOf("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "365",
                "-subj", "/CN=p0v3-private-search-ca", "-keyout", "ca-key.pem", "-out", "ca.pem",
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"))
            for ((id, subject) in listOf("node" to nodeSubject, "admin" to clientSubject) +
                if (freshReader) listOf("reader" to "p0v3-caddy-reader") else emptyList()) {
                Files.writeString(root.resolve("$id.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n" +
                    "extendedKeyUsage=" + (if (id == "node") "serverAuth,clientAuth\nsubjectAltName=DNS:$host\n" else "clientAuth\n"))
                run(root, listOf("req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256", "-subj", "/CN=$subject",
                    "-keyout", "$id-key.pem", "-out", "$id.csr"))
                run(root, listOf("x509", "-req", "-sha256", "-days", "365", "-in", "$id.csr", "-CA", "ca.pem",
                    "-CAkey", "ca-key.pem", "-CAcreateserial", "-extfile", "$id.ext", "-out", "$id.pem"))
            }
            return (listOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem") +
                if (freshReader) listOf("reader.pem", "reader-key.pem") else emptyList()).associateWith {
                Files.readString(root.resolve(it))
            }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    fun managed(authority: ManagedPrivatePki, operation: String, host: String = "opensearch",
        nodeSubject: String = host, clientSubject: String = "p0v3-admin"): Map<String, String> =
        authority.issue(operation, PrivatePkiProfile(PrivatePkiKind.SEARCH, host, nodeSubject = nodeSubject, clientSubject = clientSubject)).material

    private fun openssl(root: Path, args: List<String>) = privatePkiOpenSsl(root, args)
}
