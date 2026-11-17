package net.datamancy.platform

/** Narrow CI job transport. The job must join only the account-owned *internal*
 * network; a separately acquired Caddy sidecar is dual-homed and is the only
 * peer with an outbound route to the already-private Forgejo ingress. This
 * Caddyfile alone cannot establish effective network isolation or image custody.
 * Native peer/network readback remains mandatory before enrolling a worker.
 */
internal object ForgejoCiTransportSource {
    fun validUpstream(value: String): Boolean = runCatching {
        val uri = java.net.URI(value)
        val host = requireNotNull(uri.host)
        val octets = host.split('.')
        val numbers = octets.map { it.toInt() }
        uri.scheme == "https" && uri.userInfo == null && uri.rawPath.isEmpty() &&
            uri.rawQuery == null && uri.rawFragment == null && uri.port in 1..65535 &&
            octets.size == 4 && octets.all { it.matches(Regex("(?:0|[1-9][0-9]{0,2})")) } &&
            numbers.all { it in 0..255 } &&
            (numbers[0] == 10 || numbers[0] == 192 && numbers[1] == 168 ||
                numbers[0] == 172 && numbers[1] in 16..31)
    }.getOrDefault(false)
    fun config(generation: String, caPath: String, privateUpstream: String): String {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            caPath == "/etc/ci/forgejo-ca.pem" && validUpstream(privateUpstream)) {
            "Explicit private, sealed Caddy ingress IP and port required; no public or DNS self-loop"
        }
        return """
            {
              auto_https off
              admin off
            }
            :443 {
              tls /etc/ci/forgejo-leaf.pem /etc/ci/forgejo-leaf-key.pem
              @forgejo host forgejo.datamancy.net
              handle @forgejo {
                reverse_proxy $privateUpstream {
                  header_up Host forgejo.datamancy.net
                  transport http {
                    tls_server_name forgejo.datamancy.net
                    tls_trust_pool file $caPath
                  }
                }
              }
              respond 403
            }
        """.trimIndent() + "\n"
    }
    fun internalNetwork(generation: String): String {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        return "p0v3-ci-$generation-internal"
    }
}
