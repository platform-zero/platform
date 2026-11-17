package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/** One ingress-host/trust projection of the selected r9 *module-owned* routes.
 * An application or acceptance case cannot invent books/finance/rtc aliases:
 * caller host authorization, TLS leaf, issuer CA, and Caddy socket topology are
 * derived from the same graph that renders effective Caddy routing.
 */
internal enum class PrivateIngressTrustMode { GRAPH_ISSUED_LEAF, POST_START_CADDY_CA }
internal data class PrivateIngressTrustBinding(val hostname: String, val product: String,
    val process: String?, val routePolicies: Set<String>, val routeLabels: Set<String>,
    val mode: PrivateIngressTrustMode,
    val leafInput: String?, val keyInput: String?, val caInput: String?,
    val caddyLeafTarget: String?, val caddyKeyTarget: String?)

internal object CanonicalPrivateIngressTrust {
    private val selectedLeaves = mapOf(
        "auth.datamancy.net" to listOf("identity-web.pem","identity-web-key.pem","identity-ca.pem",
            "/run/secrets/identity-web.pem","/run/secrets/identity-web-key.pem"),
        "office.datamancy.net" to listOf("onlyoffice-office-web.pem","onlyoffice-office-web-key.pem",
            "onlyoffice-office-ca.pem","/run/secrets/office-web.pem","/run/secrets/office-web-key.pem"),
        "files.datamancy.net" to listOf("seafile-web.pem","seafile-web-key.pem","seafile-ca.pem",
            "/run/secrets/files-web.pem","/run/secrets/files-web-key.pem"),
        "work.datamancy.net" to listOf("huly-web.pem","huly-web-key.pem","huly-ca.pem",
            "/run/secrets/work-web.pem","/run/secrets/work-web-key.pem"),
        "groupware.datamancy.net" to listOf("sogo-web.pem","sogo-web-key.pem","sogo-ca.pem",
            "/run/secrets/groupware-web.pem","/run/secrets/groupware-web-key.pem"),
        "firefly.datamancy.net" to listOf("finance-ingress-web.pem","finance-ingress-web-key.pem",
            "finance-ingress-ca.pem","/run/secrets/finance-ingress-web.pem",
            "/run/secrets/finance-ingress-web-key.pem"))
    fun project(manifest: CanonicalSharedManifest,spec: PrivateDeploymentSpec): Map<String,PrivateIngressTrustBinding> {
        require(manifest.revision in setOf(9, 10) && manifest.scope == "full-private" &&
            spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE)
        val routes=requireNotNull(manifest.integratedReference).modules.flatMap { module ->
            module.privateRoutes.map { route -> module.id to route }
        }
        val caddy=spec.processes.single { it.id == "caddy" }
        require(routes.isNotEmpty() && routes.map { it.second.host }.toSet().size in 35..70)
        val observed=routes.groupBy { it.second.host }
        return observed.mapValues { (hostname, owners) ->
            val distinct=owners.map { (product,route) -> product to route.process }.distinct()
            require(distinct.size == 1) { "One graph ingress hostname cannot have competing owners" }
            val (product,process)=distinct.single()
            val policies=owners.map { it.second.policy }.toSet()
            val labels=owners.map { it.second.label }.toSet()
            require(policies.isNotEmpty() && labels.size == owners.size)
            val leaf=selectedLeaves[hostname]
            if (leaf != null) {
                require(caddy.files.any { it.file == leaf[0] && it.target == leaf[3] } &&
                    caddy.files.any { it.file == leaf[1] && it.target == leaf[4] } &&
                    spec.processes.any { p -> p.files.any { it.file == leaf[2] } }) {
                    "Selected ingress leaf/issuer CA is not graph-owned"
                }
                PrivateIngressTrustBinding(hostname,product,process,policies,labels,
                    PrivateIngressTrustMode.GRAPH_ISSUED_LEAF,
                    leaf[0],leaf[1],leaf[2],leaf[3],leaf[4])
            } else PrivateIngressTrustBinding(hostname,product,process,policies,labels,
                PrivateIngressTrustMode.POST_START_CADDY_CA,null,null,null,null,null)
        }.also { bindings ->
            require(bindings.keys == routes.map { it.second.host }.toSet() &&
                setOf("bookstack.datamancy.net","api.bookstack.datamancy.net","firefly.datamancy.net",
                    "firefly-importer.datamancy.net","office.datamancy.net","files.datamancy.net",
                    "matrix-auth.datamancy.net","matrix-rtc.datamancy.net",
                    "work.datamancy.net","groupware.datamancy.net").all { it in bindings })
        }
    }
    /** Verify the *actual* generated generation inputs, not merely the names
     * of app fragment files or a source assertion about future certificate SANs.
     */
    fun requireSelectedCertificates(manifest: CanonicalSharedManifest,spec: PrivateDeploymentSpec,
        inputs: Map<String,String>) {
        val factory=CertificateFactory.getInstance("X.509")
        project(manifest,spec).values.filter { it.mode == PrivateIngressTrustMode.GRAPH_ISSUED_LEAF }
            .forEach { binding ->
                val leaf=factory.generateCertificate(ByteArrayInputStream(inputs.getValue(
                    requireNotNull(binding.leafInput)).toByteArray())) as X509Certificate
                val ca=factory.generateCertificate(ByteArrayInputStream(inputs.getValue(
                    requireNotNull(binding.caInput)).toByteArray())) as X509Certificate
                leaf.checkValidity(); ca.checkValidity()
                require(leaf.subjectAlternativeNames.orEmpty().any { it[0] == 2 && it[1] == binding.hostname } &&
                    leaf.basicConstraints < 0 && ca.basicConstraints >= 0 && ca.keyUsage?.getOrNull(5) == true &&
                    leaf.issuerX500Principal == ca.subjectX500Principal &&
                    ca.subjectX500Principal == ca.issuerX500Principal) {
                    "Selected ingress leaf/CA cannot authenticate its graph hostname"
                }
                ca.verify(ca.publicKey); leaf.verify(ca.publicKey)
                val encoded=inputs.getValue(requireNotNull(binding.keyInput))
                    .replace(Regex("-----BEGIN [A-Z ]+-----|-----END [A-Z ]+-----|\\s"),"")
                val key=KeyFactory.getInstance("RSA").generatePrivate(
                    PKCS8EncodedKeySpec(Base64.getDecoder().decode(encoded))) as RSAPrivateCrtKey
                require((leaf.publicKey as RSAPublicKey).modulus == key.modulus) {
                    "Selected ingress key does not match its graph hostname leaf"
                }
            }
    }
    fun requireHost(manifest: CanonicalSharedManifest,spec: PrivateDeploymentSpec,
        product: String, hostname: String): PrivateIngressTrustBinding =
        requireNotNull(project(manifest,spec)[hostname]?.takeIf { it.product == product }) {
            "Requested hostname is not authorized by this generation's module-owned ingress graph"
        }
    fun requireRoute(manifest: CanonicalSharedManifest,spec: PrivateDeploymentSpec,
        product: String, policy: String, hostname: String): PrivateIngressTrustBinding =
        requireHost(manifest,spec,product,hostname).also {
            require(policy in it.routePolicies) {
                "Requested host is not selected for this acceptance route policy"
            }
        }
    /** A direct container caller may use a graph-owned Caddy alias only on an
     * actual shared WEB network. Never attach the ingress proxy to a SQL/data
     * network merely to make a vanity hostname resolve inside another service.
     */
    fun requirePrivateCaller(manifest: CanonicalSharedManifest,spec: PrivateDeploymentSpec,
        product: String, hostname: String, caller: RuntimeProcess): PrivateIngressTrustBinding {
        require(caller in spec.processes && !caller.oneShot)
        val binding=requireHost(manifest,spec,product,hostname)
        val caddy=spec.processes.single { it.id == "caddy" }
        require(caddy.networkAliases.any { alias -> alias.host == hostname &&
            alias.network in caller.networks && alias.network in caddy.networks &&
            (alias.network.endsWith("-web") || alias.network == "identity-web") }) {
            "No graph-owned private ingress alias reachable by this caller"
        }
        return binding
    }
}
