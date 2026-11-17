package net.datamancy.platform

import java.util.UUID

/** Core-owned immutable source projection for the selected r9 Keykeeper.
 * The Bao-derived token is deliberately ABSENT from prepared inputs. A
 * separately result-bound keeper-bao-late.env is created only at native
 * dependency readiness, never by rewriting keeper.env or its sealed hash.
 */
internal object CanonicalR9LateKeeperInputs {
    fun project(generation: String, introspectionSecret: String, agentSubjects: Set<String>,
        keeperPki: Map<String,String>, identityCa: String, baoCa: String): Map<String,String> {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) && introspectionSecret.isNotBlank() &&
            agentSubjects.isNotEmpty() && agentSubjects.all {
                runCatching { UUID.fromString(it).toString()==it }.getOrDefault(false)
            } && keeperPki.keys==setOf("ca.pem","web.pem","web-key.pem"))
        val environment="KEYKEEPER_GENERATION_ID=$generation\nKEYKEEPER_OIDC_ISSUER=https://auth.datamancy.net/realms/p0v3\n" +
            "KEYKEEPER_OIDC_AUDIENCE=keykeeper\nKEYKEEPER_OIDC_HUMAN_CLIENT=keykeeper-human\n" +
            "KEYKEEPER_OIDC_AGENT_CLIENT=keykeeper-agent\nKEYKEEPER_OIDC_AGENT_SUBJECTS=${agentSubjects.sorted().joinToString(",")}\n" +
            "KEYKEEPER_OIDC_INTROSPECTION_CLIENT=keykeeper-introspection\n" +
            "KEYKEEPER_OIDC_INTROSPECTION_SECRET=$introspectionSecret\n" +
            "KEYKEEPER_BAO_URL=https://bao:8200\nKEYKEEPER_BAO_MOUNT=keykeeper\n" +
            "KEYKEEPER_BAO_REMOTE_HTTPS=true\n" +
            "KEYKEEPER_PORT=8443\nKEYKEEPER_PUBLIC_ORIGIN=https://keykeeper.datamancy.net\n" +
            "KEYKEEPER_PROBE_ORIGIN=https://keeper:8443\n" +
            "KEYKEEPER_TLS_CERTIFICATE=/run/secrets/keeper-web.pem\n" +
            "KEYKEEPER_TLS_PRIVATE_KEY=/run/secrets/keeper-web-key.pem\n" +
            "KEYKEEPER_URL=https://keykeeper.datamancy.net\nKEYKEEPER_REMOTE_HTTPS=true\n" +
            "JAVA_TOOL_OPTIONS=-Djavax.net.ssl.trustStore=/trust/trust.p12 -Djavax.net.ssl.trustStorePassword=changeit\nHOME=/tmp\n"
        return mapOf("keeper.env" to environment,"identity-ca.pem" to identityCa,"bao-ca.pem" to baoCa,
            "keeper-ca.pem" to keeperPki.getValue("ca.pem"),"keeper-web.pem" to keeperPki.getValue("web.pem"),
            "keeper-web-key.pem" to keeperPki.getValue("web-key.pem"))
    }
}
