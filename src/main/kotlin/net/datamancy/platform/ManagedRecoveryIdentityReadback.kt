package net.datamancy.platform

import java.net.URLEncoder
import java.nio.file.Path
import java.util.Base64
import kotlinx.serialization.json.*

/** Fresh HTTPS readbacks of the target issuer after the original admin revision.
 * JWT claims are observational; their source is the CID+CA+leaf-pinned native
 * token endpoint, never an injected token or an offline source renderer. */
internal object ManagedRecoveryIdentityReadback {
    private fun encode(value:String)=URLEncoder.encode(value,Charsets.UTF_8)
    private fun form(vararg values:Pair<String,String>):ByteArray=values.joinToString("&") {
        "${encode(it.first)}=${encode(it.second)}" }.toByteArray()
    private fun claims(bearer:String):JsonObject {
        require(bearer.length in 80..8192 && bearer.split('.').size==3)
        return Json.parseToJsonElement(Base64.getUrlDecoder().decode(bearer.split('.')[1])
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
    }
    fun token(http:ManagedRevisionHttp,id:String,secret:String,generation:String,subject:String):String {
        require(id in setOf("managed-lane-agent","managed-lane-reader") && secret.length in 16..4096)
        val (code,data)=http.request("POST","/realms/p0v3/protocol/openid-connect/token",null,
            form("grant_type" to "client_credentials","client_id" to id,"client_secret" to secret))
        require(code==200 && data.size in 80..16384) { "Expected a genuine target-native client grant" }
        val result=Json.parseToJsonElement(data.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val bearer=result.getValue("access_token").jsonPrimitive.content
        val jwt=claims(bearer)
        require(jwt["sub"]?.jsonPrimitive?.content==subject && jwt["azp"]?.jsonPrimitive?.content==id &&
            jwt["iss"]?.jsonPrimitive?.content=="https://auth.datamancy.net/realms/p0v3" &&
            jwt["p0v3_generation"]?.jsonPrimitive?.content==generation &&
            jwt["exp"]?.jsonPrimitive?.longOrNull?.let { it>java.time.Instant.now().epochSecond }==true)
        return bearer
    }
    fun verify(bundle:GenerationBundle,root:Path,expected:String,source:GenerationBundle,
        http:ManagedRevisionHttp,sourceTokens:List<String>):Boolean {
        require(sourceTokens.size==2 && bundle.recoverySourceKopia!=null &&
            root==GenerationRuntime.BASE.resolve(bundle.request.id) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304))==expected)
        val sourceHost=requireNotNull(source.request.managedLanes?.native?.brokerHost)
        val target=requireNotNull(bundle.request.managedLanes);val host=requireNotNull(target.native.brokerHost)
        val ids=listOf("managed-lane-agent","managed-lane-reader")
        val subjects=listOf(target.lanes.first().subject,requireNotNull(target.readerSubject))
        for((index,id) in ids.withIndex()) {
            val old=sourceHost.secret(if(index==0) sourceHost.agentSecret else sourceHost.readerSecret,
                source.request.id)
            val (oldCode,_)=http.request("POST","/realms/p0v3/protocol/openid-connect/token",null,
                form("grant_type" to "client_credentials","client_id" to id,"client_secret" to old))
            require(oldCode==401) { "Imported source client secret still issues target tokens" }
            val fresh=host.secret(if(index==0) host.agentSecret else host.readerSecret,bundle.request.id)
            val bearer=token(http,id,fresh,bundle.request.id,subjects[index])
            // Keycloak native introspection (authenticated by the newly rotated
            // confidential client) must reject the exact pre-revision source token.
            val (introspectionCode,raw)=http.request("POST",
                "/realms/p0v3/protocol/openid-connect/token/introspect",null,
                form("token" to sourceTokens[index],"client_id" to id,"client_secret" to fresh))
            require(introspectionCode==200 && raw.size in 2..16384 &&
                Json.parseToJsonElement(raw.decodeToString(throwOnInvalidSequence=true)).jsonObject
                    .getValue("active").jsonPrimitive.boolean==false) {
                "Old source bearer remains active in restored target after native revocation"
            }
            if(index==1) {
                val (status,body)=http.request("GET","/admin/realms/p0v3/users/${subjects[0]}",bearer)
                require(status==200 && Json.parseToJsonElement(body.decodeToString(throwOnInvalidSequence=true))
                    .jsonObject.getValue("id").jsonPrimitive.content==subjects[0])
            }
        }
        return true
    }
}
