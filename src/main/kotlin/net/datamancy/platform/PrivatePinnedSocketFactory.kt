package net.datamancy.platform

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SNIServerName
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Per-client original-CID private bridge: keep URL hostname/SNI/PKIX intact,
 * change only TCP destination. No process/global DNS override and no proxy;
 * unrelated model API hosts still resolve normally. */
internal class PrivatePinnedSocketFactory(private val delegate: SSLSocketFactory,
    private val host: String, private val address: String) : SSLSocketFactory() {
    private val addressIp: InetAddress
    init {
        val octets=address.split('.').map { it.toIntOrNull() }
        require(host in setOf("auth.datamancy.net","keycloak","social.datamancy.net") &&
            octets.size==4 && octets.all { it != null && it in 0..255 })
        addressIp=InetAddress.getByAddress(octets.map { requireNotNull(it).toByte() }.toByteArray())
        require(addressIp.hostAddress==address && addressIp.isSiteLocalAddress)
    }
    private fun secure(socket:Socket):Socket = (socket as SSLSocket).also {
        it.sslParameters=it.sslParameters.apply {
            serverNames=listOf<SNIServerName>(SNIHostName(host))
            endpointIdentificationAlgorithm="HTTPS"
        }
    }
    override fun getDefaultCipherSuites():Array<String> = delegate.defaultCipherSuites
    override fun getSupportedCipherSuites():Array<String> = delegate.supportedCipherSuites
    override fun createSocket():Socket =
        throw IllegalArgumentException("Private original-host transport refuses unbound or DNS-resolved sockets")
    private fun dial(port:Int,local:InetAddress?=null,localPort:Int=0):Socket {
        require(port in setOf(443,8443))
        val tcp=Socket()
        try {
            if(local!=null) tcp.bind(InetSocketAddress(local,localPort))
            tcp.connect(InetSocketAddress(addressIp,port),2000)
            return secure(delegate.createSocket(tcp,host,port,true))
        } catch (failure: Exception) {
            tcp.close()
            throw failure
        }
    }
    override fun createSocket(hostname:String,port:Int):Socket {
        require(hostname==host)
        return dial(port)
    }
    override fun createSocket(hostname:String,port:Int,local:InetAddress,localPort:Int):Socket {
        require(hostname==host)
        return dial(port,local,localPort)
    }
    override fun createSocket(address:InetAddress,port:Int):Socket =
        throw IllegalArgumentException("Private original-host transport refuses DNS-resolved socket endpoints")
    override fun createSocket(address:InetAddress,port:Int,local:InetAddress,localPort:Int):Socket =
        throw IllegalArgumentException("Private original-host transport refuses DNS-resolved socket endpoints")
    override fun createSocket(socket:Socket,hostname:String,port:Int,autoClose:Boolean):Socket {
        require(hostname==host && port in setOf(443,8443) &&
            socket.inetAddress.hostAddress==address && socket.port==port)
        return secure(delegate.createSocket(socket,host,port,autoClose))
    }
}
