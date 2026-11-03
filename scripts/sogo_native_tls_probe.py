#!/usr/bin/env python3
"""Call SOGo's actual SOPE TLS socket, without any authentication or mail writes."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import ctypes as C
import ipaddress
import json
import sys


def main():
    host, port, expected = sys.argv[1:]
    assert host == 'mail' or ipaddress.ip_address(host) in ipaddress.ip_network('10.89.0.0/16')
    assert port in ('2465', '2993') and expected in ('trusted', 'denied')
    C.CDLL('/usr/local/lib/libNGStreams.so', mode=C.RTLD_GLOBAL)
    objc = C.CDLL('libobjc.so.4', mode=C.RTLD_GLOBAL)
    objc.objc_getClass.argtypes = [C.c_char_p]; objc.objc_getClass.restype = C.c_void_p
    objc.sel_registerName.argtypes = [C.c_char_p]; objc.sel_registerName.restype = C.c_void_p
    objc.objc_msg_lookup.argtypes = [C.c_void_p, C.c_void_p]; objc.objc_msg_lookup.restype = C.c_void_p
    def send(receiver, selector, args=(), types=(), result=C.c_void_p):
        assert receiver
        sel = objc.sel_registerName(selector.encode())
        return C.CFUNCTYPE(result, C.c_void_p, C.c_void_p, *types)(objc.objc_msg_lookup(receiver, sel))(receiver, sel, *args)
    def cls(name):
        return objc.objc_getClass(name.encode())
    pool = send(send(cls('NSAutoreleasePool'), 'alloc'), 'init')
    name = send(cls('NSString'), 'stringWithUTF8String:', (host.encode(),), (C.c_char_p,))
    address = send(cls('NGInternetSocketAddress'), 'addressWithPort:onHost:', (int(port), name), (C.c_int, C.c_void_p))
    sock = send(send(cls('NGActiveSSLSocket'), 'alloc'), 'initWithDomain:onHostName:', (send(address, 'domain'), name), (C.c_void_p, C.c_void_p))
    send(sock, 'validatePeerCertificate:', (True,), (C.c_bool,), result=None)
    connected = send(sock, 'connectToAddress:', (address,), (C.c_void_p,), result=C.c_bool)
    assert connected == (expected == 'trusted'), 'Native SOPE TLS result mismatch'
    if connected:
        send(sock, 'close', result=None)
    send(sock, 'release', result=None); send(pool, 'drain', result=None)
    print(json.dumps({'nativeSopeTls': True, 'port': int(port), 'trusted': connected, 'credentialsSent': False}))


if __name__ == '__main__':
    main()
