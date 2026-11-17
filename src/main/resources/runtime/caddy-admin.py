"""Pinned-controller helper: bounded Caddy admin or fixed original-host HTTPS client.
No shell, arbitrary destination, container file execution, DNS, host admin exposure, or write replay.
"""
if not __debug__:
    raise SystemExit("Optimized ingress helper refused before imports or effects")
import base64
import ctypes
import http.client
import hashlib
import ipaddress
import json
import os
import re
import resource
import signal
import socket
import ssl
import sys
from urllib.parse import quote

MAXIMUM = 4 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def enter_namespace(pid, container_id):
    require(os.geteuid() == 0, "namespace helper requires root")
    # Pin the namespace before inspecting identity. A later PID exit/reuse cannot redirect the FD.
    descriptor = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
    try:
        with open(f"/proc/{pid}/cgroup", "r", encoding="ascii") as stream:
            cgroups = stream.read(65537)
        require(len(cgroups) <= 65536 and re.search(r"(?<![a-f0-9])" + re.escape(container_id) + r"(?![a-f0-9])", cgroups),
                "PID does not belong to audited container")
        require(os.fstat(descriptor).st_ino == os.stat(f"/proc/{pid}/ns/net").st_ino, "PID namespace changed")
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.setns(descriptor, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot enter pinned network namespace")
    finally:
        os.close(descriptor)


def exchange(request, enter=enter_namespace, connection=http.client.HTTPConnection):
    require(set(request) == {"pid", "containerId", "method", "path", "etag", "body"}, "invalid helper protocol")
    pid, container_id = request["pid"], request["containerId"]
    require(type(pid) is int and 1 < pid <= 2147483647 and isinstance(container_id, str) and
            re.fullmatch(r"[a-f0-9]{64}", container_id), "invalid audited target")
    method, path, etag = request["method"], request["path"], request["etag"]
    body = None if request["body"] is None else base64.b64decode(request["body"], validate=True)
    read = method == "GET" and path == "/config/" and etag is None and body is None
    mutation = ((method == "POST" and path == "/config/") or
                (method == "PATCH" and re.fullmatch(r"/config/apps/http/servers/[a-z][a-z0-9-]{0,63}/routes", path)))
    require(read or (mutation and isinstance(etag, str) and re.fullmatch(r'"/config/ [a-f0-9]{16}"', etag)
                    and body is not None and 1 <= len(body) <= MAXIMUM), "unapproved Caddy request")
    enter(pid, container_id)
    client = connection("127.0.0.1", 2019, timeout=10)
    try:
        headers = {} if etag is None else {"If-Match": etag, "Content-Type": "application/json"}
        client.request(method, path, body=body, headers=headers)
        response = client.getresponse()
        data = response.read(MAXIMUM + 1)
        require(len(data) <= MAXIMUM, "Caddy body exceeds bound")
        return {"status": response.status, "etag": response.getheader("ETag"), "body": base64.b64encode(data).decode("ascii")}
    finally:
        client.close()


def _confine_private_client(port=443):
    """A root namespace entry is immediately reduced to an unprivileged, port-443-only client.

    Linux Landlock ABI 4+ is mandatory: even compromised request handling cannot connect to
    Caddy's privileged loopback admin on 2019 or create another network client. No fallback.
    """
    require(type(port) is int and port in (443, 3100, 3500, 9100, 9200, 8443),
            "only reviewed Caddy, Loki, Alloy, node, OpenSearch and CrowdSec TCP ports may be accessed")
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    PR_SET_NO_NEW_PRIVS, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 38, 47, 4
    require(libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == 0 and
            libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "cannot discard ambient capability or gain privilege")
    SYS_LANDLOCK_CREATE_RULESET, SYS_LANDLOCK_ADD_RULE, SYS_LANDLOCK_RESTRICT_SELF = 444, 445, 446
    LANDLOCK_CREATE_RULESET_VERSION, LANDLOCK_RULE_NET_PORT = 1, 2
    LANDLOCK_ACCESS_NET_BIND_TCP, LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 0, 1 << 1
    abi = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    require(abi >= 4, "Landlock network ABI required; no unconfined namespace client")

    class Ruleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]

    class Port(ctypes.Structure):
        _fields_ = [("allowed_access", ctypes.c_uint64), ("port", ctypes.c_uint64)]

    ruleset = Ruleset(0, LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP)
    fd = libc.syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0)
    require(fd >= 0, "cannot create network confinement")
    try:
        allowed = Port(LANDLOCK_ACCESS_NET_CONNECT_TCP, port)
        require(libc.syscall(SYS_LANDLOCK_ADD_RULE, fd, LANDLOCK_RULE_NET_PORT,
                             ctypes.byref(allowed), 0) == 0 and
                libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0) == 0,
                "cannot restrict namespace client to its single reviewed provider TCP port")
    finally:
        os.close(fd)
    os.setgroups([])
    os.setresgid(65534, 65534, 65534)
    os.setresuid(65534, 65534, 65534)
    require(os.geteuid() == 65534 and os.getegid() == 65534, "namespace client privilege drop failed")


def _tls_client(socket, host, ca):
    context = ssl.create_default_context(cadata=ca)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    return context.wrap_socket(socket, server_hostname=host)


def private_client(request, enter=enter_namespace, confine=_confine_private_client,
                   connection=http.client.HTTPConnection, tls=_tls_client):
    expected = {"operation", "operationId", "pid", "containerId", "clientNetwork", "address", "host",
                "caPem", "leafSha256", "method", "path", "token", "body", "phaseClaimSha256",
                "caseClaimSha256", "invocationId", "phase", "account", "botAccount", "idempotencyKey"}
    require(set(request) == expected and request["operation"] == "private-client", "fixed private client protocol required")
    require(type(request["pid"]) is int and 1 < request["pid"] <= 2147483647 and
            isinstance(request["containerId"], str) and re.fullmatch(r"[a-f0-9]{64}", request["containerId"]) and
            isinstance(request["operationId"], str) and re.fullmatch(r"r-[a-f0-9]{12}", request["operationId"]) and
            isinstance(request["clientNetwork"], str) and re.fullmatch(r"[a-z][a-z0-9-]{0,39}", request["clientNetwork"]) and
            isinstance(request["invocationId"], str) and re.fullmatch(r"case-[a-f0-9-]{36}", request["invocationId"]) and
            all(isinstance(request[name], str) and re.fullmatch(r"[a-f0-9]{64}", request[name])
                for name in ("leafSha256", "phaseClaimSha256", "caseClaimSha256")),
            "unbound private client or qualification claim")
    address = request["address"]
    require(isinstance(address, str) and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", address), "numeric client IP required")
    ip = ipaddress.IPv4Address(address)
    require(ip in ipaddress.ip_network("10.0.0.0/8") or ip in ipaddress.ip_network("172.16.0.0/12") or
            ip in ipaddress.ip_network("192.168.0.0/16"), "only an audited private network is reachable")
    require(request["host"] == "social.datamancy.net" and request["phase"] == "RESTORE" and
            isinstance(request["account"], str) and
            (re.fullmatch(r"rss_[a-z0-9_]+", request["account"]) or
             re.fullmatch(r"rssq_[a-f0-9]{12}", request["account"])) and
            isinstance(request["botAccount"], str) and (request["botAccount"] == "" or
                re.fullmatch(r"rssq_[a-f0-9]{12}", request["botAccount"])) and
            request["method"] == "GET" and isinstance(request["path"], str) and
            (request["path"] == "/api/v1/accounts/verify_credentials" or
             re.fullmatch(r"/api/v1/statuses/[0-9]{1,32}(?:/source)?", request["path"])),
            "foreign hostname or non-synthetic Mastodon route")
    token, ca = request["token"], request["caPem"]
    require(isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9._~+/-]{20,2048}", token) and
            isinstance(ca, str) and 1 <= len(ca) <= 65536 and "-----BEGIN CERTIFICATE-----" in ca,
            "invalid private TLS trust or scoped bot bearer")
    body = None if request["body"] is None else base64.b64decode(request["body"], validate=True)
    require(body is None and request["idempotencyKey"] is None and
            (request["botAccount"] == "" or request["botAccount"] == request["account"]),
            "RESTORE read-only client cannot carry a synthetic POST or a different principal")
    # No socket, DNS or route effects before the independently verified namespace entry and
    # irreversible capability/UID + Landlock drop. The only dial is the exact client-interface IP.
    enter(request["pid"], request["containerId"])
    confine()
    client = connection(address, 443, timeout=10)
    try:
        client.connect()
        client.sock = tls(client.sock, request["host"], ca)
        cert = client.sock.getpeercert(binary_form=True)
        require(hashlib.sha256(cert).hexdigest() == request["leafSha256"], "original source TLS leaf changed")
        headers = {"Host": request["host"], "Authorization": "Bearer " + token,
                   "Accept": "application/json", "Connection": "close"}
        client.request("GET", request["path"], body=None, headers=headers)
        response = client.getresponse()
        data = response.read(1024 * 1024 + 1)
        require(len(data) <= 1024 * 1024 and 100 <= response.status <= 599, "private response bound exceeded")
        return {"operationId": request["operationId"], "phaseClaimSha256": request["phaseClaimSha256"],
                "caseClaimSha256": request["caseClaimSha256"], "clientProcessId": os.getpid(),
                "clientNetworkInode": os.stat("/proc/self/ns/net").st_ino, "status": response.status,
                "leafSha256": request["leafSha256"], "body": base64.b64encode(data).decode("ascii")}
    finally:
        client.close()


def _native_listeners():
    bindings = {80: set(), 443: set()}
    with open("/proc/net/tcp", "r", encoding="ascii") as stream:
        data = stream.read(131073)
    require(len(data) <= 131072, "unbounded native socket inventory")
    for line in data.splitlines()[1:]:
        fields = line.split()
        require(len(fields) >= 4, "malformed native socket state")
        address, port = fields[1].split(":", 1)
        require(re.fullmatch(r"[0-9A-Fa-f]{8}", address) and re.fullmatch(r"[0-9A-Fa-f]{4}", port),
                "malformed native TCP address")
        native_port = int(port, 16)
        if native_port in bindings and fields[3] == "0A":
            bindings[native_port].add(socket.inet_ntoa(bytes.fromhex(address)[::-1]))
    with open("/proc/net/tcp6", "r", encoding="ascii") as stream:
        ipv6 = stream.read(131073)
    require(len(ipv6) <= 131072, "unbounded native IPv6 socket inventory")
    for line in ipv6.splitlines()[1:]:
        fields = line.split()
        require(len(fields) >= 4, "malformed native IPv6 socket state")
        if fields[3] == "0A":
            require(int(fields[1].split(":", 1)[1], 16) not in bindings,
                    "public listener escaped to wildcard or IPv6 address")
    return bindings


def _listener_target(request, operation, extra, enter):
    require(set(request) == {"operation", "pid", "containerId", "address"} | extra and
            request["operation"] == operation and type(request["pid"]) is int and
            1 < request["pid"] <= 2147483647 and isinstance(request["containerId"], str) and
            re.fullmatch(r"[a-f0-9]{64}", request["containerId"]) and
            isinstance(request["address"], str) and
            re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", request["address"]),
            "invalid native listener audit")
    ip = ipaddress.IPv4Address(request["address"])
    require(ip.is_private and not ip.is_loopback and not ip.is_link_local,
            "listener must be on an audited private interface")
    enter(request["pid"], request["containerId"])
    return ip, _native_listeners()


def audit_public_listeners(request, enter=enter_namespace):
    require("requireHttps" in request and type(request["requireHttps"]) is bool,
            "invalid HTTPS listener phase")
    ip, bindings = _listener_target(request, "audit-public-listeners", {"requireHttps"}, enter)
    require(bindings[80] == {str(ip)} and
            (str(ip) in bindings[443] if request["requireHttps"] else str(ip) not in bindings[443]) and
            "0.0.0.0" not in bindings[443], "native public HTTP/HTTPS listener is not pinned to primary ingress IP")
    return {"address": str(ip), "http": sorted(bindings[80]), "https": sorted(bindings[443]),
            "networkInode": os.stat("/proc/self/ns/net").st_ino}


def audit_internal_listener(request, enter=enter_namespace):
    ip, bindings = _listener_target(request, "audit-internal-listener", set(), enter)
    require(str(ip) in bindings[443] and str(ip) not in bindings[80] and
            "0.0.0.0" not in bindings[443] and "0.0.0.0" not in bindings[80],
            "private internal Caddy listener is absent or wildcard")
    return {"address": str(ip), "http": sorted(bindings[80]), "https": sorted(bindings[443]),
            "networkInode": os.stat("/proc/self/ns/net").st_ino}


def audit_absent_internal_listener(request, enter=enter_namespace):
    ip, bindings = _listener_target(request, "audit-absent-internal-listener", set(), enter)
    require(str(ip) not in bindings[443] and str(ip) not in bindings[80] and
            "0.0.0.0" not in bindings[443] and "0.0.0.0" not in bindings[80],
            "private client listener remains bound; source resume forbidden")
    return {"address": str(ip), "http": sorted(bindings[80]), "https": sorted(bindings[443]),
            "networkInode": os.stat("/proc/self/ns/net").st_ino}


def _native_client_alert(request, error):
    text = str(error).lower()
    code = next((name for name in ("certificate_required", "bad_certificate", "handshake_failure")
                 if name in text.replace(" ", "_")), None)
    require(code is not None and isinstance(error, ssl.SSLError),
            "only an actual TLS client-certificate alert can deny native exporter access")
    return {"status": 0, "responseKind": "TLS_ALERT", "body": base64.b64encode(json.dumps({
        "alertCode": code, "errorType": type(error).__name__,
        "expectedServerLeafSha256": request["leafSha256"],
        "targetContainerId": request["containerId"], "targetPid": request["pid"],
        "targetNetnsInode": request["netnsInode"], "caseClaimSha256": request["caseClaimSha256"],
        "path": "/metrics", "clientCertificateSupplied": False,
        "operationId": request["operationId"]}, sort_keys=True).encode()).decode(),
        "containerId": request["containerId"], "pid": request["pid"],
        "netnsInode": os.stat("/proc/self/ns/net").st_ino,
        "clientPid": os.getpid()}


def native_qualification(request, enter=enter_namespace, confine=_confine_private_client):
    """Exact A11 local-only socket in an audited REAL provider namespace. Never Caddy,
    never arbitrary process/host/path, RESTORE POST, or a caller-authored proof result.
    A QClient-denied foreign network probe is a distinct controller capability.
    """
    fields = {"operation", "operationId", "pid", "containerId", "netnsInode", "invocationId",
              "caseClaimSha256", "requestSha256", "serviceId", "processId", "phase", "assertion", "method",
              "path", "address", "port", "host", "caPem", "leafSha256", "clientCert",
              "clientKey", "authorization", "authorizationMode", "body"}
    require(set(request) == fields and request["operation"] == "native-qualification" and
            isinstance(request["operationId"], str) and re.fullmatch(r"nq-[a-f0-9]{12}", request["operationId"]) and
            isinstance(request["invocationId"], str) and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", request["invocationId"]) and
            type(request["pid"]) is int and 1 < request["pid"] <= 2147483647 and
            type(request["netnsInode"]) is int and request["netnsInode"] > 1 and
            isinstance(request["containerId"], str) and re.fullmatch(r"[a-f0-9]{64}", request["containerId"]) and
            isinstance(request["requestSha256"], str) and re.fullmatch(r"[a-f0-9]{64}", request["requestSha256"]) and
            isinstance(request["caseClaimSha256"], str) and re.fullmatch(r"[a-f0-9]{64}", request["caseClaimSha256"]),
            "unbound original native provider request")
    service, target = request["serviceId"], request["processId"]
    port, host, phase = request["port"], request["host"], request["phase"]
    path, method, assertion = request["path"], request["method"], request["assertion"]
    require(phase in ("INSTALL", "RESTORE") and
            assertion in ("POSITIVE", "TLS_CLIENT_DENIAL") and
            request["authorization"] is None and request["authorizationMode"] == "NONE" and
            isinstance(request["address"], str) and
            re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", request["address"]) and
            ipaddress.IPv4Address(request["address"]).is_private and
            not ipaddress.IPv4Address(request["address"]).is_loopback and
            not ipaddress.IPv4Address(request["address"]).is_link_local,
            "native helper can reach only one audited private provider address")
    loki = ((service == "loki" or service == "alloy" and target == "loki") and target == "loki" and
            port == 3100 and host == "loki" and method == "GET" and
            isinstance(path, str) and re.fullmatch(r"/loki/api/v1/query_range\?query=%7Bjob%3D%22p0v3-acceptance%22%2Crun%3D%22obs-[a-f0-9]{12}%22%7D&start=[1-9][0-9]{0,20}&end=[1-9][0-9]{0,20}&limit=10", path))
    alloy = (service == target == "alloy" and port == 3500 and host == "alloy" and
             phase == "INSTALL" and assertion == "POSITIVE" and method == "POST" and
             path == "/loki/api/v1/push")
    node = (service == "node-exporter" and target == "node" and port == 9100 and
            host == "node" and method == "GET" and path == "/metrics")
    require(loki or alloy or node, "foreign private target, cross-product read or RESTORE mutation")
    require(assertion != "TLS_CLIENT_DENIAL" or node, "only real node exporter mTLS can deny a client handshake")
    encoded = request["body"]
    body = None if encoded is None else base64.b64decode(encoded, validate=True)
    require((alloy and body is not None and 0 < len(body) <= 1024 * 1024) or
            (not alloy and body is None), "only original synthetic owned Alloy log may be sent")
    require((node and isinstance(request["caPem"], str) and
             1 <= len(request["caPem"]) <= 65536 and "-----BEGIN CERTIFICATE-----" in request["caPem"] and
             isinstance(request["leafSha256"], str) and re.fullmatch(r"[a-f0-9]{64}", request["leafSha256"])) or
            (not node and request["caPem"] is None and request["leafSha256"] is None),
            "node identity requires pinned original CA and TLS leaf")
    require((not node and request["clientCert"] is None and request["clientKey"] is None) or
            (node and assertion == "TLS_CLIENT_DENIAL" and request["clientCert"] is None and request["clientKey"] is None) or
            (node and assertion == "POSITIVE" and all(isinstance(request[k], str) and
                1 <= len(request[k]) <= 65536 and "-----BEGIN " in request[k]
                for k in ("clientCert", "clientKey"))),
            "original mTLS client certificate and key cannot be forged or omitted")
    # Namespace FD and ownership before the FIRST network socket, then Landlock on precisely
    # this provider port and irreversible UID/GID/group/capability drop (no fallback).
    enter(request["pid"], request["containerId"])
    require(os.stat("/proc/self/ns/net").st_ino == request["netnsInode"],
            "native helper entered a different provider namespace")
    confine(port)
    raw = socket.create_connection((request["address"], port), timeout=8)
    tls_socket = None
    try:
        if node:
            context = ssl.create_default_context(cadata=request["caPem"])
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            if assertion == "POSITIVE":
                import tempfile
                with tempfile.TemporaryDirectory(prefix="p0v3-native-mtls-") as directory:
                    cert = os.path.join(directory, "client.pem")
                    key = os.path.join(directory, "client-key.pem")
                    for name, value in ((cert, request["clientCert"]), (key, request["clientKey"])):
                        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                            stream.write(value)
                    context.load_cert_chain(cert, key)
            try:
                tls_socket = context.wrap_socket(raw, server_hostname="node")
                observed_leaf = hashlib.sha256(tls_socket.getpeercert(binary_form=True)).hexdigest()
                require(observed_leaf == request["leafSha256"], "original node TLS identity changed")
            except (ssl.SSLError, ConnectionResetError) as error:
                if assertion != "TLS_CLIENT_DENIAL": raise
                return _native_client_alert(request, error)
            if assertion == "TLS_CLIENT_DENIAL":
                # TLS 1.3 may alert after the handshake at first application write/read.
                try:
                    tls_socket.sendall(b"GET /metrics HTTP/1.1\r\nHost: node\r\nConnection: close\r\n\r\n")
                    response = tls_socket.recv(1)
                except (ssl.SSLError, ConnectionResetError) as error:
                    return _native_client_alert(request, error)
                raise ValueError("node accepted a no-client-certificate request")
        client = http.client.HTTPConnection(request["address"], port, timeout=8)
        client.sock = tls_socket if node else raw
        headers = {"Host": host, "Connection": "close"}
        if alloy: headers["Content-Type"] = "application/json"
        client.request(method, path, body=body, headers=headers)
        reply = client.getresponse()
        result = reply.read(1024 * 1024 + 1)
        require(200 <= reply.status <= 299 and len(result) <= 1024 * 1024,
                "positive native source response missing or unbounded")
        return {"status": reply.status, "responseKind": "HTTP", "body": base64.b64encode(result).decode(),
                "serverLeafSha256": observed_leaf if node else None,
                "containerId": request["containerId"], "pid": request["pid"],
                "netnsInode": os.stat("/proc/self/ns/net").st_ino,
                "clientPid": os.getpid()}
    finally:
        if tls_socket is not None: tls_socket.close()
        else: raw.close()


def opensearch_qualification(request, enter=enter_namespace, confine=_confine_private_client):
    """A12 sealed ORIGINAL document and fixed admin/node identities. RESTORE is GET-only;
    even a malicious acceptance adapter cannot choose index, document, socket or method.
    """
    fields = {"operation", "operationId", "pid", "containerId", "netnsInode", "invocationId",
              "caseClaimSha256", "requestSha256", "phase", "role", "action", "method", "path",
              "address", "port", "host", "caPem", "leafSha256", "clientCert", "clientKey",
              "originalPrivateText", "originalDocument", "originalSequence", "originalPrimaryTerm", "body"}
    require(set(request) == fields and request["operation"] == "opensearch-qualification" and
            isinstance(request["operationId"], str) and re.fullmatch(r"nq-[a-f0-9]{12}", request["operationId"]) and
            isinstance(request["invocationId"], str) and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", request["invocationId"]) and
            type(request["pid"]) is int and request["pid"] > 1 and
            type(request["netnsInode"]) is int and request["netnsInode"] > 1 and
            all(isinstance(request[k], str) and re.fullmatch(r"[a-f0-9]{64}", request[k])
                for k in ("containerId", "caseClaimSha256", "requestSha256", "leafSha256")) and
            request["phase"] in ("INSTALL", "RESTORE") and request["role"] in ("ADMIN", "NODE") and
            request["action"] in ("CREATE", "DOCUMENT", "HISTORY", "DENY") and
            request["port"] == 9200 and request["host"] == "opensearch" and
            isinstance(request["address"], str) and
            re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", request["address"]) and
            ipaddress.IPv4Address(request["address"]).is_private and
            not ipaddress.IPv4Address(request["address"]).is_loopback and
            not ipaddress.IPv4Address(request["address"]).is_link_local,
            "foreign private OpenSearch service/process/role identity")
    original = request["originalDocument"]
    text = request["originalPrivateText"]
    require(type(original) is dict and set(original) == {"privateText", "sourceGeneration", "version"} and
            original["privateText"] == text and original["version"] == 1 and
            isinstance(original["sourceGeneration"], str) and
            re.fullmatch(r"q-[a-f0-9]{12}", original["sourceGeneration"]) and
            isinstance(text, str) and re.fullmatch(r"a12-original-native-search-[a-z][a-z0-9-]{0,95}", text),
            "uncertain original private index document")
    require((request["phase"] == "INSTALL" and request["originalSequence"] is None and
             request["originalPrimaryTerm"] is None) or
            (request["phase"] == "RESTORE" and type(request["originalSequence"]) is int and
             request["originalSequence"] >= 0 and type(request["originalPrimaryTerm"]) is int and
             request["originalPrimaryTerm"] > 0), "original indexed sequence missing")
    document = "/p0v3-private-history/_doc/original-private-event"
    history = "/p0v3-private-history/_search?q=" + quote("privateText.keyword:" + text, safe="") + "&size=2"
    action = request["action"]
    method, path = request["method"], request["path"]
    require((action == "CREATE" and request["phase"] == "INSTALL" and request["role"] == "ADMIN" and
             method == "PUT" and path == document + "?op_type=create&refresh=wait_for" and
             original["privateText"] == "a12-original-native-search-" + request["invocationId"]) or
            (action == "DOCUMENT" and request["role"] == "ADMIN" and method == "GET" and path == document) or
            (action == "HISTORY" and request["role"] == "ADMIN" and method == "GET" and path == history) or
            (action == "DENY" and request["role"] == "NODE" and method == "GET" and path == document),
            "only original fixed admin read/create and actual limited node GET are allowed")
    require(all(isinstance(request[k], str) and 1 <= len(request[k]) <= 65536 and
                "-----BEGIN " in request[k] for k in ("caPem", "clientCert", "clientKey")),
            "OpenSearch requires sealed original server CA and role-specific mTLS cert/key")
    body = None if request["body"] is None else base64.b64decode(request["body"], validate=True)
    require((action != "CREATE" and body is None) or
            (action == "CREATE" and body is not None and len(body) <= 8192 and
             body == json.dumps(original, separators=(",", ":"), ensure_ascii=False).encode()),
            "RESTORE mutation or changed original index bytes refused")
    # No external destination or DNS. Target CID/PID/netns and opensearch-data IPv4 are
    # independently read back by the controller before the helper sees these bytes.
    enter(request["pid"], request["containerId"])
    require(os.stat("/proc/self/ns/net").st_ino == request["netnsInode"],
            "OpenSearch helper entered a different provider namespace")
    confine(9200)
    context = ssl.create_default_context(cadata=request["caPem"])
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    import tempfile
    with tempfile.TemporaryDirectory(prefix="p0v3-search-mtls-") as directory:
        cert = os.path.join(directory, "client.pem")
        key = os.path.join(directory, "client-key.pem")
        for name, value in ((cert, request["clientCert"]), (key, request["clientKey"])):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as stream: stream.write(value)
        context.load_cert_chain(cert, key)
        with socket.create_connection((request["address"], 9200), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname="opensearch") as tls:
                leaf = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
                require(leaf == request["leafSha256"], "original native OpenSearch server leaf changed")
                client = http.client.HTTPConnection(request["address"], 9200, timeout=8)
                client.sock = tls
                headers = {"Host": "opensearch", "Connection": "close"}
                if body is not None: headers["Content-Type"] = "application/json"
                client.request(method, path, body=body, headers=headers)
                reply = client.getresponse()
                payload = reply.read(1024 * 1024 + 1)
                require(len(payload) <= 1024 * 1024 and
                        (action == "CREATE" and reply.status == 201 or
                         action in ("DOCUMENT", "HISTORY") and reply.status == 200 or
                         action == "DENY" and reply.status in (401, 403)),
                        "real original-role OpenSearch response absent or unexpected")
                if action == "DENY":
                    require(text.encode() not in payload,
                            "limited node principal disclosed original private document")
                else:
                    record = json.loads(payload, object_pairs_hook=lambda pairs: _unique_pairs(pairs))
                    if action == "CREATE":
                        require(record.get("_id") == "original-private-event" and
                                record.get("_index") == "p0v3-private-history",
                                "original index create acknowledgement changed")
                    elif action == "DOCUMENT":
                        require(record.get("_id") == "original-private-event" and
                                record.get("_index") == "p0v3-private-history" and
                                record.get("_source") == original and
                                type(record.get("_seq_no")) is int and type(record.get("_primary_term")) is int and
                                (request["phase"] == "INSTALL" or
                                 record["_seq_no"] == request["originalSequence"] and
                                 record["_primary_term"] == request["originalPrimaryTerm"]),
                                "original document content, ID or sequence absent")
                    else:
                        hits = record.get("hits", {}).get("hits", [])
                        require(type(hits) is list and len(hits) <= 2 and
                                any(hit.get("_id") == "original-private-event" and
                                    hit.get("_index") == "p0v3-private-history" and
                                    hit.get("_source") == original for hit in hits),
                                "original private indexed history missing")
                return {"status": reply.status, "responseKind": "HTTP",
                        "body": base64.b64encode(payload).decode(), "serverLeafSha256": leaf,
                        "containerId": request["containerId"], "pid": request["pid"],
                        "netnsInode": os.stat("/proc/self/ns/net").st_ino, "clientPid": os.getpid()}


def crowdsec_qualification(request, enter=enter_namespace, confine=_confine_private_client):
    """A12's original isolated guard bouncer role, not a product API or general HTTPS client.
    The host actor independently pins original CA/cert/key/API-key and guard process first.
    """
    fields = {"operation", "operationId", "pid", "containerId", "netnsInode", "invocationId",
              "caseClaimSha256", "requestSha256", "phase", "assertion", "method", "path",
              "address", "port", "host", "caPem", "leafSha256", "apiKey"}
    require(set(request) == fields and request["operation"] == "crowdsec-qualification" and
            isinstance(request["operationId"], str) and re.fullmatch(r"cnq-[a-f0-9]{12}", request["operationId"]) and
            isinstance(request["invocationId"], str) and re.fullmatch(r"[a-z][a-z0-9-]{0,95}", request["invocationId"]) and
            type(request["pid"]) is int and request["pid"] > 1 and
            type(request["netnsInode"]) is int and request["netnsInode"] > 1 and
            all(isinstance(request[k], str) and re.fullmatch(r"[a-f0-9]{64}", request[k])
                for k in ("containerId", "caseClaimSha256", "requestSha256", "leafSha256")) and
            request["phase"] in ("INSTALL", "RESTORE") and
            request["assertion"] in ("POSITIVE", "NO_API_KEY") and request["method"] == "GET" and
            request["path"] in {"/v1/decisions?ip=198.51.100.18", "/v1/decisions?ip=198.51.100.19",
                                "/v1/decisions?ip=198.51.100.20"} and
            request["host"] == "guard" and request["port"] == 8443 and
            isinstance(request["address"], str) and
            re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}", request["address"]) and
            ipaddress.IPv4Address(request["address"]).is_private and
            not ipaddress.IPv4Address(request["address"]).is_loopback and
            not ipaddress.IPv4Address(request["address"]).is_link_local,
            "foreign original CrowdSec guard, case, process or fixed bouncer GET")
    require(isinstance(request["caPem"], str) and 1 <= len(request["caPem"]) <= 65536 and
            "-----BEGIN CERTIFICATE-----" in request["caPem"] and
            ((request["assertion"] == "POSITIVE" and isinstance(request["apiKey"], str) and
              re.fullmatch(r"[A-Za-z0-9._~-]{32,256}", request["apiKey"])) or
             (request["assertion"] == "NO_API_KEY" and request["apiKey"] is None)),
            "positive guard role requires pinned server TLS and original enrolled bouncer API key")
    enter(request["pid"], request["containerId"])
    require(os.stat("/proc/self/ns/net").st_ino == request["netnsInode"],
            "CrowdSec helper entered a different guard namespace")
    confine(8443)
    context = ssl.create_default_context(cadata=request["caPem"])
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    with socket.create_connection((request["address"], 8443), timeout=8) as raw:
        with context.wrap_socket(raw, server_hostname="guard") as tls:
            leaf = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
            require(leaf == request["leafSha256"], "original guard server leaf changed")
            client = http.client.HTTPConnection(request["address"], 8443, timeout=8)
            client.sock = tls
            headers = {"Host": "guard", "Connection": "close"}
            if request["assertion"] == "POSITIVE": headers["X-Api-Key"] = request["apiKey"]
            client.request("GET", request["path"], headers=headers)
            reply = client.getresponse()
            body = reply.read(1024 * 1024 + 1)
            require(len(body) <= 1024 * 1024 and
                    (request["assertion"] == "POSITIVE" and reply.status == 200 or
                     request["assertion"] == "NO_API_KEY" and reply.status in (401, 403)) and
                    (request["apiKey"] is None or request["apiKey"].encode() not in body),
                    "guard bouncer native authentication/denial was not actually observed")
            return {"status": reply.status, "responseKind": "HTTP",
                    "body": base64.b64encode(body).decode(), "serverLeafSha256": leaf,
                    "containerId": request["containerId"], "pid": request["pid"],
                    "netnsInode": os.stat("/proc/self/ns/net").st_ino, "clientPid": os.getpid()}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate search response key")
        result[key] = value
    return result


def expired(*_):
    raise TimeoutError("namespace exchange deadline exceeded")


def main():
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(30)
    try:
        raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        require(0 < len(raw) <= 8 * 1024 * 1024, "oversized helper request")
        request = json.loads(raw)
        result = (private_client(request) if request.get("operation") == "private-client" else
                  audit_public_listeners(request) if request.get("operation") == "audit-public-listeners" else
                  audit_internal_listener(request) if request.get("operation") == "audit-internal-listener" else
                  audit_absent_internal_listener(request) if request.get("operation") == "audit-absent-internal-listener" else
                  native_qualification(request) if request.get("operation") == "native-qualification" else
                  opensearch_qualification(request) if request.get("operation") == "opensearch-qualification" else
                  crowdsec_qualification(request) if request.get("operation") == "crowdsec-qualification" else
                  exchange(request))
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        sys.stdout.flush()
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Configurations can contain credentials; never include exceptions/response bodies in logs.
        sys.stderr.write("Ingress namespace exchange failed; a dispatched request must not be replayed\n")
        raise SystemExit(1)
