import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, mock_open, patch

SPEC = importlib.util.spec_from_file_location("caddy_admin", Path(__file__).resolve().parents[1] / "src/main/resources/runtime/caddy-admin.py")
admin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admin)


class CaddyAdminHelperTests(unittest.TestCase):
    def test_native_provider_rejects_foreign_hosts_paths_principals_before_namespace(self):
        intent = {"operation": "native-qualification", "operationId": "nq-0123456789ab",
                  "pid": 42, "containerId": "a" * 64, "netnsInode": 321,
                  "invocationId": "case-a11-original", "caseClaimSha256": "b" * 64,
                  "requestSha256": "c" * 64, "serviceId": "loki", "processId": "loki",
                  "phase": "RESTORE", "assertion": "POSITIVE", "method": "GET",
                  "path": "/loki/api/v1/query_range?query=%7Bjob%3D%22p0v3-acceptance%22%2Crun%3D%22obs-012345abcdef%22%7D&start=1729999999000000000&end=1730000005000000000&limit=10",
                  "address": "10.42.1.8", "port": 3100, "host": "loki", "caPem": None,
                  "leafSha256": None, "clientCert": None, "clientKey": None,
                  "authorization": None, "authorizationMode": "NONE", "body": None}
        enter, confine = Mock(), Mock()
        changes = ({"processId": "grafana"}, {"serviceId": "alloy", "method": "POST"},
                   {"port": 2019}, {"host": "127.0.0.1"}, {"address": "8.8.8.8"},
                   {"authorizationMode": "BEARER"}, {"method": "POST"},
                   {"path": "/loki/api/v1/query_range?query=bad"},
                   {"path": intent["path"].replace("limit=10", "limit=9999")},
                   {"phase": "PAUSED"}, {"caseClaimSha256": "not-a-sha"})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                admin.native_qualification({**intent, **change}, enter, confine)
        enter.assert_not_called()
        confine.assert_not_called()

    def test_native_alert_cannot_be_fabricated_from_connection_reset_or_fake_http(self):
        intent = {"leafSha256": "a" * 64, "containerId": "b" * 64,
                  "pid": 42, "netnsInode": 123, "caseClaimSha256": "c" * 64,
                  "operationId": "nq-0123456789ab"}
        with self.assertRaises(ValueError):
            admin._native_client_alert(intent, ConnectionResetError("connection reset"))
        with self.assertRaises(ValueError):
            admin._native_client_alert(intent, ValueError("certificate required"))

    def test_opensearch_fixed_original_mtls_rejects_restore_write_roles_and_unsafe_destinations(self):
        original = {'privateText': 'a12-original-native-search-case-original',
                    'sourceGeneration': 'q-0123456789ab', 'version': 1}
        path = '/p0v3-private-history/_doc/original-private-event'
        source = {'operation': 'opensearch-qualification', 'operationId': 'nq-0123456789ab',
                  'pid': 42, 'containerId': 'a' * 64, 'netnsInode': 321,
                  'invocationId': 'case-original', 'caseClaimSha256': 'b' * 64,
                  'requestSha256': 'c' * 64, 'phase': 'RESTORE', 'role': 'ADMIN',
                  'action': 'DOCUMENT', 'method': 'GET', 'path': path,
                  'address': '10.42.1.8', 'port': 9200, 'host': 'opensearch',
                  'caPem': '-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----\n',
                  'leafSha256': 'd' * 64,
                  'clientCert': '-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----\n',
                  'clientKey': '-----BEGIN PRIVATE KEY-----\nexample\n-----END PRIVATE KEY-----\n',
                  'originalPrivateText': original['privateText'], 'originalDocument': original,
                  'originalSequence': 0, 'originalPrimaryTerm': 1, 'body': None}
        enter, confine = Mock(), Mock()
        for change in ({'action': 'CREATE', 'method': 'PUT', 'body': base64.b64encode(
                           json.dumps(original, separators=(',', ':')).encode()).decode()},
                       {'role': 'NODE'}, {'action': 'DENY', 'role': 'ADMIN'},
                       {'action': 'HISTORY', 'path': '/p0v3-private-history/_search'},
                       {'path': '/_cluster/settings'}, {'host': '127.0.0.1'},
                       {'address': '8.8.8.8'}, {'port': 2019},
                       {'originalDocument': {**original, 'privateText': 'foreign'}},
                       {'body': base64.b64encode(b'foreign').decode()},
                       {'leafSha256': 'not-a-sha'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                admin.opensearch_qualification({**source, **change}, enter, confine)
        enter.assert_not_called()
        confine.assert_not_called()

    def test_crowdsec_8443_bouncer_requires_exact_keyed_or_real_no_key_role_before_namespace(self):
        source = {'operation':'crowdsec-qualification','operationId':'cnq-0123456789ab',
                  'pid':42,'containerId':'a'*64,'netnsInode':321,'invocationId':'case-original',
                  'caseClaimSha256':'b'*64,'requestSha256':'c'*64,'phase':'RESTORE',
                  'assertion':'POSITIVE','method':'GET','path':'/v1/decisions?ip=198.51.100.18',
                  'address':'10.42.1.8','port':8443,'host':'guard',
                  'caPem':'-----BEGIN CERTIFICATE-----\noriginal\n-----END CERTIFICATE-----\n',
                  'leafSha256':'d'*64, 'apiKey':'e'*40}
        enter, confine = Mock(), Mock()
        for change in ({'port':2019}, {'address':'8.8.8.8'}, {'host':'opensearch'},
                       {'method':'POST'}, {'path':'/v1/decisions?ip=198.51.100.25'},
                       {'path':'/v1/decisions?ip=198.51.100.18&foo=bar'},
                       {'assertion':'NO_API_KEY','apiKey':'e'*40},
                       {'assertion':'POSITIVE','apiKey':None},
                       {'phase':'UNKNOWN'}, {'caseClaimSha256':'foreign'},
                       {'clientCert':'foreign-extra'}, {'leafSha256':'not-a-sha'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                admin.crowdsec_qualification({**source, **change}, enter, confine)
        enter.assert_not_called()
        confine.assert_not_called()

    def request(self, method="GET", path="/config/", body=None):
        return {"pid": 42, "containerId": "a" * 64, "method": method, "path": path,
                "etag": None if method == "GET" else '"/config/ 0123456789abcdef"',
                "body": None if body is None else base64.b64encode(body).decode()}

    def test_exact_loopback_namespace_and_single_cas(self):
        enter = Mock()
        response = Mock(status=200)
        response.read.return_value = b'{"synthetic":true}'
        response.getheader.return_value = '"/config/ fedcba9876543210"'
        client = Mock()
        client.getresponse.return_value = response
        connection = Mock(return_value=client)
        result = admin.exchange(self.request("POST", body=b"{}"), enter, connection)
        enter.assert_called_once_with(42, "a" * 64)
        connection.assert_called_once_with("127.0.0.1", 2019, timeout=10)
        client.request.assert_called_once_with("POST", "/config/", body=b"{}",
                                              headers={"If-Match": '"/config/ 0123456789abcdef"', "Content-Type": "application/json"})
        client.close.assert_called_once()
        self.assertEqual(b'{"synthetic":true}', base64.b64decode(result["body"]))
        self.assertEqual(200, result["status"])

    def test_validation_precedes_namespace_or_network_effects(self):
        enter, connection = Mock(), Mock()
        requests = [self.request("DELETE"), self.request(path="/debug/"), self.request("POST", "/load", b"{}")]
        bad = self.request("POST", body=b"{}"); bad["etag"] = "unconditional"; requests.append(bad)
        bad = self.request(); bad["pid"] = 1; requests.append(bad)
        bad = self.request(); bad["containerId"] = "short"; requests.append(bad)
        bad = self.request(); bad["destination"] = "foreign"; requests.append(bad)
        for request in requests:
            with self.subTest(request=request), self.assertRaises(ValueError):
                admin.exchange(request, enter, connection)
        enter.assert_not_called()
        connection.assert_not_called()

    def test_get_patch_conflict_and_lost_ack_are_not_retried(self):
        for method, path, body in (("GET", "/config/", None), ("PATCH", "/config/apps/http/servers/owned/routes", b"[]")):
            response = Mock(status=412)
            response.read.return_value = b"conflict"
            response.getheader.return_value = None
            client = Mock(); client.getresponse.return_value = response
            self.assertEqual(412, admin.exchange(self.request(method, path, body), Mock(), Mock(return_value=client))["status"])
            self.assertEqual(1, client.request.call_count)
        client = Mock(); client.getresponse.side_effect = TimeoutError("lost acknowledgement")
        with self.assertRaises(TimeoutError):
            admin.exchange(self.request("POST", body=b"{}"), Mock(), Mock(return_value=client))
        self.assertEqual(1, client.request.call_count)
        client.close.assert_called_once()

    def test_response_bound_and_deadline(self):
        response = Mock(status=200); response.read.return_value = b"a" * (admin.MAXIMUM + 1)
        client = Mock(); client.getresponse.return_value = response
        with self.assertRaises(ValueError):
            admin.exchange(self.request(), Mock(), Mock(return_value=client))
        client.close.assert_called_once()
        with self.assertRaises(TimeoutError):
            admin.expired()

    def test_namespace_fd_is_pinned_and_container_cgroup_verified_before_setns(self):
        libc = Mock(); libc.setns.return_value = 0
        with patch.object(admin.os, "geteuid", return_value=0), patch.object(admin.os, "open", return_value=9), \
                patch.object(admin.os, "close") as close, patch("builtins.open", mock_open(read_data="0::/libpod-" + "a" * 64 + ".scope\n")), \
                patch.object(admin.os, "fstat", return_value=SimpleNamespace(st_ino=123)), \
                patch.object(admin.os, "stat", return_value=SimpleNamespace(st_ino=123)), \
                patch.object(admin.ctypes, "CDLL", return_value=libc):
            admin.enter_namespace(42, "a" * 64)
            libc.setns.assert_called_once_with(9, 0)
            close.assert_called_once_with(9)
        with patch.object(admin.os, "geteuid", return_value=0), patch.object(admin.os, "open", return_value=9), \
                patch.object(admin.os, "close") as close, patch("builtins.open", mock_open(read_data="0::/foreign.scope\n")), \
                patch.object(admin.ctypes, "CDLL") as library:
            with self.assertRaises(ValueError):
                admin.enter_namespace(42, "a" * 64)
            library.assert_not_called(); close.assert_called_once_with(9)

    def test_namespace_change_and_setns_failure_are_not_ignored(self):
        for inode, code in ((456, 0), (123, -1)):
            libc = Mock(); libc.setns.return_value = code
            with patch.object(admin.os, "geteuid", return_value=0), patch.object(admin.os, "open", return_value=9), \
                    patch.object(admin.os, "close"), patch("builtins.open", mock_open(read_data="0::/libpod-" + "a" * 64 + ".scope\n")), \
                    patch.object(admin.os, "fstat", return_value=SimpleNamespace(st_ino=123)), \
                    patch.object(admin.os, "stat", return_value=SimpleNamespace(st_ino=inode)), \
                    patch.object(admin.ctypes, "CDLL", return_value=libc):
                with self.assertRaises((ValueError, OSError)):
                    admin.enter_namespace(42, "a" * 64)
        with patch.object(admin.os, "geteuid", return_value=1000), self.assertRaises(ValueError):
            admin.enter_namespace(42, "a" * 64)


class PrivateNamespaceClientTests(unittest.TestCase):
    def request(self):
        cert = b"original TLS certificate DER"
        return {"operation": "private-client", "operationId": "r-" + "a" * 12,
                "pid": 42, "containerId": "b" * 64, "clientNetwork": "rss-client",
                "address": "10.89.0.5", "host": "social.datamancy.net",
                "caPem": "-----BEGIN CERTIFICATE-----\nORIGINAL\n-----END CERTIFICATE-----",
                "leafSha256": hashlib.sha256(cert).hexdigest(), "method": "GET",
                "path": "/api/v1/statuses/123/source", "token": "t" * 64, "body": None,
                "phaseClaimSha256": "c" * 64, "caseClaimSha256": "d" * 64,
                "invocationId": "case-" + "a" * 36, "phase": "RESTORE", "account": "rss_reader", "botAccount": "",
                "idempotencyKey": None}, cert

    def test_restored_original_sni_ca_and_private_ip_with_pid_inode_receipt(self):
        request, cert = self.request()
        order = []
        enter = Mock(side_effect=lambda *_: order.append("enter"))
        confine = Mock(side_effect=lambda: order.append("drop-uid-caps-and-confine"))
        ssl_socket = Mock(); ssl_socket.getpeercert.return_value = cert
        tls = Mock(side_effect=lambda *_: ssl_socket)
        reply = Mock(status=200); reply.read.return_value = b'{"source":"original"}'
        client = Mock(); client.sock = object(); client.getresponse.return_value = reply
        connection = Mock(side_effect=lambda *_args, **_kwargs: (order.append("dial"), client)[1])
        with patch.object(admin.os, "stat", return_value=SimpleNamespace(st_ino=456)):
            result = admin.private_client(request, enter, confine, connection, tls)
        self.assertEqual(["enter", "drop-uid-caps-and-confine", "dial"], order)
        connection.assert_called_once_with("10.89.0.5", 443, timeout=10)
        self.assertEqual("social.datamancy.net", tls.call_args.args[1])
        self.assertEqual(request["caPem"], tls.call_args.args[2])
        self.assertEqual(456, result["clientNetworkInode"])
        self.assertEqual(b'{"source":"original"}', base64.b64decode(result["body"]))
        self.assertEqual("Bearer " + "t" * 64, client.request.call_args.kwargs["headers"]["Authorization"])
        self.assertEqual("social.datamancy.net", client.request.call_args.kwargs["headers"]["Host"])
        client.close.assert_called_once()

    def test_bad_method_host_token_private_network_or_post_on_restore_precedes_namespace_entry(self):
        base, _ = self.request()
        changes = [{"host": "evil.datamancy.net"}, {"address": "127.0.0.1"},
                   {"address": "8.8.8.8"}, {"path": "/api/v1/statuses/1?secret=1"},
                   {"method": "DELETE"}, {"token": "real\r\nInjected: true"},
                   {"phase": "INSTALL", "method": "POST", "path": "/api/v1/statuses"},
                   {"body": base64.b64encode(b'{}').decode()}, {"operationId": "foreign"},
                   {"extra": "shell"}]
        for change in changes:
            request = base | change
            enter, confine, connection = Mock(), Mock(), Mock()
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                admin.private_client(request, enter, confine, connection)
            enter.assert_not_called(); confine.assert_not_called(); connection.assert_not_called()

    def test_tls_leaf_mismatch_or_lost_ack_never_reissues_private_request(self):
        request, _ = self.request()
        client = Mock(); client.sock = object()
        tls_socket = Mock(); tls_socket.getpeercert.return_value = b"changed certificate"
        with self.assertRaises(ValueError):
            admin.private_client(request, Mock(), Mock(), Mock(return_value=client), Mock(return_value=tls_socket))
        client.request.assert_not_called(); client.close.assert_called_once()
        client = Mock(); client.sock = object()
        tls_socket.getpeercert.return_value = b"original TLS certificate DER"
        client.request.side_effect = TimeoutError("lost GET acknowledgement")
        with self.assertRaises(TimeoutError):
            admin.private_client(request, Mock(), Mock(), Mock(return_value=client), Mock(return_value=tls_socket))
        self.assertEqual(1, client.request.call_count); client.close.assert_called_once()

    def test_actual_public_http_and_https_listener_ips_are_namespace_readback_not_config_claim(self):
        request = {"operation": "audit-public-listeners", "pid": 42, "containerId": "b" * 64,
                   "address": "10.89.0.3", "requireHttps": True}
        tcp = "sl local_address rem_address st\n 0: 0300590A:0050 00000000:0000 0A\n" + \
              " 1: 0300590A:01BB 00000000:0000 0A\n"
        entry = Mock()
        def open_proc(path, *args, **kwargs):
            return io.StringIO(tcp if path == "/proc/net/tcp" else "sl local_address rem_address st\n")
        with patch("builtins.open", side_effect=open_proc), \
                patch.object(admin.os, "stat", return_value=SimpleNamespace(st_ino=456)):
            observed = admin.audit_public_listeners(request, entry)
        entry.assert_called_once_with(42, "b" * 64)
        self.assertEqual(["10.89.0.3"], observed["http"])
        self.assertEqual(["10.89.0.3"], observed["https"])
        self.assertEqual(456, observed["networkInode"])
        with patch("builtins.open", side_effect=lambda path, *a, **k:
                   io.StringIO(tcp.replace("0300590A:01BB", "00000000:01BB")
                               if path == "/proc/net/tcp" else "sl local_address rem_address st\n")), \
                self.assertRaises(ValueError):
            admin.audit_public_listeners(request, Mock())
        with patch("builtins.open", side_effect=lambda path, *a, **k:
                   io.StringIO("sl local_address rem_address st\n" +
                               " 0: 00000000000000000000000000000000:01BB 00000000:0000 0A\n"
                               if path == "/proc/net/tcp6" else tcp)), \
                self.assertRaises(ValueError):
            admin.audit_public_listeners(request, Mock())

    def test_separate_internal_listener_preserves_primary_public_ports_and_refuses_wildcard(self):
        request = {"operation": "audit-internal-listener", "pid": 42,
                   "containerId": "b" * 64, "address": "10.89.0.5"}
        tcp = "sl local_address rem_address st\n 0: 0300590A:0050 00000000:0000 0A\n" + \
              " 1: 0300590A:01BB 00000000:0000 0A\n" + \
              " 2: 0500590A:01BB 00000000:0000 0A\n"
        with patch("builtins.open", side_effect=lambda path, *a, **k:
                   io.StringIO(tcp if path == "/proc/net/tcp" else "sl local_address rem_address st\n")), \
                patch.object(admin.os, "stat", return_value=SimpleNamespace(st_ino=456)):
            observed = admin.audit_internal_listener(request, Mock())
        self.assertEqual(["10.89.0.3", "10.89.0.5"], observed["https"])
        self.assertEqual(["10.89.0.3"], observed["http"])
        with patch("builtins.open", side_effect=lambda path, *a, **k:
                   io.StringIO(tcp.replace("0500590A:01BB", "00000000:01BB")
                               if path == "/proc/net/tcp" else "sl local_address rem_address st\n")), \
                self.assertRaises(ValueError):
            admin.audit_internal_listener(request, Mock())

    def test_fresh_qualification_listener_absence_is_native_and_not_inferred_from_caddy_json(self):
        request = {"operation": "audit-absent-internal-listener", "pid": 42,
                   "containerId": "b" * 64, "address": "10.89.0.5"}
        other = "sl local_address rem_address st\n 0: 0300590A:0050 00000000:0000 0A\n" + \
                " 1: 0300590A:01BB 00000000:0000 0A\n"
        with patch("builtins.open", side_effect=lambda path, *a, **k:
                   io.StringIO(other if path == "/proc/net/tcp" else "sl local_address rem_address st\n")), \
                patch.object(admin.os, "stat", return_value=SimpleNamespace(st_ino=456)):
            observed = admin.audit_absent_internal_listener(request, Mock())
        self.assertEqual(["10.89.0.3"], observed["https"])
        with patch("builtins.open", side_effect=lambda path, *a, **k:
                   io.StringIO(other + " 2: 0500590A:01BB 00000000:0000 0A\n" if path == "/proc/net/tcp"
                               else "sl local_address rem_address st\n")), \
                self.assertRaises(ValueError):
            admin.audit_absent_internal_listener(request, Mock())

    def test_landlock_abi_before_capability_drop_and_denies_all_bind_and_non443_connect(self):
        libc = Mock(); libc.syscall.side_effect = [3]
        with patch.object(admin.resource, "setrlimit"), patch.object(admin.ctypes, "CDLL", return_value=libc), \
                patch.object(admin.os, "setgroups") as groups:
            with self.assertRaises(ValueError):
                admin._confine_private_client()
            groups.assert_not_called()
        libc = Mock(); libc.syscall.side_effect = [4, 9, 0, 0]; libc.prctl.return_value = 0
        with patch.object(admin.resource, "setrlimit"), patch.object(admin.ctypes, "CDLL", return_value=libc), \
                patch.object(admin.os, "setgroups") as groups, patch.object(admin.os, "setresgid") as gid, \
                patch.object(admin.os, "setresuid") as uid, patch.object(admin.os, "geteuid", return_value=65534), \
                patch.object(admin.os, "getegid", return_value=65534), patch.object(admin.os, "close") as close:
            admin._confine_private_client()
            self.assertEqual(4, libc.syscall.call_count)
            self.assertEqual(3, libc.syscall.call_args_list[1].args[1]._obj.handled_access_net)
            self.assertEqual(2, libc.syscall.call_args_list[2].args[2]._obj.allowed_access)
            self.assertEqual(443, libc.syscall.call_args_list[2].args[2]._obj.port)
            groups.assert_called_once_with([]); gid.assert_called_once_with(65534, 65534, 65534)
            uid.assert_called_once_with(65534, 65534, 65534); close.assert_called_once_with(9)


class CaddyQualifiedAdapterTests(unittest.TestCase):
    """Mocked original-state protocol only; never reaches a service, browser or public ACME."""

    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[2] / "acceptance/runners/caddy-native.py"
        spec = importlib.util.spec_from_file_location("caddy_native_qualified", path)
        cls.adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.adapter)

    def restored(self):
        module = self.adapter
        host = "auth.datamancy.net"
        fixture = b"original synthetic bytes, not a service"
        source = {"container": "p0v3-live-q-000000000001-owned-caddy", "networks": ["source-net"],
                  "volumes": ["source-data"], "hosts": {
            host: {"bodySha256": module.digest(fixture), "certificateSha256": "a" * 64}}}
        request = {"schemaVersion": 1, "invocation": {"serviceId": "caddy", "surface": "HEADLESS", "variant": "NATIVE",
            "requiredAssertions": sorted(module.BASE | module.RESTORE),
            "binding": {"generationId": "q-000000000002", "phase": "RESTORE"}},
            "context": {"hosts": {host: {"nonce": "n" * 32, "bodySha256": module.digest(fixture), "path": "/fixture"}},
                "foreignHost": "foreign.datamancy.net", "address": "10.0.0.2", "runtimeSpec": "/unit/manifest",
                "bridge": {"originalHosts": [host], "address": "10.0.0.2", "clientNetwork": "client-net",
                    "sourceStoppedProofSha256": "b" * 64, "targetPrivateReadinessSha256": "c" * 64}},
            "sourceOracle": source}
        spec = {"name": "q-000000000002-caddy", "ingress": None,
                "processes": [{"id": "caddy", "oneShot": False, "command": ["run"], "networks": ["client-net"],
                    "networkAliases": [{"network": "client-net", "host": host}]}]}
        observed = {"NetworkSettings": {"Networks": {"client-net": {}}},
                    "Mounts": [{"Type": "volume", "Name": "target-data"}]}
        original = {"State": {"Running": False}, "NetworkSettings": {"Networks": {"source-net": {}}},
                    "Mounts": [{"Type": "volume", "Name": "source-data"}]}
        return request, ("p0v3-live-q-000000000002-caddy-caddy", spec, observed, spec["processes"][0]), original, fixture

    def test_restore_keeps_original_sni_and_cert_without_cookie_or_http01(self):
        request, runtime, old, fixture = self.restored()
        module = self.adapter
        def response(host, address, port, path, token=None, tls_context=None):
            self.assertEqual(443, port)
            self.assertEqual("10.0.0.2", address)
            self.assertIsNone(token)
            if host == request["context"]["foreignHost"]:
                raise module.ssl.SSLError("foreign SNI rejected by synthetic bridge")
            self.assertEqual("auth.datamancy.net", host)
            return 200, fixture, {"sha256": "a" * 64, "expires": 9999999999, "serial": "01"}
        with patch.object(module, "runtime", return_value=runtime), patch.object(module, "inspect", return_value=old), \
             patch.object(module, "request_http", side_effect=response) as exchange:
            assertions, oracle, observation = module.probe(request)
        self.assertEqual(request["sourceOracle"], oracle)
        self.assertTrue(all(assertions.values()))
        self.assertEqual("a" * 64, observation["restoredOriginal"]["auth.datamancy.net"]["sha256"])
        self.assertEqual({}, observation["renewed"])
        self.assertEqual(2, exchange.call_count)

    def test_running_source_or_wrong_bridge_alias_fails_before_any_http(self):
        request, runtime, old, _ = self.restored()
        module = self.adapter
        with patch.object(module, "runtime", return_value=runtime), patch.object(module, "inspect", return_value=dict(old, State={"Running": True})), \
             patch.object(module, "request_http") as exchange, self.assertRaises(ValueError):
            module.probe(request)
            exchange.assert_not_called()
        request["context"]["bridge"]["clientNetwork"] = "foreign-net"
        with patch.object(module, "runtime", return_value=runtime), patch.object(module, "inspect", return_value=old), \
             patch.object(module, "request_http") as exchange, self.assertRaises(ValueError):
            module.probe(request)
            exchange.assert_not_called()


if __name__ == "__main__":
    unittest.main()
