import base64
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, mock_open, patch

SPEC = importlib.util.spec_from_file_location("caddy_admin", Path(__file__).resolve().parents[1] / "src/main/resources/runtime/caddy-admin.py")
admin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admin)


class CaddyAdminHelperTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
