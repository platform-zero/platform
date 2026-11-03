import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import identity_secrets as m


class FakeApi:
    origin = "https://identity:8443"
    pin = "a" * 64

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, path, token=None, body=None, **kwargs):
        self.calls.append((method, path, token, body, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response(method, path, token, body) if callable(response) else response


class IdentitySecretsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.journal = m.Journal(self.root)
        self.authority = Mock()
        self.authority.authorize.return_value = "operator"

    def tearDown(self):
        self.tmp.cleanup()

    def test_private_files_reject_links_permissions_and_duplicate_keys(self):
        path = self.root / "secret"
        m.private_create(path, b"secret")
        self.assertEqual(b"secret", m.private_read(path))
        with self.assertRaises(FileExistsError):
            m.private_create(path, b"replacement")
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(m.Refused):
            m.private_read(link)
        link.unlink()
        os.link(path, link)
        with self.assertRaises(m.Refused):
            m.private_read(path)
        link.unlink()
        path.chmod(0o644)
        with self.assertRaises(m.Refused):
            m.private_read(path)
        with self.assertRaises(m.Refused):
            m.object_json(b'{"x":1,"x":2}')
        with self.assertRaises(m.Refused):
            m.object_json(b'[]')

    def test_rotation_custody_is_directly_consumable_and_rejects_non_token_envelopes(self):
        path = self.root / "custody"
        m.private_create(path, m.canonical({"token": "replacement", "accessor": "public-accessor"}))
        self.assertEqual("replacement", m.read_token(path))
        raw = self.root / "raw"
        m.private_create(raw, b"operator-token\n")
        self.assertEqual("operator-token", m.read_token(raw))
        invalid = self.root / "invalid"
        m.private_create(invalid, b'{"token":null}')
        with self.assertRaises(m.Refused):
            m.read_token(invalid)

    def test_journal_durable_intent_blocks_replay_new_id_and_tampering(self):
        action = Mock(side_effect=TimeoutError())
        with self.assertRaises(TimeoutError):
            self.journal.execute("op1", {"scope": "one"}, action)
        self.assertEqual(1, action.call_count)
        with self.assertRaises(m.Refused):
            self.journal.execute("op1", {"scope": "one"}, action)
        with self.assertRaises(m.Refused):
            self.journal.execute("op2", {"scope": "one"}, action)
        self.assertEqual(7, self.journal.execute("op3", {"scope": "other"}, lambda: 7))
        raw = self.journal.path.read_bytes()
        self.journal.path.write_bytes(raw.replace(b'"one"', b'"two"'))
        with self.assertRaises(m.Refused):
            with self.journal.locked():
                pass

    def test_interrupted_append_and_complete_replay_denied(self):
        self.journal.execute("ok", {"scope": "one"}, lambda: None)
        with self.assertRaises(m.Refused):
            self.journal.execute("ok", {"scope": "one"}, lambda: None)
        with self.journal.path.open("ab") as f:
            f.write(b'{')
        with self.assertRaises(m.Refused):
            with self.journal.locked():
                pass

    def test_introspection_requires_issuer_audience_expiry_subject_and_scope(self):
        valid = {"active": True, "iss": FakeApi.origin + "/realms/p0v3", "sub": "operator",
                 "aud": ["controller"], "exp": 101, "scope": "bao:recover"}
        for change in ({}, {"active": False}, {"iss": "https://foreign"}, {"sub": "other"},
                       {"aud": "wrong"}, {"exp": 100}, {"exp": True}, {"scope": "identity:manage"}):
            api = FakeApi([dict(valid, **change)])
            authority = m.IdentityAuthority(api, "p0v3", "introspect", "secret", "controller", ["operator"])
            if change:
                with self.assertRaises(m.Refused):
                    authority.authorize("bearer", "bao:recover", now=100)
            else:
                self.assertEqual("operator", authority.authorize("bearer", "bao:recover", now=100))

    def test_onboard_retains_custody_and_requires_both_actions(self):
        created = {}
        def create(method, path, token, body):
            created.update(body)
            return {}
        api = FakeApi([create, lambda *args: created])
        lifecycle = m.IdentityLifecycle(api, "p0v3", "bearer", self.authority, self.journal)
        result = lifecycle.onboard("onboard", "owner", self.root / "custody")
        self.assertTrue(result["onboardingRequired"])
        self.assertEqual({"UPDATE_PASSWORD", "CONFIGURE_TOTP"}, set(created["requiredActions"]))
        self.assertTrue(created["credentials"][0]["temporary"])
        password = m.object_json(m.private_read(self.root / "custody"))["temporaryPassword"]
        self.assertNotIn(password, self.journal.path.read_text())
        self.assertNotIn("bearer", self.journal.path.read_text())
        self.assertEqual(result["subject"], created["id"])

    def test_retirement_disables_exact_subject_and_revokes_sessions(self):
        subject = "11111111-1111-4111-8111-111111111111"
        api = FakeApi([{"id": subject}, {}, {}, {"enabled": False}])
        lifecycle = m.IdentityLifecycle(api, "p0v3", "bearer", self.authority, self.journal)
        self.assertTrue(lifecycle.retire("retire", subject)["retired"])
        self.assertEqual(["GET", "PUT", "POST", "GET"], [c[0] for c in api.calls])
        self.assertEqual({"enabled": False}, api.calls[1][3])
        self.assertTrue(api.calls[2][1].endswith(subject + "/logout"))

    def test_client_rotation_and_explicit_old_secret_retirement(self):
        client = "11111111-1111-4111-8111-111111111111"
        secret = "replacement-secret-long"
        api = FakeApi([{"id": client, "publicClient": False, "clientAuthenticatorType": "client-secret"},
                       {"value": secret}, {"value": secret}, {"value": secret}, {}, {"value": secret}])
        lifecycle = m.IdentityLifecycle(api, "p0v3", "bearer", self.authority, self.journal)
        self.assertTrue(lifecycle.rotate_client("rotate", client, self.root / "client")["rotated"])
        self.assertTrue(lifecycle.retire_rotated_client("retire", client, secret)["previousSecretRetired"])
        self.assertEqual("DELETE", api.calls[4][0])
        self.assertTrue(api.calls[4][1].endswith("/client-secret/rotated"))
        self.assertNotIn(secret, self.journal.path.read_text())

    def test_bao_rotation_checks_scoped_lease_and_persists_private_token(self):
        api = FakeApi([{"data": {"policies": ["issuer"], "ttl": 3600}},
                       {"auth": {"client_token": "new-secret", "accessor": "new"}},
                       {"data": {"policies": ["keykeeper"], "ttl": 300, "accessor": "new", "orphan": True}}])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        self.assertEqual("new", lifecycle.rotate("rotate", "issuer-token", "keeper", ["keykeeper"], self.root / "token")["accessor"])
        self.assertEqual("new-secret", m.object_json(m.private_read(self.root / "token"))["token"])
        self.assertNotIn("new-secret", self.journal.path.read_text())
        self.assertFalse(api.calls[1][3]["renewable"])
        self.assertTrue(api.calls[1][3]["no_default_policy"])

    def test_root_admin_and_same_token_retirement_rejected(self):
        api = FakeApi([{"data": {"policies": ["root"], "ttl": 3600}}])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        with self.assertRaises(m.Refused):
            lifecycle.rotate("rotate", "root", "keeper", ["keykeeper"], self.root / "token")
        self.assertFalse(self.journal.path.exists())
        data = {"data": {"policies": ["keykeeper"], "ttl": 300, "accessor": "same"}}
        api.responses = [data, data]
        with self.assertRaises(m.Refused):
            lifecycle.retire("retire", "old", "new", ["keykeeper"])

    def test_bao_retirement_checks_old_denial_and_replacement_survival(self):
        old = {"data": {"policies": ["keykeeper"], "ttl": 300, "accessor": "old"}}
        new = {"data": {"policies": ["keykeeper"], "ttl": 300, "accessor": "new", "orphan": True}}
        api = FakeApi([old, new, {}, {"errors": ["permission denied"]}, new])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        self.assertTrue(lifecycle.retire("retire", "old-token", "new-token", ["keykeeper"])["retired"])
        self.assertEqual((403,), api.calls[3][4]["expected"])

    def binding(self):
        return {"endpoint": FakeApi.origin, "leafSha256": FakeApi.pin, "clusterId": "cluster",
                "snapshotReceiptSha256": "b" * 64, "generation": "q-111111111111"}

    def test_recovery_unseal_requires_identity_lineage_threshold_and_cluster(self):
        sealed = {"initialized": True, "sealed": True, "progress": 0, "type": "shamir", "t": 2}
        api = FakeApi([sealed, dict(sealed, progress=1), dict(sealed, sealed=False, cluster_id="cluster")])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        verify = Mock()
        result = lifecycle.unseal("recover", self.binding(), ["a" * 32, "b" * 32], verify)
        self.assertFalse(result["publicActivation"])
        self.assertEqual(3, verify.call_count)
        self.authority.authorize.assert_called_once_with("bearer", "bao:recover")
        self.assertNotIn("a" * 32, self.journal.path.read_text().replace("a" * 64, "PIN"))
        self.assertIsNone(api.calls[1][2])  # no root token for threshold unseal

    def test_uncertain_unseal_never_replays_even_under_new_operation_id(self):
        sealed = {"initialized": True, "sealed": True, "progress": 0, "type": "shamir", "t": 1}
        api = FakeApi([sealed, TimeoutError(), sealed])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        with self.assertRaises(TimeoutError):
            lifecycle.unseal("recover", self.binding(), ["s" * 32], Mock())
        with self.assertRaises(m.Refused):
            lifecycle.unseal("new-operation", self.binding(), ["s" * 32], Mock())
        self.assertEqual(1, sum(c[0] == "POST" for c in api.calls))

    def test_unseal_bad_lineage_wrong_pin_uninitialized_partial_progress_and_cluster(self):
        sealed = {"initialized": True, "sealed": True, "progress": 0, "type": "shamir", "t": 1}
        for change in ({"initialized": False}, {"sealed": False}, {"progress": 1}, {"type": "awskms"}, {"t": 2}):
            api = FakeApi([dict(sealed, **change)])
            with self.assertRaises(m.Refused):
                m.BaoLifecycle(api, "bearer", self.authority, self.journal).unseal("no", self.binding(), ["s" * 32], Mock())
            self.assertEqual(1, len(api.calls))
        api = FakeApi([])
        with self.assertRaises(m.Refused):
            m.BaoLifecycle(api, "bearer", self.authority, self.journal).unseal(
                "no", dict(self.binding(), leafSha256="c" * 64), ["s" * 32], Mock())
        self.assertEqual([], api.calls)
        api = FakeApi([sealed, dict(sealed, sealed=False, cluster_id="foreign")])
        with self.assertRaises(m.Refused):
            m.BaoLifecycle(api, "bearer", self.authority, self.journal).unseal("badcluster", self.binding(), ["s" * 32], Mock())
        self.assertEqual("intent", m.object_json(self.journal.path.read_bytes().splitlines()[0])["phase"])

    def test_https_pins_before_sending_and_never_redirects_or_leaks_response(self):
        ca = self.root / "ca"
        m.private_create(ca, b"synthetic")
        connection = Mock()
        connection.sock.getpeercert.return_value = b"leaf"
        response = connection.getresponse.return_value
        response.status = 302
        response.read.return_value = b'{"secret":"DO-NOT-LOG"}'
        with patch.object(m.ssl, "create_default_context"), patch.object(m.http.client, "HTTPSConnection", return_value=connection):
            api = m.Https("https://identity:8443", ca, m.digest(b"leaf"))
            with self.assertRaises(m.Refused) as caught:
                api.request("POST", "/path", token="bearer", body={"secret": "input"})
            self.assertNotIn("DO-NOT-LOG", str(caught.exception))
            self.assertEqual(1, connection.request.call_count)
            connection.reset_mock()
            connection.sock.getpeercert.return_value = b"foreign"
            with self.assertRaises(m.Refused):
                api.request("POST", "/path", body={"secret": "input"})
            connection.request.assert_not_called()
            for origin in ("http://identity", "https://user@identity", "https://identity/path", "https://identity?x=y"):
                with self.assertRaises(m.Refused):
                    m.Https(origin, ca, "a" * 64)


if __name__ == "__main__":
    unittest.main()
