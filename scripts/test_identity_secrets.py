import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
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
        self.authority.generation = "q-111111111111"

    def tearDown(self):
        self.tmp.cleanup()

    def test_bao_cli_uses_separately_pinned_original_keycloak_admin(self):
        def secret(name, value):
            path = self.root / name
            m.private_create(path, value.encode())
            return str(path)

        identity = {'origin': 'https://keycloak:8443', 'caFile': '/private/keycloak-ca',
            'leafSha256': 'a' * 64, 'authorityOrigin': 'https://auth.datamancy.net',
            'authorityCaFile': '/private/public-ca', 'authorityLeafSha256': 'b' * 64,
            'realm': 'p0v3', 'introspectionClient': 'identity-controller', 'audience': 'controller',
            'allowedSubjects': ['11111111-1111-4111-8111-111111111111'], 'generation': 'q-111111111111',
            'introspectionSecretFile': secret('client-secret', 'private-secret'),
            'bearerFile': secret('operator-bearer', 'operator-bearer')}
        bao = {'origin': 'https://bao:8200', 'caFile': '/private/bao-ca',
            'leafSha256': 'c' * 64, 'operatorTokenFile': secret('bao-operator', 'bao-operator')}
        request = {'identity': identity, 'bao': bao, 'operation': 'unique-bao-rotation',
            'action': 'rotate-bao-token', 'journalDirectory': str(self.root),
            'role': 'keykeeper-reader', 'policies': ['keykeeper-read'], 'custodyFile': str(self.root / 'new-token')}
        source = secret('request', json.dumps(request))
        with patch.object(m, 'Https') as tls, patch.object(m, 'IdentityAuthority') as authority, \
                patch.object(m, 'IdentityLifecycle'), patch.object(m, 'BaoLifecycle') as lifecycle:
            transports = [Mock(origin='https://keycloak:8443'),
                          Mock(origin='https://auth.datamancy.net'), Mock(origin='https://bao:8200')]
            tls.side_effect = transports
            lifecycle.return_value.rotate.return_value = {'rotated': True}
            self.assertEqual(0, m.main([source]))
            self.assertEqual(3, tls.call_count)
            self.assertEqual('https://keycloak:8443', tls.call_args_list[0].args[0])
            self.assertEqual('https://auth.datamancy.net', tls.call_args_list[1].args[0])
            self.assertEqual('https://bao:8200', tls.call_args_list[2].args[0])
            self.assertIs(authority.call_args.args[-1], transports[0])
            self.assertIs(lifecycle.call_args.args[0], transports[2])
            self.assertIs(lifecycle.call_args.args[2], authority.return_value)
        with patch.object(m, 'Https') as tls:
            with self.assertRaises(m.Refused):
                m.identity_admin_https({**identity, 'origin': 'https://bao:8200'})
            with self.assertRaises(m.Refused):
                m.bao_https({**bao, 'origin': 'https://keycloak:8443'})
            tls.assert_not_called()

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

    def test_original_operator_pkce_private_verifier_callback_and_one_time_scoped_grant(self):
        authority = Mock()
        authority.api.origin = "https://auth.datamancy.net"
        authority.generation = "q-111111111111"
        authority.api.request.return_value = {"token_type": "Bearer", "expires_in": 300,
                                              "access_token": "fresh-original-owner-token-private"}
        flow = m.OperatorPkce(authority, self.journal)
        result = flow.prepare("prepare-pkce", self.root / "pkce-verifier")
        self.assertTrue(result["browserMfaRequired"])
        self.assertIn("code_challenge_method=S256", result["authorizationUrl"])
        self.assertIn("client_id=identity-controller", result["authorizationUrl"])
        verifier = m.object_json(m.private_read(self.root / "pkce-verifier"))
        self.assertNotIn(verifier["verifier"], self.journal.path.read_text())
        self.assertNotIn(verifier["verifier"], result["authorizationUrl"])
        redirect = m.OperatorPkce.REDIRECT + "?code=actual-browser-authorization-code&state=" + verifier["state"]
        with self.assertRaises(m.Refused):
            flow.redeem("foreign", redirect.replace(verifier["state"], "foreign"), self.root / "pkce-verifier",
                        self.root / "operator-token")
        token = flow.redeem("redeem-pkce", redirect, self.root / "pkce-verifier", self.root / "operator-token")
        self.assertTrue(token["operatorAuthorized"])
        self.assertEqual("fresh-original-owner-token-private", m.read_token(self.root / "operator-token"))
        self.assertNotIn("fresh-original-owner-token-private", self.journal.path.read_text())
        self.assertEqual(["identity:manage", "bao:recover", "credentials:rotate"],
                         [call.args[1] for call in authority.authorize.call_args_list])
        with self.assertRaises(m.Refused):
            flow.redeem("redeem-again", redirect, self.root / "pkce-verifier", self.root / "operator-token")
        authority.api.request.assert_called_once()

    def test_operator_pkce_lost_ack_refuses_new_code_exchange_or_old_generation(self):
        authority = Mock()
        authority.api.origin = "https://auth.datamancy.net"
        authority.generation = "q-111111111111"
        flow = m.OperatorPkce(authority, self.journal)
        flow.prepare("prepare-pkce", self.root / "pkce-verifier")
        verifier = m.object_json(m.private_read(self.root / "pkce-verifier"))
        redirect = m.OperatorPkce.REDIRECT + "?code=actual-browser-authorization-code&state=" + verifier["state"]
        authority.api.request.side_effect = TimeoutError()
        with self.assertRaises(TimeoutError):
            flow.redeem("lost-ack", redirect, self.root / "pkce-verifier", self.root / "operator-token")
        with self.assertRaises(m.Refused):
            flow.redeem("new-id", redirect, self.root / "pkce-verifier", self.root / "operator-token")
        self.assertEqual(1, authority.api.request.call_count)
        authority.generation = "q-222222222222"
        with self.assertRaises(m.Refused):
            flow.redeem("foreign-generation", redirect, self.root / "pkce-verifier", self.root / "operator-token")
        self.assertFalse((self.root / "operator-token").exists())

    def test_introspection_requires_issuer_audience_expiry_subject_and_scope(self):
        original = "11111111-1111-4111-8111-111111111111"
        valid = {"active": True, "iss": FakeApi.origin + "/realms/p0v3", "sub": original,
                 "aud": ["controller"], "exp": 101, "scope": "bao:recover",
                 "azp": "identity-controller", "p0v3_generation": "q-111111111111"}
        for change in ({}, {"active": False}, {"iss": "https://foreign"},
                       {"sub": "22222222-2222-4222-8222-222222222222"},
                       {"aud": "wrong"}, {"exp": 100}, {"exp": True}, {"scope": "identity:manage"},
                       {"azp": "keykeeper-human"}, {"p0v3_generation": "q-222222222222"}):
            api = FakeApi([dict(valid, **change), {"id": original, "username": "owner", "enabled": True}])
            authority = m.IdentityAuthority(api, "p0v3", "introspect", "secret", "controller", [original],
                                            "q-111111111111", api)
            if change:
                with self.assertRaises(m.Refused):
                    authority.authorize("bearer", "bao:recover", now=100)
            else:
                self.assertEqual(original, authority.authorize("bearer", "bao:recover", now=100))
                self.assertEqual(("GET", "/admin/realms/p0v3/users/" + original), api.calls[-1][:2])
        for user in ({"id": original, "username": "replacement", "enabled": True},
                     {"id": original, "username": "owner", "enabled": False},
                     {"id": "22222222-2222-4222-8222-222222222222", "username": "owner", "enabled": True},
                     m.Refused("native Keycloak denied")):
            api = FakeApi([valid, user])
            authority = m.IdentityAuthority(api, "p0v3", "introspect", "secret", "controller", [original],
                                            "q-111111111111", api)
            with self.assertRaises(m.Refused):
                authority.authorize("bearer", "bao:recover", now=100)

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
        api = FakeApi([{"data": {"policies": ["keykeeper-issuer"], "ttl": 3600,
                                 "accessor": "issuer", "orphan": True,
                                 "renewable": True, "period": 86400}},
                       {"auth": {"client_token": "new-secret", "accessor": "new"}},
                       {"data": {"policies": ["keykeeper"], "ttl": 43000, "accessor": "new", "orphan": True}}])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        self.assertEqual("new", lifecycle.rotate("rotate", "issuer-token", "keeper", ["keykeeper"], self.root / "token")["accessor"])
        self.assertEqual("new-secret", m.object_json(m.private_read(self.root / "token"))["token"])
        self.assertNotIn("new-secret", self.journal.path.read_text())
        self.assertFalse(api.calls[1][3]["renewable"])
        self.assertTrue(api.calls[1][3]["no_default_policy"])
        with self.assertRaises(m.Refused):
            lifecycle.rotate("foreign-role", "issuer-token", "admin", ["root"], self.root / "foreign")
        with self.assertRaises(m.Refused):
            lifecycle.rotate("too-short", "issuer-token", "keeper", ["keykeeper"],
                             self.root / "short", ttl=3600)

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
        self.assertNotIn("shares", self.journal.path.read_text())
        self.assertIsNone(api.calls[1][2])  # no root token for threshold unseal

    def test_cold_identity_adoption_updates_only_original_mappers_then_revokes_sessions(self):
        agent = "11111111-1111-4111-8111-111111111111"
        ids = {"keykeeper-agent": {"clientId": "22222222-2222-4222-8222-222222222222",
                                   "mapperId": "33333333-3333-4333-8333-333333333333"},
               "keykeeper-human": {"clientId": "44444444-4444-4444-8444-444444444444",
                                   "mapperId": "55555555-5555-4555-8555-555555555555"}}
        binding = {"sourceGeneration": "q-111111111111", "generation": "q-222222222222",
                   "agentSubject": agent, "clientMappers": ids}
        user = {"id": agent, "serviceAccountClientId": "keykeeper-agent", "enabled": True}
        def model(name):
            return {"id": ids[name]["mapperId"], "name": "keykeeper-generation",
                    "protocolMapper": "oidc-hardcoded-claim-mapper", "config": {
                        "claim.name": "p0v3_generation", "claim.value": binding["sourceGeneration"],
                        "access.token.claim": "true"}}
        agent_model, human_model = model("keykeeper-agent"), model("keykeeper-human")
        def read_updated(method, path, token, body):
            original = agent_model if "22222222" in path else human_model
            return dict(original, config=dict(original["config"], **{"claim.value": binding["generation"]}))
        api = FakeApi([user, {"id": ids["keykeeper-agent"]["clientId"], "clientId": "keykeeper-agent", "enabled": True},
                       agent_model, {"id": ids["keykeeper-human"]["clientId"], "clientId": "keykeeper-human", "enabled": True},
                       human_model, {}, read_updated, {}, read_updated, user, {}])
        lifecycle = m.IdentityLifecycle(api, "p0v3", "bearer", self.authority, self.journal)
        verified = Mock(return_value={"generation": binding["generation"],
                                      "sourceGeneration": binding["sourceGeneration"], "publicActivation": False})
        result = lifecycle.adopt_recovered_generation("adopt", binding, verified)
        self.assertEqual(binding["generation"], result["generation"])
        self.assertFalse(result["publicActivation"])
        self.assertEqual(1, verified.call_count)
        self.assertEqual(["PUT", "PUT", "POST"], [c[0] for c in api.calls if c[0] in ("PUT", "POST")])
        self.assertEqual("/admin/realms/p0v3/logout", api.calls[-1][1])
        self.assertNotIn("bearer", self.journal.path.read_text())
        self.assertEqual(2, sum("claim.value" in str(c[3]) and c[3]["config"]["claim.value"] == binding["generation"]
                                for c in api.calls if c[0] == "PUT"))
        # Journalled completion cannot be repeated under the same operation identity.
        api.responses = [user, {"id": ids["keykeeper-agent"]["clientId"], "clientId": "keykeeper-agent", "enabled": True},
                         agent_model, {"id": ids["keykeeper-human"]["clientId"], "clientId": "keykeeper-human", "enabled": True},
                         human_model]
        with self.assertRaises(m.Refused):
            lifecycle.adopt_recovered_generation("adopt", binding, verified)
        self.assertEqual(1, sum(c[1] == "/admin/realms/p0v3/logout" for c in api.calls))
        other = FakeApi([])
        with self.assertRaises(m.Refused):
            m.IdentityLifecycle(other, "p0v3", "bearer", self.authority, m.Journal(self.root)).adopt_recovered_generation(
                "foreign", binding, lambda _: {"generation": "q-333333333333", "sourceGeneration": binding["sourceGeneration"],
                                              "publicActivation": False})
        self.assertEqual([], other.calls)

    def test_cold_adoption_preserves_owner_reader_and_updates_five_exact_native_generation_mappers(self):
        original = "q-111111111111"; restored = "q-222222222222"
        owner = "11111111-1111-4111-8111-111111111111"
        agent = "22222222-2222-4222-8222-222222222222"
        lane = "33333333-3333-4333-8333-333333333333"
        reader = "44444444-4444-4444-8444-444444444444"
        clients = ["identity-controller", "keykeeper-agent", "keykeeper-human", "managed-lane-agent",
                   "managed-lane-reader"]
        pinned = {name: {"clientId": str(uuid.UUID(int=20 + index)),
                         "mapperId": str(uuid.UUID(int=40 + index))}
                  for index, name in enumerate(clients)}
        def mapper(name, generation):
            return {"id": pinned[name]["mapperId"],
                    "name": "identity-generation" if name == "identity-controller" else "keykeeper-generation",
                    "protocolMapper": "oidc-hardcoded-claim-mapper",
                    "config": {"claim.name": "p0v3_generation", "claim.value": generation,
                               "access.token.claim": "true"}}
        binding = {"sourceGeneration": original, "generation": restored, "agentSubject": agent,
                   "managedLaneAgentSubject": lane, "managedLaneReaderSubject": reader,
                   "ownerSubject": owner, "clientMappers": pinned}
        service = lambda name, subject: {"id": subject, "enabled": True, "serviceAccountClientId": name}
        responses = [{"id": owner, "username": "owner", "enabled": True},
                     service("keykeeper-agent", agent), service("managed-lane-agent", lane),
                     service("managed-lane-reader", reader)]
        for name in clients:
            responses += [{"id": pinned[name]["clientId"], "clientId": name, "enabled": True}, mapper(name, original)]
        for name in clients: responses += [{}, mapper(name, restored)]
        responses += [service("keykeeper-agent", agent), service("managed-lane-agent", lane),
                      service("managed-lane-reader", reader), {}]
        api = FakeApi(responses)
        self.authority.subjects = {owner}
        result = m.IdentityLifecycle(api, "p0v3", "original-owner-bearer", self.authority, self.journal) \
            .adopt_recovered_generation("adopt-all", binding,
                lambda _: {"generation": restored, "sourceGeneration": original, "publicActivation": False})
        self.assertEqual(owner, binding["ownerSubject"])
        self.assertEqual(lane, result["managedLaneAgentSubject"])
        self.assertEqual(reader, result["managedLaneReaderSubject"])
        self.assertEqual(5, sum(c[0] == "PUT" for c in api.calls))
        self.assertEqual("/admin/realms/p0v3/logout", api.calls[-1][1])
        self.assertNotIn("original-owner-bearer", self.journal.path.read_text())
        self.assertTrue(all(c[3]["config"]["claim.value"] == restored for c in api.calls if c[0] == "PUT"))

    def test_first_install_bao_initialization_requires_stage_proof_and_private_custody(self):
        binding = {"generation": "q-111111111111", "member": "bao-member", "endpoint": FakeApi.origin,
                   "leafSha256": FakeApi.pin}
        sealed = {"initialized": False, "sealed": True}
        initialized = {"initialized": True, "sealed": True, "progress": 0,
                       "type": "shamir", "t": 2, "cluster_id": "original-cluster"}
        api = FakeApi([sealed, {"keys_base64": ["a" * 32, "b" * 32, "c" * 32],
                                "root_token": "private-initial-root-token"}, initialized])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        proof = Mock(return_value={"generation": binding["generation"], "member": binding["member"],
                                   "publicActivation": False})
        result = lifecycle.initialize("initial", binding, self.root / "custody", proof, shares=3, threshold=2)
        self.assertTrue(result["initializedSealed"])
        self.assertEqual("original-cluster", result["clusterId"])
        self.assertEqual(2, result["threshold"])
        self.assertEqual("private-initial-root-token", m.read_token(self.root / "custody"))
        self.assertNotIn("private-initial-root-token", self.journal.path.read_text())
        self.assertNotIn("a" * 32, self.journal.path.read_text())
        self.assertEqual(1, sum(c[0] == "POST" for c in api.calls))
        api.responses = [sealed]
        with self.assertRaises(m.Refused):
            lifecycle.initialize("other", binding, self.root / "custody", proof)
        self.assertEqual(1, sum(c[0] == "POST" for c in api.calls))
        invalid = FakeApi([])
        with self.assertRaises(m.Refused):
            m.BaoLifecycle(invalid, "bearer", self.authority, m.Journal(self.root)).initialize(
                "foreign", binding, self.root / "different", lambda _: {"generation": "q-222222222222",
                                                                     "member": binding["member"], "publicActivation": False})
        self.assertEqual([], invalid.calls)

    def test_first_install_bao_bootstraps_real_kv_policy_role_and_private_issuer_before_root_retirement(self):
        binding = dict(self.binding(), member="bao-member")
        proof = Mock(return_value={"generation": binding["generation"], "member": binding["member"],
                                   "publicActivation": False})
        mount = {"data": {"keykeeper/": {"type": "kv", "options": {"version": "2"}}}}
        holder = {}
        def policy(name):
            return lambda *_: {"data": {"policy": holder[name]}}
        def record(name):
            def capture(method, path, token, body):
                holder[name] = body["policy"]
                return {}
            return capture
        api = FakeApi([{"initialized": True, "sealed": False, "cluster_id": "cluster"},
                       {"data": {"sys/": {"type": "system"}}},
                       {"data": {"policies": ["root"], "accessor": "original-root"}},
                       {}, record("keeper"), record("issuer"), {}, {}, {},
                       {"data": {"role_id": "original-approle-role-id"}},
                       {"data": {"secret_id": "private-approle-secret-id", "secret_id_accessor": "original-secret-accessor"}},
                       {"auth": {"client_token": "private-scoped-issuer", "accessor": "issuer-accessor"}},
                       {"data": {"policies": ["keykeeper-issuer"], "accessor": "issuer-accessor",
                                 "orphan": True, "renewable": True, "period": 86400, "ttl": 86000}},
                       mount, policy("keeper"), policy("issuer"),
                       {"data": {"allowed_policies": ["keykeeper"], "orphan": True}},
                       {"data": {"token_policies": ["keykeeper-issuer"], "bind_secret_id": True,
                                 "secret_id_num_uses": 0, "secret_id_ttl": 0,
                                 "token_no_default_policy": True, "token_period": 86400}},
                       {"data": {"role_id": "original-approle-role-id"}}])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        result = lifecycle.bootstrap_keykeeper("bootstrap", binding, "private-root", self.root / "issuer",
                                               self.root / "protected-recovery", proof)
        self.assertEqual("keykeeper", result["kvMount"])
        self.assertEqual("private-approle-secret-id",
                         m.object_json(m.private_read(self.root / "protected-recovery"))["secretId"])
        self.assertEqual("private-scoped-issuer", m.read_token(self.root / "issuer"))
        self.assertNotIn("private-scoped-issuer", self.journal.path.read_text())
        self.assertNotIn("private-approle-secret-id", self.journal.path.read_text())
        self.assertNotIn("private-root", self.journal.path.read_text())
        self.assertEqual(["/v1/sys/mounts/keykeeper", "/v1/sys/policies/acl/keykeeper",
                          "/v1/sys/policies/acl/keykeeper-issuer", "/v1/auth/token/roles/keeper",
                          "/v1/sys/auth/approle", "/v1/auth/approle/role/keeper-issuer",
                          "/v1/auth/approle/role/keeper-issuer/secret-id", "/v1/auth/token/create"],
                         [path for method, path, *_ in api.calls if method in ("POST", "PUT")])
        with self.assertRaises(m.Refused):
            lifecycle.bootstrap_keykeeper("bootstrap", binding, "private-root", self.root / "issuer",
                                          self.root / "protected-recovery", proof)

    def test_aged_cold_recovery_reissues_original_approle_into_new_periodic_issuer(self):
        original = "q-111111111111"; target = "q-222222222222"
        recovery = self.root / "original-recovery-custody"
        m.private_create(recovery, m.canonical({"generation": original, "clusterId": "cluster",
                                                "roleId": "original-role-id-private", "secretId": "original-secret-private",
                                                "secretAccessor": "original-secret-accessor"}))
        binding = dict(self.binding(), sourceGeneration=original, generation=target,
                       sourceRecoveryCustodySha256=m.digest(m.private_read(recovery)))
        self.authority.generation = target
        proof = Mock(return_value={"generation": target, "sourceGeneration": original, "publicActivation": False})
        status = {"initialized": True, "sealed": False, "cluster_id": "cluster"}
        grant = {"auth": {"client_token": "new-target-issuer-private", "accessor": "target-accessor"}}
        observed = {"data": {"policies": ["keykeeper-issuer"], "ttl": 86400, "period": 86400,
                             "accessor": "target-accessor", "orphan": True, "renewable": True}}
        api = FakeApi([status, grant, observed])
        lifecycle = m.BaoLifecycle(api, "target-generation-owner-bearer", self.authority, self.journal)
        result = lifecycle.recover_issuer("recover-issuer", binding, recovery, self.root / "target-issuer", proof)
        self.assertEqual(target, result["generation"])
        self.assertFalse(result["publicActivation"])
        self.assertEqual("new-target-issuer-private", m.read_token(self.root / "target-issuer"))
        self.assertNotIn("original-secret-private", self.journal.path.read_text())
        self.assertNotIn("new-target-issuer-private", self.journal.path.read_text())
        self.assertEqual({"role_id": "original-role-id-private", "secret_id": "original-secret-private"}, api.calls[1][3])
        with self.assertRaises(m.Refused):
            lifecycle.recover_issuer("fresh-id", binding, recovery, self.root / "target-issuer", proof)
        self.assertEqual(1, sum(c[1] == "/v1/auth/approle/login" for c in api.calls))
        foreign = FakeApi([])
        with self.assertRaises(m.Refused):
            m.BaoLifecycle(foreign, "bearer", self.authority, self.journal).recover_issuer(
                "foreign", dict(binding, sourceRecoveryCustodySha256="a" * 64), recovery,
                self.root / "foreign-issuer", proof)
        self.assertEqual([], foreign.calls)

    def test_scoped_issuer_renewal_preserves_original_accessor_and_uncertainty(self):
        live = {"data": {"policies": ["keykeeper-issuer"], "orphan": True,
                         "renewable": True, "period": 86400, "ttl": 1800,
                         "accessor": "original-scoped-accessor"}}
        status = {"initialized": True, "sealed": False, "cluster_id": "cluster"}
        renewed = {"data": dict(live["data"], ttl=86000)}
        api = FakeApi([status, live, {"auth": {"renewable": True}}, renewed])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        self.assertTrue(lifecycle.renew_issuer("renew", "secret-issuer", "cluster")["renewed"])
        self.assertEqual(("POST", "/v1/auth/token/renew-self"), api.calls[2][:2])
        self.assertNotIn("secret-issuer", self.journal.path.read_text())
        api.responses = [status, live]
        with self.assertRaises(m.Refused):
            lifecycle.renew_issuer("renew", "secret-issuer", "cluster")
        self.assertEqual(1, sum(c[1] == "/v1/auth/token/renew-self" for c in api.calls))
        other = FakeApi([status, live, TimeoutError()])
        (self.root / "other-journal").mkdir(mode=0o700)
        lifecycle = m.BaoLifecycle(other, "bearer", self.authority, m.Journal(self.root / "other-journal"))
        with self.assertRaises(TimeoutError):
            lifecycle.renew_issuer("lost-ack", "secret-issuer", "cluster")
        other.responses = [status, live]
        with self.assertRaises(m.Refused):
            lifecycle.renew_issuer("fresh-id", "secret-issuer", "cluster")
        self.assertEqual(1, sum(c[1] == "/v1/auth/token/renew-self" for c in other.calls))

    def test_bao_bootstrap_existing_mount_and_uncertain_role_refuse_new_operation(self):
        binding = dict(self.binding(), member="bao-member")
        proof = lambda _: {"generation": binding["generation"], "member": binding["member"],
                           "publicActivation": False}
        state = {"initialized": True, "sealed": False, "cluster_id": "cluster"}
        api = FakeApi([state, {"data": {"keykeeper/": {"type": "kv"}}}])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        with self.assertRaises(m.Refused):
            lifecycle.bootstrap_keykeeper("existing", binding, "private-root", self.root / "issuer",
                                          self.root / "protected-recovery", proof)
        self.assertEqual(0, sum(c[0] == "POST" for c in api.calls))
        api.responses = [state, {"data": {"sys/": {"type": "system"}}},
                         {"data": {"policies": ["root"], "accessor": "original"}},
                         {}, {}, {}, TimeoutError()]
        with self.assertRaises(TimeoutError):
            lifecycle.bootstrap_keykeeper("uncertain", binding, "private-root", self.root / "issuer",
                                          self.root / "protected-recovery", proof)
        api.responses = [state, {"data": {"sys/": {"type": "system"}}},
                         {"data": {"policies": ["root"], "accessor": "original"}}]
        with self.assertRaises(m.Refused):
            lifecycle.bootstrap_keykeeper("new-operation", binding, "private-root", self.root / "issuer",
                                          self.root / "protected-recovery", proof)
        self.assertEqual(1, sum(c[1] == "/v1/sys/mounts/keykeeper" for c in api.calls))

    def test_initial_root_retirement_is_exact_cluster_and_retains_uncertain_outcome(self):
        status = {"initialized": True, "sealed": False, "cluster_id": "cluster"}
        root = {"data": {"policies": ["root"], "accessor": "root-accessor"}}
        api = FakeApi([status, root, {}, {"errors": ["permission denied"]}])
        lifecycle = m.BaoLifecycle(api, "bearer", self.authority, self.journal)
        self.journal.execute("prepared", {"action": "bao-bootstrap-keykeeper", "scope": api.origin,
                                          "clusterId": "cluster"}, lambda: None)
        self.assertTrue(lifecycle.retire_initial_root("root-op", "root-private-value", "cluster")["rootRetired"])
        self.assertNotIn("root-private-value", self.journal.path.read_text())
        self.assertNotIn("root-accessor", self.journal.path.read_text())
        self.assertEqual((403,), api.calls[-1][-1]["expected"])
        api.responses = [status, root]
        with self.assertRaises(m.Refused):
            lifecycle.retire_initial_root("root-op", "root-private-value", "cluster")
        self.assertEqual(1, sum(call[0] == "POST" for call in api.calls))
        bad = FakeApi([dict(status, cluster_id="foreign")])
        with self.assertRaises(m.Refused):
            m.BaoLifecycle(bad, "bearer", self.authority, m.Journal(self.root)).retire_initial_root("foreign", "root", "cluster")
        (self.root / "without-bootstrap").mkdir(mode=0o700)
        unprepared = FakeApi([status, root])
        with self.assertRaises(m.Refused):
            m.BaoLifecycle(unprepared, "bearer", self.authority, m.Journal(self.root / "without-bootstrap")) \
                .retire_initial_root("premature", "root-private-value", "cluster")
        self.assertEqual(0, sum(c[0] == "POST" for c in unprepared.calls))

    def test_unseal_journal_never_records_optional_private_binding_fields(self):
        sealed = {"initialized": True, "sealed": True, "progress": 0, "type": "shamir", "t": 1}
        api = FakeApi([sealed, dict(sealed, sealed=False, cluster_id="cluster")])
        binding = dict(self.binding(), privateRecoveryShare="never-journal-this-private-value")
        m.BaoLifecycle(api, "bearer", self.authority, self.journal).unseal("recover", binding, ["s" * 32], Mock())
        self.assertNotIn("never-journal-this-private-value", self.journal.path.read_text())

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
