import json
from pathlib import Path
import tempfile
import unittest

import identity_recovery as recovery
from identity_secrets import Refused, canonical, digest, private_create


class RecoveryAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.generations = self.base / "generations"
        self.runtime = self.base / "runtime"
        self.source = "q-111111111111"
        self.target = "q-222222222222"
        for path in (self.generations, self.runtime, self.generations / self.source,
                     self.generations / self.target, self.runtime / "target-bao"):
            path.mkdir(mode=0o700)
        self.root = self.generations / self.target
        original = {"request": {"id": self.source}, "members": [{"member": {"name": "source-bao"},
                    "runtimeFingerprint": "c" * 64, "spec": {"processes": [{"id": "bao", "oneShot": False}]}}]}
        source_raw = canonical(original)
        private_create(self.generations / self.source / "bundle.json", source_raw)
        self.lineage = {"schemaVersion": 1, "id": "cap-111111111111", "generation": self.source,
                        "bundleSha256": digest(source_raw), "snapshotId": "1" * 32, "rootObjectId": "k" * 32,
                        "manifestSha256": "d" * 64, "files": 3, "plaintextBytes": 123,
                        "image": "repo/kopia@sha256:" + "a" * 64, "imageId": "b" * 64}
        receipt_raw = canonical(self.lineage)
        self.receipt_hash = digest(receipt_raw)
        spec = {"name": "target-bao", "processes": [{"id": "bao", "oneShot": False,
                "command": ["server", "-config=/run/secrets/bao.hcl"], "environmentFile": "bao.env"}]}
        manifest_raw = canonical(spec)
        env = b"BAO_ADDR=https://bao:8200\nBAO_CACERT=/run/secrets/ca.pem\nHOME=/tmp\n"
        cert = b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n"  # Synthetic DER bytes; no TLS connection.
        pin = {"member": {"name": "target-bao"}, "runtimeFingerprint": "e" * 64, "spec": spec,
               "manifestSha256": digest(manifest_raw), "inputHashes": {"bao.env": digest(env), "web.pem": digest(cert)}}
        self.bundle = {"request": {"id": self.target}, "recoverySourceKopia": self.lineage, "members": [pin]}
        target_raw = canonical(self.bundle)
        self.binding = {"generation": self.target, "targetBundleSha256": digest(target_raw),
                        "snapshotReceiptSha256": self.receipt_hash, "member": "target-bao",
                        "endpoint": "https://bao:8200", "leafSha256": digest(b"\x01\x02\x03")}
        records = {
            "bundle.json": self.bundle,
            "recovery.source.json": self.lineage,
            "stage.intent.json": {"action": "restore-import", "bundleSha256": digest(target_raw)},
            "stage.result.json": {"action": "restore-import", "bundleSha256": digest(target_raw), "passed": True,
                                  "fences": {"target-bao": "fence"}},
            "target-bao.import.intent.json": {"action": "import-member", "bundleSha256": digest(target_raw)},
            "target-bao.import.result.json": {"name": "target-bao", "fingerprint": "e" * 64, "maintenanceId": "fence"},
            "recovery.check.json": {"generation": self.source, "capsule": self.lineage["id"],
                "bundleSha256": self.lineage["bundleSha256"], "archiveSha256": "", "kopiaSnapshotId": "1" * 32,
                "kopiaReceiptSha256": self.receipt_hash, "members": [
                    {"name": "source-bao", "fingerprint": "c" * 64, "retiredInitializers": []}]},
        }
        for name, value in records.items():
            private_create(self.root / name, canonical(value))
        private_create(self.runtime / "target-bao.json", manifest_raw)
        private_create(self.runtime / "target-bao" / "bao.env", env)
        private_create(self.runtime / "target-bao" / "web.pem", cert)
        marker = f"p0v3-native-volume-import-v1\n{'e' * 64}\n{self.receipt_hash}\n".encode()
        for name in ("runtime.import.intent", "runtime.import.complete"):
            private_create(self.runtime / "target-bao" / name, marker)

    def tearDown(self):
        self.tmp.cleanup()

    def verify(self):
        return recovery.verify_recovery(self.binding, generation_base=self.generations, runtime_base=self.runtime)

    def mutate(self, name, edit):
        path = self.root / name
        obj = json.loads(path.read_text())
        edit(obj)
        path.write_bytes(canonical(obj))

    def test_first_install_requires_staged_bao_tls_daemon_and_no_recovery_lineage(self):
        fresh = dict(self.bundle)
        fresh.pop("recoverySourceKopia")
        data = canonical(fresh)
        (self.root / "bundle.json").write_bytes(data)
        binding = {"generation": self.target, "member": "target-bao", "targetBundleSha256": digest(data),
                   "endpoint": "https://bao:8200", "leafSha256": digest(b"\x01\x02\x03")}
        (self.root / "stage.intent.json").write_bytes(canonical({"action": "stage", "bundleSha256": digest(data)}))
        private_create(self.root / "target-bao.stage.intent.json", canonical({"action": "stage-member", "bundleSha256": digest(data)}))
        private_create(self.root / "target-bao.stage.result.json", canonical([{"id": "bao", "state": "running", "exitCode": None}]))
        result = recovery.verify_install(binding, generation_base=self.generations, runtime_base=self.runtime)
        self.assertFalse(result["publicActivation"])
        self.assertFalse(result["initialized"])
        (self.root / "target-bao.stage.result.json").write_bytes(canonical([{"id": "bao", "state": "exited", "exitCode": 1}]))
        with self.assertRaises(Refused):
            recovery.verify_install(binding, generation_base=self.generations, runtime_base=self.runtime)

    def test_exact_original_snapshot_and_daemon_import_authorize_only_private_recovery(self):
        result = self.verify()
        self.assertEqual("1" * 32, result["snapshotId"])
        self.assertFalse(result["publicActivation"])

    def test_external_anchor_is_not_replaced_by_local_record(self):
        self.binding["targetBundleSha256"] = "f" * 64
        with self.assertRaises(Refused):
            self.verify()

    def test_tls_pin_and_endpoint_must_match_the_imported_daemon_inputs(self):
        original = dict(self.binding)
        for key, value in (("leafSha256", "f" * 64), ("endpoint", "https://foreign:8200")):
            self.binding = dict(original, **{key: value})
            with self.assertRaises(Refused):
                self.verify()

    def test_missing_member_marker_refuses_even_with_successful_stage(self):
        (self.runtime / "target-bao" / "runtime.import.complete").unlink()
        with self.assertRaises(FileNotFoundError):
            self.verify()

    def test_failed_stage_foreign_fence_and_replayed_initializer_refused(self):
        cases = [
            ("stage.result.json", lambda o: o.update(passed=False)),
            ("target-bao.import.result.json", lambda o: o.update(maintenanceId="foreign")),
            ("recovery.check.json", lambda o: o["members"][0].update(retiredInitializers=["invented-init"])),
            ("recovery.check.json", lambda o: o.update(runtimeImported=True)),
            ("recovery.source.json", lambda o: o.update(snapshotId="2" * 32)),
            ("target-bao.import.intent.json", lambda o: o.update(priorIntentSha256="f" * 64)),
        ]
        for name, edit in cases:
            path = self.root / name
            raw = path.read_bytes()
            self.mutate(name, edit)
            with self.assertRaises(Refused, msg=name):
                self.verify()
            path.write_bytes(raw)

    def test_current_credential_manifest_and_original_source_must_remain_anchored(self):
        for path in (self.runtime / "target-bao" / "bao.env", self.runtime / "target-bao.json",
                     self.generations / self.source / "bundle.json"):
            raw = path.read_bytes()
            path.write_bytes(raw + b" ")
            with self.assertRaises(Refused):
                self.verify()
            path.write_bytes(raw)

    def test_symlink_and_world_readable_controller_records_refused(self):
        path = self.root / "stage.result.json"
        path.chmod(0o644)
        with self.assertRaises(Refused):
            self.verify()
        path.chmod(0o600)
        moved = self.root / "moved"
        path.rename(moved)
        path.symlink_to(moved)
        with self.assertRaises(Refused):
            self.verify()


if __name__ == "__main__":
    unittest.main()
