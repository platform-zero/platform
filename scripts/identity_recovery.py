"""Read-only admission for explicit Bao unseal of a controller-imported generation.

Mirrors the controller's completedCaptureSource proof; never synthesizes receipts,
replays initializers, removes fences, promotes a recovery, or resumes its source.
The target bundle hash and snapshot receipt hash must be anchored by the operator
outside the recovery directory. Private controller records are trusted local inputs,
not independent attestation against a compromised controller UID.
"""
from pathlib import Path
import re
import ssl
from identity_secrets import HASH, ID, digest, object_json, private_directory, private_read, require

GENERATION_BASE = Path("/mnt/media/p0-v3/release-generations")
RUNTIME_BASE = Path("/mnt/media/p0-v3/runtime-deployments")
GENERATION = re.compile(r"q-[a-f0-9]{12}\Z")


def verify_recovery(binding, *, generation_base=GENERATION_BASE, runtime_base=RUNTIME_BASE):
    generation = binding.get("generation", "")
    expected = binding.get("targetBundleSha256", "")
    receipt_hash = binding.get("snapshotReceiptSha256", "")
    member = binding.get("member", "")
    require(GENERATION.fullmatch(generation) and HASH.fullmatch(expected) and HASH.fullmatch(receipt_hash) and
            ID.fullmatch(member), "Externally anchored recovery binding required")
    root = private_directory(Path(generation_base) / generation)
    def record(name):
        return object_json(private_read(root / name))
    bundle_raw = private_read(root / "bundle.json")
    require(digest(bundle_raw) == expected, "Target bundle changed")
    bundle = object_json(bundle_raw)
    require(bundle.get("request", {}).get("id") == generation and bundle.get("recoverySourceArchiveSha256") is None and
            bundle.get("ownership") is None and bundle.get("assemblySha256") is None, "Not a private Kopia recovery")
    lineage = bundle.get("recoverySourceKopia")
    require(isinstance(lineage, dict) and lineage.get("schemaVersion", 1) == 1 and
            GENERATION.fullmatch(lineage.get("generation", "")) and lineage["generation"] != generation and
            re.fullmatch(r"[a-f0-9]{32,64}", lineage.get("snapshotId", "")) and
            HASH.fullmatch(lineage.get("bundleSha256", "")), "Invalid original snapshot lineage")
    source_raw = private_read(root / "recovery.source.json")
    require(object_json(source_raw) == lineage and digest(source_raw) == receipt_hash,
            "Original snapshot receipt changed")
    parent_root = private_directory(Path(generation_base) / lineage["generation"])
    parent_raw = private_read(parent_root / "bundle.json")
    require(digest(parent_raw) == lineage["bundleSha256"], "Original source bundle changed")
    parent = object_json(parent_raw)
    require(parent.get("request", {}).get("id") == lineage["generation"], "Foreign source generation")
    pins = bundle.get("members", [])
    names = [pin["member"]["name"] for pin in pins]
    require(names and len(names) == len(set(names)) and member in names and all(ID.fullmatch(n) for n in names),
            "Invalid recovery cohort")
    stage = record("stage.result.json")
    intent = record("stage.intent.json")
    require(intent.get("action") == "restore-import" and intent.get("bundleSha256") == expected and
            intent.get("priorIntentSha256") is None and stage.get("action") == "restore-import" and
            stage.get("bundleSha256") == expected and stage.get("passed") is True and stage.get("failureType") is None and
            stage.get("priorIntentSha256") is None and set(stage.get("fences", {})) == set(names) and
            all(isinstance(f, str) and f for f in stage["fences"].values()), "Incomplete generation import journal")
    check = record("recovery.check.json")
    require(check.get("generation") == lineage["generation"] and check.get("capsule") == lineage["id"] and
            check.get("bundleSha256") == lineage["bundleSha256"] and check.get("archiveSha256") == "" and
            check.get("kopiaSnapshotId") == lineage["snapshotId"] and check.get("kopiaReceiptSha256") == receipt_hash and
            check.get("runtimeImported", False) is False and check.get("functionalRestoreVerified", False) is False,
            "Recovery check does not bind original snapshot")
    originals = parent.get("members", [])
    checked = check.get("members", [])
    require(len(originals) == len(checked) == len(pins), "Recovery source cohort changed")
    for old, observed in zip(originals, checked):
        require(observed.get("name") == old["member"]["name"] and observed.get("fingerprint") == old["runtimeFingerprint"] and
                set(observed.get("retiredInitializers", [])) ==
                {p["id"] for p in old["spec"]["processes"] if p.get("oneShot", False)}, "Initializer retirement changed")
    for pin in pins:
        name = pin["member"]["name"]
        spec = pin["spec"]
        require(spec["name"] == name and spec["processes"] and not any(p.get("oneShot", False) for p in spec["processes"]),
                "Recovered daemon scope regained an initializer")
        member_intent = record(name + ".import.intent.json")
        imported = record(name + ".import.result.json")
        require(member_intent.get("action") == "import-member" and member_intent.get("bundleSha256") == expected and
                member_intent.get("priorIntentSha256") is None and imported.get("name") == name and
                imported.get("fingerprint") == pin["runtimeFingerprint"] and
                imported.get("maintenanceId") == stage["fences"][name], "Incomplete member import journal")
        runtime = private_directory(Path(runtime_base) / name)
        marker = f"p0v3-native-volume-import-v1\n{pin['runtimeFingerprint']}\n{receipt_hash}\n".encode()
        for file in ("runtime.import.intent", "runtime.import.complete"):
            require(private_read(runtime / file) == marker, "Native import lineage changed")
        # The controller's retained exact manifest/input closure must still match the imported bundle.
        manifest = private_read(Path(runtime_base) / (name + ".json"))
        require(digest(manifest) == pin["manifestSha256"] and object_json(manifest) == spec, "Runtime manifest changed")
        inputs = runtime
        for file, checksum in pin["inputHashes"].items():
            require(isinstance(file, str) and file not in (".", "..") and "/" not in file and HASH.fullmatch(checksum),
                    "Invalid input binding")
            require(digest(private_read(inputs / file)) == checksum, "Recovered runtime input changed")
        if name == member:
            bao = [p for p in spec["processes"] if p["id"] == "bao"]
            require(len(bao) == 1 and bao[0].get("command") == ["server", "-config=/run/secrets/bao.hcl"] and
                    bao[0].get("environmentFile") == "bao.env", "Exact Bao daemon required")
            env = private_read(inputs / "bao.env").decode()
            pairs = [line.split("=", 1) for line in env.splitlines() if line]
            require(all(len(pair) == 2 for pair in pairs), "Malformed Bao environment")
            environment = dict(pairs)
            require(len(environment) == len(pairs) and set(environment) == {"BAO_ADDR", "BAO_CACERT", "HOME"},
                    "Recovery authority cannot be a daemon input")
            require(environment["BAO_ADDR"] == binding.get("endpoint") and
                    environment["BAO_CACERT"] == "/run/secrets/ca.pem", "Recovery endpoint differs from imported daemon")
            certificate = ssl.PEM_cert_to_DER_cert(private_read(inputs / "web.pem").decode("ascii"))
            require(digest(certificate) == binding.get("leafSha256"), "Recovery TLS identity differs from imported daemon")
    return {"generation": generation, "snapshotId": lineage["snapshotId"], "publicActivation": False}
