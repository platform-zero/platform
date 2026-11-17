#!/usr/bin/env python3
"""Read-only implementation census. Never imports or executes product/runner code.

Reports missing declared entrypoints separately from phase-declaration metadata and
explicit references to related source. None establishes workflow implementation,
runtime verification, artifact availability, or release qualification.
"""
import argparse
import hashlib
import json
from pathlib import Path


PHASES = {"INSTALL", "RESTORE"}
STATUSES = {"missing-code", "source-present", "unit-verified"}
# Diagnostic recognition only. Actual execution authority comes from the approved plan,
# not this census. Presence is never runtime or qualification evidence.
CURRENT_POLICY = {
    "operator": "direct-main-assistant-no-subagents",
    "executionBoundary": "bounded-development-through-two-qualification-cycles",
    "workerPolicy": {
        "maximumImplementationWorkers": 1,
        "coordinatorProductionWrites": True,
        "nestedAgents": False,
        "writeAuthority": "direct-implementation-preserve-existing-work",
        "inactivePaths": "historical-claims-not-current-authority",
    },
    "currentLimits": {
        "allowed": ["source-read-search-diff", "source-and-test-writes", "builds-and-targeted-tests",
                    "inventory-execution", "artifact-acquisition-and-image-builds",
                    "bounded-integration-and-two-qualification-cycles"],
        "forbidden": ["subagents", "public-production-cutover", "historical-rss-publication",
                      "irreversible-external-actions", "unrelated-host-changes",
                      "uncertain-effect-replay", "git-publication"],
        "futureExecution": "public-cutover-and-external-effects-require-separate-authorization",
        "sourceReviewIsTesting": False,
        "sourceCompletion": "not-established-by-census",
        "qualification": {"completed": 0, "required": 2},
    },
}


def current_policy(scope):
    if any(scope.get(field) != expected for field, expected in CURRENT_POLICY.items()):
        raise ValueError("Stale or overbroad implementation policy")
    return {field: scope[field] for field in CURRENT_POLICY}


def document(root, name):
    path = root / name
    if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
        raise ValueError(f"Unsafe or absent inventory input: {name}")
    raw = path.read_bytes()
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError(f"Oversized inventory input: {name}")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def source(root, name):
    if not isinstance(name, str) or not name or Path(name).is_absolute() or any(
            part in {"", ".", ".."} for part in name.split("/")):
        raise ValueError("Invalid source dependency path")
    path = root / name
    if path.is_symlink() or path.resolve() != path.absolute():
        raise ValueError(f"Linked source dependency: {name}")
    if not path.is_file():
        return {"path": name, "present": False, "sha256": None}
    return {"path": name, "present": True, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def inventory(workspace):
    root = Path(workspace).resolve(strict=True)
    paths = {
        "products": "platform/src/main/resources/products.json",
        "manifest": "acceptance/cases/manifest.json",
        "clients": "acceptance/cases/official-clients.json",
        "android": "acceptance/cases/android-apps.json",
        "scope": "platform/release/implementation-scope.json",
    }
    inputs = {name: document(root, path) for name, path in paths.items()}
    products, manifest, clients, android, scope = (inputs[key][0] for key in paths)
    policy = current_policy(scope)  # Reject stale/overbroad policy; never confer execution authority.
    if any(item[0].get("schemaVersion") != (2 if key == "manifest" else 1) for key, item in inputs.items()):
        raise ValueError("Unsupported inventory schema")
    selected = set(products["products"])
    targets = {row["serviceId"] for row in manifest["targets"]}
    if len(targets) != len(manifest["targets"]) or len(selected) != 39 or len(selected) != len(products["products"]) or not selected <= targets:
        raise ValueError("Selected catalog and manifest disagree")
    if len(clients["targets"]) != len(targets) or {row["target"] for row in clients["targets"]} != targets:
        raise ValueError("Official-client classification is incomplete")
    domains = scope["domains"]
    owners = {}
    for domain in domains:
        if domain["status"] not in STATUSES or not domain["blockers"] and domain["status"] == "missing-code":
            raise ValueError("Invalid domain status")
        for target in domain["targets"]:
            if target in owners:
                raise ValueError(f"Duplicate implementation owner: {target}")
            owners[target] = domain["id"]
        domain["sources"] = [source(root, path) for path in domain.pop("sourceFiles")]
        if any(not item["present"] for item in domain["sources"]):
            raise ValueError(f"Missing declared domain source: {domain['id']}")
        # A manual status alone must never manufacture a unit-verification claim.
        if domain["status"] == "unit-verified":
            raise ValueError("Unit verification requires a separately fingerprint-bound checkpoint")
    if set(owners) != targets:
        raise ValueError("Every manifest target requires exactly one implementation owner")
    references = scope.get("adapterSourceReferences", {})
    adapters = {case["adapter"] for case in manifest["cases"]}
    if not isinstance(references, dict) or not set(references) <= adapters:
        raise ValueError("Related sources must reference declared adapters")
    related = {}
    for adapter, names in references.items():
        if not isinstance(names, list) or not all(isinstance(name, str) for name in names) or len(names) != len(set(names)):
            raise ValueError("Invalid related source references")
        related[adapter] = [source(root, name) for name in sorted(names)]
    cases, keys = [], set()
    for case in manifest["cases"]:
        key = "--".join(case[field] for field in ("serviceId", "journey", "surface", "variant"))
        if key in keys or case["serviceId"] not in targets:
            raise ValueError("Duplicate or foreign acceptance case")
        keys.add(key)
        files = [source(root / "acceptance", name) for name in sorted(set(
            [case["runner"], case["adapter"]] + case.get("runnerFiles", [])))]
        declared = set(case.get("implementedPhases", []))
        if not declared <= PHASES:
            raise ValueError("Unknown implementation phase")
        missing = [row["path"] for row in files if not row["present"]]
        cases.append({"key": key, "owner": owners[case["serviceId"]], "dependencies": files,
                      "adapter": case["adapter"], "missingFiles": missing,
                      "entrypointStatus": "missing-declared-files" if missing else "declared-files-present-not-verified",
                      "phaseDeclarations": {"declared": sorted(declared), "undeclared": sorted(PHASES - declared),
                                            "basis": "manifest-metadata-not-implementation-assessment"},
                      "relatedSources": related.get(case["adapter"], []),
                      "relatedSourceBasis": "explicit-scope-references-not-verified-replacements",
                      "assertions": {"INSTALL": case["assertions"], "RESTORE": case["restoreAssertions"]},
                      "semanticVerification": "not-established-by-census"})
    required_android = {row["target"] for row in clients["targets"] if row.get("androidRequired") is True}
    pinned_android = set()
    for app in android["apps"]:
        if all(isinstance(app.get(key), str) and len(app[key]) == 64 and set(app[key]) <= set("0123456789abcdef")
               for key in ("sha256", "signerSha256")) and app.get("packageName"):
            pinned_android.update(app["serviceIds"])
    missing_android = sorted(required_android - pinned_android)
    missing_files = sorted({name for row in cases for name in row["missingFiles"]})
    for domain in domains:
        domain["declaredStatus"] = domain.pop("status")
        domain["reportedBlockers"] = domain.pop("blockers")
        domain["assessmentBasis"] = "manual-scope-metadata-not-reconciled-by-census"
    return {"schemaVersion": 2, "diagnosticOnly": True, "runtimeVerified": False,
            "completionAssessment": "not-assessed-no-completion-percentage",
            "interpretation": {
                "missingFiles": "Exact manifest-declared paths absent; related code may exist elsewhere.",
                "phaseDeclarations": "Undeclared phases are metadata gaps, not counts of unimplemented workflows.",
                "relatedSources": "Explicit source references only; not wired adapters or semantic verification.",
                "androidPins": "Catalog metadata only; neither installed artifact custody nor upstream availability checked.",
                "verification": "This census does not execute code or read qualification/test evidence."},
            "reportedQualification": {**policy["currentLimits"]["qualification"],
                                      "basis": "implementation-scope-policy-not-verified-trial-evidence"},
            "implementationPolicy": policy,
            "inputSha256": {name: item[1] for name, item in inputs.items()},
            "counts": {"products": len(selected), "targets": len(targets), "variants": len(cases),
                       "variantsWithMissingDeclaredFiles": sum(bool(row["missingFiles"]) for row in cases),
                       "missingDeclaredFileCount": len(missing_files),
                       "variantsWithIncompletePhaseDeclarations": sum(bool(row["phaseDeclarations"]["undeclared"]) for row in cases),
                       "phaseDeclarations": {
                           "neitherDeclared": sum(not row["phaseDeclarations"]["declared"] for row in cases),
                           "installOnly": sum(row["phaseDeclarations"]["declared"] == ["INSTALL"] for row in cases),
                           "restoreOnly": sum(row["phaseDeclarations"]["declared"] == ["RESTORE"] for row in cases),
                           "bothDeclared": sum(not row["phaseDeclarations"]["undeclared"] for row in cases)}},
            "missingDeclaredFiles": missing_files,
            "artifactCatalog": android,
            "artifactPrerequisites": {"missingOfficialAndroidPins": missing_android, "availabilityVerified": False},
            "domains": domains, "cases": cases,
            "complete": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    print(json.dumps(inventory(args.workspace), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
