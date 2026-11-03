import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import implementation_inventory as census


class ImplementationInventoryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.products = [f"product-{n}" for n in range(39)]
        self.documents = {
            "platform/src/main/resources/products.json": {"products": self.products},
            "acceptance/cases/official-clients.json": {"targets": [{"target": p} for p in self.products]},
            "acceptance/cases/android-apps.json": {"apps": []},
            "platform/release/implementation-scope.json": {"domains": [{"id": "unit", "status": "source-present",
                "targets": self.products, "sourceFiles": ["platform/real-source.py"], "blockers": ["integration"]}]},
            "acceptance/cases/manifest.json": {"targets": [{"serviceId": p} for p in self.products], "cases": [{
                "serviceId": self.products[0], "journey": "workflow", "surface": "HEADLESS", "variant": "NATIVE",
                "runner": "scripts/runner.py", "adapter": "runners/absent.py", "runnerFiles": [],
                "assertions": ["native-state"], "restoreAssertions": ["original-state"], "implementedPhases": ["INSTALL"]}]},
        }
        for name, value in self.documents.items():
            value["schemaVersion"] = 2 if name == "acceptance/cases/manifest.json" else 1
        self.write()
        for name in ["platform/real-source.py", "acceptance/scripts/runner.py"]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("raise RuntimeError('must never be imported or executed')\n")

    def write(self):
        for name, value in self.documents.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value))

    def test_census_is_read_only_and_presence_never_means_semantic_completion(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        report = census.inventory(self.root)
        self.assertEqual(39, report["counts"]["products"])
        self.assertEqual(1, report["counts"]["variantsWithMissingFiles"])
        self.assertEqual(["runners/absent.py"], report["cases"][0]["missingFiles"])
        self.assertEqual(["RESTORE"], report["cases"][0]["missingPhases"])
        self.assertFalse(report["complete"])
        self.assertFalse(report["runtimeVerified"])
        self.assertEqual(0, report["qualificationTrials"])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()})
        output = []
        with patch("sys.argv", ["inventory", "--workspace", str(self.root)]), patch("builtins.print", output.append):
            census.main()
        self.assertEqual(report, json.loads(output[0]))

    def test_complete_phase_declarations_and_files_are_still_not_verification(self):
        case = self.documents["acceptance/cases/manifest.json"]["cases"][0]
        case["implementedPhases"] = ["INSTALL", "RESTORE"]
        case["adapter"] = "scripts/runner.py"
        self.write()
        report = census.inventory(self.root)
        self.assertEqual(0, report["counts"]["variantsWithMissingFiles"])
        self.assertEqual(0, report["counts"]["variantsWithMissingPhases"])
        self.assertFalse(report["complete"])
        self.assertEqual("not-established-by-census", report["cases"][0]["semanticVerification"])

    def test_artifact_pins_are_separate_from_source_and_not_availability_proof(self):
        self.documents["acceptance/cases/official-clients.json"]["targets"][0]["androidRequired"] = True
        self.write()
        report = census.inventory(self.root)
        self.assertEqual([self.products[0]], report["artifactPrerequisites"]["missingOfficialAndroidPins"])
        self.documents["acceptance/cases/android-apps.json"]["apps"] = [{
            "serviceIds": [self.products[0]], "packageName": "unit.synthetic", "sha256": "a" * 64,
            "signerSha256": "invalid"}]
        self.write()
        self.assertEqual([self.products[0]], census.inventory(self.root)["artifactPrerequisites"]["missingOfficialAndroidPins"])
        self.documents["acceptance/cases/android-apps.json"]["apps"][0]["signerSha256"] = "b" * 64
        self.write()
        report = census.inventory(self.root)
        self.assertEqual([], report["artifactPrerequisites"]["missingOfficialAndroidPins"])
        self.assertFalse(report["artifactPrerequisites"]["availabilityVerified"])

    def test_catalog_ownership_classification_and_phase_errors_fail_closed(self):
        original = copy.deepcopy(self.documents)
        mutations = [
            lambda d: d["acceptance/cases/manifest.json"].update(schemaVersion=999),
            lambda d: d["acceptance/cases/manifest.json"]["targets"].append({"serviceId": self.products[0]}),
            lambda d: d["acceptance/cases/official-clients.json"]["targets"].append({"target": self.products[0]}),
            lambda d: d["platform/src/main/resources/products.json"]["products"].append(self.products[0]),
            lambda d: d["acceptance/cases/official-clients.json"]["targets"].pop(),
            lambda d: d["platform/release/implementation-scope.json"]["domains"].append(copy.deepcopy(d["platform/release/implementation-scope.json"]["domains"][0])),
            lambda d: d["platform/release/implementation-scope.json"]["domains"][0]["targets"].pop(),
            lambda d: d["platform/release/implementation-scope.json"]["domains"][0].update(status="unit-verified"),
            lambda d: d["platform/release/implementation-scope.json"]["domains"][0].update(status="missing-code", blockers=[]),
            lambda d: d["platform/release/implementation-scope.json"]["domains"][0].update(sourceFiles=["missing.kt"]),
            lambda d: d["acceptance/cases/manifest.json"]["cases"][0].update(implementedPhases=["QUALIFIED"]),
            lambda d: d["acceptance/cases/manifest.json"]["cases"].append(copy.deepcopy(d["acceptance/cases/manifest.json"]["cases"][0])),
        ]
        for mutate in mutations:
            self.documents = copy.deepcopy(original)
            mutate(self.documents)
            self.write()
            with self.assertRaises(ValueError):
                census.inventory(self.root)

    def test_dependencies_cannot_escape_through_paths_or_links(self):
        for name in ["../outside", "/etc/passwd", "a/./b", "a//b", ""]:
            with self.assertRaises(ValueError):
                census.source(self.root, name)
        (self.root / "linked").symlink_to(self.root / "platform", target_is_directory=True)
        with self.assertRaises(ValueError):
            census.source(self.root, "linked/real-source.py")
        with self.assertRaises(ValueError):
            census.document(self.root, "linked/real-source.py")
        with self.assertRaises(ValueError):
            census.document(self.root, "absent")
        huge = self.root / "huge.json"
        with huge.open("wb") as stream:
            stream.truncate(4 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            census.document(self.root, "huge.json")


if __name__ == "__main__":
    unittest.main()
