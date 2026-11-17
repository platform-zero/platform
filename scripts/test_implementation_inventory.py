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
            "platform/release/implementation-scope.json": {
                **copy.deepcopy(census.CURRENT_POLICY),
                "domains": [{"id": "unit", "status": "source-present",
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
        self.assertEqual(2, report["schemaVersion"])
        self.assertEqual(1, report["counts"]["variantsWithMissingDeclaredFiles"])
        self.assertEqual(1, report["counts"]["missingDeclaredFileCount"])
        self.assertEqual(["runners/absent.py"], report["cases"][0]["missingFiles"])
        self.assertEqual(["RESTORE"], report["cases"][0]["phaseDeclarations"]["undeclared"])
        self.assertEqual("missing-declared-files", report["cases"][0]["entrypointStatus"])
        self.assertEqual("not-assessed-no-completion-percentage", report["completionAssessment"])
        self.assertFalse(report["complete"])
        self.assertFalse(report["runtimeVerified"])
        self.assertEqual(0, report["reportedQualification"]["completed"])
        self.assertEqual("implementation-scope-policy-not-verified-trial-evidence", report["reportedQualification"]["basis"])
        self.assertEqual({field: self.documents["platform/release/implementation-scope.json"][field]
                          for field in ("operator", "executionBoundary", "workerPolicy", "currentLimits")},
                         report["implementationPolicy"])
        self.assertFalse(report["implementationPolicy"]["currentLimits"]["sourceReviewIsTesting"])
        self.assertEqual({"completed": 0, "required": 2},
                         report["implementationPolicy"]["currentLimits"]["qualification"])
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob("*") if p.is_file()})
        output = []
        with patch("sys.argv", ["inventory", "--workspace", str(self.root)]), patch("builtins.print", output.append):
            census.main()
        self.assertEqual(report, json.loads(output[0]))

    def test_stale_or_overbroad_policy_is_refused_not_granted(self):
        original = copy.deepcopy(self.documents)
        scope = "platform/release/implementation-scope.json"
        mutations = [
            lambda p: p.update(operator="sole-operator"),
            lambda p: p.update(executionBoundary="offline-compilation-and-unit-tests-only"),
            lambda p: p["workerPolicy"].update(maximumImplementationWorkers=3),
            lambda p: p["workerPolicy"].update(coordinatorProductionWrites=False),
            lambda p: p["workerPolicy"].update(nestedAgents=True),
            lambda p: p["workerPolicy"].update(writeAuthority="entire-repository"),
            lambda p: p["currentLimits"]["forbidden"].remove("public-production-cutover"),
            lambda p: p["currentLimits"]["allowed"].append("unit-tests"),
            lambda p: p["currentLimits"].update(futureExecution="automatically-authorized"),
            lambda p: p["currentLimits"].update(sourceReviewIsTesting=True),
            lambda p: p["currentLimits"]["qualification"].update(completed=1),
            lambda p: p.pop("workerPolicy"),
        ]
        for mutate in mutations:
            self.documents = copy.deepcopy(original)
            mutate(self.documents[scope])
            self.write()
            with self.assertRaises(ValueError):
                census.inventory(self.root)

    def test_complete_phase_declarations_and_files_are_still_not_verification(self):
        case = self.documents["acceptance/cases/manifest.json"]["cases"][0]
        case["implementedPhases"] = ["INSTALL", "RESTORE"]
        case["adapter"] = "scripts/runner.py"
        self.write()
        report = census.inventory(self.root)
        self.assertEqual(0, report["counts"]["variantsWithMissingDeclaredFiles"])
        self.assertEqual(0, report["counts"]["variantsWithIncompletePhaseDeclarations"])
        self.assertEqual("declared-files-present-not-verified", report["cases"][0]["entrypointStatus"])
        self.assertFalse(report["complete"])
        self.assertEqual("not-established-by-census", report["cases"][0]["semanticVerification"])
        self.assertTrue(report["diagnosticOnly"])
        self.assertFalse(report["runtimeVerified"])
        self.assertEqual(0, report["reportedQualification"]["completed"])
        self.assertEqual("not-established-by-census",
                         report["implementationPolicy"]["currentLimits"]["sourceCompletion"])

    def test_related_code_does_not_fill_missing_entrypoints_or_phase_declarations(self):
        scope = self.documents["platform/release/implementation-scope.json"]
        scope["adapterSourceReferences"] = {"runners/absent.py": ["platform/real-source.py", "platform/also-absent.py"]}
        self.write()
        report = census.inventory(self.root)
        row = report["cases"][0]
        self.assertEqual("missing-declared-files", row["entrypointStatus"])
        self.assertEqual(["RESTORE"], row["phaseDeclarations"]["undeclared"])
        self.assertEqual([False, True], [source["present"] for source in row["relatedSources"]])
        self.assertEqual(64, len(row["relatedSources"][1]["sha256"]))
        self.assertEqual("not-established-by-census", row["semanticVerification"])
        self.assertFalse(report["complete"])
        domain = report["domains"][0]
        self.assertEqual("source-present", domain["declaredStatus"])
        self.assertEqual(["integration"], domain["reportedBlockers"])
        self.assertEqual("manual-scope-metadata-not-reconciled-by-census", domain["assessmentBasis"])

    def test_phase_metadata_breakdown_is_separate_from_unique_missing_paths(self):
        manifest = self.documents["acceptance/cases/manifest.json"]
        template = manifest["cases"][0]
        manifest["cases"] = [dict(template, serviceId=self.products[i], implementedPhases=phases)
                             for i, phases in enumerate([[], ["INSTALL"], ["RESTORE"], ["INSTALL", "RESTORE"]])]
        self.write()
        report = census.inventory(self.root)
        self.assertEqual(4, report["counts"]["variantsWithMissingDeclaredFiles"])
        self.assertEqual(1, report["counts"]["missingDeclaredFileCount"])
        self.assertEqual(3, report["counts"]["variantsWithIncompletePhaseDeclarations"])
        self.assertEqual({"neitherDeclared": 1, "installOnly": 1, "restoreOnly": 1, "bothDeclared": 1},
                         report["counts"]["phaseDeclarations"])
        self.assertNotIn("variantsWithMissingPhases", report["counts"])
        self.assertTrue(all("missingPhases" not in row for row in report["cases"]))

    def test_related_source_references_must_be_safe_and_declared(self):
        scope = self.documents["platform/release/implementation-scope.json"]
        for references in [[], {"runners/foreign.py": []}, {"runners/absent.py": "platform/real-source.py"},
                           {"runners/absent.py": ["../outside"]},
                           {"runners/absent.py": ["platform/real-source.py", "platform/real-source.py"]}]:
            scope["adapterSourceReferences"] = references
            self.write()
            with self.assertRaises(ValueError):
                census.inventory(self.root)

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
