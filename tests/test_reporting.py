"""Report contract, provenance, and untrusted display-data tests."""
import copy
import csv
import io
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from scubatank.reporting import (
    build_report, render_csv, render_html, render_markdown, validate_report,
    write_reports,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-10-02T12:00:00Z"
HASH = "a" * 64
VERSIONS = {"nist": "800-53 Rev. 5", "attack": "18.1"}


def example():
    mapping = {"id": "AC-6", "title": "Least Privilege", "framework_version": VERSIONS["nist"],
               "source_digest": HASH, "rationale": "Delegated authority crosses a privileged identity boundary.",
               "status": "project-proposed"}
    attack = dict(mapping, id="T1098", title="Account Manipulation", framework_version=VERSIONS["attack"])
    finding = {
        "schema_version": "0.2.0", "run_id": "run-demo", "rule_version": "0.1.0",
        "framework_versions": VERSIONS, "adapter_versions": {"bloodhound": "0.1.0"},
        "source_versions": {"graph": "8.1.0"}, "finding_id": "finding-1",
        "check_id": "ST.CORR.IDENTITY.001", "status": "Fail", "severity": "High",
        "confidence": "High", "coverage": "partial", "message": "A group can reset a linked administrator's AD password.",
        "evidence_refs": ["graph#/records/0"], "affected_entity_ids": ["ad:forest:group", "ad:forest:user"],
        "missing_evidence": [], "cause_id": "delegated-reset", "limitations": ["Password-reset authority does not establish MFA bypass."],
        "mappings": {"status": "project-proposed", "nist": [mapping], "attack": [attack]},
        "paths": [{"path_id": "path-1", "entity_ids": ["ad:forest:group", "ad:forest:user"],
                   "edge_ids": ["edge-1"], "evidence_refs": ["graph#/records/0"], "claim": "Observed reset authority", "limitations": []}],
        "remediation": [{"action_id": "remove-reset", "title": "Review the delegated reset permission",
                         "rationale": "Removing this permission breaks the supported reset path.", "breaks_edge_ids": ["edge-1"],
                         "affected_entity_ids": ["ad:forest:group", "ad:forest:user"], "evidence_refs": ["graph#/records/0"],
                         "owner": None, "exception": None}],
    }
    args = {
        "run_id": "run-demo", "generated_at": NOW, "framework_versions": VERSIONS,
        "adapter_versions": {"bloodhound": "0.1.0"}, "source_versions": {"graph": "8.1.0"},
        "sources": [{"source_id": "graph", "producer": "BloodHound", "producer_version": "8.1.0",
                     "adapter_version": "0.1.0", "collected_at": NOW, "scope": {"forest_id": "forest"},
                     "sha256": HASH, "path": "graph.json", "completeness": "partial"}],
        "entities": [{"id": "ad:forest:group", "kind": "Group", "label": "Help desk", "properties": {}, "evidence_refs": ["graph#/records/0"]},
                     {"id": "ad:forest:user", "kind": "User", "label": "Administrator", "properties": {}, "evidence_refs": ["graph#/records/0"]}],
        "edges": [{"id": "edge-1", "source_id": "ad:forest:group", "target_id": "ad:forest:user", "type": "ForceChangePassword",
                   "semantics": "BloodHound supported relationship", "evidence_refs": ["graph#/records/0"]}],
        "evidence": {"graph#/records/0": {"source_id": "graph", "pointer": "/records/0", "sha256": HASH}},
        "coverage": "partial", "limitations": ["The demonstration is synthetic."], "synthetic": True,
        "scope": {"forest_id": "forest"},
    }
    return finding, args


def schema_validator(name):
    resources = []
    for path in (ROOT / "schemas").glob("*.schema.json"):
        data = json.loads(path.read_text(encoding="utf-8"))
        resources.append((path.name, Resource.from_contents(data)))
    registry = Registry().with_resources(resources)
    return Draft202012Validator(json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8")),
                                registry=registry, format_checker=FormatChecker())


class ReportTests(unittest.TestCase):
    def report(self):
        finding, args = example()
        return build_report([finding], **args)

    def test_report_contract_has_traceable_run_and_source_pins(self):
        report = self.report()
        schema_validator("report.schema.json").validate(report)
        self.assertEqual(report["run_id"], report["findings"][0]["run_id"])
        self.assertEqual(report["evidence"]["graph#/records/0"]["sha256"], HASH)
        self.assertNotIn("pass_percentage", report)

    def test_legacy_contract_remains_separate(self):
        finding, _ = example()
        legacy = {key: finding[key] for key in ("finding_id", "check_id", "status", "severity", "confidence", "coverage", "message", "evidence_refs", "affected_entity_ids", "missing_evidence")}
        legacy.update(schema_version="0.1.0", mappings={"status": "project-proposed", "nist": ["AC-6"], "attack": ["T1098"]})
        schema_validator("finding.schema.json").validate(legacy)
        self.assertFalse(schema_validator("finding-v2.schema.json").is_valid(legacy))
        legacy.update(status="Unknown", missing_evidence=["Current role evidence"], evidence_refs=[], affected_entity_ids=[])
        schema_validator("finding.schema.json").validate(legacy)

    def test_missing_v2_metadata_rejected_by_committed_schema(self):
        finding, _ = example()
        for key in ("run_id", "rule_version", "framework_versions", "adapter_versions", "source_versions", "cause_id", "paths", "limitations"):
            changed = copy.deepcopy(finding)
            del changed[key]
            with self.subTest(key=key):
                self.assertFalse(schema_validator("finding-v2.schema.json").is_valid(changed))

    def test_invalid_states_and_mapping_provenance_rejected(self):
        finding, _ = example()
        for key, value in (("status", "Secure"), ("confidence", "Certain"), ("coverage", "everything")):
            changed = copy.deepcopy(finding)
            changed[key] = value
            self.assertFalse(schema_validator("finding-v2.schema.json").is_valid(changed))
        changed = copy.deepcopy(finding)
        changed["mappings"]["attack"][0]["source_digest"] = "not-a-digest"
        self.assertFalse(schema_validator("finding-v2.schema.json").is_valid(changed))

    def test_unknown_requires_missing_evidence_and_pass_requires_complete(self):
        finding, args = example()
        finding.update(status="Unknown", missing_evidence=["Current identity link"], confidence="Unknown")
        build_report([finding], **args)
        finding["missing_evidence"] = []
        with self.assertRaises(ValueError):
            build_report([finding], **args)
        finding.update(status="Pass", coverage="partial")
        with self.assertRaises(ValueError):
            build_report([finding], **args)

    def test_dangling_refs_and_duplicate_identity_rejected(self):
        finding, args = example()
        finding["evidence_refs"] = ["unknown#/record"]
        with self.assertRaisesRegex(ValueError, "evidence"):
            build_report([finding], **args)
        finding, args = example()
        args["entities"].append(dict(args["entities"][0], label="Conflicting label"))
        with self.assertRaisesRegex(ValueError, "duplicate"):
            build_report([finding], **args)
        finding, args = example()
        finding["paths"][0]["edge_ids"] = ["missing-edge"]
        with self.assertRaisesRegex(ValueError, "edge"):
            build_report([finding], **args)

    def test_run_and_framework_pin_conflicts_rejected(self):
        finding, args = example()
        finding["run_id"] = "different-run"
        with self.assertRaisesRegex(ValueError, "run_id"):
            build_report([finding], **args)
        finding, args = example()
        finding["mappings"]["attack"][0]["framework_version"] = "unknown"
        with self.assertRaisesRegex(ValueError, "framework"):
            build_report([finding], **args)

    def test_shared_actions_preserve_every_finding_path(self):
        finding, args = example()
        other = copy.deepcopy(finding)
        other["finding_id"] = "finding-2"
        other["paths"][0]["path_id"] = "path-2"
        report = build_report([other, finding], **args)
        self.assertEqual(len(report["remediation"]), 1)
        self.assertEqual(report["remediation"][0]["finding_ids"], ["finding-1", "finding-2"])
        self.assertEqual(report["remediation"][0]["path_ids"], ["path-1", "path-2"])
        self.assertEqual(sum(len(row["paths"]) for row in report["findings"]), 2)

    def test_conflicting_action_text_is_not_silently_merged(self):
        finding, args = example()
        other = copy.deepcopy(finding)
        other["finding_id"] = "finding-2"
        other["remediation"][0]["title"] = "Different operation"
        with self.assertRaisesRegex(ValueError, "action"):
            build_report([finding, other], **args)

    def test_html_escapes_imported_text_and_uses_local_anchors(self):
        finding, args = example()
        unsafe = '<script>fetch("https://example.invalid")</script> & "quoted"'
        finding["message"] = unsafe
        args["entities"][0]["label"] = unsafe
        text = render_html(build_report([finding], **args))
        self.assertNotIn(unsafe, text)
        self.assertIn("&lt;script&gt;", text)
        self.assertIn("Synthetic demonstration", text)
        self.assertIn('id="status-filter"', text)
        self.assertIn("<details", text)
        self.assertIn("Content-Security-Policy", text)
        self.assertNotIn('src="http', text)
        self.assertNotIn('href="http', text)

    def test_csv_neutralizes_formula_and_fullwidth_prefixes(self):
        for unsafe in ('=HYPERLINK("https://example.invalid")', "  +1", "\t@SUM(1)", "＝1+1", "\r-2"):
            finding, args = example()
            finding["message"] = unsafe
            rows = list(csv.DictReader(io.StringIO(render_csv(build_report([finding], **args)))))
            with self.subTest(unsafe=unsafe):
                self.assertTrue(rows[0]["message"].startswith("'"))

    def test_markdown_escapes_html_and_table_delimiters(self):
        finding, args = example()
        finding["message"] = "<img src=x onerror=alert(1)> | [click](javascript:alert(1))"
        output = render_markdown(build_report([finding], **args))
        self.assertNotIn("<img", output)
        self.assertIn("&#124;", output)
        self.assertIn("\\[click\\]", output)

    def test_deterministic_output_and_nonimplemented_summary(self):
        report = self.report()
        self.assertEqual(render_html(report), render_html(copy.deepcopy(report)))
        self.assertEqual(render_csv(report), render_csv(copy.deepcopy(report)))
        finding, args = example()
        finding.update(status="NotImplemented", paths=[], remediation=[], evidence_refs=[], affected_entity_ids=[])
        text = render_html(build_report([finding], **args))
        self.assertIn("1 specification is not implemented", text)
        self.assertNotIn('class="finding"', text)

    def test_write_outputs_have_fixed_names(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            outputs = write_reports(self.report(), directory)
            self.assertEqual(set(outputs), {"json", "html", "csv", "markdown"})
            self.assertEqual(json.loads(outputs["json"].read_text(encoding="utf-8")), self.report())
            self.assertEqual({path.name for path in outputs.values()}, {"report.json", "report.html", "findings.csv", "report.md"})

    def test_report_rejects_excessive_text_and_malformed_provenance(self):
        finding, args = example()
        finding["message"] = "x" * 20001
        with self.assertRaises(ValueError):
            build_report([finding], **args)

    def test_adapter_coverage_errors_and_semantics_versions_are_preserved(self):
        finding, args = example()
        args["sources"][0].update(producer_schema="bloodhound-cypher-9.7.1",
                                  completeness={"complete": False, "capabilities": ["processed-relationships"]},
                                  collection_errors=["Scope was limited"], exclusions=["Uncollected domain"])
        args["edges"][0]["semantics_version"] = "bloodhound-ce/9.7.1"
        report = build_report([finding], **args)
        self.assertEqual(report["sources"][0], args["sources"][0])
        self.assertIn("Uncollected domain", render_html(report))
        self.assertIn("Scope was limited", render_markdown(report))
        args["coverage"] = "complete"
        with self.assertRaisesRegex(ValueError, "coverage"):
            build_report([finding], **args)

    def test_observation_ledger_preserves_source_pointer_and_value(self):
        finding, args = example()
        del args["evidence"]
        args["observations"] = [{"ref": "graph#/records/0", "value": {"type": "ForceChangePassword"}}]
        report = build_report([finding], **args)
        self.assertEqual(report["evidence"]["graph#/records/0"]["value"], {"type": "ForceChangePassword"})
        args["observations"].append({"ref": "graph#/records/0", "value": {"type": "Different edge"}})
        with self.assertRaisesRegex(ValueError, "Conflicting evidence"):
            build_report([finding], **args)

    def test_remediation_edge_must_belong_to_its_finding_path(self):
        finding, args = example()
        args["edges"].append(dict(args["edges"][0], id="unrelated-edge"))
        finding["remediation"][0]["breaks_edge_ids"] = ["unrelated-edge"]
        with self.assertRaisesRegex(ValueError, "remediation"):
            build_report([finding], **args)

    def test_report_source_pin_and_hash_conflicts_rejected(self):
        finding, args = example()
        args["evidence"]["graph#/records/0"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "hash"):
            build_report([finding], **args)
        finding, args = example()
        args["source_versions"]["graph"] = "unsupported"
        finding["source_versions"] = args["source_versions"]
        with self.assertRaisesRegex(ValueError, "Source version"):
            build_report([finding], **args)

    def test_raw_preview_is_bounded_without_truncating_json_observation(self):
        finding, args = example()
        args["evidence"]["graph#/records/0"]["value"] = "z" * 6000
        report = build_report([finding], **args)
        output = render_html(report)
        self.assertIn("Preview shortened", output)
        self.assertNotIn("z" * 6000, output)
        self.assertEqual(len(report["evidence"]["graph#/records/0"]["value"]), 6000)

    def test_upstream_result_is_visible_as_scoped_context(self):
        finding, args = example()
        args["upstream_findings"] = [{"id": "graph:MS.AAD.3.1v1", "source_id": "graph", "policy_id": "MS.AAD.3.1v1",
                                      "product": "aad", "result": "Fail", "criticality": "SHALL", "details": "<MFA baseline finding>",
                                      "annotations": {}, "evidence_refs": ["graph#/records/0"]}]
        report = build_report([finding], **args)
        self.assertIn('<a href="#upstream">Imported baseline results</a>', render_html(report))
        self.assertIn("aad · Policy ID: MS.AAD.3.1v1 · Result: Fail", render_html(report))
        self.assertIn("Criticality: SHALL", render_html(report))
        self.assertIn("MS.AAD.3.1v1", render_markdown(report))
        self.assertIn("&lt;MFA baseline finding&gt;", render_html(report))

    def test_identity_link_references_must_resolve(self):
        finding, args = example()
        args["identity_links"] = [{"id": "link-1", "ad_entity_id": "ad:forest:user", "cloud_entity_id": "missing-cloud-user",
                                  "method": "verified-source-anchor", "conflict": False, "evidence_refs": ["graph#/records/0"]}]
        with self.assertRaisesRegex(ValueError, "identity"):
            build_report([finding], **args)

    def test_html_repeated_labels_cannot_amplify_output_without_limit(self):
        finding, args = example()
        for entity in args["entities"]:
            entity["label"] = "a" * 14000
        findings = []
        for index in range(300):
            changed = copy.deepcopy(finding)
            changed["finding_id"] = f"finding-{index}"
            changed["paths"][0]["path_id"] = f"path-{index}"
            findings.append(changed)
        report = build_report(findings, **args)
        with self.assertRaisesRegex(ValueError, "output limit"):
            render_html(report)

    def test_standalone_report_writer_rejects_unc_before_resolution(self):
        with patch("pathlib.Path.resolve", side_effect=AssertionError("A UNC output must not be resolved")):
            with self.assertRaisesRegex(ValueError, "UNC"):
                write_reports(self.report(), "\\\\untrusted.invalid\\share\\reports")

    def test_source_collection_window_and_collector_pins_are_preserved(self):
        finding, args = example()
        args["sources"][0].update(observation_window={"oldest_at": "2026-09-01T00:00:00Z", "newest_at": NOW},
                                  collector_versions={"SharpHound": "2.8.1", "AzureHound": "2.9.0"})
        report = build_report([finding], **args)
        self.assertEqual(report["sources"][0]["collector_versions"], args["sources"][0]["collector_versions"])
        self.assertIn("2026-09-01T00:00:00Z", render_html(report))
        self.assertIn("SharpHound", render_markdown(report))
        finding, args = example()
        args["evidence"]["graph#/records/0"]["pointer"] = "not-a-json-pointer"
        with self.assertRaises(ValueError):
            build_report([finding], **args)


if __name__ == "__main__":
    unittest.main()
