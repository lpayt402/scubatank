"""Real offline adapters, joins, pinned Rego and reports on synthetic exports."""
import copy
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from scubatank import assessment
from scubatank.importers import import_manifest

ROOT=Path(__file__).resolve().parents[1]
FIXTURE=ROOT/"fixtures/demo"
AS_OF="2026-10-02T08:00:00Z"


class PipelineTests(unittest.TestCase):
    def setUp(self): self.bundle=import_manifest(FIXTURE/"manifest.json")

    def assess(self,bundle=None,root=FIXTURE):
        return assessment.assess(bundle or self.bundle,as_of=AS_OF,evidence_root=root)

    def test_imported_pipeline_establishes_six_paths_one_blocked_and_incomplete_cases(self):
        report=self.assess()
        self.assertEqual({f["check_id"] for f in report["findings"] if f["status"]=="Fail"},set(assessment.RULES))
        self.assertEqual(report["counts"]["Fail"],6)
        self.assertEqual(report["counts"]["Pass"],1)
        self.assertGreater(report["counts"]["Unknown"],0)
        self.assertEqual(report["coverage"],"partial")
        self.assertTrue(report["synthetic"])
        self.assertLess(len(report["findings"]),132)

    def test_every_report_claim_has_record_hash_and_source_pointer(self):
        report=self.assess()
        for finding in report["findings"]:
            for ref in finding["evidence_refs"]:
                record=report["evidence"][ref]
                self.assertEqual(len(record["sha256"]),64)
                self.assertEqual(record["source_id"]+"#"+record["pointer"],ref)

    def test_no_root_is_explicit_unknown(self):
        report=self.assess(root=None)
        self.assertEqual({f["status"] for f in report["findings"]},{"Unknown"})
        self.assertTrue(all(any("original" in gap.lower() for gap in f["missing_evidence"]) for f in report["findings"]))

    def test_modified_normalized_fact_is_rejected_when_raw_inputs_are_unchanged(self):
        b=copy.deepcopy(self.bundle)
        next(f for f in b["facts"] if f["predicate"]=="password_authority")["value"]="cloud"
        with self.assertRaisesRegex(ValueError,"normalized"):
            self.assess(b)

    def test_fixed_metadata_is_deterministic(self):
        self.assertEqual(self.assess(),self.assess())

    def test_import_and_assess_make_no_python_network_calls(self):
        with patch.object(socket,"create_connection",side_effect=AssertionError("no network")),patch.object(socket.socket,"connect",side_effect=AssertionError("no network")):
            b=import_manifest(FIXTURE/"manifest.json")
            self.assess(b)

    def test_nested_membership_remediation_names_the_shared_user_edge(self):
        edges={"a-group-edge":{"id":"a-group-edge","source_id":"group-a","target_id":"group-b","type":"MemberOf","evidence_refs":["source#/1"]},
            "z-user-edge":{"id":"z-user-edge","source_id":"user-a","target_id":"group-a","type":"MemberOf","evidence_refs":["source#/0"]}}
        c={"rule_id":"ST.CORR.IDENTITY.003","edge_ids":["a-group-edge","z-user-edge"],"entity_ids":["user-a","group-a","group-b"]}
        entities={"user-a":{"kind":"ADUser"},"group-a":{"kind":"ADGroup"},"group-b":{"kind":"ADGroup"}}
        action=assessment._action(c,edges,entities)[0]
        self.assertEqual(action["breaks_edge_ids"],["z-user-edge"])

    def test_native_active_role_schedules_must_cover_the_assessment_time(self):
        expired="2026-10-02T07:30:00Z"
        epoch=int(datetime(2026,10,2,7,30,tzinfo=timezone.utc).timestamp()*1000)
        for end,additional,expected in ((expired,False,"Unknown"),
                (f"/Date({epoch})/",False,"Unknown"),
                (AS_OF,False,"Unknown"),(expired,True,"Fail")):
            with self.subTest(end=end,additional=additional),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)/"exports";shutil.copytree(FIXTURE,root)
                path=root/"scubagear.json";data=json.loads(path.read_text(encoding="utf-8"))
                assignments=data["Raw"]["privileged_roles"][0]["Assignments"]
                for assignment in assignments:assignment["EndDateTime"]=end
                if additional:
                    current=copy.deepcopy(assignments[0]);current["Id"]="synthetic-still-active"
                    current["EndDateTime"]="2026-10-02T09:00:00Z";assignments.append(current)
                path.write_text(json.dumps(data),encoding="utf-8")
                imported=import_manifest(root/"manifest.json")
                report=self.assess(imported,root)
                affected=[f for f in report["findings"] if f["check_id"] in
                    ("ST.CORR.IDENTITY.001","ST.CORR.IDENTITY.003")]
                self.assertIn(expected,{f["status"] for f in affected})
                if not additional:
                    self.assertNotIn("Fail",{f["status"] for f in affected})
                    self.assertTrue(any("assessment time" in gap for f in affected for gap in f["missing_evidence"]))


if __name__=="__main__":unittest.main()
