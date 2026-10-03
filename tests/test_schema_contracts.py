"""Committed validation for the original contracts and versioned successors."""
import copy
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator

ROOT=Path(__file__).resolve().parents[1]


class SchemaContracts(unittest.TestCase):
    def schema(self,name):return json.loads((ROOT/"schemas"/name).read_text(encoding="utf-8"))
    def valid(self,name,value):return Draft202012Validator(self.schema(name)).is_valid(value)
    def finding(self):
        return {"schema_version":"0.1.0","finding_id":"synthetic","check_id":"ST.CORR.IDENTITY.001", "status":"Unknown","severity":"High","confidence":"Unknown","coverage":"partial","message":"Synthetic missing evidence","evidence_refs":[],"affected_entity_ids":[],"missing_evidence":["No collected evidence"],"mappings":{"status":"project-proposed","nist":["AC-3"],"attack":["T1098"]}}
    def test_every_committed_schema_has_valid_schema_structure(self):
        for path in (ROOT/"schemas").glob("*.schema.json"):
            with self.subTest(schema=path.name):Draft202012Validator.check_schema(self.schema(path.name))
    def test_original_unknown_finding_remains_accepted(self):
        self.assertTrue(self.valid("finding.schema.json",self.finding()))
    def test_original_fail_without_evidence_is_rejected(self):
        f=self.finding();f.update(status="Fail",missing_evidence=[])
        self.assertFalse(self.valid("finding.schema.json",f))
    def test_original_pass_with_partial_coverage_is_rejected(self):
        f=self.finding();f.update(status="Pass",missing_evidence=[],evidence_refs=["source#/0"])
        self.assertFalse(self.valid("finding.schema.json",f))
    def test_new_finding_metadata_cannot_be_silently_omitted(self):
        self.assertFalse(self.valid("finding-v2.schema.json",self.finding()))
    def test_not_collected_source_has_no_invented_artifact(self):
        s={"source_id":"missing","producer":"scubagear","producer_version":"unknown","producer_schema":"unknown","collected_at":None,"scope":{"boundaries":[],"complete":False},"collection_status":"not-collected","sha256":None,"relative_path":None}
        b={"schema_version":"0.1.0","run_id":"11111111-1111-4111-8111-111111111111","synthetic":True,"sources":[s],"entities":[],"relationships":[],"facts":[]}
        self.assertTrue(self.valid("evidence-bundle.schema.json",b))
        s.update(collection_status="complete",scope={"boundaries":[],"complete":True})
        self.assertFalse(self.valid("evidence-bundle.schema.json",b))


if __name__=="__main__":unittest.main()
