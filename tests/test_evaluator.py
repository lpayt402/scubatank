"""Bounded rule predicates and typed joins; all inputs here are synthetic."""
import copy
import unittest
from scubatank import evaluator

WHEN = "2026-10-02T12:00:00Z"
AD = "ad:forest-a:user-a"
CLOUD = "cloud:tenant-a:user-a"
ACTOR = "ad:forest-a:helpdesk"


def bundle():
    return {
        "schema_version": "1.0.0", "synthetic": True,
        "sources": [{"source_id": "graph", "producer": "BloodHound CE",
            "producer_version": "9.7.1", "producer_schema": "unified-graph",
            "adapter_version": "1.0.0", "collected_at": WHEN,
            "observation_window": {"oldest_at":WHEN,"newest_at":WHEN},"collector_versions":{"test":"synthetic-not-executed"},
            "scope": {"forest_id": "forest-a", "tenant_id": "tenant-a"},
            "sha256": "a" * 64, "path": "graph.json", "completeness": "partial",
            "collection_errors": [], "exclusions": []}],
        "entities": [{"id": AD, "kind": "ADUser", "boundary_id": "forest-a", "native_id": "user-a", "label": "A", "properties": {}, "evidence_refs": ["graph#/nodes/1"]},
            {"id": CLOUD, "kind": "CloudUser", "boundary_id": "tenant-a", "native_id": "user-a", "label": "A", "properties": {}, "evidence_refs": ["graph#/nodes/2"]},
            {"id": ACTOR, "kind": "ADGroup", "boundary_id": "forest-a", "native_id": "helpdesk", "label": "Help desk", "properties": {}, "evidence_refs": ["graph#/nodes/3"]}],
        "edges": [{"id": "reset", "source_id": ACTOR, "target_id": AD, "type": "ForceChangePassword", "semantics": "upstream-derived", "evidence_refs": ["graph#/edges/0"]}],
        "identity_links": [{"id": "link", "ad_entity_id": AD, "cloud_entity_id": CLOUD, "method": "established_id_link", "conflict": False, "evidence_refs": ["graph#/links/0"]}],
        "facts": [], "issues": [], "coverage": [], "upstream_findings": [],
        "observations": [],
    }


def fact(b, subject, predicate, value):
    n = len(b["facts"])
    b["facts"].append({"id": "f" + str(n), "subject_id": subject,
        "predicate": predicate, "value": value,
        "evidence_refs": ["graph#/facts/" + str(n)]})


def identity_positive():
    b = bundle()
    for subject, key, value in [(AD,"enabled",True),(CLOUD,"enabled",True),
            (AD,"approved_controllers",[]),(CLOUD,"active_privileged_role",True),
            (CLOUD,"password_authority","ad"),(CLOUD,"password_flow_applicable",True)]:
        fact(b, subject, key, value)
    return b


class JoinTests(unittest.TestCase):
    def candidates(self, b):
        return evaluator.prepare_candidates(b, as_of=WHEN)

    def identity(self, b):
        return next(c for c in self.candidates(b) if c["rule_id"] == "ST.CORR.IDENTITY.001" and c["entity_ids"])

    def test_reset_joins_verified_scoped_identity_and_retains_records(self):
        c = self.identity(identity_positive())
        self.assertTrue(all(c["checks"].values()))
        self.assertIn("reset", c["edge_ids"])
        self.assertIn("graph#/links/0", c["evidence_refs"])
        self.assertEqual(set(c["entity_ids"]), {AD,CLOUD,ACTOR})

    def test_each_removed_prerequisite_stays_unknown(self):
        base = identity_positive()
        for f in base["facts"]:
            with self.subTest(predicate=f["predicate"], subject=f["subject_id"]):
                b = copy.deepcopy(base)
                b["facts"].remove(f)
                self.assertIn(None, self.identity(b)["checks"].values())
                self.assertTrue(self.identity(b)["gaps"])

    def test_cloud_password_authority_disproves_this_path(self):
        b = identity_positive()
        next(f for f in b["facts"] if f["predicate"] == "password_authority")["value"] = "cloud"
        self.assertFalse(self.identity(b)["checks"]["ad_password_authority"])

    def test_same_labels_without_link_do_not_join(self):
        b = identity_positive(); b["identity_links"] = []
        self.assertIsNone(self.identity(b)["checks"]["identity_link"])

    def test_conflict_blocks_positive_claim(self):
        b = identity_positive(); b["identity_links"][0]["conflict"] = True
        self.assertTrue(self.identity(b)["integrity_gaps"])

    def test_conflicting_facts_stay_unknown(self):
        b = identity_positive(); fact(b,CLOUD,"active_privileged_role",False)
        self.assertIsNone(self.identity(b)["checks"]["active_privileged_role"])

    def test_stale_or_future_evidence_blocks_claim(self):
        for timestamp in ("2026-09-01T12:00:00Z","2026-10-03T12:00:00Z"):
            b = identity_positive(); b["sources"][0]["collected_at"] = timestamp
            self.assertTrue(self.identity(b)["integrity_gaps"])

    def test_cross_forest_relationship_blocks_claim(self):
        b = identity_positive(); b["entities"][2]["boundary_id"] = "forest-b"
        self.assertTrue(self.identity(b)["integrity_gaps"])

    def test_candidate_or_unsupported_edge_is_not_authority(self):
        for field,value in (("semantics","candidate"),("type","GenericWrite")):
            b = identity_positive(); b["edges"][0][field] = value
            c = next(c for c in self.candidates(b) if c["rule_id"] == "ST.CORR.IDENTITY.001")
            self.assertIsNone(c["checks"]["reset_authority"])

    def test_no_graph_edge_is_unknown_not_a_pass(self):
        b = identity_positive(); b["edges"] = []
        c = next(c for c in self.candidates(b) if c["rule_id"] == "ST.CORR.IDENTITY.001")
        self.assertTrue(c["gaps"])

    def test_only_six_implemented_rules_are_selected(self):
        self.assertEqual(len({c["rule_id"] for c in self.candidates(bundle())}),6)

    def test_sync_host_without_cloud_entities_has_unknown_tenant_link(self):
        b = bundle(); host=b["entities"][0]; host["kind"]="ADComputer"
        b["edges"][0]["type"]="AdminTo";b["identity_links"]=[]
        b["entities"]=[host,b["entities"][2]]
        fact(b,AD,"sync_host_confirmed",True);fact(b,AD,"sync_tenant_id","tenant-a")
        fact(b,AD,"approved_controllers",[])
        c=next(c for c in self.candidates(b) if c["rule_id"]=="ST.CORR.SYNC.001")
        self.assertIsNone(c["checks"]["tenant_link"])

    def test_preserved_entity_conflict_blocks_affected_path(self):
        b=identity_positive();b["issues"]=[{"code":"EntityConflict","entity_ids":[AD],"message":"conflicting enabled state"}]
        self.assertTrue(self.identity(b)["integrity_gaps"])

    def test_denied_or_unresolved_relationship_is_not_effective_authority(self):
        for props in ({"denied":True},{"denied":"true"},{"denied":1},{"preconditions":0},{"preconditions":{"effective":False}},{"preconditions":{"effective":None}}):
            b=identity_positive();b["edges"][0]["properties"]=props
            self.assertTrue(self.identity(b)["integrity_gaps"])

    def test_changed_supported_producer_version_blocks_claim(self):
        b=identity_positive();b["sources"][0]["producer_version"]="99.0"
        self.assertTrue(self.identity(b)["integrity_gaps"])

    def test_export_time_does_not_refresh_old_graph_observations(self):
        b=identity_positive();b["sources"][0]["observation_window"]["oldest_at"]="2026-09-01T12:00:00Z"
        self.assertTrue(self.identity(b)["integrity_gaps"])

    def test_missing_graph_observation_window_is_unknown(self):
        b=identity_positive();del b["sources"][0]["observation_window"]
        self.assertTrue(self.identity(b)["integrity_gaps"])


if __name__ == "__main__": unittest.main()
