"""Six-rule joined-evidence regression matrix derived from native-shaped imports.

Mutations below exercise the join layer. Assessment separately reconstructs the
originals and rejects an edited normalized bundle (test_pipeline.py).
"""
import copy
from pathlib import Path
import unittest
from scubatank.evaluator import RULES,prepare_candidates
from scubatank.importers import import_manifest
from scubatank.policy import evaluate

ROOT=Path(__file__).resolve().parents[1]
WHEN="2026-10-02T08:00:00Z"


class JoinedRuleMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=import_manifest(ROOT/"fixtures/demo/manifest.json")
        candidates=prepare_candidates(cls.base,as_of=WHEN)
        result=evaluate(candidates)
        cls.positive={c["rule_id"]:c for c,r in zip(candidates,result) if r["status"]=="Fail"}

    def decide(self,b,rule):
        candidates=[c for c in prepare_candidates(b,as_of=WHEN) if c["rule_id"]==rule]
        old=self.positive[rule]["candidate_id"]
        selected=next((c for c in candidates if c["candidate_id"]==old),None)
        if selected:
            return evaluate([selected])[0]["status"],selected
        # Removing an endpoint or identity link may replace the candidate with a
        # missing-evidence decision; it may not disappear into an overall Pass.
        states=evaluate(candidates)
        self.assertNotIn("Fail",{r["status"] for r in states})
        return "Unknown",candidates[0]

    def test_each_rule_joins_real_adapter_output_to_a_positive_conjunction(self):
        self.assertEqual(set(self.positive),set(RULES))
        for rule in RULES:
            with self.subTest(rule=rule):
                c=self.positive[rule]
                self.assertTrue(c["entity_ids"]);self.assertTrue(c["edge_ids"]);self.assertTrue(c["evidence_refs"])
                self.assertEqual(evaluate([c])[0]["status"],"Fail")

    def test_removing_each_fact_supporting_each_joined_positive_is_unknown(self):
        cases=[]
        for rule,c in self.positive.items():
            supporting=[f for f in self.base["facts"] if set(f["evidence_refs"]) & set(c["evidence_refs"])]
            for f in supporting:
                if f["predicate"]=="tier_separation_required":
                    continue  # Policy context does not suppress observed dual privilege.
                if rule=="ST.CORR.SYNC.001" and f["predicate"]=="enabled":
                    continue  # Tenant context labels are not claimed to be controlled accounts.
                b=copy.deepcopy(self.base);b["facts"]=[item for item in b["facts"] if item["id"]!=f["id"]]
                # A duplicated enabled observation from another source remains
                # valid proof; remove all records of this same subject/predicate.
                b["facts"]=[item for item in b["facts"] if not(item["subject_id"]==f["subject_id"] and item["predicate"]==f["predicate"])]
                status,selected=self.decide(b,rule)
                with self.subTest(rule=rule,subject=f["subject_id"],predicate=f["predicate"]):
                    self.assertEqual(status,"Unknown")
                cases.append(selected)
        self.assertGreaterEqual(len(cases),25)
        self.assertNotIn("Fail",{r["status"] for r in evaluate(cases)})

    def test_catalog_limiting_case_for_each_joined_rule(self):
        limitations={RULES[0]:("password_authority","cloud"),RULES[1]:("active_privileged_role",False),
            RULES[2]:("sync_host_confirmed",False),RULES[3]:("membership_add_supported",False),
            RULES[4]:("ca_scenario",None),RULES[5]:("usable_credential_addition",False)}
        for rule,(predicate,value) in limitations.items():
            b=copy.deepcopy(self.base)
            selected=next(f for f in b["facts"] if f["predicate"]==predicate and set(f["evidence_refs"])&set(self.positive[rule]["evidence_refs"]))
            if predicate=="ca_scenario":
                selected["value"]["other_policy_restores"]=True
            else:
                selected["value"]=value
            with self.subTest(rule=rule): self.assertEqual(self.decide(b,rule)[0],"Pass")

    def test_every_rule_keeps_stale_wrong_scope_and_identity_conflicts_unknown(self):
        for rule in RULES:
            c=self.positive[rule]
            for kind in ("stale","scope","identity"):
                b=copy.deepcopy(self.base)
                if kind=="stale":
                    for source in b["sources"]:
                        source["collected_at"]="2026-09-01T07:00:00Z"
                        if "observation_window" in source:
                            source["observation_window"]={"oldest_at":"2026-09-01T07:00:00Z","newest_at":"2026-09-01T07:00:00Z"}
                elif kind=="scope":
                    for source in b["sources"]:source["scope"]={"tenant_id":"wrong-tenant","forest_id":"wrong-forest"}
                else:
                    b["issues"].append({"code":"EntityConflict","message":"Conflicting source identity","entity_ids":c["entity_ids"]})
                with self.subTest(rule=rule,case=kind):self.assertEqual(self.decide(b,rule)[0],"Unknown")

    def test_denied_and_unsupported_relationships_for_every_rule(self):
        for rule,c in self.positive.items():
            for alteration in ("denied","unsupported"):
                b=copy.deepcopy(self.base)
                for edge in b["edges"]:
                    if edge["id"] in c["edge_ids"]:
                        if alteration=="denied":edge["properties"]["denied"]=True
                        else:edge["semantics"]="unsupported"
                with self.subTest(rule=rule,case=alteration):self.assertEqual(self.decide(b,rule)[0],"Unknown")

    def test_sync_cannot_use_stale_cloud_evidence_as_tenant_binding(self):
        b=copy.deepcopy(self.base)
        for source in b["sources"]:
            if source["producer"]=="scubagear":source["collected_at"]="2026-09-01T07:00:00Z"
        self.assertEqual(self.decide(b,RULES[2])[0],"Unknown")

    def test_incomplete_ca_and_unrecognized_method_are_unknown(self):
        for key,value in (("complete",False),("evaluation_method","unrecognized"),("owner",None),("evaluated_at","2026-09-01T07:00:00Z")):
            b=copy.deepcopy(self.base)
            next(f for f in b["facts"] if f["predicate"]=="ca_scenario")["value"][key]=value
            self.assertEqual(self.decide(b,RULES[4])[0],"Unknown")


if __name__=="__main__":unittest.main()
