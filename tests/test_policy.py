"""Final Rego predicates run against the exact pinned OPA binary."""
import copy
import unittest
from scubatank import policy

RULE_CHECKS = {
    "ST.CORR.IDENTITY.001": ["reset_authority","identity_link","unapproved_controller","ad_account_enabled","cloud_account_enabled","ad_password_authority","password_flow_applicable","active_privileged_role"],
    "ST.CORR.IDENTITY.003": ["identity_link","membership_path","ad_control_plane","ad_account_enabled","cloud_account_enabled","active_privileged_role"],
    "ST.CORR.SYNC.001": ["host_admin","unapproved_controller","sync_host_confirmed","tenant_link"],
    "ST.CORR.GROUP.001": ["membership_control","identity_link","unapproved_controller","membership_add_supported","sensitive_grant_effective"],
    "ST.CORR.GROUP.006": ["membership_control","identity_link","unapproved_controller","membership_add_supported","scenario_context","scenario_user_enabled","scenario_complete","scenario_enforced_exclusion","no_restoring_policy"],
    "ST.CORR.APPLICATION.001": ["reset_authority","identity_link","unapproved_controller","ad_account_enabled","cloud_account_enabled","ad_password_authority","password_flow_applicable","application_owner","usable_credential_addition","service_principal_binding","sensitive_application_permissions"],
}


def candidate(rule):
    return {"candidate_id":"example","rule_id":rule,"checks":{k:True for k in RULE_CHECKS[rule]},"gaps":[],"integrity_gaps":[]}


class PolicyTests(unittest.TestCase):
    def status(self, c):
        return policy.evaluate([c])[0]["status"]

    def test_six_positive_conjunctions(self):
        for rule in RULE_CHECKS:
            with self.subTest(rule=rule): self.assertEqual(self.status(candidate(rule)),"Fail")

    def test_every_missing_prerequisite_is_unknown(self):
        cases = []
        for rule,checks in RULE_CHECKS.items():
            for key in checks:
                c = candidate(rule); c["checks"][key] = None
                cases.append(c)
        self.assertEqual({r["status"] for r in policy.evaluate(cases)}, {"Unknown"})

    def test_each_known_false_prerequisite_disproves_specific_predicate(self):
        cases = []
        for rule,checks in RULE_CHECKS.items():
            for key in checks:
                if key == "scenario_complete":
                    continue  # An explicitly incomplete policy evaluation is Unknown.
                c = candidate(rule); c["checks"][key] = False
                cases.append(c)
        self.assertEqual({r["status"] for r in policy.evaluate(cases)}, {"Pass"})

    def test_stale_conflicting_wrong_scope_are_unknown_even_when_checks_true(self):
        for gap in ("stale","conflicting identities","wrong tenant","unsupported producer version"):
            c=candidate("ST.CORR.IDENTITY.001");c["integrity_gaps"]=[gap]
            self.assertEqual(self.status(c),"Unknown")

    def test_one_ca_exclusion_is_insufficient(self):
        c=candidate("ST.CORR.GROUP.006");c["checks"]["no_restoring_policy"]=None
        self.assertEqual(self.status(c),"Unknown")
        c["checks"]["no_restoring_policy"]=False
        self.assertEqual(self.status(c),"Pass")

    def test_incomplete_scenario_never_reports_pass(self):
        c=candidate("ST.CORR.GROUP.006");c["checks"]["scenario_complete"]=False
        self.assertEqual(self.status(c),"Unknown")

    def test_reset_rule_does_not_request_mfa_bypass(self):
        c=candidate("ST.CORR.IDENTITY.001")
        self.assertEqual(self.status(c),"Fail")
        self.assertNotIn("mfa_bypass",c["checks"])

    def test_unknown_rule_is_not_implemented(self):
        c=candidate("ST.CORR.SYNC.001");c["rule_id"]="ST.CORR.SYNC.999"
        self.assertEqual(self.status(c),"NotImplemented")


if __name__ == "__main__": unittest.main()
