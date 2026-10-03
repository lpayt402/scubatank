package scubatank.hybrid

import rego.v1

# The adapter/join layer must provide every listed scoped prerequisite.
# No graph traversal, policy simulation or network operation runs here.
requirements := {
    "ST.CORR.IDENTITY.001": ["reset_authority", "identity_link", "unapproved_controller", "ad_account_enabled", "cloud_account_enabled", "ad_password_authority", "password_flow_applicable", "active_privileged_role"],
    "ST.CORR.IDENTITY.003": ["identity_link", "membership_path", "ad_control_plane", "ad_account_enabled", "cloud_account_enabled", "active_privileged_role"],
    "ST.CORR.SYNC.001": ["host_admin", "unapproved_controller", "sync_host_confirmed", "tenant_link"],
    "ST.CORR.GROUP.001": ["membership_control", "identity_link", "unapproved_controller", "membership_add_supported", "sensitive_grant_effective"],
    "ST.CORR.GROUP.006": ["membership_control", "identity_link", "unapproved_controller", "membership_add_supported", "scenario_context", "scenario_user_enabled", "scenario_complete", "scenario_enforced_exclusion", "no_restoring_policy"],
    "ST.CORR.APPLICATION.001": ["reset_authority", "identity_link", "unapproved_controller", "ad_account_enabled", "cloud_account_enabled", "ad_password_authority", "password_flow_applicable", "application_owner", "usable_credential_addition", "service_principal_binding", "sensitive_application_permissions"],
}

incomplete(c) if count(c.integrity_gaps) > 0
incomplete(c) if count(c.gaps) > 0
incomplete(c) if {
    c.rule_id == "ST.CORR.GROUP.006"
    object.get(c.checks, "scenario_complete", null) != true
}
incomplete(c) if {
    some key in requirements[c.rule_id]
    object.get(c.checks, key, null) == null
}
incomplete(c) if {
    some value in c.checks
    value == null
}
incomplete(c) if {
    some value in c.checks
    not is_boolean(value)
}

exposed(c) if {
    every key in requirements[c.rule_id] {
        c.checks[key] == true
    }
    every value in c.checks {
        value == true
    }
}

status(c) := "NotImplemented" if not requirements[c.rule_id]
else := "Unknown" if incomplete(c)
else := "Fail" if exposed(c)
else := "Pass"

results := [{"candidate_id": c.candidate_id, "rule_id": c.rule_id, "status": status(c)} |
    some c in input.candidates
]
