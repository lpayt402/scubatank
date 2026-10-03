"""Join scoped evidence into six bounded rule candidates.

No ACL interpretation, credential operations, policy simulation or live calls.
Final exposure conjunctions and result states are evaluated by OPA.
"""
from collections import deque
from datetime import datetime, timezone
import hashlib
import json

RULES = (
    "ST.CORR.IDENTITY.001", "ST.CORR.IDENTITY.003", "ST.CORR.SYNC.001",
    "ST.CORR.GROUP.001", "ST.CORR.GROUP.006", "ST.CORR.APPLICATION.001",
)
RULE_VERSION = "1.0.0"
ALLOWED_EDGES = {"ForceChangePassword", "MemberOf", "AdminTo", "AddMember", "AZOwns", "AZAddSecret"}
MAX_PATH_DEPTH = 12
MAX_CANDIDATES = 5000


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Observation times must include a timezone")
    return parsed.astimezone(timezone.utc)


class Join:
    def __init__(self, bundle, as_of, max_age_hours):
        self.bundle = bundle
        self.entities = {e["id"]: e for e in bundle["entities"]}
        self.sources = {s["source_id"]: s for s in bundle["sources"]}
        self.edges = sorted(bundle["edges"], key=lambda e: e["id"])
        self.links = bundle["identity_links"]
        self.facts = bundle["facts"]
        self.as_of = timestamp(as_of)
        self.max_age_hours = max_age_hours

    def new(self, rule, entities=(), edges=()):
        return {"rule_id": rule, "checks": {}, "gaps": [], "integrity_gaps": [],
            "entity_ids": sorted(set(entities)), "edge_ids": sorted(e["id"] for e in edges),
            "evidence_refs": [], "limitations": [], "context": {}}

    def refs(self, c, refs, entities=()):
        c["evidence_refs"] = sorted(set(c["evidence_refs"]).union(refs))
        for ref in refs:
            sid = ref.partition("#")[0]
            source = self.sources.get(sid)
            if source is None:
                c["integrity_gaps"].append("Unresolved evidence source: " + sid)
                continue
            try:
                age = (self.as_of - timestamp(source["collected_at"])).total_seconds() / 3600
                if age < 0 or age > self.max_age_hours:
                    c["integrity_gaps"].append("Evidence outside the assessment window: " + sid)
            except (ValueError, TypeError, KeyError):
                c["integrity_gaps"].append("Missing or invalid collection time: " + sid)
            if source.get("producer") in ("bloodhound-ce","BloodHound CE"):
                window=source.get("observation_window")
                if not isinstance(window,dict):
                    c["integrity_gaps"].append("Underlying graph collection window is missing: " + sid)
                else:
                    try:
                        oldest,newest=timestamp(window["oldest_at"]),timestamp(window["newest_at"])
                        age=(self.as_of-oldest).total_seconds()/3600
                        if newest<oldest or newest>self.as_of or age>self.max_age_hours:
                            c["integrity_gaps"].append("Underlying graph observations are outside the assessment window: " + sid)
                    except (ValueError,TypeError,KeyError):
                        c["integrity_gaps"].append("Underlying graph collection window is invalid: " + sid)
                if not source.get("collector_versions"):
                    c["integrity_gaps"].append("Underlying graph collector versions are missing: " + sid)
            if source.get("collection_errors"):
                c["integrity_gaps"].append("Source has collection errors: " + sid)
            scope = source.get("scope", {})
            versions={"bloodhound-ce":"9.7.1","BloodHound CE":"9.7.1","scubagear":"1.8.0","operator-evidence":"1.0.0"}
            if source.get("producer") not in versions or source.get("producer_version") != versions[source["producer"]]:
                c["integrity_gaps"].append("Unsupported producer version: " + sid)
            for eid in entities:
                entity = self.entities.get(eid)
                if not entity:
                    continue
                key = "forest_id" if entity["kind"].startswith("AD") else "tenant_id"
                if scope.get(key) != entity["boundary_id"]:
                    c["integrity_gaps"].append("Evidence scope does not establish " + eid + ": " + sid)

    def include_entity(self, c, eid):
        if eid in self.entities:
            c["entity_ids"] = sorted(set(c["entity_ids"]) | {eid})
            self.refs(c, self.entities[eid]["evidence_refs"], (eid,))
            for issue in self.bundle.get("issues",[]):
                if issue["code"] in ("EntityConflict","IdentityConflict") and eid in issue.get("entity_ids",[]):
                    c["integrity_gaps"].append("Conflicting identity evidence: " + eid)

    def check(self, c, name, value, gap):
        c["checks"][name] = value
        if value is None:
            c["gaps"].append(gap)

    def fact(self, c, subject, predicate):
        found = [f for f in self.facts if f["subject_id"] == subject and f["predicate"] == predicate]
        for item in found:
            self.refs(c, item["evidence_refs"], (subject,))
        if predicate == "active_privileged_role":
            current = []
            for item in found:
                try:
                    starts = timestamp(item["valid_from"]) if "valid_from" in item else None
                    ends = timestamp(item["valid_until"]) if "valid_until" in item else None
                    if starts and ends and starts >= ends:
                        raise ValueError("Invalid role schedule")
                    if (starts is None or starts <= self.as_of) and (ends is None or self.as_of < ends):
                        current.append(item)
                except (ValueError, TypeError, KeyError, AttributeError):
                    c["integrity_gaps"].append("Invalid active-role validity bounds: " + subject)
            if found and not current:
                c["gaps"].append("No retained active role assignment covers the assessment time: " + subject)
            # Several assignments are independent positive observations. An
            # expired assignment does not conflict with one that still applies.
            # Expiry alone cannot establish absence of other current roles.
            found = current
        values = {json.dumps(f["value"], sort_keys=True) for f in found}
        if len(values) != 1:
            if len(values) > 1:
                c["integrity_gaps"].append("Conflicting facts: " + subject + "/" + predicate)
            return None
        return found[0]["value"]

    def boolean(self, c, subject, predicate, check_name=None):
        value = self.fact(c, subject, predicate)
        result = value if type(value) is bool else None
        self.check(c, check_name or predicate, result, "Required fact: " + str(subject) + "/" + predicate)
        return result

    def edge(self, c, edge, expected, from_kinds, to_kinds):
        source = self.entities.get(edge["source_id"])
        target = self.entities.get(edge["target_id"])
        supported = edge["type"] == expected and edge.get("semantics") == "upstream-derived"
        supported = supported and source and target and source["kind"] in from_kinds and target["kind"] in to_kinds
        if not supported:
            return None
        for entity in (source, target):
            self.include_entity(c, entity["id"])
        self.refs(c, edge["evidence_refs"], (source["id"], target["id"]))
        if source["kind"].startswith("AD") and target["kind"].startswith("AD") and source["boundary_id"] != target["boundary_id"]:
            c["integrity_gaps"].append("Cross-forest authority is outside this rule's supported semantics")
        if source["kind"].startswith("Cloud") and target["kind"].startswith("Cloud") and source["boundary_id"] != target["boundary_id"]:
            c["integrity_gaps"].append("Cross-tenant authority is outside this rule's supported semantics")
        props=edge.get("properties",{})
        if "denied" in props and (type(props["denied"]) is not bool or props["denied"] is True):
            c["integrity_gaps"].append("Relationship carries a denied or invalid qualifier: " + edge["id"])
        preconditions=props.get("preconditions",{})
        if not isinstance(preconditions,dict) or any(v is not True for v in preconditions.values()):
            c["integrity_gaps"].append("Relationship has unresolved or unsatisfied preconditions: " + edge["id"])
        return True

    def cloud_link(self, c, ad_id, cloud_kind):
        links = [l for l in self.links if l["ad_entity_id"] == ad_id]
        cloud_ids = {l["cloud_entity_id"] for l in links}
        if len(cloud_ids) != 1 or any(l.get("conflict") or l.get("method") != "established_id_link" for l in links):
            self.check(c, "identity_link", None, "An unambiguous established synchronized identity link is required")
            if links:
                c["integrity_gaps"].append("Conflicting or unsupported synchronized identity link")
                for link in links:
                    self.refs(c, link["evidence_refs"])
            return None
        cloud_id = next(iter(cloud_ids))
        cloud = self.entities.get(cloud_id)
        if not cloud or cloud["kind"] != cloud_kind:
            self.check(c, "identity_link", None, "Synchronized identity link has an unsupported entity type")
            return None
        self.include_entity(c, cloud_id)
        for link in links:
            self.refs(c, link["evidence_refs"], (ad_id, cloud_id))
        # One cloud identity cannot be established against multiple AD objects.
        if any(l["cloud_entity_id"] == cloud_id and l["ad_entity_id"] != ad_id for l in self.links):
            c["integrity_gaps"].append("Multiple AD objects claim this cloud identity")
        self.check(c, "identity_link", True, "")
        return cloud_id

    def unapproved(self, c, target_id, actor_id):
        approved = self.fact(c, target_id, "approved_controllers")
        value = actor_id not in approved if isinstance(approved, list) and all(isinstance(a,str) for a in approved) else None
        self.check(c, "unapproved_controller", value, "Complete approved-controller inventory required for " + target_id)

    def password(self, c, ad_id, cloud_id):
        self.boolean(c, ad_id, "enabled", "ad_account_enabled")
        self.boolean(c, cloud_id, "enabled", "cloud_account_enabled")
        authority = self.fact(c, cloud_id, "password_authority")
        self.check(c, "ad_password_authority", authority == "ad" if authority in ("ad","cloud") else None,
            "Actual password authority required for " + str(cloud_id))
        self.boolean(c, cloud_id, "password_flow_applicable")

    def memberships(self, start):
        queue = deque([(start, [])]); seen = {start}
        while queue:
            node, path = queue.popleft()
            for edge in self.edges:
                if edge["source_id"] != node or edge["type"] != "MemberOf" or edge.get("semantics") != "upstream-derived":
                    continue
                target = edge["target_id"]
                if target in seen or len(path) >= MAX_PATH_DEPTH:
                    continue
                seen.add(target)
                next_path = path + [edge]
                yield target, next_path
                queue.append((target, next_path))


def prepare_candidates(bundle, *, as_of, max_age_hours=24):
    if not 0 < max_age_hours <= 24 * 365:
        raise ValueError("max_age_hours must be positive and at most one year")
    join = Join(bundle, as_of, max_age_hours)
    candidates = []

    # A processed password-reset relationship does not establish cloud authentication bypass.
    for edge in join.edges:
        if edge["type"] != "ForceChangePassword":
            continue
        ad_id, actor = edge["target_id"], edge["source_id"]
        c = join.new(RULES[0], (ad_id,actor), (edge,))
        join.check(c,"reset_authority",join.edge(c,edge,"ForceChangePassword",("ADUser","ADGroup"),("ADUser",)),"Supported effective reset authority is required")
        cloud = join.cloud_link(c,ad_id,"CloudUser")
        join.unapproved(c,ad_id,actor)
        join.password(c,ad_id,cloud)
        join.boolean(c,cloud,"active_privileged_role")
        c["limitations"].append("Password-reset authority is not MFA bypass or proof of a successful cloud sign-in.")
        candidates.append(c)

    # Transitive membership is bounded to the same AD forest; no trust or service nesting inference.
    for link in sorted(join.links, key=lambda l:l["id"]):
        ad = join.entities.get(link["ad_entity_id"])
        if not ad or ad["kind"] != "ADUser":
            continue
        paths = list(join.memberships(ad["id"]))
        targets = [(group,path) for group,path in paths if any(f["subject_id"]==group and f["predicate"]=="ad_control_plane" for f in join.facts)]
        if not targets:
            targets = [(None,[])]
        for group,path in targets:
            c = join.new(RULES[1],(ad["id"],),path)
            cloud = join.cloud_link(c,ad["id"],"CloudUser")
            for member in path:
                join.check(c,"membership_"+member["id"],join.edge(c,member,"MemberOf",("ADUser","ADGroup"),("ADGroup",)),"Supported AD membership required")
            join.check(c,"membership_path",True if path else None,"Resolved effective control-plane group membership required")
            join.boolean(c,group,"ad_control_plane")
            join.boolean(c,ad["id"],"enabled","ad_account_enabled")
            join.boolean(c,cloud,"enabled","cloud_account_enabled")
            join.boolean(c,cloud,"active_privileged_role")
            c["context"]["tier_separation_required"] = join.fact(c,cloud,"tier_separation_required")
            c["limitations"].append("Dual standing authority is evidenced configuration, not evidence of compromise. Eligible roles alone do not establish this predicate.")
            candidates.append(c)

    for edge in join.edges:
        if edge["type"] != "AdminTo":
            continue
        host,actor = edge["target_id"],edge["source_id"]
        c = join.new(RULES[2],(host,actor),(edge,))
        join.check(c,"host_admin",join.edge(c,edge,"AdminTo",("ADUser","ADGroup"),("ADComputer",)),"Supported effective local administration required")
        join.unapproved(c,host,actor)
        join.boolean(c,host,"sync_host_confirmed")
        tenant = join.fact(c,host,"sync_tenant_id")
        # A host inventory record must identify a tenant included in the imported cloud evidence.
        tenants = {e["boundary_id"] for e in bundle["entities"] if e["kind"].startswith("Cloud")}
        join.check(c,"tenant_link",True if isinstance(tenant,str) and tenant in tenants else None,"Confirmed synchronization deployment and assessed tenant linkage required")
        if tenant in tenants:
            for cloud_entity in bundle["entities"]:
                if cloud_entity["kind"].startswith("Cloud") and cloud_entity["boundary_id"]==tenant:
                    join.refs(c,cloud_entity["evidence_refs"],(cloud_entity["id"],))
        c["context"]["tenant_id"] = tenant
        c["limitations"].append("Local administrative authority does not establish network reachability or control of cloud-native administrators.")
        candidates.append(c)

    for edge in join.edges:
        if edge["type"] != "AddMember":
            continue
        group,actor = edge["target_id"],edge["source_id"]
        for rule in RULES[3:5]:
            c = join.new(rule,(group,actor),(edge,))
            join.check(c,"membership_control",join.edge(c,edge,"AddMember",("ADUser","ADGroup"),("ADGroup",)),"Supported effective AD membership-write permission required")
            cloud = join.cloud_link(c,group,"CloudGroup")
            join.unapproved(c,group,actor)
            join.boolean(c,cloud,"membership_add_supported")
            if rule == RULES[3]:
                join.boolean(c,cloud,"sensitive_grant_effective")
                c["limitations"].append("This path concerns a supported application/resource grant. It does not establish Entra role assignment or unsupported nested membership.")
            else:
                scenario = join.fact(c,cloud,"ca_scenario")
                scenario = scenario if isinstance(scenario,dict) else {}
                context_keys = ("user_id","resource_id","group_id","evaluated_policy_ids","evaluation_method","sign_in_conditions","required_protection")
                context_ok = all(scenario.get(k) for k in context_keys) and scenario.get("group_id") == cloud and scenario.get("prospective_membership") is True
                context_ok = context_ok and scenario.get("evaluation_method") in ("microsoft-graph-conditional-access-evaluate-v1","operator-reviewed-combined-policy-scenario")
                context_ok = context_ok and isinstance(scenario.get("evaluated_policy_ids"),list) and all(isinstance(p,str) and p for p in scenario["evaluated_policy_ids"])
                context_ok = context_ok and isinstance(scenario.get("sign_in_conditions"),dict) and scenario.get("required_protection") == "mfa"
                context_ok = context_ok and bool(scenario.get("owner")) and bool(scenario.get("evaluated_at"))
                if scenario.get("evaluated_at"):
                    try:
                        age=(join.as_of-timestamp(scenario["evaluated_at"])).total_seconds()/3600
                        if age<0 or age>max_age_hours:
                            c["integrity_gaps"].append("Conditional Access scenario is outside the assessment window")
                    except (ValueError,TypeError):
                        c["integrity_gaps"].append("Conditional Access scenario has invalid evaluation time")
                scenario_user = join.entities.get(scenario.get("user_id"))
                context_ok = context_ok and scenario_user and scenario_user["kind"] == "CloudUser" and scenario_user["boundary_id"] == join.entities.get(cloud,{}).get("boundary_id")
                if scenario_user:
                    join.include_entity(c,scenario_user["id"])
                join.boolean(c,scenario.get("user_id"),"enabled","scenario_user_enabled")
                join.check(c,"scenario_context",True if context_ok else None,"Complete prospective user/resource/group scenario and evaluated policy set required")
                for name in ("complete","enforced_exclusion"):
                    value = scenario.get(name)
                    result = value if type(value) is bool else None
                    if name == "complete" and result is not True:
                        result = None
                    join.check(c,"scenario_"+name,result,"Complete Conditional Access scenario field required: "+name)
                restored = scenario.get("other_policy_restores")
                join.check(c,"no_restoring_policy",not restored if type(restored) is bool else None,"Combined enabled-policy evaluation is required; a single exclusion is insufficient")
                c["context"]["ca_scenario"] = scenario
                c["limitations"].append("Conditional Access outcome is imported scenario evidence. ScubaTank does not simulate policy or treat one policy exclusion as an effective bypass.")
            candidates.append(c)

    for edge in join.edges:
        if edge["type"] != "ForceChangePassword":
            continue
        ad,actor = edge["target_id"],edge["source_id"]
        base = join.new(RULES[5],(ad,actor),(edge,))
        join.check(base,"reset_authority",join.edge(base,edge,"ForceChangePassword",("ADUser","ADGroup"),("ADUser",)),"Supported source-account control required")
        cloud = join.cloud_link(base,ad,"CloudUser")
        owners = [e for e in join.edges if e["source_id"]==cloud and e["type"]=="AZOwns"]
        if not owners:
            owners = [None]
        for owner in owners:
            c = json.loads(json.dumps(base))
            app = owner["target_id"] if owner else None
            if owner:
                c["edge_ids"].append(owner["id"])
            join.check(c,"application_owner",join.edge(c,owner,"AZOwns",("CloudUser",),("CloudApplication",)) if owner else None,"Verified owner of the actual application is required")
            join.unapproved(c,ad,actor)
            join.password(c,ad,cloud)
            join.boolean(c,app,"usable_credential_addition")
            sp = join.fact(c,app,"service_principal_id")
            service = join.entities.get(sp) if isinstance(sp,str) else None
            valid_sp = service and service["kind"]=="CloudServicePrincipal" and service["boundary_id"]==join.entities.get(app,{}).get("boundary_id")
            join.check(c,"service_principal_binding",True if valid_sp else None,"Application-to-service-principal binding in the same tenant required")
            if valid_sp:
                join.include_entity(c,sp)
            join.boolean(c,sp,"sensitive_application_permissions")
            c["limitations"].append("Ownership alone is not credential-write authority. Usable credential addition and sensitive app-only grants require separate evidence; no credential is created.")
            candidates.append(c)

    for rule in RULES:
        if not any(c["rule_id"] == rule for c in candidates):
            c = join.new(rule)
            c["checks"] = {"reset_authority" if rule==RULES[0] else "source_path":None}
            c["gaps"] = ["No supported, scoped path evidence for this rule; absence of an edge does not establish a Pass."]
            candidates.append(c)
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError("Assessment exceeds the bounded 5000-candidate limit; narrow the exported graph")
    for c in candidates:
        for key in ("gaps","integrity_gaps","limitations","entity_ids","edge_ids","evidence_refs"):
            c[key] = sorted(set(c[key]))
        key = json.dumps([c["rule_id"],c["entity_ids"],c["edge_ids"]],sort_keys=True)
        c["candidate_id"] = hashlib.sha256(key.encode()).hexdigest()[:24]
    return sorted(candidates,key=lambda c:(c["rule_id"],c["candidate_id"]))
