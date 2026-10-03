"""Reconstruct imported evidence, join supported paths and package OPA decisions."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import uuid

from .evidence import confined_path, read_json, validate_bundle
from .evaluator import RULES, RULE_VERSION, prepare_candidates, timestamp
from .importers import import_manifest
from .policy import evaluate
from .reporting import build_report
from tools.catalog import load_catalog

ROOT=Path(__file__).resolve().parents[1]


def reverify(bundle, evidence_root):
    """Re-derive all normalized records, not just the hashes of raw files."""
    validate_bundle(bundle)
    if evidence_root is None:
        return False
    manifest=confined_path(Path(evidence_root),bundle["manifest"]["path"])
    if hashlib.sha256(manifest.read_bytes()).hexdigest()!=bundle["manifest"]["sha256"]:
        raise ValueError("Original import manifest digest differs from the imported bundle")
    reconstructed=import_manifest(manifest)
    if reconstructed!=bundle:
        raise ValueError("The normalized bundle differs from a fresh import of its original evidence; reimport before assessment")
    return True


def mapping(rule,pins):
    output={"status":"project-proposed"}
    for framework in ("attack","nist"):
        metadata=pins["frameworks"][framework]
        records=metadata["techniques" if framework=="attack" else "controls"]
        index={record["id"]:record for record in records}
        output[framework]=[{"id":m["id"],"title":index[m["id"]]["title"],
            "framework_version":metadata["version"],"source_digest":metadata["sha256"],
            "rationale":m["rationale"],"status":"project-proposed"} for m in pins["rules"][rule][framework]]
    return output


def _action(c,edges,entities):
    allowed={"ForceChangePassword":("Restrict source-account password-reset delegation","Remove the unintended reset permission. This breaks the linked paths at their first evidenced authority edge. Review legitimate support duties before changing delegation."),
        "MemberOf":("Separate directory and cloud administration","Remove unneeded control-plane group membership from the shared account and use separate administrative identities. Removing this membership breaks the evidenced directory side of the shared-privilege path."),
        "AdminTo":("Restrict synchronization-host administration","Remove the unintended local administrative grant and place the synchronization host within its approved administrative boundary. This breaks the evidenced host-control edge."),
        "AddMember":("Restrict source-group membership management","Remove the unintended membership-write permission or move the sensitive authorization into a separately governed group. Removing the permission breaks each evidenced path through this group.")}
    chosen=next((edges[e] for e in c["edge_ids"] if edges[e]["type"] in allowed),None)
    if c["rule_id"]=="ST.CORR.IDENTITY.003":
        chosen=next((edges[e] for e in c["edge_ids"] if edges[e]["type"]=="MemberOf" and entities[edges[e]["source_id"]]["kind"]=="ADUser"),None)
    if chosen is None:
        return []
    title,rationale=allowed[chosen["type"]]
    return [{"action_id":"restrict:"+chosen["id"],"title":title,"rationale":rationale,
        "breaks_edge_ids":[chosen["id"]],"affected_entity_ids":c["entity_ids"],
        "evidence_refs":chosen["evidence_refs"],"owner":None,"exception":None}]


def assess(bundle, *, as_of=None, max_age_hours=24, opa=None, evidence_root=None):
    verified=reverify(bundle,evidence_root)
    as_of=as_of or datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
    timestamp(as_of)
    candidates=prepare_candidates(bundle,as_of=as_of,max_age_hours=max_age_hours)
    if not verified:
        for c in candidates:
            c["integrity_gaps"].append("Original evidence has not been reverified. Supply the local evidence root so the saved manifest can reconstruct the normalized records.")
    results=evaluate(candidates,opa=opa)
    result_index={r["candidate_id"]:r for r in results}
    if len(result_index)!=len(candidates):
        raise ValueError("OPA returned duplicate candidate identifiers")
    pins=read_json(ROOT/"config/framework-pins.json")
    frameworks={name:data["version"] for name,data in pins["frameworks"].items()}
    adapters={s["producer"]:s["adapter_version"] for s in bundle["sources"]}
    source_versions={s["source_id"]:s["producer_version"] for s in bundle["sources"]}
    run_id=str(uuid.uuid5(uuid.NAMESPACE_URL,json.dumps([bundle["run_id"],as_of,max_age_hours,RULE_VERSION],sort_keys=True)))
    checks={c["id"]:c for c in load_catalog(ROOT)["checks"]}
    edges={e["id"]:e for e in bundle["edges"]}
    entities={e["id"]:e for e in bundle["entities"]}
    findings=[]
    for c in candidates:
        status=result_index[c["candidate_id"]]["status"]
        title=checks[c["rule_id"]]["title"]
        if status=="Fail":
            message=title+". The imported evidence establishes this scoped configuration path."
        elif status=="Pass":
            disproved=", ".join(key.replace("_"," ") for key,value in c["checks"].items() if value is False)
            message=title+". This specific path is disproved by the evidenced condition: "+disproved+"."
        else:
            message=title+". Required evidence is incomplete or cannot support a reliable decision."
        gaps=sorted(set(c["gaps"]+c["integrity_gaps"])) if status=="Unknown" else []
        if status=="Unknown" and not gaps:
            gaps=["The final predicate has an incomplete or unsupported prerequisite."]
        actions=_action(c,edges,entities) if status=="Fail" else []
        cause=actions[0]["action_id"] if actions else "path:"+c["candidate_id"]
        findings.append({"schema_version":"0.2.0","run_id":run_id,"rule_version":RULE_VERSION,
            "framework_versions":frameworks,"adapter_versions":adapters,"source_versions":source_versions,
            "finding_id":c["candidate_id"],"check_id":c["rule_id"],"status":status,
            "severity":checks[c["rule_id"]]["severity"],"confidence":"Unknown" if status=="Unknown" else "Medium",
            "coverage":"complete" if status=="Pass" else "partial","message":message,
            "evidence_refs":c["evidence_refs"],"affected_entity_ids":c["entity_ids"],"missing_evidence":gaps,
            "mappings":mapping(c["rule_id"],pins),"cause_id":cause,"limitations":c["limitations"],
            "paths":[{"path_id":"path:"+c["candidate_id"],"entity_ids":c["entity_ids"],"edge_ids":c["edge_ids"],
                "evidence_refs":c["evidence_refs"],"claim":message,"limitations":c["limitations"]}] if c["entity_ids"] else [],
            "remediation":actions,"validation_state":"synthetic-tested"})
    scopes={"forest_ids":sorted({s["scope"]["forest_id"] for s in bundle["sources"] if "forest_id" in s["scope"]}),
        "tenant_ids":sorted({s["scope"]["tenant_id"] for s in bundle["sources"] if "tenant_id" in s["scope"]})}
    limitations=["Only six bounded correlations are implemented and tested with synthetic evidence. The remaining 126 catalog entries remain specifications.",
        "Complete finding coverage describes the required proof for a specific scoped predicate. Overall forest, tenant, and catalog coverage remains partial.",
        "Source observations and hashes identify the imported bytes; they do not authenticate the producer's claims. Owner-reviewed facts retain attestation provenance.",
        "No live-environment validation, exploitation, tenant connection, credential collection or automatic remediation was performed.",
        "SCuBA results are original upstream posture context. A tenant-wide failure is not a per-user authentication bypass.",
        "Framework mappings are project-proposed partial evidence and potential behavior; they are not certification or detection coverage."]
    if not verified:
        limitations.append("Original inputs were not reconstructed for this run; every rule decision remains Unknown.")
    return build_report(findings,run_id=run_id,generated_at=as_of,framework_versions=frameworks,
        adapter_versions=adapters,source_versions=source_versions,sources=bundle["sources"],
        entities=bundle["entities"],edges=bundle["edges"],coverage="partial",limitations=limitations,
        synthetic=bundle["synthetic"],scope=scopes,observations=bundle["observations"],
        identity_links=bundle["identity_links"],upstream_findings=bundle["upstream_findings"])
