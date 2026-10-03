"""Offline reports with explicit result states and source-record traceability."""
from __future__ import annotations

import base64
import copy
import csv
import hashlib
import html
import io
import json
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from .evidence import local_path


VERSION = "0.2.0"
STATUSES = ("Pass", "Fail", "Unknown", "NotApplicable", "Error", "NotImplemented", "ReviewRequired")
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_READABLE_BYTES = 8 * 1024 * 1024
MAX_HTML_FINDINGS = 500
MAX_HTML_EVIDENCE = 5000
MAX_RAW_PREVIEW = 4096
ROOT = Path(__file__).resolve().parents[1]


class _BoundedLines(list):
    def __init__(self, lines=()):
        super().__init__()
        self.size = 0
        self.extend(lines)

    def append(self, line):
        self.size += len(line.encode("utf-8")) + 1
        if self.size > MAX_READABLE_BYTES:
            raise ValueError("Readable report exceeds the 8 MiB output limit; reduce the assessment scope")
        super().append(line)

    def extend(self, lines):
        for line in lines:
            self.append(line)


class _BoundedCSV(io.StringIO):
    def __init__(self):
        super().__init__(newline="")
        self.size = 0

    def write(self, value):
        self.size += len(value.encode("utf-8"))
        if self.size > MAX_REPORT_BYTES:
            raise ValueError("CSV report exceeds the 32 MiB output limit; reduce the assessment scope")
        return super().write(value)


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    resources = []
    for name in ("finding-v2.schema.json", "report.schema.json"):
        data = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(data)
        resources.append((name, Resource.from_contents(data)))
    registry = Registry().with_resources(resources)
    return Draft202012Validator(resources[1][1].contents, registry=registry, format_checker=FormatChecker())


def _bounded(value: Any, depth: int = 0) -> None:
    if depth > 40:
        raise ValueError("Report JSON nesting exceeds 40 levels")
    if isinstance(value, str) and len(value) > 20000:
        raise ValueError("Report text exceeds 20000 characters")
    if isinstance(value, dict):
        if len(value) > 200000:
            raise ValueError("Report object exceeds the property limit")
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("Report keys must be strings")
            _bounded(key, depth + 1)
            _bounded(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > 200000:
            raise ValueError("Report array exceeds the record limit")
        for child in value:
            _bounded(child, depth + 1)


def _index(rows: list[dict], key: str, kind: str) -> dict[str, dict]:
    result = {}
    for row in rows:
        identifier = row[key]
        if identifier in result:
            raise ValueError(f"Report has duplicate {kind} ID: {identifier}")
        result[identifier] = row
    return result


def _actions(findings: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    fields = ("breaks_edge_ids", "affected_entity_ids", "evidence_refs", "finding_ids", "path_ids", "cause_ids")
    for finding in findings:
        if finding["status"] not in ("Fail", "ReviewRequired"):
            continue
        for action in finding["remediation"]:
            identifier = action["action_id"]
            if identifier not in grouped:
                grouped[identifier] = copy.deepcopy(action)
                grouped[identifier].update(finding_ids=[], path_ids=[], cause_ids=[])
            target = grouped[identifier]
            if any(target[key] != action[key] for key in ("title", "rationale", "owner", "exception")):
                raise ValueError(f"Conflicting remediation action: {identifier}")
            for key in fields[:3]:
                target[key] = sorted(set(target[key]) | set(action[key]))
            target["finding_ids"].append(finding["finding_id"])
            target["cause_ids"].append(finding["cause_id"])
            target["path_ids"].extend(path["path_id"] for path in finding["paths"]
                                      if set(path["edge_ids"]) & set(action["breaks_edge_ids"]))
    for action in grouped.values():
        for key in fields:
            action[key] = sorted(set(action[key]))
    return [grouped[key] for key in sorted(grouped)]


def _source_coverage(source: dict) -> str:
    completeness = source["completeness"]
    if isinstance(completeness, dict):
        return "complete" if completeness["complete"] else "partial"
    return completeness


def validate_report(report: dict) -> None:
    """Validate the committed schema and references without fetching anything."""
    _bounded(report)
    try:
        encoded = json.dumps(report, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError("Report must contain finite JSON data") from error
    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError("Report exceeds the 32 MiB output limit")
    errors = sorted(_validator().iter_errors(report), key=lambda error: str(error.json_path))
    if errors:
        error = errors[0]
        raise ValueError(f"Invalid report at {error.json_path}: {error.message[:500]}")
    sources = _index(report["sources"], "source_id", "source")
    entities = _index(report["entities"], "id", "entity")
    edges = _index(report["edges"], "id", "edge")
    _index(report["findings"], "finding_id", "finding")
    evidence = report["evidence"]

    def refs(row: dict) -> None:
        for ref in row.get("evidence_refs", []):
            if ref not in evidence:
                raise ValueError(f"Unresolved evidence reference: {ref}")

    def ids(values: list[str], index: dict, kind: str) -> None:
        for identifier in values:
            if identifier not in index:
                raise ValueError(f"Unresolved {kind} reference: {identifier}")

    for ref, record in evidence.items():
        if record["source_id"] not in sources:
            raise ValueError(f"Unresolved evidence source: {record['source_id']}")
        if ref != record["source_id"] + "#" + record["pointer"]:
            raise ValueError(f"Evidence reference and pointer disagree: {ref}")
        if record["sha256"] != sources[record["source_id"]]["sha256"]:
            raise ValueError(f"Evidence source hash disagrees: {ref}")
    for source in sources.values():
        if report["source_versions"].get(source["source_id"]) != source["producer_version"]:
            raise ValueError(f"Source version missing or conflicting: {source['source_id']}")
    for entity in entities.values():
        refs(entity)
    for edge in edges.values():
        ids([edge["source_id"], edge["target_id"]], entities, "entity")
        refs(edge)
    for link in report["identity_links"]:
        ids([link["ad_entity_id"], link["cloud_entity_id"]], entities, "identity")
        refs(link)
    _index(report["identity_links"], "id", "identity link")
    _index(report["upstream_findings"], "id", "upstream finding")
    for upstream in report["upstream_findings"]:
        if upstream["source_id"] not in sources:
            raise ValueError("Unresolved upstream finding source")
        refs(upstream)
    for finding in report["findings"]:
        for key in ("run_id", "framework_versions", "adapter_versions", "source_versions"):
            if finding[key] != report[key]:
                raise ValueError(f"Finding {key} conflicts with the report envelope")
        ids(finding["affected_entity_ids"], entities, "entity")
        refs(finding)
        _index(finding["paths"], "path_id", "path")
        for path in finding["paths"]:
            ids(path["entity_ids"], entities, "entity")
            ids(path["edge_ids"], edges, "edge")
            refs(path)
            if any(edges[edge]["source_id"] not in path["entity_ids"] or edges[edge]["target_id"] not in path["entity_ids"]
                   for edge in path["edge_ids"]):
                raise ValueError("Path edges must belong to the path's entities")
        for action in finding["remediation"]:
            ids(action["affected_entity_ids"], entities, "entity")
            ids(action["breaks_edge_ids"], edges, "edge")
            refs(action)
            path_edges = {edge for path in finding["paths"] for edge in path["edge_ids"]}
            if not set(action["breaks_edge_ids"]).issubset(path_edges):
                raise ValueError("A remediation edge must belong to its finding's supported paths")
        for framework in ("nist", "attack"):
            for mapping in finding["mappings"][framework]:
                if mapping["framework_version"] != report["framework_versions"].get(framework):
                    raise ValueError(f"Mapping framework version conflicts: {framework}")
                if finding["mappings"]["status"] == "independently-reviewed" and mapping["status"] != "independently-reviewed":
                    raise ValueError("An independently reviewed mapping contains a proposed entry")
    expected_counts = {status: sum(finding["status"] == status for finding in report["findings"]) for status in STATUSES}
    if report["counts"] != expected_counts:
        raise ValueError("Report counts disagree with findings")
    if report["remediation"] != _actions(report["findings"]):
        raise ValueError("Report remediation summary disagrees with findings")
    if report["coverage"] == "complete" and (any(_source_coverage(source) != "complete" or source.get("collection_errors") or source.get("exclusions") for source in sources.values())
                                              or any(finding["coverage"] != "complete" for finding in report["findings"] if finding["status"] != "NotImplemented")):
        raise ValueError("Complete report coverage requires complete source and finding coverage")


def build_report(findings: list[dict], *, run_id: str, generated_at: str,
                 framework_versions: dict, adapter_versions: dict, source_versions: dict,
                 sources: list[dict], entities: list[dict] | None = None, edges: list[dict] | None = None,
                 coverage: str = "partial", limitations=(), synthetic: bool = False, scope: dict | None = None,
                 evidence: dict | None = None, observations: list[dict] | None = None,
                 identity_links: list[dict] | None = None, upstream_findings: list[dict] | None = None) -> dict:
    """Build an immutable-by-convention report. Inputs are copied, never relabeled."""
    ledger = copy.deepcopy(evidence or {})
    source_index = _index(sources, "source_id", "source")
    supplied_observations = list(observations or [])
    for source in sources:
        supplied_observations.extend(source.get("observations", []))
    for observation in supplied_observations:
        ref = observation["ref"]
        if "#" not in ref:
            raise ValueError(f"Malformed evidence reference: {ref}")
        source_id, pointer = ref.split("#", 1)
        if source_id not in source_index:
            raise ValueError(f"Unresolved evidence source: {source_id}")
        row = {"source_id": source_id, "pointer": pointer, "sha256": source_index[source_id]["sha256"],
               "value": copy.deepcopy(observation["value"])}
        if ref in ledger and ledger[ref] != row:
            raise ValueError(f"Conflicting evidence observation: {ref}")
        ledger[ref] = row
    ordered = sorted(copy.deepcopy(findings), key=lambda finding: (finding["check_id"], finding["finding_id"]))
    report = {"schema_version": VERSION, "run_id": run_id, "generated_at": generated_at,
              "framework_versions": copy.deepcopy(framework_versions), "adapter_versions": copy.deepcopy(adapter_versions),
              "source_versions": copy.deepcopy(source_versions), "scope": copy.deepcopy(scope or {}),
              "synthetic": synthetic, "coverage": coverage, "limitations": list(limitations),
              "sources": sorted(copy.deepcopy(sources), key=lambda row: row["source_id"]),
              "entities": sorted(copy.deepcopy(entities or []), key=lambda row: row["id"]),
              "edges": sorted(copy.deepcopy(edges or []), key=lambda row: row["id"]),
              "identity_links": copy.deepcopy(identity_links or []), "evidence": ledger,
              "upstream_findings": copy.deepcopy(upstream_findings or []), "findings": ordered,
              "remediation": _actions(ordered), "counts": {state: Counter(finding["status"] for finding in ordered)[state] for state in STATUSES}}
    validate_report(report)
    return report


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _anchor(kind: str, value: str) -> str:
    return kind + "-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def _md(value: Any) -> str:
    value = re.sub(r"([\\`*_{}\[\]()#!])", r"\\\1", str(value))
    value = html.escape(value, quote=True).replace("|", "&#124;")
    return value.replace("\r", " ").replace("\n", " ")


def _csv_safe(value: Any) -> str:
    value = str(value)
    stripped = value.lstrip()
    if stripped.startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def render_csv(report: dict) -> str:
    """Spreadsheet-view export; JSON is the lossless machine-readable contract."""
    validate_report(report)
    stream = _BoundedCSV()
    fields = ("run_id", "finding_id", "check_id", "rule_version", "status", "severity", "confidence", "coverage", "message",
              "cause_id", "affected_entity_ids", "path_ids", "edge_ids", "evidence_refs", "source_sha256", "source_times",
              "missing_evidence", "limitations", "remediation_ids", "framework_versions", "adapter_versions", "source_versions")
    writer = csv.DictWriter(stream, fieldnames=fields, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writeheader()
    sources = {source["source_id"]: source for source in report["sources"]}
    for finding in report["findings"]:
        row = {key: finding[key] for key in fields if key in finding}
        source_ids = sorted({report["evidence"][ref]["source_id"] for ref in finding["evidence_refs"]})
        row.update(path_ids=[path["path_id"] for path in finding["paths"]],
                   edge_ids=sorted({edge for path in finding["paths"] for edge in path["edge_ids"]}),
                   source_sha256={identifier: sources[identifier]["sha256"] for identifier in source_ids},
                   source_times={identifier: sources[identifier]["collected_at"] for identifier in source_ids},
                   remediation_ids=[action["action_id"] for action in finding["remediation"]])
        writer.writerow({key: _csv_safe(json.dumps(value, sort_keys=True, ensure_ascii=False) if isinstance(value, (list, dict)) else value)
                         for key, value in row.items()})
    return stream.getvalue()


def render_markdown(report: dict) -> str:
    validate_report(report)
    lines = _BoundedLines(["# ScubaTank assessment\n\nTrust Assurance and Normalization Kit (TANK).", "", f"Run: {_md(report['run_id'])} · Generated: {_md(report['generated_at'])}", "",
                          f"Coverage: **{report['coverage']}**. Counts describe evaluated predicates; there is no overall passing score."])
    if report["synthetic"]:
        lines.extend(["", "**Synthetic demonstration. These findings validate fixture behavior and do not describe a real organization.**"])
    lines.extend(["", "## Proposed remediation", ""])
    if not report["remediation"]:
        lines.append("This run has no evidence-backed remediation actions. Review the Unknown and incomplete results.")
    for action in report["remediation"]:
        lines.extend([f"- **{_md(action['title'])}** — {_md(action['rationale'])}",
                      f"  Findings: {_md(', '.join(action['finding_ids']))}. Supported edges to break: {_md(', '.join(action['breaks_edge_ids']) or 'None established')}.",
                      f"  Owner: {_md(action['owner'] or 'Unassigned')}. Exception: {_md(action['exception'] or 'None recorded')}."])
    lines.extend(["", "## Findings", ""])
    entities = {row["id"]: row for row in report["entities"]}
    edges = {row["id"]: row for row in report["edges"]}
    for finding in report["findings"]:
        if finding["status"] == "NotImplemented":
            continue
        lines.extend([f"### {_md(finding['check_id'])} · {finding['status']}", "", _md(finding["message"]), "",
                      f"Severity: {finding['severity']}; confidence: {finding['confidence']}; coverage: {finding['coverage']}; rule: {_md(finding['rule_version'])}.",
                      f"Finding: {_md(finding['finding_id'])}; cause: {_md(finding['cause_id'])}."])
        for path in finding["paths"]:
            lines.extend(["", f"Path {_md(path['path_id'])}: {_md(path['claim'])}"])
            for edge_id in path["edge_ids"]:
                edge = edges[edge_id]
                lines.append(f"- {_md(entities[edge['source_id']]['label'])} ({_md(edge['source_id'])}) → {_md(edge['type'])} → {_md(entities[edge['target_id']]['label'])} ({_md(edge['target_id'])}); edge {_md(edge_id)}; {_md(edge['semantics'])}.")
            lines.extend(f"- Path limit: {_md(limit)}" for limit in path["limitations"])
        lines.extend(f"- Missing evidence: {_md(item)}" for item in finding["missing_evidence"])
        lines.extend(f"- Limitation: {_md(item)}" for item in finding["limitations"])
        lines.extend(["", "Evidence: " + _md(", ".join(finding["evidence_refs"]) or "None available"), "", "Framework mappings:"])
        for framework in ("nist", "attack"):
            for mapping in finding["mappings"][framework]:
                lines.append(f"- {_md(mapping['id'])} — {_md(mapping['title'])}; {_md(mapping['framework_version'])}; {mapping['status']}. {_md(mapping['rationale'])} Source SHA-256: {_md(mapping['source_digest'])}.")
    if report["counts"]["NotImplemented"]:
        lines.extend(["", f"{report['counts']['NotImplemented']} catalog specifications have no implemented detector and are omitted from the finding list."])
    if report["upstream_findings"]:
        lines.extend(["", "## Upstream assessment context", "", "These producer results retain their original scope. A baseline failure does not establish MFA bypass for a particular identity."])
        for upstream in report["upstream_findings"]:
            lines.append(f"- {_md(upstream['policy_id'])} ({_md(upstream['product'])}): {_md(upstream['result'])}; {_md(upstream['details'])}; source {_md(upstream['source_id'])}; evidence {_md(', '.join(upstream['evidence_refs']))}; annotations {_md(json.dumps(upstream['annotations'], sort_keys=True))}.")
    lines.extend(["", "## Evidence and scope", ""])
    for source in report["sources"]:
        lines.append(f"- {_md(source['source_id'])}: {_md(source['producer'])} {_md(source['producer_version'])}; adapter {_md(source['adapter_version'])}; collected {_md(source['collected_at'])}; coverage {_source_coverage(source)}; scope {_md(json.dumps(source['scope'], sort_keys=True))}; file {_md(source['path'])}; SHA-256 {_md(source['sha256'])}.")
        for key in ("completeness", "collection_errors", "exclusions", "observation_window", "collector_versions"):
            if source.get(key):
                lines.append(f"  {_md(key)}: {_md(json.dumps(source[key], sort_keys=True))}")
    for ref, record in sorted(report["evidence"].items()):
        lines.append(f"- {_md(ref)}: source {_md(record['source_id'])}; JSON pointer {_md(record['pointer'] or '(root)')}; SHA-256 {_md(record['sha256'])}.")
    lines.extend(["", "Assessment limits:"] + [f"- {_md(item)}" for item in report["limitations"]])
    return "\n".join(lines) + "\n"


_STYLE = """
:root{color-scheme:light}*{box-sizing:border-box}
body{margin:8px;background:#f0f0f0;color:#000;font:.8125rem/1.45 Tahoma,Verdana,Arial,sans-serif}
a{color:#0000ee;text-decoration:underline;overflow-wrap:anywhere}a:visited{color:#551a8b}a:hover{color:#000080}:focus-visible{outline:2px dotted #000080;outline-offset:2px}
.skip{position:absolute;left:12px;top:-80px;background:#fff;padding:8px;z-index:5}.skip:focus{top:12px}
header,main,footer{max-width:980px;margin:0 auto;padding:12px;background:#fff;border:1px solid #808080;overflow-wrap:anywhere}main{border-top:0;border-bottom:0}
h1{font:700 1.55em/1.3 Tahoma,Verdana,Arial,sans-serif;color:#203040;margin:8px 0}h2{font:700 1.1em/1.4 Tahoma,Verdana,Arial,sans-serif;background:#e5e5e5;border:1px solid #aaa;padding:4px 6px;margin:14px 0 6px}h3{font-size:1.05em;margin:8px 0 4px}h4{font-size:1em;margin:8px 0 4px}p{margin:4px 0 7px}.eyebrow{font-weight:700;color:#404040}.muted{color:#404040}
.banner{border:1px solid #808080;padding:8px;margin:10px 0}.warning>strong{color:#800000}
nav{border-top:1px solid #808080;padding-top:4px;margin-top:10px}nav a{display:inline-block;padding:4px 0}
table{border-collapse:collapse;width:100%;table-layout:fixed}caption{text-align:left;font-weight:700;margin:0 0 4px}th,td{text-align:left;padding:3px 6px;border:1px solid #aaa;vertical-align:top;overflow-wrap:anywhere}thead{background:#e5e5e5}.properties{margin:8px 0}.properties th{width:7em;background:#f3f3f3}.results th:nth-child(2){width:4rem}.results td:nth-child(2){font-weight:700}.results a{display:inline-block;padding:3px 0}
section{margin-bottom:14px}.action,.source,.finding{margin:6px 0;padding:0 0 8px;border:1px solid #aaa}.action>p,.source>p,.finding>p,.finding>.meta,.finding>ul,.finding>details{margin-left:6px;margin-right:6px}.status{font-weight:700;color:#404040}.finding[data-status=Fail] .status{color:#800000}.meta{margin:6px 0}.meta span{display:inline-block;margin-right:12px}
.controls{margin:8px 0}.controls>div{display:inline-block;vertical-align:top;margin:0 16px 8px 0}.controls label{display:block;font-weight:700;margin-bottom:3px}select,input{font:inherit;min-height:2em;max-width:100%;color:#000;background:#f8f8f8;border:1px solid #888;padding:3px 4px}input{width:22em}.controls p{margin:0}
details{margin:6px 0}summary{cursor:pointer;font-weight:700;min-height:2em;padding:4px 6px;background:#e5e5e5;border:1px solid #aaa}.action>summary,.source>summary,.finding>summary{border:0;border-bottom:1px solid #aaa}summary h3{display:inline;font:inherit;margin:0}code,pre{font:.93em/1.4 'Courier New',Courier,monospace}code{overflow-wrap:anywhere}pre{border:1px solid #aaa;background:#f3f3f3;padding:6px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:400px;overflow:auto}ul,ol{padding-left:24px}li{margin:4px 0}.path-edge{border:1px solid #aaa;padding:6px;margin:6px 0}[hidden]{display:none!important}footer{font-size:.93em;color:#404040}
@media(max-width:600px){body{margin:4px;font-size:1rem}header,main,footer{padding:8px}.controls>div{display:block;margin:0 0 8px}input{width:100%}th,td{padding:4px}}
@media print{body{margin:0;background:#fff}.controls,nav,.skip{display:none}.finding,.action,.source{break-inside:avoid}details{display:block}details>*{display:block}header,main,footer{max-width:none;border:0}a,a:visited{color:inherit}}
"""

_SCRIPT = """
const statusFilter=document.getElementById('status-filter');
const searchInput=document.getElementById('search');
const findings=Array.from(document.querySelectorAll('.finding'));
function applyFilters(){const state=statusFilter.value;const term=searchInput.value.trim().toLocaleLowerCase();let visible=0;for(const finding of findings){finding.hidden=(state!=='all'&&finding.dataset.status!==state)||!finding.dataset.search.toLocaleLowerCase().includes(term);if(!finding.hidden)visible++;}document.getElementById('filter-count').textContent=visible+' of '+findings.length+' findings shown';}
statusFilter.addEventListener('change',applyFilters);searchInput.addEventListener('input',applyFilters);
for(const link of document.querySelectorAll('[data-filter]')){link.addEventListener('click',()=>{statusFilter.value=link.dataset.filter;applyFilters();});}
function revealAnchor(){const target=document.getElementById(decodeURIComponent(location.hash.slice(1)));if(!target)return;for(let node=target;node;node=node.parentElement){if(node.tagName==='DETAILS')node.open=true;}if(target.classList.contains('finding')&&target.hidden){statusFilter.value='all';searchInput.value='';applyFilters();}target.scrollIntoView();}
window.addEventListener('hashchange',revealAnchor);applyFilters();revealAnchor();
"""


def _hash_csp(value: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode("ascii") + "'"


def render_html(report: dict) -> str:
    """Render an offline document. Imported values never become markup or URLs."""
    validate_report(report)
    entities = {row["id"]: row for row in report["entities"]}
    edges = {row["id"]: row for row in report["edges"]}
    sources = {row["source_id"]: row for row in report["sources"]}
    visible = [finding for finding in report["findings"] if finding["status"] != "NotImplemented"][:MAX_HTML_FINDINGS]
    referenced = sorted({ref for finding in visible for ref in finding["evidence_refs"]}
                        | {ref for finding in visible for path in finding["paths"] for ref in path["evidence_refs"]}
                        | {ref for finding in visible for action in finding["remediation"] for ref in action["evidence_refs"]}
                        | {ref for finding in visible for path in finding["paths"] for eid in path["edge_ids"] for ref in edges[eid]["evidence_refs"]}
                        | {ref for upstream in report["upstream_findings"][:500] for ref in upstream["evidence_refs"]})[:MAX_HTML_EVIDENCE]
    ref_set = set(referenced)

    def evidence_links(refs: list[str]) -> str:
        return ", ".join(f'<a href="#{_anchor("evidence", ref)}">{_escape(ref)}</a>' if ref in ref_set else f'<code>{_escape(ref)}</code> (see JSON)' for ref in refs) or "No evidence available"

    def finding_links(ids: list[str]) -> str:
        displayed = {finding["finding_id"] for finding in visible}
        return ", ".join(f'<a href="#{_anchor("finding", identifier)}">{_escape(identifier)}</a>' if identifier in displayed else _escape(identifier) + " (see JSON)" for identifier in ids)

    csp = "default-src 'none'; base-uri 'none'; form-action 'none'; connect-src 'none'; style-src " + _hash_csp(_STYLE) + "; script-src " + _hash_csp(_SCRIPT)
    out = _BoundedLines(['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
           f'<meta http-equiv="Content-Security-Policy" content="{_escape(csp)}"><title>ScubaTank assessment — {_escape(report["run_id"])}</title><style>{_STYLE}</style></head><body>',
           '<a class="skip" href="#main">Skip to report</a><header><div class="eyebrow">ScubaTank · Trust Assurance and Normalization Kit (TANK)</div><h1>Hybrid security assessment</h1>',
           '<p class="muted">Review the authority paths supported by this run, the evidence that is missing, and the changes that would break each supported path.</p>',
           f'<table class="properties"><caption>Report details</caption><tbody><tr><th scope="row">Run</th><td><code>{_escape(report["run_id"])}</code></td></tr><tr><th scope="row">Generated</th><td>{_escape(report["generated_at"])}</td></tr></tbody></table>'])
    if report["synthetic"]:
        out.append('<div class="banner"><strong>Synthetic demonstration</strong><p>These results describe fictional fixtures. They test import and assessment behavior; they do not validate a real tenant, forest, or collection tool deployment.</p></div>')
    out.append(f'<div class="banner{ " warning" if report["coverage"] != "complete" else ""}"><strong>Assessment coverage: {report["coverage"]}</strong><p>Counts describe bounded predicates in the assessed scope. There is no overall passing score. A permission path does not establish exploitation, cloud sign-in, or MFA bypass.</p></div>')
    baseline_link = ' | <a href="#upstream">Imported baseline results</a>' if report["upstream_findings"] else ''
    out.append('<nav aria-label="Report sections"><a href="#actions">Remediation</a> | <a href="#findings">Findings</a>' + baseline_link + ' | <a href="#sources">Sources and coverage</a> | <a href="#evidence">Evidence</a></nav></header><main id="main" tabindex="-1">')
    out.append('<section aria-label="Result counts"><table class="results"><caption>Result counts</caption><thead><tr><th scope="col">Result</th><th scope="col">Count</th><th scope="col">Meaning</th></tr></thead><tbody>')
    titles = {"Fail": "Supported exposures", "Unknown": "Unknown results", "Pass": "Disproved predicates", "ReviewRequired": "Review needed", "Error": "Errors", "NotApplicable": "Not applicable"}
    for state in ("Fail", "Unknown", "Pass", "ReviewRequired", "Error", "NotApplicable"):
        out.append(f'<tr><th scope="row"><a href="#findings" data-filter="{state}">{state}</a></th><td>{report["counts"][state]}</td><td>{titles[state]}</td></tr>')
    out.append('</tbody></table></section><section id="actions"><h2>Proposed remediation</h2>')
    if not report["remediation"]:
        out.append('<p>This run has no evidence-backed remediation actions. Review the Unknown and incomplete results.</p>')
    for action in report["remediation"][:100]:
        out.extend([f'<details class="action" open><summary><h3>{_escape(action["title"])}</h3></summary><p>{_escape(action["rationale"])}</p>',
                    f'<p>Supported edges to break: <code>{_escape(", ".join(action["breaks_edge_ids"]) or "None established")}</code>.</p>',
                    f'<p>Affected objects: {_escape(", ".join(entities[identifier]["label"] + " (" + identifier + ")" for identifier in action["affected_entity_ids"]))}</p>',
                    f'<p>Findings: {finding_links(action["finding_ids"])}</p><p>Evidence: {evidence_links(action["evidence_refs"])}</p>',
                    f'<p class="muted">Owner: {_escape(action["owner"] or "Unassigned")} · Exception: {_escape(action["exception"] or "None recorded")}</p></details>'])
    if len(report["remediation"]) > 100:
        out.append('<p>Additional remediation actions are preserved in the JSON report.</p>')
    out.append('</section><section id="findings"><h2>Findings</h2><div class="controls"><div><label for="status-filter">Result</label><select id="status-filter"><option value="all">All results</option>')
    out.extend(f'<option value="{state}">{state}</option>' for state in STATUSES if state != "NotImplemented")
    out.append('</select></div><div><label for="search">Search findings or objects</label><input id="search" type="search" placeholder="Check ID, message, or object"></div><p id="filter-count" class="muted" aria-live="polite"></p></div><noscript><p>All findings are visible. Search and filters require JavaScript; evidence panels work without it.</p></noscript>')
    if report["counts"]["NotImplemented"]:
        count = report["counts"]["NotImplemented"]
        out.append(f'<p class="muted">{count} {"specification is" if count == 1 else "specifications are"} not implemented. No result is inferred from those specifications.</p>')
    if len(visible) < sum(report["counts"][state] for state in STATUSES if state != "NotImplemented"):
        out.append(f'<p class="banner">This bounded HTML view shows the first {MAX_HTML_FINDINGS} findings. The JSON and CSV preserve every finding.</p>')
    for finding in visible:
        search = " ".join([finding["check_id"], finding["message"]] + [entities[identifier]["label"] + " " + identifier for identifier in finding["affected_entity_ids"]])[:10000]
        out.extend([f'<details class="finding" id="{_anchor("finding", finding["finding_id"])}" data-status="{finding["status"]}" data-search="{_escape(search)}" open>',
                    f'<summary><h3>{_escape(finding["check_id"])}: <span class="status">{finding["status"]}</span></h3></summary><p>{_escape(finding["message"])}</p>',
                    f'<div class="meta"><span>Severity: <strong>{finding["severity"]}</strong></span><span>Confidence: <strong>{finding["confidence"]}</strong></span><span>Coverage: <strong>{finding["coverage"]}</strong></span><span>Rule: {_escape(finding["rule_version"])}</span></div>'])
        if finding["missing_evidence"]:
            out.append('<div class="banner warning"><strong>Evidence needed</strong><ul>' + "".join(f'<li>{_escape(item)}</li>' for item in finding["missing_evidence"]) + '</ul></div>')
        if finding["limitations"]:
            out.append('<ul>' + "".join(f'<li>{_escape(item)}</li>' for item in finding["limitations"]) + '</ul>')
        out.append(f'<details><summary>Objects, paths, and evidence · {len(finding["paths"])} paths</summary><p>Finding <code>{_escape(finding["finding_id"])}</code> · Shared cause <code>{_escape(finding["cause_id"])}</code></p>')
        for identifier in finding["affected_entity_ids"]:
            entity = entities[identifier]
            out.append(f'<p><strong>{_escape(entity["label"])}</strong> · {_escape(entity["kind"])} · <code>{_escape(identifier)}</code></p>')
        for link in report["identity_links"]:
            if link["ad_entity_id"] in finding["affected_entity_ids"] or link["cloud_entity_id"] in finding["affected_entity_ids"]:
                out.append(f'<p>Identity link <code>{_escape(link["id"])}</code>: {_escape(link["ad_entity_id"])} ↔ {_escape(link["cloud_entity_id"])}<br>Method: {_escape(link["method"])} · Conflict: {str(link["conflict"]).lower()}<br>Evidence: {evidence_links(link["evidence_refs"])}</p>')
        for path in finding["paths"]:
            out.append(f'<h4>Path {_escape(path["path_id"])}</h4><p>{_escape(path["claim"])}</p>')
            for edge_id in path["edge_ids"]:
                edge = edges[edge_id]
                out.append(f'<div class="path-edge"><strong>{_escape(entities[edge["source_id"]]["label"])}</strong> → {_escape(edge["type"])} → <strong>{_escape(entities[edge["target_id"]]["label"])}</strong><br><code>{_escape(edge_id)}</code> · {_escape(edge["semantics"])} · {_escape(edge.get("semantics_version", "Version unavailable"))}<br>Evidence: {evidence_links(edge["evidence_refs"])}</div>')
            out.append('<p>Path evidence: ' + evidence_links(path["evidence_refs"]) + '</p>')
            out.extend(f'<p class="muted">Path limit: {_escape(limit)}</p>' for limit in path["limitations"])
        out.append('<p>Finding evidence: ' + evidence_links(finding["evidence_refs"]) + '</p></details>')
        out.append('<details><summary>Framework mappings and source versions</summary><p>Mappings are proposed project judgments. They do not establish control compliance, certification, or ATT&amp;CK detection coverage.</p>')
        for framework in ("nist", "attack"):
            for mapping in finding["mappings"][framework]:
                out.append(f'<p><strong>{_escape(mapping["id"])} — {_escape(mapping["title"])}</strong><br>{_escape(mapping["framework_version"])} · {_escape(mapping["status"])}<br>{_escape(mapping["rationale"])}<br>Source SHA-256: <code>{_escape(mapping["source_digest"])}</code></p>')
        out.append('</details></details>')
    out.append('</section>')
    if report["upstream_findings"]:
        out.append('<section id="upstream"><h2>Imported baseline results</h2><p>These producer results retain their original scope, result and criticality. A baseline failure does not establish MFA bypass for a particular identity.</p>')
        for upstream in report["upstream_findings"][:500]:
            out.append(f'<details><summary>{_escape(upstream["product"])} · Policy ID: {_escape(upstream["policy_id"])} · Result: {_escape(upstream["result"])}</summary><p>Criticality: {_escape(upstream["criticality"])} · Source: {_escape(upstream["source_id"])}</p><p>{_escape(upstream["details"])}</p><p>Evidence: {evidence_links(upstream["evidence_refs"])}</p><pre>{_escape(json.dumps(upstream["annotations"], indent=2, sort_keys=True))}</pre></details>')
        if len(report["upstream_findings"]) > 500:
            out.append('<p>Additional upstream findings are preserved in JSON.</p>')
        out.append('</section>')
    out.append('<section id="sources"><h2>Sources and coverage</h2><p>Source files supply the collection times and scopes. Generating a new report does not refresh those observations.</p>')
    for source in report["sources"]:
        out.append(f'<details class="source" open><summary><h3>{_escape(source["producer"])} {_escape(source["producer_version"])}</h3></summary><p>Source <code>{_escape(source["source_id"])}</code> · Adapter {_escape(source["adapter_version"])} · Coverage <strong>{_source_coverage(source)}</strong></p><p>Collected {_escape(source["collected_at"])}</p><p>Scope <code>{_escape(json.dumps(source["scope"], sort_keys=True))}</code></p><p>File <code>{_escape(source["path"])}</code><br>SHA-256 <code>{_escape(source["sha256"])}</code></p>')
        for key in ("completeness", "collection_errors", "exclusions", "observation_window", "collector_versions"):
            if source.get(key):
                out.append(f'<p>{_escape(key)}: <code>{_escape(json.dumps(source[key], sort_keys=True))}</code></p>')
        out.append('</details>')
    out.append('<details><summary>Run pins and scope</summary><pre>' + _escape(json.dumps({key: report[key] for key in ("scope", "framework_versions", "adapter_versions", "source_versions")}, indent=2, sort_keys=True)) + '</pre></details>')
    out.append('<ul>' + "".join(f'<li>{_escape(item)}</li>' for item in report["limitations"]) + '</ul></section><section id="evidence"><h2>Evidence records</h2><p>These local references identify the retained source record and source file hash. No link fetches the source or runs its contents.</p>')
    for ref in referenced:
        record = report["evidence"][ref]
        source = sources[record["source_id"]]
        out.append(f'<details id="{_anchor("evidence", ref)}"><summary>{_escape(ref)}</summary><p>Producer {_escape(source["producer"])} {_escape(source["producer_version"])} · Collected {_escape(source["collected_at"])}</p><p>JSON pointer <code>{_escape(record["pointer"] or "(root)")}</code><br>Source SHA-256 <code>{_escape(record["sha256"])}</code></p>')
        if "value" in record:
            raw = json.dumps(record["value"], sort_keys=True, indent=2, ensure_ascii=False)
            out.append('<pre>' + _escape(raw[:MAX_RAW_PREVIEW]) + '</pre>')
            if len(raw) > MAX_RAW_PREVIEW:
                out.append('<p>Preview shortened. The JSON report retains the complete observation.</p>')
        out.append('</details>')
    out.append('</section></main><footer>Read-only assessment · Review proposed changes before operating on a live environment. Exceptions do not change the technical finding state.</footer><script>' + _SCRIPT + '</script></body></html>')
    return "\n".join(out)


def write_reports(report: dict, output_dir: str | Path) -> dict[str, Path]:
    """Write fixed local filenames; imported values never select output paths."""
    validate_report(report)
    content = {"json": ("report.json", json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"),
               "html": ("report.html", render_html(report)), "csv": ("findings.csv", render_csv(report)),
               "markdown": ("report.md", render_markdown(report))}
    if len(content["json"][1].encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("Formatted JSON report exceeds the 32 MiB output limit; reduce the assessment scope")
    directory = local_path(output_dir).resolve()
    local_path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    result = {}
    for kind, (name, text) in content.items():
        path = directory / name
        if path.is_symlink() or path.resolve().parent != directory:
            raise ValueError("Report output cannot follow a symbolic link outside its directory")
        path.write_text(text, encoding="utf-8", newline="")
        result[kind] = path
    return result
