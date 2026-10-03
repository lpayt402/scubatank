# Finding and report contract

ScubaTank reports use schema version `0.2.0`. [The finding schema](../schemas/finding-v2.schema.json) describes one bounded result. [The report schema](../schemas/report.schema.json) wraps those results with run metadata, imported objects, relationship semantics, source coverage, retained observations, and remediation actions. The report writer validates both the schema and cross-references before creating files.

The original [`0.1.0` finding schema](../schemas/finding.schema.json) remains available for catalog-era consumers. It accepts the original shape, including Unknown results. A legacy finding cannot be inserted into a `0.2.0` report by changing its version string: run, rule, adapter, source, and framework provenance must be supplied. Tests exercise both contracts; there is no automatic migration that invents missing metadata.

## Metadata and evidence

Every finding carries `run_id`, `rule_version`, `framework_versions`, `adapter_versions`, and `source_versions`. The version maps must agree with the report envelope. `source_versions` uses source IDs as keys, with each source's producer version as the value. Report generation time is separate from source collection time.

Each evidence reference has the shape `source-id#/json/pointer`. The report's `evidence` dictionary resolves it to `source_id`, `pointer`, and `sha256`, with the retained observation in `value` when supplied. The digest identifies the exact source file; it is not a separately hashed record or a guarantee that the source observation is true. JSON pointers select records inside that file. Sources retain producer and adapter versions, producer schema, source path, scope, completeness, collection errors, and exclusions. These paths are display text; reports do not open or execute them.

Optional `observation_window` records declared `oldest_at` and `newest_at` collection times, separately from the graph query or export timestamp. Optional `collector_versions` retains the producer-declared collector version map. These declarations do not establish native collector export conformance or show that a collector ran during this assessment. Reports display them unchanged; the evaluator decides whether the underlying observations are current enough for a rule.

Entities retain their stable IDs and boundaries. Paths retain their own IDs, objects, typed upstream relationships, evidence references, claims, and limitations. A report rejects a missing source, dangling object or edge, duplicate identity ID, conflicting source digest, or remediation edge outside its finding's paths. Identity and freshness judgments belong to the evaluator; the report preserves its Unknown state and stated evidence gaps.

`Fail` means the stated exposure predicate is supported. `Pass` requires complete evidence for that predicate. `Unknown`, `ReviewRequired`, `Error`, and `NotApplicable` remain visible. An unimplemented specification is counted separately and omitted from the human finding list. Partial scope does not produce a passing percentage or an overall security score.

## Framework mappings and validation

NIST and ATT&CK entries carry the exact framework title, pinned framework version, source SHA-256, rationale, and mapping status. `project-proposed` and `independently-reviewed` describe the mapping judgment. They do not mean the organization passed a control or that ScubaTank provides ATT&CK detection coverage. A mapping's version must match its framework pin in the envelope.

The optional finding `validation_state` records `synthetic-tested`, `not-validated`, or `live-validated`. The demonstration uses synthetic validation. A valid schema, verified source hash, or reviewed mapping does not establish live-environment validation.

## Remediation and exceptions

A finding's remediation action identifies the operation, rationale, supported edges it would break, affected objects, evidence, owner, and any recorded exception. Actions sharing an `action_id` are grouped in the report only when their title, rationale, owner, and exception agree. Grouping unions all finding, cause, path, edge, object, and evidence references; it does not delete findings or paths. Conflicting action text produces an error.

Only Fail and ReviewRequired findings contribute to the short remediation list. An Unknown finding's evidence needs remain visible in its finding section. Remediation is advice for review, never an automatic change. An exception does not change the technical result to Pass. Owner and exception fields are plain text or null; this version does not implement a risk-acceptance approval workflow.

## Local output and display safety

`write_reports(report, output_dir)` creates four fixed filenames:

| File | Purpose |
| --- | --- |
| `report.json` | Complete versioned report and retained observations |
| `report.html` | Self-contained local report with state filters, search, path panels, and evidence expansion |
| `findings.csv` | Spreadsheet-view export with result and provenance columns |
| `report.md` | Findings, remediation, framework mappings, and source ledger |

Run details and result counts use compact tables with scoped headers. Each state link selects the finding filter. The page uses Tahoma-style system fonts, grey section headings, square borders, underlined links and native controls. Remediation actions, findings and source records can be collapsed; they start open so evidence gaps and limitations are visible. Finding links reopen their target and clear a filter that would hide it. Relative font sizes support enlarged text, and the layout reflows at narrow widths. The appearance follows older Windows administration reports; this does not establish Internet Explorer compatibility or require Java.

Imported baseline results have a section link when present. Each expandable record identifies its product, policy ID, original result, criticality, source, details, annotations and evidence. This uses the product and result context described in [ScubaGear 1.8.0's report guide](https://github.com/cisagov/ScubaGear/blob/2d01e711fcb74f615e1fbea6d06556a8dcbff11f/docs/execution/reports.md). These imported results remain separate from ScubaTank's authority-path findings. ScubaTank does not implement ScubaGear's live collection, product selection, YAML configuration interface or ActionPlan workflow, and this report does not imply CISA affiliation or endorsement.

The HTML uses no remote assets or fetches. Imported text is escaped with [Python's `html.escape`](https://docs.python.org/3/library/html.html#html.escape); object IDs become hashed local anchors. A Content Security Policy permits only the report's hashed script and stylesheet. Native disclosure panels keep evidence available without JavaScript. Filters have visible labels, keyboard focus, and a live result count; disclosure behavior follows [W3C's keyboard guidance](https://www.w3.org/WAI/ARIA/apg/patterns/disclosure/). These are implemented accessibility measures, not a claim of a complete WCAG audit.

CSV cells are quoted. Formula-leading text, including whitespace and full-width variants, receives a leading apostrophe. This changes display data, so JSON remains the machine-readable contract. Spreadsheet applications can change escaping when a CSV is edited and resaved; there is no universal defense across every application. See [OWASP's CSV injection guidance](https://community.owasp.org/attacks/CSV_Injection). Treat the generated file as a viewing export and use JSON for downstream processing.

The report writer bounds JSON and CSV output to 32 MiB, HTML and Markdown output to 8 MiB, nesting to 40 levels, and individual strings to 20,000 characters. Rendering stops with an explicit error if repeated object labels would expand a small input beyond the output limit; reduce the assessment scope in that case. The HTML shows at most 500 evaluated findings, 100 grouped actions, 500 upstream findings, and 5,000 referenced evidence records. Evidence previews stop at 4,096 characters. Any shortened view says so; JSON and CSV preserve the complete accepted report. File contents do not select output paths. UNC and URI output paths are rejected before filesystem resolution, and existing symbolic links cannot redirect a report file outside the chosen directory. Imported observations remain local and can contain sensitive organizational configuration; normal output handling rules still apply.

## Validation

Run report contract and safety tests with:

```text
python -m unittest discover -s tests -p test_reporting.py -v
```

The committed tests cover legacy compatibility, required metadata, result semantics, source and framework pin conflicts, dangling references, duplicate IDs, action grouping, malformed provenance, untrusted HTML/Markdown, CSV formulas, bounded previews, and deterministic output. Browser smoke validation checks the actual generated HTML offline, including filters, search, fragment targets, evidence expansion, viewport layout, and absence of outbound requests. For the table layout it also checks skip-link focus, table headers, text contrast, 320-pixel reflow and 200% text resizing. Finding sections are checked for keyboard collapse and reopening through filtered fragment links. The contrast and reflow checks follow [W3C's contrast guidance](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html) and [reflow guidance](https://www.w3.org/WAI/WCAG22/Understanding/reflow.html). Native finding and evidence disclosures are checked with JavaScript disabled.

When Playwright and Chromium are already installed, run the separate browser check:

```text
python tests/reporting_browser_smoke.py
python tests/reporting_browser_smoke.py --report .build/demo/report.html
```

This opt-in command does not install packages or browsers. It writes desktop and mobile screenshots and a browser/version/check ledger under `.build/reporting-smoke/`. The default command generates three fictional reporting fixtures; it is a report interaction test, not a producer-format conformance test. The `--report` form checks an existing report without replacing it.
