# Development handoff

## Objective

Develop hybrid correlations from established tool outputs. Validate the selected imports, identity joins, rule prerequisites and reports before expanding beyond the six implemented rules. Collection stays with the upstream tools.

## Current state

The offline 0.2.0 workflow implements the six correlations selected below, with pinned ScubaGear and processed BloodHound imports, strict evidence/report schemas, identity-link validation, OPA predicates and local HTML/JSON/CSV/Markdown reports. The demonstration covers six exposure paths, a blocked reset path and incomplete cases. Validation uses synthetic exports and a licensed public ScubaGear contract excerpt. Live environments and collector execution have not been validated.

PowerShell now exposes plan, import, validate, assess, report and demo workflows. The catalog keeps all 132 original specifications; 126 remain unimplemented and do not appear as assessment checks. Start with `scripts/Demo.ps1`, [import formats](import-formats.md), [report contract](report-contract.md) and [validation](validation.md). The milestones below record the design and acceptance boundaries used for this release.

## Review assignments

Use stronger reasoning for adapters, identity matching, effective authorization, and mappings. Use normal/fast execution for mechanical documentation and fixture work. Where the runtime supports parallel agents, assign up to four bounded reviewers: upstream adapters and licensing; identity/graph semantics; framework mappings; tests and reporting safety. Reviewers remain read-only until their findings are reconciled. Assign non-overlapping implementation files afterward.

Repository edits and synthetic tests are allowed. Explicit bootstrap installs the reviewed pinned offline dependencies. Assessment commands never install anything. Live collection, production changes, package publication, deployment and new broad collectors require separate authorization. Start with targeted file discovery and keep real source exports outside Git.

## Milestone 1: versioned evidence imports

Implement versioned adapters for a pinned ScubaGear JSON contract and one supported SharpHound/AzureHound/BloodHound evidence path. Prefer processed BloodHound relationships when the rule requires derived permissions. Document exactly which evidence each source supplies. Do not substitute a homegrown effective-ACL engine.

Create synthetic or approved sanitized producer-shaped fixtures. Preserve upstream IDs, versions, timestamps, scope, exclusions, errors, and raw evidence references. Support separately collected AD and cloud bundles. Define and validate the evidence manifest before building joins. Reject unknown schema versions and malformed/truncated input, and cap file sizes, JSON depth, ZIP expansion, and record counts. XML imports disable DTDs/external entities. Imports are offline and cannot execute report contents.

Acceptance: known version fixtures import deterministically; omitted raw evidence stays unknown; unknown versions fail clearly; same names in different tenants do not merge; duplicate/conflicting records are surfaced; no authentication or network activity happens during import. Add an exact source-field-to-normalized-field map and tests for every adapter.

## Milestone 2: six hybrid correlations

Build these first: `ST.CORR.IDENTITY.001`, `ST.CORR.IDENTITY.003`, `ST.CORR.SYNC.001`, `ST.CORR.GROUP.001`, `ST.CORR.GROUP.006`, and `ST.CORR.APPLICATION.001`.

Use OPA/Rego for the final bounded predicates. Consume established relationship semantics rather than deriving every right again. For any unavailable prerequisite, return Unknown and identify the missing provider/field. GROUP.006 must not become a homemade complete Conditional Access simulator; accept supported scenario evidence or leave the outcome unknown.

For every rule, test the positive conjunction; removal of each prerequisite; its catalog limiting case; stale/conflicting evidence; wrong forest/tenant; denied or unsupported relationships; and a changed upstream version. Check IDs and mappings against pinned official framework data. Add exact ATT&CK technique titles, source digests, per-technique rationale, and independent mapping review before calling the rule validated.

Acceptance: all six rules have reproducible synthetic tests and independent semantics review. No live-environment validation is implied. An unimplemented rule returns NotImplemented and is excluded from pass-rate calculations.

## Milestone 3: reports and remediation

Produce a self-contained local HTML report, JSON, and formula-safe CSV. Lead with the few remediation actions that break evidenced paths. Show affected objects, path edges, upstream findings, confidence, coverage, source times, limitations, and owner/exception fields. A missing collector should be visible immediately, not hidden in a log. Escape all imported display text and use no remote assets.

Acceptance: end-to-end fixtures cover an evidenced exposure path, a blocked path, and incomplete evidence. Every reported claim can be traced to input records. Deduplication preserves affected objects. Repeat runs are deterministic apart from explicit run metadata. Browser smoke tests check links, filters, evidence expansion, and offline operation.

## Later milestones

Add opt-in runners for approved existing tools only after provider versions, artifact digests, permissions, collection profiles, SOC coordination, cancellation, and output protections are tested. Then add federation, certificates, cloud-to-on-premises management, visibility, and recovery in small reviewed groups. Investigate gaps through `docs/collection-gaps.md`; obtain approval before new live collection. Owner and recovery attestations remain dated assisted evidence; they cannot independently establish machine-verified results.

## Delivery record

Report changed files, commands run, tests passed/failed/not run, implemented check IDs, provider versions, remaining unknowns, and the next acceptance gate. Update `docs/validation.md`. Commit the intended work and push only to the authorized branch. Do not force-push or label the suite production-ready.
