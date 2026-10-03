# Architecture

scuba TANK (trust assurance and normalization kit) imports saved evidence, normalizes identities and relationships, evaluates bounded rules and produces local reports.

## Processing stages

```text
Existing authorized exports / explicitly approved tool runs
  ScubaGear | SharpHound + AzureHound | BloodHound | Microsoft tooling
                            |
                 Versioned input adapters
                            |
          Evidence bundle + source coverage ledger
                            |
      Stable identity links + typed upstream relationships
                            |
             Bounded hybrid correlation rules
                            |
       Findings + control mappings + remediation evidence
```

Collection and inference are separate operations. Operators can collect AD and cloud data with different accounts on different machines. ScubaTank should never require a single account to hold all collection permissions. Offline analysis makes no outbound requests.

## Inputs and adapters

Every adapter declares accepted producer versions, schema versions, required fields, optional fields, source identifiers, and known omissions. It either imports a known shape or reports UnsupportedVersion/InvalidInput. It never guesses a schema from an HTML page title.

The ScubaGear adapter preserves `MetaData`, `Results`, `Raw`, annotations, original policy IDs and version suffixes, tool version, report UUID, and product coverage. `Raw` may be absent or incomplete. A CSV report is not equivalent to the full JSON export. `ScubaGearResultsBaselineSchema.json` is a baseline-analyzer schema, not the results-file contract; use the upstream output documentation instead. See `SCUBA-SCHEMA` and `SCUBA-MAPPINGS` in the source registry.

The implemented graph route accepts a processed BloodHound response. Raw SharpHound output requires separate processing to derive those relationships. Preserve collector and graph-engine versions. Do not recreate access-control or AD CS edge derivation from scratch under a generic `Controls` edge.

Adapters attach provenance to facts. They do not decide whether an organization passes a security control.

## Identity and relationship model

An AD entity is namespaced by forest plus object GUID/SID. A cloud entity is namespaced by tenant plus object ID. Devices, service principals, applications, and users remain distinct types. Preserve source-anchor configuration rather than assuming objectGUID is always the anchor. A proposed hard/soft match is not an established synchronized identity.

Identity links record the matching method, source records, confidence, collection times, and conflicts. Contradictory identifiers block the affected correlation. Labels are for display, not joining.

Relationships have type, direction, source and destination IDs, source-tool semantics, prerequisites, and evidence. Distinguish observed memberships, effective permissions, asserted paths, configuration hypotheses, and operator attestations. Active and eligible roles are different. App-only and delegated permissions are different. A management relationship is not automatically network reachability or privileged execution.

Trust is directional. Group nesting only propagates where the relevant directory and target service support it. A linked GPO is not resultant policy. A CA in AD is not automatically trusted by Entra certificate authentication.

## Policy engine

Use OPA/Rego for new hybrid predicates rather than inventing a policy language. Compute supported graph relationships with established graph tooling, then give bounded, normalized facts to OPA. Do not put unbounded forest traversal into Rego or PowerShell.

Each rule states applicability, the conjunction that establishes exposure, required evidence, exceptions, limiting cases, expected secure state, remediation, and proposed mappings. New rules receive stable `ST.CORR.*` or `ST.POST.*` IDs. Do not overload CISA's `MS.*` identifiers.

A SCuBA finding is linked only when its subject and scenario actually overlap the path. For Conditional Access, preserve policy state, include/exclude scope, authentication strength, resources, and other applicable policies. A tenant-wide failure is context, not automatic proof a specific user can bypass MFA. Preserve accepted upstream exceptions without hiding the associated exposure.

## Result semantics

`Fail`: the rule's exposure predicate is positively established. `Pass`: the specific applicable predicate is disproved with complete required coverage, not a claim the environment is safe. `Unknown`: required evidence is missing, stale, conflicting, or unsupported. `NotApplicable`: feature absence or exclusion from scope is established. `Error`: collection, parsing, or evaluation failed. `NotImplemented`: no validated detector exists. `ReviewRequired`: an ownership, exception, or other human decision is unresolved.

A verified example path may be reported even if other parts of the environment were not assessed, but the report must retain incomplete overall coverage. Never award an overall passing score from a partial scan. Accepted risk is a separate disposition with an owner, justification, expiry, and evidence; it does not change the technical result to Pass.

## Reports and run comparison

The workflow writes local, self-contained HTML with evidence panels and grouped remediation, plus JSON, CSV and Markdown. Labels and imported text are escaped; formula-leading CSV cells are neutralized. Keep raw secrets out of the inputs and outputs. Reports require no external CDNs, trackers, uploaded graphs, or AI summaries.

Use separate severity, evidence confidence, and collection coverage fields. Avoid a made-up numerical risk score. Deduplicate shared causes while preserving every affected path and source finding. Compare runs only across compatible schemas, scopes, identities, tool/rule versions, and evidence windows; otherwise label the difference Unknown rather than Fixed.

PowerShell is the operator interface. ScubaGear may require its own supported Windows PowerShell process; a PowerShell 7 orchestrator does not make all upstream collectors cross-platform. Exchange data between processes through versioned files, not shared module state. No mandatory graph database is needed just to inspect the catalog; richer graph analysis can depend on an operator-managed BloodHound instance.
