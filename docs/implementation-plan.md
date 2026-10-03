# Offline assessment release plan

This plan records the six-rule import-to-report release. The supplied synthetic demonstration runs without credentials. Live collection remains a separate operation.

## Design decisions

Use processed BloodHound relationships rather than deriving effective ACLs from collector records. Keep ScubaGear findings as upstream posture evidence; tenant-wide results do not establish a user's effective authentication policy. Supplement missing operational context with explicit dated evidence records. An attestation retains its provenance and is never represented as collector output.

Keep the original 0.1.0 schemas for compatibility. Add separate strict schemas for imported evidence and 0.2.0 findings/reports, including run, rule, framework, adapter and producer versions. Unknown versions fail before assessment. Identity links require scoped stable IDs and evidence; display labels are never join keys.

Python handles bounded file validation, identity joins, typed graph paths and report packaging. Pinned OPA evaluates the final six rule predicates. PowerShell provides Windows operator commands. No assessment command installs a dependency or contacts a tenant. Explicit bootstrap obtains pinned, hash-verified dependencies for the offline workflow.

## Work and acceptance

- [x] Importers: pin official ScubaGear and BloodHound CE contracts; document field maps, license review and digests. Preserve source observations, references, collection errors, exclusions and scope. Test malformed inputs, traversal, hash/ref failures, duplicates, identity conflicts, size/depth limits and unsupported versions.
- [x] Rules: implement IDENTITY.001, IDENTITY.003, SYNC.001, GROUP.001, GROUP.006 and APPLICATION.001 with evidence-linked joins. Test each positive conjunction, missing prerequisite, limiting case, stale/conflicting source, wrong boundary and unsupported relationship/version. Missing authority or scenario evidence is Unknown. Password reset is not MFA bypass; an exclusion requires combined effective-policy scenario evidence.
- [x] Reports: generate local HTML, JSON, Markdown and formula-safe CSV. Preserve paths and affected identities when grouping remediation. Include original posture results separately and label synthetic evidence. Verify schema compatibility, traceability, escaping, filter/evidence interaction and offline browser behavior.
- [x] Workflow: expose plan, import, validate, assess, report and a one-command demonstration. Verify Python and both available Windows PowerShell editions, pin dependency artifacts, investigate the actual hosted CI diagnostic, and run the full equivalent local checks if hosting remains blocked.
- [x] Delivery: review the integrated semantics, update current-state documentation, commit only intended files on main, check remote head before a normal push, and verify the exact pushed head and CI outcome. Include report examples and operational requirements without a production-validation claim.

## Research notes

The handoff defines the six-rule acceptance gate. Its architecture separates source facts, identity joins and final OPA predicates. Sources are pinned to publisher release and source artifacts. A saved processed BloodHound graph can supply supported relationships without requiring ScubaTank to run a privileged collector or install a graph database.

The two alternatives considered were importing raw ACL exports and launching collectors by default. Raw ACL parsing would require a new permission engine, while default collection would exceed this offline milestone's operational authorization. The chosen file boundary permits later adapters without changing a historical report's schema or meaning.
