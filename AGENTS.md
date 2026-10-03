# Working on ScubaTank

Read `README.md`, `docs/HANDOFF.md`, `docs/tooling.md`, and `docs/architecture.md`. Work on the next bounded milestone, not the entire roadmap at once.

## Reuse before writing

Established tools own collection and their native analysis. ScubaGear owns SCuBA assessment. SharpHound/AzureHound own their supported collection. BloodHound owns its supported graph semantics. Microsoft tooling supplies Windows baseline and resultant-policy evidence. ScubaTank owns the cross-source joins, correlation, evidence handling, and reporting.

Before adding custom collection, record the missing evidence field, tools and versions evaluated, why they cannot supply it, the narrow supported API/export proposed, required access, operational impact, and a validation oracle in `docs/collection-gaps.md`. Obtain approval before implementing a new live collector. Do not silently fall back to a custom scanner because a dependency is missing or blocked.

## Evidence and safety

- Missing evidence is Unknown, not Pass. An unimplemented detector is NotImplemented. Absence of a feature is NotApplicable only when established within the assessed scope.
- Preserve upstream results, tool versions, collection scope, errors, timestamps, exclusions, annotations, and evidence pointers. Do not reinterpret an upstream pass as proof of effective security everywhere.
- Never join users on display name, UPN, or email alone. Namespace stable IDs by forest/tenant and record the match method and conflicts.
- Not every graph edge is traversable. Respect upstream semantics, supported versions, trust direction, group scope, deny rights, inheritance, authentication mode, and effective policy.
- A path or misconfiguration is not proof of exploitation. Never collect passwords, hashes, private keys, managed-password attributes, or bearer tokens as evidence.
- Live targets require explicit authorization. No production writes, exploit tests, certificate requests, automatic remediation, endpoint-protection bypass, or broad forest/host scans.
- Imported files are untrusted data. No execution or arbitrary URL fetching from file contents. Keep raw assessment data out of Git and test only with synthetic or approved sanitized fixtures.
- ScubaTank's mappings are proposed project judgments. Do not call them official mappings, full control assessments, certification, or ATT&CK detection coverage.

## Execution and review

Use stronger reasoning for authorization and correlation semantics. Use bounded parallel reviewers for adapters, identity/graph correctness, mappings, and tests when available. Reviewers remain read-only until implementation is assigned; divide implementation files to avoid overlapping edits. The coordinating agent reconciles findings and owns integration.

Start with targeted discovery and a short plan. Run tests before and after changes. Write positive, negative, missing-evidence, stale-evidence, wrong-boundary, and upstream-version tests. A catalog test is not a detector test. Do not claim a command ran unless it did.

Stop at the selected milestone's acceptance gate, after three failed correction cycles, or at a concrete blocker. Record the blocker and next action. Repository edits and synthetic tests are permitted for an assigned milestone; live collection, package publication, deployment, broad dependency changes, and production changes need separate approval. Commit intended files only. Do not force-push.

Write like an administrator explaining a problem to another administrator. State what was found, why it matters, the evidence, and the fix. Avoid promotional claims, fabricated certainty, fake customer stories, and decorative complexity.
