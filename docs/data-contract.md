# Evidence and finding contracts

The original `evidence-bundle.schema.json` and `finding.schema.json` remain 0.1.0 design contracts for historical compatibility. The implemented importer uses `import-manifest.schema.json` and `assessment-evidence.schema.json` (1.0.0); the implemented findings and reports use `finding-v2.schema.json` and `report.schema.json` (0.2.0). Every finding carries run, rule, framework, adapter and source versions. [Report contract](report-contract.md) describes the envelope. Legacy design records are validated separately and are not silently upgraded into assessed findings.

Structural validation uses a maintained JSON Schema implementation. After schema validation, the importer enforces constraints that JSON Schema alone cannot establish: unique source/entity/fact IDs; resolved evidence pointers; matching file hashes; confined file paths; approved producer/schema versions; consistent source boundaries; valid observation windows; and supported relationship types and directions.

Every source records producer version, producer schema, collection time, boundaries, completeness, file digest, and a local relative path. The graph route also needs original observation windows and declared collector versions. Assessment reconstructs the complete normalized bundle from the saved manifest and files before evaluating a reliable decision. The path stays under the approved local evidence root; imports reject traversal, external symlinks, UNC paths and URIs. Hashes identify the imported bytes, not the truth or authenticity of the producer's claims.

Use evidence references such as `source-id#/documented/json/pointer`. Preserve original files in access-controlled storage. The bundle retains normalized records and original source observations for traceability. Inputs must be credential-free: known secret-bearing keys are rejected, but free text is not a comprehensive secret scan. A redacted export must retain a documented stable pseudonymization scheme or its cross-source joins become Unknown.

Entities have typed, boundary-scoped identifiers. Relationships distinguish observed facts, upstream-derived semantics, operator attestations, and candidate paths. Candidate edges do not become traversable merely because they are in a graph. A complete relationship needs its upstream semantics/version, prerequisites, and source records.

Facts state a subject, predicate, value, and source references. False, null, absent, failed collection, and an unsupported property are different conditions. Do not convert them all to false. Record scope and failures even when a producer returns an empty list.

A finding separates technical result, severity, confidence, coverage, missing evidence, and mappings. The schema rejects a Fail without evidence/affected objects, an Unknown without a stated gap, and a Pass with incomplete coverage or missing prerequisites. More detailed semantic checks are still required; the schema cannot tell whether a purported permission is effective or whether MFA applies.

For future run comparison, key findings by stable rule/version and affected identities, not display labels. Preserve original run, framework, rule, adapter, and producer versions. A vanished source or reduced collection scope is not a fixed vulnerability.
