# Structural schema checks

The historical structural assertions below are now committed regression tests in `tests/test_schema_contracts.py`. Importer and reporting tests also validate their strict versioned schemas and reject malformed references, unresolved endpoints, changed versions and missing report metadata. Assessment adds semantic checks and reconstructs normalized records from original inputs. Schema validation alone remains insufficient to establish authority.

On October 2, 2026, both JSON Schemas were checked with `jsonschema` 4.26.0's `Draft202012Validator.check_schema`. Five synthetic assertions also passed: a properly explained Unknown finding is accepted; a Fail without evidence is rejected; a Pass with partial coverage is rejected; a not-collected source with null artifact/time metadata is accepted; and a complete source without an artifact digest/path is rejected.

Those five assertions cover structure. The implemented importers and evaluator separately check file confinement, hashes, cross-references, scope, identity links, freshness, and supported permission interpretation. Schema acceptance alone cannot establish those properties.

A source that was not collected has no invented digest, file path, or observation time. Those values are null and the source's scope is incomplete. Failed collection may retain a real error artifact, but it cannot represent complete security coverage.
