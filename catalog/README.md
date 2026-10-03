# Check catalog

The source of truth is the pipe-delimited `.psv` files. They are plain UTF-8 text, one check per row, with named columns. Use `Import-Csv -Delimiter '|'` or Python's standard CSV reader; do not split arbitrary imported assessment data this way.

A check ID is `ST.CORR.<AREA>.<number>` or `ST.POST.<AREA>.<number>`. Numbers do not change when wording changes. The row contains the exposure condition, required evidence, remediation, limiting case, severity, ATT&CK IDs, NIST IDs, and the NIST mapping rationale. `areas.json` supplies scope, join rules, and shared sources. `config/collection-routes.json` assigns preferred established tools and identifies evidence gaps. Extra row sources are added to the area's sources, not substituted for them.

Every check is currently **specified**. None is a validated detector. Every row has both framework mappings, but the mappings are project proposals requiring independent review. `metadata.json` fixes the catalog version and scope. Do not turn an unimplemented check into Pass.

| Correlation area | Checks | Source |
| --- | ---: | --- |
| Privileged identities | 10 | [identity](correlation/identity.psv) |
| Synchronization | 8 | [sync](correlation/sync.psv) |
| Federation, PTA and SSO | 8 | [federation](correlation/federation.psv) |
| Trust boundaries | 8 | [trust](correlation/trust.psv) |
| Group authorization | 8 | [group](correlation/group.psv) |
| Workloads and applications | 10 | [application](correlation/application.psv) |
| Certificates | 8 | [certificate](correlation/certificate.psv) |
| Kerberos and directory control | 8 | [kerberos](correlation/kerberos.psv) |
| Host administration | 8 | [host](correlation/host.psv) |
| GPO and host policy | 8 | [policy](correlation/policy.psv) |
| Visibility | 8 | [visibility](correlation/visibility.psv) |
| Recovery | 8 | [recovery](correlation/recovery.psv) |

The supporting areas add eight checks each: [AD](posture/directory.psv), [authentication](posture/auth.psv), [Windows Server](posture/server.psv), and [identity operations](posture/operations.psv).

Run `python tools/catalog.py` from the repository root to generate `.build/catalog/checks.json`, `checks.csv`, and `checks.md`. The generated records include provider routes, source links, result limitations, and the required positive/negative/missing-evidence/version test contract. Generation is offline and does not execute a security check.

Before implementing a rule, resolve its data dependencies and upstream versions, split the predicate into explicit facts, identify the secure or nonapplicable counterexample, and build producer-shaped fixtures. Keep the catalog and actual detector status in sync. See [mapping policy](../docs/mappings.md) and [handoff](../docs/HANDOFF.md).
