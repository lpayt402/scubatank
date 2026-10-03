# Import existing evidence

ScubaTank reads three file contracts: consolidated ScubaGear 1.8.0 JSON, a saved BloodHound CE 9.7.1 Cypher graph response, and dated operator evidence in the ScubaTank 1.0.0 format. Import requires local files. It does not connect to tenants or domains, download a tool, run a collector, or execute imported commands.

Put a `manifest.json` beside the saved files. [The demo manifest](../fixtures/demo/manifest.json) shows the complete contract. Real assessment exports belong outside Git. Set `synthetic` to `false` for authorized real observations. Give each source a unique ID, exact producer version/schema, relative file path, explicit tenant and/or forest boundary, and completeness/capability declaration. A SHA-256 expectation can be supplied; otherwise the importer computes and preserves the file digest. BloodHound and supplemental evidence need an explicit timezone-bearing collection timestamp. ScubaGear supplies its timestamp natively.

The manifest and normalized bundle have strict, versioned schemas. [import-manifest.schema.json](../schemas/import-manifest.schema.json) forbids unsupported fields, including inline facts. [assessment-evidence.schema.json](../schemas/assessment-evidence.schema.json) defines normalized records. Facts must originate in a hashed JSON file. Every imported file is retained as a root observation; every normalized record points to the original JSON location. Manifest identity/hash, adapter versions and a deterministic import run ID support later reimport verification.

## ScubaGear

Use the consolidated `ScubaResults_{UUID}.json` emitted without `KeepIndividualJSON`. CSV and the baseline-analyzer schema are different contracts. The adapter reads the [pinned Merge-JsonOutput producer](https://github.com/cisagov/ScubaGear/blob/2d01e711fcb74f615e1fbea6d06556a8dcbff11f/PowerShell/ScubaGear/Modules/Orchestrator.psm1) and was checked against its [public sample report](https://github.com/cisagov/ScubaGear/blob/2d01e711fcb74f615e1fbea6d06556a8dcbff11f/PowerShell/ScubaGear/Sample-Reports/ScubaResults_fa5589b7-d528-4f80.json). That public sample imported 92 original controls and six stable entities. It supplied no supported direct active role facts for the bounded rules; the importer preserved that limitation.

| Native field | Normalized use |
| --- | --- |
| `MetaData.Tool`, `ToolVersion` | Must agree with ScubaGear and pinned `1.8.0` |
| `MetaData.TenantId` | Cloud namespace; must equal manifest scope |
| `MetaData.TimestampZulu`, `ReportUUID` | Source time and preserved run provenance |
| `ProductsAssessed`, `ProductAbbreviationMapping` | Original product coverage retained in observations |
| `Results.<product>[group].Controls[control]` | Upstream finding, retaining control/version ID, result, criticality and details |
| `Requirement`, comments, resolution date, original/omitted/incorrect results | Retained in finding annotations and original record |
| `Summary`, `AnnotatedFailedPolicies`, `Raw.scuba_config` | Retained observations; relevant control annotations copied without reclassifying upstream status |
| `Raw.privileged_users.<objectID>` | Tenant-scoped CloudUser; display name, roles and immutable ID preserved |
| `Raw.privileged_service_principals.<objectID>` | Distinct tenant-scoped service principal |
| `Raw.privileged_roles[].RoleTemplateId`, `Assignments[]` | Direct in-window Global Administrator/PRA assignment can establish `active_privileged_role` |
| `AssignmentType`, `MemberType`, `DirectoryScopeId`, `StartDateTime`, `EndDateTime` | Direct assigned/activated tenant-root schedules only; finite boundaries become ISO UTC `valid_from`/`valid_until` on each role fact; explicit null differs from a missing field |
| `Raw.*_unsuccessful_commands` | Collection errors and incomplete source coverage |

An active-role fact is never inferred from a role name alone. Eligible, expired, future and group-mediated schedules remain raw context. Missing `Raw`, schedules, roles or successful commands do not become a passing security result. ScubaGear failures are baseline context; one tenant-level failure does not establish a particular user's effective Conditional Access outcome.

Each supported assignment keeps its own fact and native evidence pointer. The importer checks activity at the native collection time and preserves finite validity boundaries from Microsoft `/Date(epoch_ms)/` or timezone-bearing ISO schedules. Assessment must also check those boundaries at its own `as_of` time: a role that expires between collection and assessment no longer establishes active authority. Explicit null boundaries remain open ended; the importer does not invent dates. Operator evidence records retain their existing contract.

## BloodHound

Use an authorized saved HTTP JSON response from `POST /api/v2/graphs/cypher` with `include_properties: true`. The operator should save the full response body and record the installed engine version, collector versions/profiles, approved scope, query coverage and original collection time in the manifest or retained operator evidence. A query export is a scoped view; a missing edge is not proof that permission is absent. Live BloodHound query and collector setup remain operation-time tasks.

The graph manifest must record `observation_window.oldest_at` and `newest_at` for the original contributing collections, plus `collector_versions` keyed by contributing tool. Export time cannot refresh an old imported graph. Missing collection window or collector metadata marks graph coverage incomplete. The oldest observation controls freshness. Collector versions are provenance declarations; this adapter does not claim to validate each collector's raw format. Demo collector labels say `synthetic-not-executed` because no collectors ran.

The accepted native graph is `data.nodes` keyed by database node ID, `data.edges` as an array, and optional `node_keys`, `edge_keys`, `literals`. The [pinned Go serialization](https://github.com/SpecterOps/BloodHound/blob/1219d5020352051f4169a23e19f6040579d2ac39/cmd/api/src/model/unified_graph.go) specifies details omitted from the OpenAPI description: edges carry `id`, and property values can be scalar JSON values. A `data: []` graph, raw collector ZIP, or OpenGraph ingestion payload does not satisfy this export contract.

| Native field | Normalized use |
| --- | --- |
| `data.nodes.<dbID>.objectId` | Stable SID/GUID or cloud UUID, scoped by forest or tenant |
| `kind` / `kinds` | Distinct AD and cloud entity types; original kind array retained |
| `label` | Display only; never used for identity joining |
| `properties` | Native values retained; actual boolean `enabled` can produce an observed fact |
| `isTierZero`, `lastSeen` | Retained properties; neither proves authority or collection freshness |
| `data.edges[].id`, `source`, `target` | Unique edge identity; database IDs must resolve to exported stable entities |
| `kind`, `properties` | Typed upstream relationship and original prerequisite/deny fields preserved |
| Manifest collection time and boundaries | Provenance supplied separately because the API graph body lacks engine/collector scope metadata |

Only known edge types receive upstream-derived semantics. Evaluation admits the smaller per-rule allowlist. Unsupported types remain visible with `UnsupportedRelationship`; ScubaTank does not create a generic control edge or interpret raw ACLs. BloodHound supplies the native relationship semantics. Scope, deny conditions, unresolved prerequisites and supported endpoint types still constrain evaluation.

## Operator evidence and identity links

[supplemental.json](../fixtures/demo/supplemental.json) is a synthetic example of assisted evidence. Its `entities`, `facts` and `identity_links` are hashed observations, not in-manifest claims. Fact predicates are a bounded allowlist used by the six implemented correlations. An approved-controller inventory must contain imported stable entity IDs in the target boundary. An empty array explicitly declares that no controller is approved. An incomplete inventory cannot establish absence and its approval fact is withheld.

User links require `verified-source-anchor`, an explicit supported anchor attribute (`objectGUID` or `mS-DS-ConsistencyGuid`), equal AD/cloud immutable values, and `verified: true`. Group links require `verified-onpremises-sid`, the exact native AD SID and matching cloud on-premises SID. The normalized method is `established_id_link`; the original verification record remains available. These are operator verification attestations; labels, email, UPN and proposed soft matches cannot establish links. Conflicting claims within the same boundary mark links conflicted and block affected conclusions.

The Conditional Access record uses `evaluation_method: operator-reviewed-combined-policy-scenario`, a review owner/time, stable user/group IDs, actual resource, evaluated policy IDs, sign-in conditions, required protection, prospective-membership state, combined-policy outcome and completeness. Only this explicit attestation route is admitted. The project does not yet claim conformance to a live Microsoft scenario evaluation API. A single group exclusion, an unevaluated restoring policy or incomplete scenario remains Unknown.

## Input limits and validation

Each file is limited to 16 MiB, 64 JSON levels and 200,000 JSON values. A manifest admits at most 32 files. Duplicate JSON keys, nonfinite numbers, duplicate native identities/edges, unknown versions, malformed pointers, missing endpoints, path traversal, absolute source paths, UNC inputs and URI inputs fail before assessment. No archive extraction or XML parsing is implemented. Source exclusions/errors remain in the bundle; reports can inspect them.

Explicit secret-bearing keys such as access tokens, password hashes, private keys and managed-password values are rejected before source observations are retained. This checks known field names, not every possible secret embedded in free text; authorized exports must remain credential-free. The importer hashes the same byte snapshot it parses, so a changed second file read cannot substitute unrelated provenance.

Demo files contain invented identities and scenarios. They test producer-shaped parsing and bounded evaluation. ScubaGear's pinned official public sample was also parsed locally. BloodHound validation uses its pinned producer serialization and synthetic response; no live BloodHound export or actual enterprise authorization has been validated. The exact sources, file digests, licenses and these separate validation claims are in [source-pins.json](source-pins.json).

The importer is offline Python code, tested here on Windows with Python 3.12. ScubaGear and BloodHound retain their own platform, licensing and collection requirements. Import capability does not promise that their live collectors run on every platform.
