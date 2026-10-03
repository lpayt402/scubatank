# Six-rule implementation review

The selected rules establish bounded configuration and authority exposures. They do not establish exploitation, successful authentication, remote reachability, or complete assessment of a tenant or forest.

The implementation was reviewed against the catalog and primary documentation on October 2, 2026. Framework identifiers and titles were resolved from the pinned official data in [framework-pins.json](../config/framework-pins.json). Review covered [evaluator.py](../scubatank/evaluator.py), [hybrid.rego](../policies/hybrid.rego), [policy.py](../scubatank/policy.py), [assessment.py](../scubatank/assessment.py), the admitted import contracts, and the regression tests. The implementation release passed all 140 Python tests, including known role-assignment expiry between collection and assessment. Synthetic testing and source review do not constitute validation against a live environment.

## Evidence requirements

A usable path needs stable, namespaced identifiers; a supported relationship with its original direction and provenance; evidence within the assessment's collection window; and source coverage for the affected forest, tenant, and objects. A label, email address, UPN, or host naming convention cannot supply these prerequisites.

An identity link must establish the actual synchronized object, including the configured source-anchor method or another supported authoritative linkage. The same source object cannot silently link to conflicting cloud objects. An upstream claim and an operator attestation remain distinguishable records. An attestation needs a named evidence source, timestamp, scope, and explanation of what was checked; declaring a Boolean does not make it independently machine verified.

Use a processed BloodHound relationship only for the supported edge semantics. A raw collector ACL is not a processed effective relationship. The current bounded route accepts supported edges, not an arbitrary generic `Controls` edge. Denied relationships, candidate relationships, malformed qualifiers, unknown versions, unresolved prerequisites, conflicting identities, stale facts, or scope mismatch cannot become an exposure. These qualifier guards preserve explicit limitations in imported properties; they do not implement or validate an upstream ACL deny engine.

The processed graph export time cannot stand in for the underlying observations' collection times. The manifest must retain the oldest and newest graph observation times and the contributing collector versions. Missing metadata, stale underlying observations, or a future observation makes the affected path Unknown even when the graph response was exported recently.

A positive path can be reported with partial overall source coverage when every prerequisite of that particular path is evidenced. The report must retain the partial coverage. A Pass requires complete evidence for the specific applicable predicate, including a supported limiting case. An absent path in a partial graph is Unknown. A malformed input is rejected before evaluation. A rule outside the implemented set remains NotImplemented.

Known temporal bounds also constrain a fact. A ScubaGear role assignment observed active at collection cannot support privilege after its recorded end time. If every supported assignment has expired, the affected active-role prerequisite becomes Unknown; that alone does not prove the account has no other privilege. A still-valid supported assignment can retain the positive prerequisite. Observations remain dated snapshots, rather than assertions that no configuration changed after collection.

## Relationship semantics

| Edge | Supported statement | Additional boundary |
| --- | --- | --- |
| `ForceChangePassword` | The source principal can reset the target AD user's password without knowing its current password. | This does not prove a cloud password flow, MFA bypass, account enablement, or successful sign-in. |
| `MemberOf` | The source principal belongs to an AD security group. | Do not propagate through trusts or assume a cloud service honors nesting. Effective control-plane membership and group classification need evidence. |
| `AdminTo` | The principal is a local administrator on the target computer. | This is host authority; no remote execution or network reachability is asserted. A name containing SYNC does not identify a synchronization deployment. |
| `AddMember` | The principal can add members to the target AD security group. | The target service must support the exact synchronized membership flow and effective grant. Do not infer an Entra role-assignable synced group. |
| `AZOwns` | The cloud principal owns the identified Entra object. | Ownership does not alone establish a usable credential write or unrestricted modification of every application. `AZOwner` is an Azure resource-management edge with different semantics. |

Primary edge references: [ForceChangePassword](https://bloodhound.specterops.io/resources/edges/force-change-password), [MemberOf](https://bloodhound.specterops.io/resources/edges/member-of), [AdminTo](https://bloodhound.specterops.io/resources/edges/admin-to), [AddMember](https://bloodhound.specterops.io/resources/edges/add-member), and [AZOwns](https://bloodhound.specterops.io/resources/edges/az-owns).

The processed graph import contract is BloodHound CE 9.7.1 at commit `1219d5020352051f4169a23e19f6040579d2ac39`. Its native response serializer is [unified_graph.go](https://github.com/SpecterOps/BloodHound/blob/1219d5020352051f4169a23e19f6040579d2ac39/cmd/api/src/model/unified_graph.go); the [pinned OpenAPI document](https://github.com/SpecterOps/BloodHound/blob/1219d5020352051f4169a23e19f6040579d2ac39/packages/go/openapi/src/openapi.yaml) describes `/api/v2/graphs/cypher`. The Go serializer includes an edge `id` while its generated OpenAPI edge schema omits that property; the importer follows the native serializer. A producer-shaped synthetic fixture validates the admitted contract and does not imply a live BloodHound export was collected. Current web edge documentation alone is not proof of conformance to that pinned contract.

## Rule prerequisites

### ST.CORR.IDENTITY.001

Establish all of the following: an effective reset edge from an unapproved controller to an enabled AD user; a verified synchronized Entra user link; an active privileged cloud role with its scope; AD as the applicable password authority; and a supported password flow for the affected account. Record the approved-controller inventory and authentication context.

The finding concerns source authenticator authority behind cloud privilege. Its message must explicitly retain the independent cloud authentication boundary. Cloud-managed passwords, a disabled relevant account, or an evidenced inapplicable password flow break this particular path. Missing password authority, flow, role state, or controller inventory gives Unknown. A reset edge never proves MFA bypass.

[Microsoft's password hash synchronization documentation](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization) explains that an in-scope synchronized password updates the cloud password; it also records flow and temporary-password conditions. A general tenant setting is insufficient to prove that the specific account is in the supported flow.

### ST.CORR.IDENTITY.003

Establish the same verified identity across the AD-to-Entra link, effective AD control-plane membership, and an active privileged cloud role with its scope. Similar names do not join identities. Eligible-only cloud roles do not establish standing cloud privilege.

Keep organizational tier/separation policy as evidence and context. The catalog predicate is shared standing authority; an attestation that no separation policy exists must not silently erase that authority. Any narrower implementation scope must be stated in the report and reviewed. An evidenced absence of either effective AD control-plane membership or active cloud privilege disproves this specific predicate when the relevant coverage is complete.

[Microsoft's hybrid protection guidance](https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks) supports separation of cloud administration from the on-premises boundary. This remains a project exposure judgment, not a statement that Microsoft's entire architecture guidance was assessed.

### ST.CORR.SYNC.001

Establish an unapproved principal's effective local administrative authority over a confirmed synchronization host, a supported deployment/connector binding to the assessed tenant, and the approved host-controller inventory. Host and tenant IDs must match the actual deployment evidence.

A hostname alone supplies no deployment evidence. An evidenced non-synchronization host or approved controller breaks this predicate with complete coverage. Unknown host role, tenant binding, controller inventory, or host authority remains Unknown. Do not infer takeover of unrelated cloud-native administrators, network reachability, credential extraction, or an executed authentication change.

### ST.CORR.GROUP.001

Establish an unapproved principal's effective AD group membership-write authority; an authoritative link to the synchronized cloud group; a supported membership-add/synchronization flow for the relevant identity; and an effective sensitive application/resource grant for that exact cloud group and target scope.

A grant description or an upstream edge alone cannot substitute for target-service support. Unsupported nesting, an inapplicable membership flow, an absent effective grant, or an approved source controller breaks this bounded predicate when complete evidence establishes the limiting case. No cloud directory role is inferred from a synchronized group.

### ST.CORR.GROUP.006

Establish the source membership-write authority and authoritative group link, then consume a complete supported scenario showing that adding the relevant identity to the synchronized group creates an exclusion from an enabled authentication policy and that no other enabled applicable policy restores the specified protection.

The scenario must identify the user, resource, desired authentication requirement, collection/evaluation time, relevant conditions, policy set, and how the prospective membership change was evaluated. A current group exclusion does not prove a prospective user's effective outcome. A single excluded policy gives Unknown without the combined-policy evidence. Another effective policy restoring the requirement disproves the exposure. Report-only policies do not restore enforcement.

Microsoft documents that [all applicable policies must be satisfied](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-policies). The current supported [What If evaluation API](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0) evaluates supplied sign-in conditions, but its result is an estimate for that scenario. The [tool documentation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/what-if-tool) notes that it omits service dependencies and cannot evaluate conditions omitted from the request. Preserve those limitations; do not build a replacement Conditional Access simulator or claim a live MFA bypass.

The offline release admits `operator-reviewed-combined-policy-scenario` attestations for `required_protection: mfa`. The record includes an owner, evaluation timestamp, prospective membership assertion, explicit evaluated policy IDs, sign-in conditions, group/user/resource IDs, and matching source scope. The prospective user must be an enabled, evidenced cloud identity in the same tenant as the group. An incomplete evaluation or stale evaluation time remains Unknown. The attestation's provenance and confidence remain visible. It cannot be promoted to a native Graph import or live evaluation without its own adapter and validation.

### ST.CORR.APPLICATION.001

Establish a supported source account-control path to an application owner; the authoritative AD-to-cloud user link; ownership of the exact application; the owner's effective ability to add a usable credential under current restrictions; the corresponding service principal; and sensitive granted application permissions on that service principal.

For the initial reset-based control route, also require an enabled relevant account, AD password authority, and an applicable password flow. Preserve the independent authentication boundary needed to exercise the owner operation. Missing effective owner capability remains Unknown even when AZOwns exists. Credential restrictions preventing usable addition or an evidenced absence of sensitive application permissions breaks the specific predicate. Delegated scopes do not establish app-only authority.

The application object and service principal are distinct IDs. A client ID, display name, ownership label, or delegated permission request is insufficient. No credential is created or exercised. Microsoft's [application and service-principal documentation](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals) describes the distinction; [application addPassword](https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0) is a reference for the supported operation, not an instruction to perform it during assessment.

## Framework review

The exact titles, STIX object versions, source commits, hashes, and per-rule rationales are in [framework-pins.json](../config/framework-pins.json). All selected ATT&CK IDs resolve to active, nondeprecated objects in Enterprise ATT&CK 19.2. The selected NIST base-control IDs resolve in the NIST 5.2.0 OSCAL catalog.

The mappings stay project-proposed after technical review. They describe potential behavior and partial control evidence, not observed adversary activity, ATT&CK detection coverage, a full control assessment, or certification.

| Mapping | Review boundary |
| --- | --- |
| T1098, Account Manipulation | The reset route concerns authority to replace a source authenticator, not an observed account change. |
| T1078.002, Domain Accounts; T1078.004, Cloud Accounts | Account privilege or a supported path is a prospective exposure; no valid-account use or compromise is observed. |
| T1556.007, Hybrid Identity | Host authority creates an opportunity to influence hybrid identity. No authentication mechanism change is evidenced by host membership alone. |
| T1098.007, Additional Local or Domain Groups | This mapping is justified by the evidenced AD domain-group membership edit. It is not a generic cloud group manipulation label. |
| T1098.001, Additional Cloud Credentials | The effective owner capability concerns usable workload credentials. Ownership or delegated consent alone is insufficient. |
| AC-5, Separation of Duties | Shared privilege is partial evidence; the duties matrix and organizational policy still need review. |
| SC-7, Boundary Protection | Retained as contextual proposed mapping for synchronization infrastructure. Local administrator membership alone does not assess managed network interfaces or satisfy SC-7. |

Official data: [MITRE's pinned Enterprise STIX](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack-19.2.json), [NIST's pinned OSCAL catalog](https://raw.githubusercontent.com/usnistgov/oscal-content/bc8a528770033611df899b3d52703fb3dc91a20d/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json), and [NIST's release description](https://github.com/usnistgov/oscal-content/releases/tag/v1.4.0). Preserve the [MITRE license](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/LICENSE.txt) and [NIST public-domain/CC0 terms](https://raw.githubusercontent.com/usnistgov/oscal-content/bc8a528770033611df899b3d52703fb3dc91a20d/LICENSE.md) when redistributing extracted data.

## Regression review matrix

The review checked these result boundaries. The Rego tests exercise every required prerequisite as missing and every supported false prerequisite as a limiting case. The joined matrix separately tests real adapter output from producer-shaped synthetic files, removal of supporting facts, a catalog limiting case for each rule, stale/scope/conflict cases, and unsupported or denied relationships. An incomplete Conditional Access evaluation remains Unknown even when its completeness field is explicitly false.

| Case | Expected result |
| --- | --- |
| Complete supported positive conjunction | Fail, with the exact path, source records, and rule/version metadata. |
| Missing required fact or edge | Unknown, naming the prerequisite; no inferred false value. |
| Each supported false prerequisite/limiting case with complete coverage | Pass for the bounded applicable predicate. |
| Denied/candidate edge, unsupported edge version, unresolved edge prerequisites | Unknown or rejected unsupported input, never Fail. |
| Stale source or incompatible collection windows | Unknown for the affected path. |
| Wrong forest/tenant or mismatched scenario IDs | Unknown for the affected join. |
| Same labels across different boundaries | Distinct objects; no identity link. |
| Duplicate/conflicting authoritative identity links or facts | Conflict surfaced; affected result Unknown or rejected input. |
| Changed upstream producer/schema version | Explicit unsupported version; no heuristic import. |
| Eligible-only cloud privilege | No active-role exposure from eligibility alone. |
| Role assignment expires between collection and assessment, or exactly at assessment | Unknown when only expired support remains; another still-valid supported assignment can retain the positive prerequisite. |
| AD/cloud disabled account or cloud-managed password in reset route | Limiting case, with complete evidence; no MFA claim. |
| GROUP.006 single exclusion or missing complete policy combination | Unknown; the admitted attestation must distinguish report-only policies from enforcement. |
| GROUP.006 another enabled policy restores protection | Bounded Pass with complete scenario evidence. |
| APPLICATION.001 owner without credential capability, delegated-only scopes, mismatched service principal | No supported credential exposure; missing facts Unknown. |
| Partial graph with no discovered path | Unknown, not a forest/tenant-wide Pass. |

The implementation review used:

```powershell
python -m unittest discover -s tests -p 'test_*.py' -v
```

It passed 140 tests in 25.641 seconds on Windows amd64 with Python 3.12.10 and OPA 1.21.1. The run used normal Windows file permissions because the restricted execution token could not access Python-created temporary test directories. This was a local run; it makes no statement about hosted CI.

| Test group | Passed tests | Review evidence |
| --- | ---: | --- |
| [Importers](../tests/test_importers.py) | 48 | Pinned public ScubaGear excerpt; producer-shaped graph parsing; scope/version/identity conflicts; malformed references; path limits; exact parsed-byte hashes; finite, mixed and open-ended role schedules. |
| [Typed joins](../tests/test_evaluator.py) | 17 | Identity prerequisites; missing/stale/future graph evidence; wrong boundaries; explicit and malformed deny/precondition qualifiers. |
| [OPA predicates](../tests/test_policy.py) | 8 | All six positive conjunctions; every missing prerequisite; supported false prerequisites; incomplete scenarios and unimplemented rules. |
| [Joined six-rule matrix](../tests/test_rule_matrix.py) | 7 | Each rule's imported positive and limiting case; supporting-fact removal; stale/scope/conflict cases; denied/unsupported edges; stale cloud tenant context. |
| [End-to-end pipeline](../tests/test_pipeline.py) | 8 | Six supported synthetic paths, one disproved path, five incomplete cases; source pointers/hashes; deterministic output; raw-input reconstruction; no Python network calls; ISO and Microsoft date-format expiry, exact end-time boundary, and mixed expired/current assignments. |
| [Reports](../tests/test_reporting.py) | 25 | Versioned envelopes; references and remediation edges; original schema separation; grouped paths; escaping; formula-safe CSV; bounded rendering; local output paths. |
| [Schema contracts](../tests/test_schema_contracts.py) | 6 | Committed schema validity; original 0.1.0 acceptance; required new metadata; evidence requirements for Pass and Fail. |
| Catalog, CLI and bootstrap | 21 | Catalog guards; runnable offline demo; explicit implemented providers; verified existing runtime and rejected mismatched binary. |

Assessment reconstructs the normalized bundle from its saved manifest and source files before making supported decisions. Unchanged raw hashes do not excuse edited normalized facts. Without the original evidence root, every result is Unknown. Reports retain the source observation, pointer, digest, versions, affected objects, and limitations. The demo yielded six Fail, one Pass, and five Unknown results while overall coverage remained partial.

Each remediation action identifies an actual contributing authority edge. The nested membership regression verifies that the shared user's membership edge is selected, so the proposed action matches the object it names. Removing that edge breaks the recorded conjunction; the report does not claim to eliminate every alternative path. Remediation is advice only and performs no directory or tenant change.

## Runtime verification

OPA 1.21.1 is pinned to publisher release artifacts in [framework-pins.json](../config/framework-pins.json). On this Windows workspace, the downloaded executable's SHA-256 matched both GitHub's official release asset metadata and the publisher's companion checksum file. Windows Authenticode inspection returned NotSigned; no publisher signature verification is claimed. The executable reported Rego v1 on windows/amd64. This verifies the selected artifact and local invocation; it does not imply Linux or macOS execution tests.

Assessments must use an explicit local OPA executable or the documented prepared tool path. The assessor must not download `latest` or silently install a runtime. Framework datasets and the test runtime were sourced during development; no real organization assessment data was uploaded, and no live tenant or directory was contacted.
