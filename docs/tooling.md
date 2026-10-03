# Providers and collection boundaries

ScubaTank imports and joins evidence from separate assessments. Established tools retain responsibility for LDAP, host and cloud collection and their native analysis.

## Provider responsibilities

| Responsibility | Preferred tool | ScubaTank processing |
| --- | --- | --- |
| M365 baseline assessment | CISA ScubaGear | Preserve and link its JSON findings to affected hybrid paths |
| AD objects, memberships, ACL observations, trusts, AD CS data | SpecterOps SharpHound | Versioned import, collection coverage, identity links; do not duplicate collection |
| Entra and Azure relationship data | SpecterOps AzureHound | Correlate directory/resource scope with the on-premises evidence |
| Supported permission and attack-path semantics | BloodHound | Consume supported derived relationships and add bounded hybrid context |
| Windows/GPO baseline comparison | Microsoft Security Compliance Toolkit: Policy Analyzer, LGPO export, GPO2PolicyRules | Import supported comparison/export data and bind it to the actual host/role |
| Resultant policy, audit and host metadata gaps | Supported Microsoft exports/cmdlets, only after gap review | Narrow adapters for evidence an existing provider cannot supply |
| Existing identity posture findings | Defender for Identity, when deployed | Optional corroboration; preserve assessment scope, timestamps, license and sensor gaps |
| Broader AD posture | PingCastle, operator supplied and licensed | Optional report import after format and terms review |
| Existing independent assessment | Purple Knight, operator supplied | Optional evidence/attestation input; do not claim a stable public integration API |
| Hybrid rule evaluation and tests | OPA/Rego, Pester, Python unittest for catalog tooling | Project rules and adapter contracts, not another policy/test framework |

Three offline routes are implemented: ScubaGear 1.8.0 consolidated JSON, BloodHound CE 9.7.1 processed Cypher graph responses and ScubaTank 1.0.0 assisted-evidence records. Other integrations remain planned. `config/providers.json` records format validation separately from live validation. [Source pins](source-pins.json) documents exact publisher commits, digests, licenses and tested contract boundaries.

## Default workflow

The implemented workflow is **import-only**. An operator supplies exports collected with approved tools. ScubaTank reads those files without creating service principals, changing a tenant, granting domain-wide rights, or installing a forest scanner.

Any future collection plan must specify the exact tool/version, commands, scope, accounts, expected endpoints, output locations, duration limits, and operational impact before execution. Missing dependencies must produce an explicit setup requirement; they cannot trigger a replacement collector.

ScubaGear, SharpHound, and AzureHound do not need to run with the same identity or on the same machine. Azure resource collection is optional and separately scoped from Entra collection. Use the current publisher's per-method permissions documentation; do not default to Domain Admin or Global Administrator.

## Collection scope and permissions

SharpHound's default and `All` modes can contact more than domain controllers. A proposed directory-only profile should use the supported directory-only methods for the pinned release; host, registry, certificate-service, session, and user-right collection need separate scope and approval. Directory-only data cannot prove effective local administrator membership, actual GPO application, or network reachability everywhere. Read-only collection still generates traffic and telemetry. Coordinate with the SOC; never disable EDR, change logging, or use evasion flags to get collection through.

BloodHound's supported derived edges are preferred over new PowerShell access-check logic, but the report must retain their documented preconditions and limitations. No tool's finding proves exploitation. When tools disagree, retain both claims and their versions for review.

The Security Compliance Toolkit can apply settings as well as inspect them. ScubaTank only permits approved export, parse, and comparison operations. No LGPO import/apply, no baseline installation scripts, and no SetObjectSecurity changes. Policy Analyzer includes interactive workflows; do not promise a headless API that has not been tested. Exported GPO intent is not the same as effective host policy.

PingCastle's publisher distinguishes internal use from commercial incorporation and revenue-generating services. Do not bundle its code/binary, silently download it, or make it a required dependency. Operator-supplied licensed use is the initial integration model. Purple Knight is likewise optional; validate the actual edition, terms, and export format before promising automation. CIS benchmark text and numbered recommendations are not copied into this repository.

## Dependency admission

Before enabling an adapter or runner, record the publisher URL, exact version, provenance, supported output shape, license review, required permissions, platform requirements, expected side effects, and fixture/test results. Pin an approved artifact digest and verify publisher signatures where available. A version string without a validated artifact is not a supply-chain check.

Never fetch `latest` during an assessment. Never install modules during import. Never execute a command read from a report or concatenate untrusted fields into a shell command. Use typed argument arrays and an allowlisted operation plan. Treat ZIP/XML/JSON input as hostile: bound size/count/depth, reject traversal and duplicate identities, disable XML external entities, and reject unknown schemas.

The explicit bootstrap downloads only hash-pinned offline dependencies. Import and assessment use saved evidence without launching collectors, contacting targets or installing modules. OPA evaluates bounded normalized predicates; ScubaTank does not implement a replacement permission engine.

## References

[SharpHound methods](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound-flags), [SharpHound permissions](https://bloodhound.specterops.io/collect-data/sharphound-data-permissions), [AzureHound](https://bloodhound.specterops.io/collect-data/ce-collection/azurehound), [AzureHound least privilege](https://specterops.io/blog/2026/06/08/keeping-a-short-leash-new-azurehound-least-privilege-documentation/), [Microsoft SCT](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10), [PingCastle terms](https://www.pingcastle.com/download/), [Purple Knight](https://www.semperis.com/purple-knight/).
