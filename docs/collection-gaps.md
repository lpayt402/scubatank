# Collection gaps

Before proposing collection for a missing field, check the pinned providers' supported exports.

No custom live collector is approved. Test the exact supported exports from the selected upstream versions first. The table lists candidate gaps for investigation; it does not establish that existing tools lack the evidence.

| Candidate gap | First place to look | Evidence required before custom work |
| --- | --- | --- |
| Authoritative source anchors and password authority | ScubaGear raw data, AzureHound, Microsoft Graph and supported synchronization exports | Which required property is actually missing, and its supported interpretation |
| Active/staging Connect, Cloud Sync, PTA or AD FS host binding | Existing asset inventory, provider data, supported Microsoft service configuration export | Stable host/service/tenant binding, not a guessed hostname |
| GPO resultant policy and endpoint restrictions | SCT, gpresult/RSOP, GroupPolicy module, endpoint-management export | Intent-versus-effective-state distinction and policy precedence |
| Key-use boundary and credential metadata | Existing certificate inventory, supported provider metadata | Access metadata only; never secret extraction or key export |
| Recovery ownership, independent backups and exercises | Backup product reports and owner attestations | Defined requirement, dated evidence, responsible owner, and coverage |
| Effective user-specific Conditional Access scenario | Supported Microsoft evaluation evidence plus original policy exports | All relevant policy conditions; no homemade full CA simulator in the first milestone |

## Required gap record

Use a named section with: proposed check IDs; exact missing field; established tools and pinned versions tested; sample output pointers; reason existing output is insufficient; proposed supported API/cmdlet/export; minimum permissions; target scope; secrets explicitly excluded; expected traffic and side effects; validation oracle; negative and missing-data tests; maintenance owner; approval status.

Status starts as Proposed. It can become Approved only after the user or maintainer accepts the narrow implementation. Add a provider to `config/providers.json` before code, and remove duplicated collection when an upstream tool later supplies the field. No catch-all `Get-Everything` collector.
