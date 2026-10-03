# Mapping method

The catalog maps each specified check to NIST SP 800-53 Revision 5 and Enterprise ATT&CK. A check can have multiple mappings, each with its own rationale.

The working reference versions are **NIST SP 800-53 Rev. 5, release 5.2.0**, and **Enterprise ATT&CK v19.2**, reviewed on October 2, 2026. Enterprise coverage is needed because hybrid paths extend beyond Windows into identity providers, SaaS, and IaaS. Framework versions and source URLs are recorded with generated output.

## Mapping scope

A NIST mapping means the check contributes **partial evidence** relevant to a control objective. It does not assess the whole control, an entire control family, an organization's selected baseline, FedRAMP authorization, or compliance. The `nist_rationale` explains the connection for each check. Control enhancements should only be added after their exact requirement is reviewed; the initial catalog primarily maps base controls.

ATT&CK describes possible adversary behavior associated with an exposure, not a control requirement. Each mapping is classified as potential behavior, visibility gap, or recovery impact. A visibility check can reference the behavior it would help investigate without claiming that the behavior occurred. A recovery test mapped to T1490 does not detect backup destruction.

The project mappings are proposed and require independent technical review. Identifier syntax validation is not semantic validation. Before marking a rule validated, resolve every ID against the pinned official Enterprise STIX and NIST OSCAL releases; retain the source digest, title, deprecated/revoked state, and exact mapping rationale. Review current IDs rather than copying old tables. For example, the selected ATT&CK version uses T1685 for tool impairment, including T1685.001 for Windows event logging and T1685.002 for cloud logging.

## Preserve upstream attribution

ScubaGear's NIST mappings are explicitly constrained to the FedRAMP High baseline. Keep those CISA mappings with the original SCuBA control/version. ScubaTank's wider project mappings are separate records, never overwritten into an upstream result or presented as a CISA-approved extension.

A failed SCuBA control only strengthens a hybrid finding when its evidence applies to the affected principal/resource/scenario. Original annotations, exclusions, and known collection failures remain visible. A passed tenant-level check is not proof all effective scenarios are protected.

## CIS and Microsoft baselines

CIS is a reference source, not a bundled ruleset or certification. Exact CIS mappings remain `not-mapped` until the specific benchmark edition, version, profile, recommendation, and permitted use have been reviewed. Do not invent section numbers. Do not reproduce proprietary benchmark content or claim CIS conformance.

Microsoft baseline applicability must specify server version/build and role. Prefer SCT-produced evidence to rewritten registry comparisons. A domain controller and member server do not share every baseline requirement. Optional features, supported replacements, and organization-specific requirements need explicit applicability.

## Review gate

For each mapping, ask whether the observed fact actually supports the chosen technique/control; whether the mapping is too broad or implies unobserved activity; and whether a narrower supported identifier exists. Document disagreements. Keep mapping changes versioned independently of the rule predicate and preserve historical reports.

Primary references: [NIST publication and 5.2.0 update](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), [ATT&CK versions](https://attack.mitre.org/resources/versions/), [SCuBA mappings](https://github.com/cisagov/ScubaGear/blob/91852a8099c18f35c10e8d3ad31d59fa6be67c79/docs/misc/mappings.md), [CIS Windows Server](https://www.cisecurity.org/benchmark/microsoft_windows_server).
