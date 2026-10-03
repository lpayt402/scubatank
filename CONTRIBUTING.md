# Contributing

Start with an issue or a focused change that names the evidence gap or check being improved. Existing tool outputs are preferred to new collectors. Read `docs/tooling.md` before proposing another collection implementation.

A new check needs a stable ID, precise scope, an evidence-backed predicate, a secure/limiting counterexample, concrete remediation, proposed NIST and ATT&CK mappings with rationale, source/version references, and a preferred provider route. Exact CIS recommendations require a licensed version/profile review; do not paste benchmark text here.

A new adapter needs producer-shaped sanitized fixtures, strict supported-version behavior, collection coverage and error handling, source provenance, hostile-input tests, documented permissions, and a licensing review. Never commit customer exports, credentials, private keys, or environment-specific inventories.

Run catalog validation and relevant Pester/OPA tests. State which tests ran and which did not. Keep the change small enough to review and do not update unrelated dependencies or frameworks in the same patch. A written rule, passing schema, and passing mock test are separate from lab validation.

Explain findings in ordinary language. Technical identifiers are useful; slogans and claims of guaranteed security are not. Contributions should make the result easier for an administrator to verify and fix.
