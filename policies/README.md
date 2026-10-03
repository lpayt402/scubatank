# Hybrid policy implementation

OPA/Rego is the intended evaluator for new ScubaTank predicates. No production Rego detector is included yet. Do not replace the established upstream policy/graph engines with a custom PowerShell rules language.

Implement the six rules in Milestone 2 after producer adapters and identity links have tests. Each rule consumes bounded normalized facts with evidence references, not raw secrets or arbitrary commands. Missing prerequisites produce Unknown; unimplemented rules produce NotImplemented. Keep confidence, coverage, and technical result separate.

Use `opa test` for rule tests. Pin a reviewed OPA version and test both v1 syntax and the exact supported runtime before adding a runner. Cover positive, limiting, missing, stale, contradictory, wrong-boundary, and unsupported-version cases. Never import network data during offline evaluation. Map each predicate to exact source fields and preserve the upstream interpretation of derived graph edges.
