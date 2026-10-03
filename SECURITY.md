# Security

ScubaTank is a development foundation. Do not treat it as a production security boundary or run new live collection without explicit authorization and review.

Assessment exports can expose directory topology, privileged relationships, application grants, and recovery dependencies even without passwords. Keep them in access-controlled local storage, encrypt them at rest where required, set retention limits, and never attach them to a public issue. Use synthetic or approved sanitized samples.

Do not retrieve password values, credential hashes, bearer tokens, managed passwords, private keys, or backup credential databases. Read authorization and configuration metadata only. Do not disable EDR, logging, TLS validation, or signing to make a provider work. Coordinate approved collection with the responsible operations and security teams.

For a suspected vulnerability in ScubaTank, use the repository's private vulnerability-reporting channel when available. If it is unavailable, open a minimal issue asking for a private contact without disclosing exploit details, secrets, or customer data. Do not post raw assessment bundles.

Imports must remain offline and treat input as data. Unknown schema, missing evidence, parser errors, and incomplete scope must be visible in results rather than converted into clean bills of health.
