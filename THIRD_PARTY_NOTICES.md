# Third-party licenses and attribution

ScubaTank is independent of CISA, Microsoft, NIST, MITRE, CIS, SpecterOps, Netwrix, and Semperis. Product and framework names identify sources and proposed integration points. They do not imply endorsement, partnership, certification, or authorship of this project's mappings.

The MIT license in this repository applies to original ScubaTank code and documentation. It does not relicense third-party tools, datasets, benchmark text, reports, or exports. No third-party collector binary or proprietary ruleset is bundled.

ScubaGear states that its project is CC0 unless otherwise noted; individual baseline documents can include separately attributed licensed material. This repository links to that material and does not copy its policy text into a derivative baseline. Preserve relevant notices if future contributions reuse upstream code or content.

Live collectors remain separate operator-managed installations. The explicit offline bootstrap obtains OPA 1.21.1 under Apache-2.0 and six hash-locked Python dependencies: jsonschema 4.26.0 (MIT), attrs 26.1.0 (MIT), jsonschema-specifications 2025.9.1 (MIT), referencing 0.37.0 (MIT), rpds-py 2026.5.1 (MIT) and typing-extensions 4.15.0 (PSF-2.0). The upstream wheels retain their licenses. [Python pins](config/python-pins.json) and [runtime pins](config/runtime-pins.json) record official artifact digests. Downloaded binaries and dependency code stay outside Git.

The BloodHound CE 9.7.1 processed graph format is based on its Apache-2.0 publisher contract. ScubaGear 1.8.0 contract validation uses its CC0 public example with baseline prose omitted in the retained excerpt. Full source-format license notices are in [third_party/licenses](third_party/licenses). No collector code or proprietary ruleset is incorporated.

Extracted Enterprise ATT&CK 19.2 identifiers and titles retain the [MITRE license](third_party/licenses/MITRE-ATTACK.txt): "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." NIST SP 800-53 Rev. 5 release 5.2.0 identifiers and titles come from NIST's public-domain/CC0 OSCAL content. [Framework pins](config/framework-pins.json) record exact source commits and data digests. Project mapping rationales are original ScubaTank judgments and remain proposed.

PingCastle's publisher places conditions on commercial incorporation and revenue-generating use. Its proposed integration is optional, operator supplied, and subject to license review. Purple Knight integration likewise requires edition, terms, and export-format review. No stable public automation interface is assumed.

CIS benchmark documents and recommendation numbers are not reproduced here. Exact CIS mappings are deliberately unpopulated pending version/profile and permitted-use review. NIST and ATT&CK references are proposed analytical mappings, not a claim to satisfy a certification or implement an entire framework.

See `catalog/sources.json` and `docs/tooling.md` for publisher references. Recheck applicable terms before release or commercial distribution.
