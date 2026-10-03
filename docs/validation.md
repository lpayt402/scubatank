# Offline assessment validation

## Policy-style report and baseline context: October 3, 2026

The HTML report uses small system fonts, compact tables, grey borders and native expandable sections. Actions, findings and source records start open. Imported baseline results have their own navigation link and show the product, policy ID, original result and criticality alongside retained source evidence. The terminology was checked against the pinned ScubaGear 1.8.0 report guide. This change adds no collection or assessment controls.

All 146 Python tests passed in 30.850 seconds. Windows PowerShell 5.1 and PowerShell 7 each passed all 19 Pester tests. Catalog generation retained 132 specifications. The demo's bundle, assessment JSON, report JSON, CSV and Markdown remained byte-identical to the earlier report; the README and ASCII artwork are unchanged.

The actual demo and three reporting fixtures passed offline checks with Playwright 1.62.0 and Chromium 151.0.7922.34. Keyboard collapse, filtered finding links, evidence expansion, result filters and search worked. Native finding and evidence panels worked with JavaScript disabled. The report reflowed at 390 and 320 pixels and with text enlarged to 200%; the lowest observed text contrast was 8.23:1. There were no external requests, browser errors or broken fragments. These are bounded browser checks, not Internet Explorer support or a complete accessibility audit.

## Plain HTML report layout: October 2, 2026

The report uses a compact results table, grey section bars, square borders, blue underlined links and basic browser controls. Remediation, findings and source records are plain text sections. The README, ASCII artwork, canonical TANK wording, rule behavior and all report evidence remain unchanged.

All 146 Python tests passed in 22.862 seconds; each Windows shell passed all 19 Pester tests. Before-and-after bundles, assessment JSON, report JSON, CSV and Markdown were byte-identical. Only the HTML presentation changed.

Playwright 1.62.0 and Chromium 151.0.7922.34 passed filter links, search, keyboard disclosure, evidence expansion and fragment checks. The table exposes column and row headers; the keyboard skip link focuses the main report. The demo reflows at 390 and 320 pixels and with text enlarged to 200%. The lowest observed text contrast was 9.39:1. Native disclosures also work with JavaScript disabled. There were no external requests, browser errors or broken fragments. These checks cover the generated demo; they are not a complete accessibility audit.

## Project name expansion: October 2, 2026

The README and architecture use scuba TANK (trust assurance and normalization kit). The expansion also appears in CLI help, Python package and PowerShell module descriptions, and HTML/Markdown reports. Package identifiers and ASCII artwork are unchanged.

The naming update passed all 146 Python tests in 23.156 seconds and all 19 Pester tests in each Windows shell. Structured demo outputs remained byte-identical to the copy-pass baseline. Documentation links and offline report behavior passed the same checks recorded below, including the 390-pixel layout.

## Documentation and report copy: October 2, 2026

The README, handoff and technical docs use specific headings and describe the implemented workflow in the present tense. CLI help and the HTML/Markdown report labels were revised. Commands, check IDs, source links, licenses, the ASCII tank and assessment behavior were preserved.

All 146 Python tests passed in 22.880 seconds. Both Windows PowerShell editions passed all 19 Pester tests, and catalog generation retained all 132 specifications. Before-and-after demo evidence bundles, assessment JSON, report JSON and CSV were byte-identical.

The copy audit checked 62 local documentation links and their fragment targets. All 16 user-facing Markdown documents rendered with CommonMark and table support. The README was inspected on desktop and at 390 pixels. The generated report passed its offline filter, search, keyboard, evidence and fragment checks with Playwright 1.62.0 and Chromium 151.0.7922.34. There were no external requests, browser errors or broken report fragments.

## Cosmetic tweaks: October 2, 2026

The README and interactive CLI share the same original ASCII tank. The CLI prints it to stderr only when stdin, stdout and stderr are terminals. Piped or redirected streams suppress it; `--quiet` works before or after each command and preserves command output. Help follows the same behavior.

All 146 Python tests passed locally, including six banner tests and the existing assessment regressions. Both Windows PowerShell editions passed all 19 Pester tests. A real terminal invocation and redirected JSON output were checked, and the README code block and terminal appearance were visually inspected. This pass changes presentation only.

## Local results: October 2, 2026

The offline release runs pinned importers, typed identity and authority joins, OPA predicates, and versioned reports. Its six implemented correlations were tested with synthetic exports and explicit operational attestations. The committed public ScubaGear excerpt also exercises the pinned publisher's consolidated report structure. A development import of the full public example preserved 92 controls and six stable entities; it supplied no supported direct active-role facts.

The implementation release passed 140 Python tests on Windows amd64, Python 3.12.10 and OPA 1.21.1. These include committed schema validation and original 0.1.0 compatibility, malformed references, traversal and UNC rejection, unsupported formats, conflicting identities, source reconstruction, stale and cross-scope evidence, all six joined predicates and limiting cases, report traceability, and output escaping. Native role schedules must cover the assessment time; an expired assignment alone leaves privilege Unknown, while another supported current assignment can establish it.

Pester 5.7.1 passed all 19 tests in Windows PowerShell 5.1.26100.9444 and PowerShell 7.6.5. Both test sets execute the import, validate, assess and report commands, test literal paths containing shell punctuation, and verify incomplete evidence. The PowerShell demo also completed. `python tools/catalog.py` generated the unchanged 132-entry specification catalog.

The fixed-time demo produced 12 decisions: six Fail, one Pass and five Unknown. Overall coverage remains partial. Its four grouped remediation actions retain the contributing edges and paths. Repeated generation with fixed inputs and metadata produces identical reports. Import and assessment tests prohibit Python socket connections.

An offline browser check of the final HTML passed with Playwright 1.62.0 and Chromium 151.0.7922.34. It tested every status filter, search reset, keyboard disclosure, evidence expansion, fragment targets and a 390-pixel viewport. There were zero external requests, browser errors or broken fragment targets. Screenshots and the check receipt are generated under `.build/demo/browser-smoke`.

## Hosted workflow diagnosis

The earlier run [37002563734](https://github.com/lpayt402/ScubaTank-prep/actions/runs/37002563734) failed before creating jobs. Inspection with actionlint 1.7.12 identified an invalid expression at line 28: `shell: ${{ matrix.shell }}` used a context that GitHub does not permit in `steps.shell`. The revised workflow uses explicit `powershell` and `pwsh` steps. Actionlint validates that workflow. There is no evidence attributing the historical failure to billing.

The new workflow pins checkout/setup-python revisions, Python dependency hashes, Pester and OPA artifacts. [Run 37012147435](https://github.com/lpayt402/ScubaTank-prep/actions/runs/37012147435) passed both jobs for commit `5049823578a39f9fb534d2c2e01f11ef8920a56a`. Ubuntu 24.04 passed all 140 Python tests, catalog generation and the offline demo. Windows Server 2022 passed all 140 Python tests, all 19 Pester tests in each configured PowerShell edition, and both shell demonstrations.

The first revised run reached both runners. Linux passed; Windows exposed a test assertion comparing the short and long spellings of the same temporary path. The assertion now compares canonical paths without changing runtime behavior or removing digest/network checks. The successful run above verifies that correction. Current commit status is available in [Actions](https://github.com/lpayt402/scubatank/actions).

## Validation scope

No live AD, Entra, Microsoft 365 or Azure collection was performed. BloodHound graph fixtures follow the reviewed CE 9.7.1 serializer; no production graph or live collector validation is claimed. Assisted context is dated operator evidence, not output from a native Graph or AD connector. The remaining 126 catalog entries remain specifications and do not appear as implemented checks.

Selected ATT&CK 19.2 and NIST SP 800-53 revision 5 release 5.2.0 mappings were checked against pinned STIX/OSCAL records and independently reviewed. They remain proposed project mappings; they do not establish compliance, technique execution or complete control coverage. [Rule review](rule-review.md) records the sources and reasoning.

Only the listed Windows versions were executed locally. The Python/OPA core was also executed on Ubuntu 24.04 in the hosted run above. That does not establish Linux support for upstream collectors. macOS artifacts are pinned but execution remains untested. No proprietary tool compatibility, live-tenant readiness or production assurance is claimed.

## Repeat the checks

```powershell
.\scripts\Demo.ps1
.\scripts\Install-TestTools.ps1
.\scripts\Test.ps1
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py' -v
.\.venv\Scripts\python.exe tools/catalog.py
```

Optional browser verification requires Playwright and an installed Chromium browser. The runtime workflow does not install browser tooling:

```text
python tests/reporting_browser_smoke.py --report .build/demo/reports/report.html --output .build/demo/browser-smoke
```
