# scuba TANK (trust assurance and normalization kit)

```text
          o
       o
      _||_
     /____\       ScubaTank
    |      |---.  Hybrid security assessment
    |      |   |
    |      |   '---[o]
    |______|
```

ScubaTank joins saved Microsoft cloud findings with AD identity, group and host authority. Reports show the evidence supporting each path and the permission changes that would break its required relationships.

The offline workflow imports evidence, validates identity links, evaluates six hybrid correlations with OPA, and produces local HTML, JSON, CSV and Markdown reports. It requires no credentials to run the demonstration. Live collection and automatic remediation remain disabled.

## Run the demonstration on Windows

Install Python 3.12, clone this repository, and run from its root in Windows PowerShell 5.1 or PowerShell 7:

```powershell
.\scripts\Demo.ps1
```

The first run creates a local `.venv`, installs the hash-locked Python wheels and obtains the hash-verified OPA 1.21.1 binary. Setup uses the network. The demonstration then runs offline against clearly labeled synthetic exports. Repeat it without setup:

```powershell
.\scripts\Demo.ps1 -SkipBootstrap
```

Open `.build/demo/reports/report.html`. The demo produces six exposure findings, one blocked path and five Unknown decisions. The report groups the findings into four permission changes while preserving each path. Its source drawer shows the original records, hashes, collection times and version pins. The other files are `report.json`, `findings.csv` and `report.md`; the imported bundle and assessment envelope sit beside the reports directory.

The demo results are reproducible synthetic tests. Live tenants, forests and collector deployments have not been validated.

## Implemented correlations

| Check | Implemented evidence path |
| --- | --- |
| `ST.CORR.IDENTITY.001` | Effective AD password-reset authority to a verified synced account with an active privileged cloud role and an applicable AD password flow |
| `ST.CORR.IDENTITY.003` | The same verified identity has resolved AD control-plane membership and an active privileged cloud role |
| `ST.CORR.SYNC.001` | An unapproved local administrator controls a confirmed synchronization host linked to the assessed tenant |
| `ST.CORR.GROUP.001` | An AD membership editor controls a verified synced group with a supported sensitive application/resource grant |
| `ST.CORR.GROUP.006` | A source-group edit changes an explicitly reviewed prospective MFA policy scenario, with no effective restoring policy |
| `ST.CORR.APPLICATION.001` | A source-account reset path reaches an application owner with evidenced usable credential-write capability and sensitive app-only grants |

The catalog still contains 100 correlation and 32 posture specifications. The remaining 126 entries are not detectors and are excluded from assessment results. ScubaGear's original posture findings are preserved separately; ScubaTank does not relabel those as its own implemented posture checks.

Password reset does not establish MFA bypass. One Conditional Access exclusion does not establish an effective bypass. Missing, stale, conflicting or unsupported evidence produces Unknown. A Pass disproves one scoped predicate with complete required evidence; the report keeps overall coverage partial.

## Import authorized local exports

The admitted formats are ScubaGear 1.8.0 consolidated JSON, a saved BloodHound CE 9.7.1 processed Cypher graph response, and ScubaTank 1.0.0 assisted-evidence records. Raw SharpHound ZIP and AzureHound collector JSON are not interchangeable with the processed graph route. [Import formats](docs/import-formats.md) documents exact fields, collection windows, stable identity links and declared coverage. [Source pins](docs/source-pins.json) records publisher commits and digests.

```powershell
Import-Module .\PowerShell\ScubaTank\ScubaTank.psd1
Get-ScubaTankPlan
Import-ScubaTankEvidence -ManifestPath C:\Assessments\Example\manifest.json -OutputPath .build\bundle.json
Test-ScubaTankEvidence -Path .build\bundle.json -EvidenceRoot C:\Assessments\Example
Invoke-ScubaTankAssessment -BundlePath .build\bundle.json -EvidenceRoot C:\Assessments\Example -OutputPath .build\assessment.json
Export-ScubaTankReport -AssessmentPath .build\assessment.json -OutputDirectory .build\reports
```

Assessment reconstructs the normalized bundle from its original manifest and source files. An edited normalized record fails that comparison. Without the original evidence root, all decisions remain Unknown. Imports accept local disk files, make no outbound requests, and never execute source content. Sensitive real exports belong outside Git.

The equivalent CLI runs from the repository root using the Python environment created by bootstrap. On Windows, replace `python` below with `.\.venv\Scripts\python.exe`; on Linux, use `.venv/bin/python` after installing the locked dependencies.

Interactive invocations show the tank banner on stderr. Redirecting or piping any stream suppresses it, so stdout remains clean JSON. Use `--quiet` before or after the command to hide the banner while keeping the result, for example `python -m scubatank plan --quiet`.

```text
python -m scubatank plan
python -m scubatank import --manifest fixtures/demo/manifest.json --output .build/bundle.json
python -m scubatank validate .build/bundle.json --evidence-root fixtures/demo
python -m scubatank assess --bundle .build/bundle.json --evidence-root fixtures/demo --as-of 2026-10-02T08:00:00Z --output .build/assessment.json
python -m scubatank report --assessment .build/assessment.json --output-dir .build/reports
```

The explicit setup command is `python -m scubatank.bootstrap --output-dir .build/tools`, after installing `requirements.lock` with `--require-hashes --only-binary=:all:`. The Windows script handles both steps. Windows Python 3.12, Windows PowerShell 5.1 and PowerShell 7 are tested locally. The Python/OPA core also passes hosted Ubuntu 24.04 tests. macOS OPA artifacts are pinned but execution remains untested. See [Windows workflow](docs/windows-workflow.md) and [validation](docs/validation.md) for the tested versions and hosted CI result.

## Run the tests

```powershell
.\scripts\Install-TestTools.ps1
.\scripts\Test.ps1
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py" -v
.\.venv\Scripts\python.exe tools/catalog.py
```

The tests cover native-shaped imports, schema compatibility, path/hash/reference validation, identity conflicts, all six joined predicates and limiting cases, freshness, denial qualifiers, report traceability and safe output. [Report contract](docs/report-contract.md) describes the versioned envelope. [Rule review](docs/rule-review.md) records the independent semantic review and proposed framework mappings.

At operation time, confirm authorized collection scope, the actual producer versions, contributing collection windows and the operational context the exports cannot supply. Use established collectors under their own approved permissions. ScubaTank does not collect credentials, probe a live organization or apply the reported changes.

ScubaTank is an independent project maintained by Lee Payton. Product names identify sources; they imply no endorsement. See [third-party notices](THIRD_PARTY_NOTICES.md).
