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

CISA's Secure Cloud Business Applications (SCuBA) project publishes secure configuration baselines and assessment tools. Its [ScubaGear](https://github.com/cisagov/ScubaGear) project covers Microsoft 365; [ScubaGoggles](https://github.com/cisagov/ScubaGoggles) covers Google Workspace. ScubaTank is an independent tool for correlating selected saved findings and identity evidence across Microsoft cloud and Active Directory. It joins stable AD identity, group membership, and host authority to cloud roles and grants using verified identity links.

ScubaTank imports only consolidated ScubaGear 1.8.0 JSON, saved BloodHound CE 9.7.1 processed `POST /api/v2/graphs/cypher` responses with `include_properties: true`, and dated ScubaTank 1.0.0 operator evidence. It preserves upstream baseline findings and evaluates six bounded hybrid correlations. It does not import ScubaGoggles, raw SharpHound ZIPs, raw AzureHound JSON, or perform live collection.

## Quick demo

Use Python 3.12 (the tested Windows version) and Windows PowerShell 5.1 or PowerShell 7. From the repository root, run:

```powershell
.\scripts\Demo.ps1
```

On first run, the script creates `.venv`, installs the hash-locked Python packages, and downloads the hash-verified OPA 1.21.1 binary. This setup needs network access. Later runs can skip setup:

```powershell
.\scripts\Demo.ps1 -SkipBootstrap
```

The demo uses synthetic evidence. It writes `report.html`, `report.json`, `findings.csv`, and `report.md` to `.build/demo/reports`, with the bundle and assessment beside that directory. The supplied fixture produces six Fail, one Pass, and five Unknown decisions, grouped into four suggested actions. These are fixture results, not results from a live organization. Check the generated files and open the HTML report with:

```powershell
Get-ChildItem .build\demo\reports
Invoke-Item .build\demo\reports\report.html
```

## Use your own saved evidence

Keep authorized real exports in the ignored repository-root directory `private-input`; generated bundles, assessments, and reports go in the ignored `private-output` directory. Create a manifest from [`fixtures/demo/manifest.json`](fixtures/demo/manifest.json), then set `synthetic` to `false` and provide the producer version, scope, collection times, completeness metadata, and source file paths. The importer computes SHA-256 digests when you do not provide them. See [Import formats](docs/import-formats.md) for the accepted fields and evidence requirements, and [source pins](docs/source-pins.json) for publisher versions and digests.

From the repository root, import and assess the manifest, retaining the original files so validation can reconstruct the bundle:

```powershell
Import-Module .\PowerShell\ScubaTank\ScubaTank.psd1
Get-ScubaTankPlan

Import-ScubaTankEvidence -ManifestPath .\private-input\manifest.json `
    -OutputPath .\private-output\bundle.json
Test-ScubaTankEvidence -Path .\private-output\bundle.json `
    -EvidenceRoot .\private-input
Invoke-ScubaTankAssessment -BundlePath .\private-output\bundle.json `
    -EvidenceRoot .\private-input -OutputPath .\private-output\assessment.json `
    -OpaPath .\.build\tools\opa.exe
Export-ScubaTankReport -AssessmentPath .\private-output\assessment.json `
    -OutputDirectory .\private-output\reports

Get-ChildItem .\private-output\reports
Invoke-Item .\private-output\reports\report.html
```

`Demo.ps1` performs setup. For a separate setup step, run `.\scripts\Bootstrap.ps1` before these commands. Import and assessment use local files and make no network requests. By default, evidence is evaluated against the current time with a 24-hour maximum age; missing, stale, conflicting, or out-of-scope evidence remains Unknown. A password-reset path does not establish MFA bypass, and one Conditional Access exclusion does not establish an effective bypass. For the equivalent Python CLI, use `.\.venv\Scripts\python.exe -m scubatank --help` on Windows after setup, or `.venv/bin/python` on Linux after installing locked dependencies. The Python/OPA core is exercised in Ubuntu 24.04 CI; this does not establish support for live collection on Linux. macOS is untested.

## Tests

After running `Demo.ps1` or `Bootstrap.ps1` for the locked Python dependencies and OPA, install the pinned Pester 5.7.1 test dependency. Then run the checks for the installed PowerShell shells and Python environment:

```powershell
.\scripts\Install-TestTools.ps1
powershell.exe -NoProfile -File scripts\Test.ps1
pwsh.exe -NoProfile -File scripts\Test.ps1
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py' -v
.\.venv\Scripts\python.exe tools\catalog.py
```

`Install-TestTools.ps1` downloads the pinned dependency. Run only the PowerShell command for a shell installed on your machine.

## Implemented correlations

| Check | Implemented evidence path |
| --- | --- |
| `ST.CORR.IDENTITY.001` | Effective AD password-reset authority to a verified synced account with an active privileged cloud role and an applicable AD password flow |
| `ST.CORR.IDENTITY.003` | The same verified identity has resolved AD control-plane membership and an active privileged cloud role |
| `ST.CORR.SYNC.001` | An unapproved local administrator controls a confirmed synchronization host linked to the assessed tenant |
| `ST.CORR.GROUP.001` | An AD membership editor controls a verified synced group with a supported sensitive application/resource grant |
| `ST.CORR.GROUP.006` | A source-group edit changes an explicitly reviewed prospective MFA policy scenario, with no effective restoring policy |
| `ST.CORR.APPLICATION.001` | A source-account reset path reaches an application owner with evidenced usable credential-write capability and sensitive app-only grants |

The catalog contains 100 correlation and 32 posture specifications; the other 126 entries are not detectors and do not appear as assessment results. ScubaGear findings remain separate from ScubaTank's six implemented correlations. Missing facts, conflicting stable identities, stale evidence, or incomplete scope produce Unknown; a Pass disproves one scoped predicate with complete required evidence. Overall coverage is partial.

The manifest and normalized bundle use versioned schemas. Assessment reconstructs the bundle from the original manifest and files; edited normalized records fail that comparison. The importer retains source records, hashes, collection times, versions, exclusions, and evidence pointers. It does not execute imported content or fetch URLs from it. Sensitive real exports belong outside Git. See [report contract](docs/report-contract.md) and [rule review](docs/rule-review.md).

ScubaTank is an independent project maintained by Lee Payton. Product names identify sources and do not imply endorsement. See [third-party notices](THIRD_PARTY_NOTICES.md) for licenses and notices.
