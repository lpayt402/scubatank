# Run ScubaTank on Windows

ScubaTank reads saved, authorized exports and writes local assessment reports. It does not connect to a tenant, domain, or BloodHound server. The six implemented correlations have synthetic tests; no live-environment validation is claimed. The remaining catalog entries describe future checks.

Python 3.12, Windows PowerShell 5.1, and PowerShell 7 are the Windows test targets. Install Python from [python.org](https://www.python.org/downloads/windows/) if it is absent. The repository-local environment keeps project packages separate from other tools. The assessment workflow requires Python 3.12 or newer; later versions are not part of the recorded Windows test result. The catalog compiler's earlier Python 3.10 requirement does not apply to the assessment workflow.

## Run the demonstration

From the repository directory:

```powershell
.\scripts\Demo.ps1
```

The first run creates `.venv`, installs the exact packages and hashes in `requirements.lock`, and downloads the pinned OPA binary with its recorded digest. Only this explicit bootstrap step uses the network. The demo imports synthetic producer-shaped evidence, evaluates the implemented rules, and writes reports under `.build/demo`. The fixture is test data, not an assessment of a real organization.

After setup, run without dependency installation:

```powershell
.\scripts\Demo.ps1 -SkipBootstrap -OutputDirectory .build\offline-demo
```

For a machine whose script policy blocks local scripts, use a process-only invocation:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\Demo.ps1
```

This does not change the machine or user execution policy. Python and OPA setup must have completed before the offline option can run. Live ScubaGear or BloodHound-family collection remains a separate, authorized operator activity.

## Import and assess saved evidence

Keep real exports on local disk and outside Git, such as `private-input`. The manifest records the accepted adapter version, producer version, scope, source files, timestamps, and evidence hashes. See [the import formats](import-formats.md) for the supported formats and their limitations.

```powershell
Import-Module .\PowerShell\ScubaTank\ScubaTank.psd1
Get-ScubaTankPlan
Get-ScubaTankProvider

Import-ScubaTankEvidence -ManifestPath .\private-input\manifest.json `
    -OutputPath .\private-output\bundle.json
Test-ScubaTankEvidence -Path .\private-output\bundle.json `
    -EvidenceRoot .\private-input
Invoke-ScubaTankAssessment -BundlePath .\private-output\bundle.json `
    -EvidenceRoot .\private-input -OutputPath .\private-output\assessment.json `
    -OpaPath .\.build\tools\opa.exe
Export-ScubaTankReport -AssessmentPath .\private-output\assessment.json `
    -OutputDirectory .\private-output\reports
```

Import, validation, assessment, and report commands do not install dependencies or make network requests. They invoke `.venv\Scripts\python.exe` when present; `-PythonPath` selects an existing interpreter explicitly. Paths with spaces are passed as separate arguments. Report contents are never treated as commands.

Supply `-EvidenceRoot` during validation and assessment to recheck the retained source bytes. Structural validation alone does not verify the original evidence. An assessment without those bytes remains Unknown for raw integrity. Missing facts, conflicting stable identities, stale evidence, and mismatched scope also remain visible. Password-reset authority does not establish MFA bypass; one Conditional Access exclusion does not establish effective-policy bypass.

Assessment defaults to a 24-hour evidence window. `-AsOf '2026-10-02T12:00:00Z' -MaxAgeHours 12` supplies an explicit evaluation time and age limit. Use a consistent time for reproducible comparisons, and retain the original exports with the generated reports.

## Run the development checks

Download the pinned Pester test dependency into local build storage, then run the suite in each installed shell:

```powershell
.\scripts\Install-TestTools.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\Test.ps1
pwsh -NoProfile -File scripts\Test.ps1
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py' -v
.\.venv\Scripts\python.exe tools\catalog.py
```

`Install-TestTools.ps1` verifies the Pester 5.7.1 package SHA256 before extracting it. It does not install a global PowerShell module. The tests do not need registry access.

The hosted workflow uses literal `powershell` and `pwsh` steps. The earlier run [37002563734](https://github.com/lpayt402/ScubaTank-prep/actions/runs/37002563734) failed before jobs existed: the previous `shell: ${{ matrix.shell }}` expression uses an unavailable context at that location. Actionlint 1.7.12 reproduced the error at line 28; the corrected workflow passes its syntax check. [Validation](validation.md) records the successful hosted runs and their tested commits.

The Python core is also exercised by the Linux CI job. This does not establish Linux support for ScubaGear collection or for every provider listed in the catalog.
