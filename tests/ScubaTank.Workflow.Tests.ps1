BeforeAll {
    $RepoRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $RepoRoot 'PowerShell/ScubaTank/ScubaTank.psd1') -Force
}

Describe 'ScubaTank offline workflow arguments' {
    BeforeEach {
        Mock Invoke-ScubaTankPython { $Arguments } -ModuleName ScubaTank
    }

    It 'passes import paths as separate arguments including shell punctuation' {
        $manifest = 'C:\evidence with spaces\tenant;$(whoami).json'
        $output = 'C:\assessment output\bundle.json'
        $arguments = @(Import-ScubaTankEvidence -ManifestPath $manifest -OutputPath $output)
        $arguments.Count | Should -Be 5
        $arguments[0] | Should -Be 'import'
        $arguments[2] | Should -Be $manifest
        $arguments[4] | Should -Be $output
    }

    It 'can validate with the source root for hash rechecks' {
        $arguments = @(Test-ScubaTankEvidence -Path 'bundle.json' -EvidenceRoot 'C:\authorized exports')
        $arguments | Should -Contain '--evidence-root'
        $arguments[-1] | Should -Be 'C:\authorized exports'
    }

    It 'passes evaluation time, age, and pinned OPA explicitly' {
        $arguments = @(Invoke-ScubaTankAssessment -BundlePath 'bundle.json' -OutputPath 'assessment.json' -AsOf '2026-10-02T12:00:00Z' -MaxAgeHours 12 -OpaPath 'C:\tools\opa.exe')
        $arguments | Should -Contain '--as-of'
        $arguments | Should -Contain '--max-age-hours'
        $arguments | Should -Contain '--opa'
        $arguments[-1] | Should -Be 'C:\tools\opa.exe'
    }

    It 'rejects an invalid evidence age before running a process' {
        { Invoke-ScubaTankAssessment -BundlePath 'bundle.json' -OutputPath 'assessment.json' -MaxAgeHours 0 } | Should -Throw
        Should -Invoke Invoke-ScubaTankPython -ModuleName ScubaTank -Times 0 -Exactly
    }

    It 'rejects a UNC import path before opening a source or running a process' {
        { Import-ScubaTankEvidence -ManifestPath '\\uncontacted.invalid\share\manifest.json' -OutputPath 'bundle.json' } | Should -Throw '*local*'
        Should -Invoke Invoke-ScubaTankPython -ModuleName ScubaTank -Times 0 -Exactly
    }

    It 'passes assessment and report directory separately' {
        $arguments = @(Export-ScubaTankReport -AssessmentPath 'assessment.json' -OutputDirectory 'C:\reports with spaces')
        $arguments | Should -Contain '--assessment'
        $arguments[-1] | Should -Be 'C:\reports with spaces'
    }

    It 'passes demo output and an explicit pinned evaluator' {
        $arguments = @(Invoke-ScubaTankDemo -OutputDirectory 'C:\demo output' -OpaPath 'C:\tools\opa.exe')
        $arguments[0] | Should -Be 'demo'
        $arguments[-1] | Should -Be 'C:\tools\opa.exe'
    }
}

Describe 'ScubaTank native process failures' {
    It 'reports a missing Python executable without installing anything' {
        { Test-ScubaTankEvidence -Path 'missing.json' -PythonPath (Join-Path $TestDrive 'no-python.exe') } | Should -Throw '*Python*'
    }

    It 'restores the current directory after a Python error' {
        $before = (Get-Location).Path
        { Test-ScubaTankEvidence -Path (Join-Path $TestDrive 'missing.json') } | Should -Throw
        (Get-Location).Path | Should -Be $before
    }
}

Describe 'ScubaTank pinned dependency setup' {
    It 'returns one setup object without mixing process progress into its pipeline' {
        # This suite requires explicit bootstrap first; tests must not install dependencies.
        Test-Path -LiteralPath (Join-Path $RepoRoot '.venv/scubatank-requirements.sha256') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $RepoRoot '.build/tools/opa.exe') | Should -BeTrue
        $installedHash = (Get-Content -LiteralPath (Join-Path $RepoRoot '.venv/scubatank-requirements.sha256') -Raw).Trim()
        $lockHash = (Get-FileHash -LiteralPath (Join-Path $RepoRoot 'requirements.lock') -Algorithm SHA256).Hash.ToLowerInvariant()
        $installedHash | Should -Be $lockHash
        $setup = @(& (Join-Path $RepoRoot 'scripts/Bootstrap.ps1'))
        $setup.Count | Should -Be 1
        Test-Path -LiteralPath $setup[0].PythonPath -PathType Leaf | Should -BeTrue
        $setup[0].RequirementsSha256 | Should -Match '^[0-9a-f]{64}$'
    }
}

Describe 'ScubaTank end-to-end offline operator workflow' {
    BeforeAll {
        $exports = Join-Path $TestDrive 'exports with spaces;$(ignored)'
        $bundlePath = Join-Path $TestDrive 'bundle with spaces;$(ignored).json'
        $assessmentPath = Join-Path $TestDrive 'assessment with spaces;$(ignored).json'
        $reportDirectory = Join-Path $TestDrive 'reports with spaces;$(ignored)'
        $opaPath = Join-Path $RepoRoot '.build/tools/opa.exe'
        Copy-Item -LiteralPath (Join-Path $RepoRoot 'fixtures/demo') -Destination $exports -Recurse
        Import-ScubaTankEvidence -ManifestPath (Join-Path $exports 'manifest.json') -OutputPath $bundlePath | Out-Null
    }

    It 'imports and rechecks literal file paths with spaces and shell punctuation' {
        Test-Path -LiteralPath $bundlePath -PathType Leaf | Should -BeTrue
        { Test-ScubaTankEvidence -Path $bundlePath -EvidenceRoot $exports | Out-Null } | Should -Not -Throw
        $bundle = Get-Content -LiteralPath $bundlePath -Raw -Encoding UTF8 | ConvertFrom-Json
        $bundle.synthetic | Should -BeTrue
        $bundle.sources.Count | Should -Be 3
    }

    It 'assesses only the six implemented rule IDs while retaining incomplete cases' {
        Invoke-ScubaTankAssessment -BundlePath $bundlePath -EvidenceRoot $exports -OutputPath $assessmentPath -AsOf '2026-10-02T08:00:00Z' -OpaPath $opaPath | Out-Null
        $assessment = Get-Content -LiteralPath $assessmentPath -Raw -Encoding UTF8 | ConvertFrom-Json
        @($assessment.findings | Select-Object -ExpandProperty check_id -Unique).Count | Should -Be 6
        @($assessment.findings | Where-Object status -eq 'Fail').Count | Should -BeGreaterThan 0
        @($assessment.findings | Where-Object status -eq 'Pass').Count | Should -BeGreaterThan 0
        @($assessment.findings | Where-Object status -eq 'Unknown').Count | Should -BeGreaterThan 0
        @($assessment.findings | Where-Object status -eq 'NotImplemented').Count | Should -Be 0
    }

    It 'keeps findings Unknown when original source bytes are not reverified' {
        $unverifiedPath = Join-Path $TestDrive 'unverified assessment.json'
        Invoke-ScubaTankAssessment -BundlePath $bundlePath -OutputPath $unverifiedPath -AsOf '2026-10-02T08:00:00Z' -OpaPath $opaPath | Out-Null
        $assessment = Get-Content -LiteralPath $unverifiedPath -Raw -Encoding UTF8 | ConvertFrom-Json
        @($assessment.findings | Where-Object status -ne 'Unknown').Count | Should -Be 0
        @($assessment.findings | Where-Object { ($_.missing_evidence -join ' ') -match 'Original evidence has not been reverified' }).Count | Should -Be $assessment.findings.Count
    }

    It 'writes readable reports whose findings preserve the assessment run ID' {
        # Each test can run by itself; create an assessment explicitly here.
        Invoke-ScubaTankAssessment -BundlePath $bundlePath -EvidenceRoot $exports -OutputPath $assessmentPath -AsOf '2026-10-02T08:00:00Z' -OpaPath $opaPath | Out-Null
        Export-ScubaTankReport -AssessmentPath $assessmentPath -OutputDirectory $reportDirectory | Out-Null
        foreach ($file in @('report.json', 'report.html', 'findings.csv', 'report.md')) {
            Test-Path -LiteralPath (Join-Path $reportDirectory $file) -PathType Leaf | Should -BeTrue
        }
        $report = Get-Content -LiteralPath (Join-Path $reportDirectory 'report.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        @($report.findings | Where-Object { $_.run_id -ne $report.run_id }).Count | Should -Be 0
        @($report.findings | Select-Object -ExpandProperty check_id -Unique).Count | Should -Be 6
        (Get-Content -LiteralPath (Join-Path $reportDirectory 'report.html') -Raw -Encoding UTF8) | Should -Match 'Synthetic demonstration'
    }
}
