BeforeAll {
    $RepoRoot = Split-Path $PSScriptRoot -Parent
    Import-Module (Join-Path $RepoRoot 'PowerShell/ScubaTank/ScubaTank.psd1') -Force
}

Describe 'ScubaTank catalog and planning interface' {
    It 'lists the specified scope without running checks' {
        @(Get-ScubaTankCheck).Count | Should -Be 132
        @(Get-ScubaTankCheck -Kind correlation).Count | Should -Be 100
        @(Get-ScubaTankCheck -Kind posture).Count | Should -Be 32
    }
    It 'distinguishes the six synthetic-tested correlations from specifications' {
        @(Get-ScubaTankCheck | Where-Object Implementation -eq 'synthetic-tested').Count | Should -Be 6
        @(Get-ScubaTankCheck | Where-Object Implementation -eq 'specified').Count | Should -Be 126
        @(Get-ScubaTankCheck -Kind posture | Where-Object Implementation -ne 'specified').Count | Should -Be 0
    }
    It 'lists providers but enables no execution' {
        @(Get-ScubaTankProvider).Count | Should -Be 10
        @(Get-ScubaTankProvider | Where-Object execution_enabled).Count | Should -Be 0
    }
    It 'returns a non-executing plan' {
        $plan = Get-ScubaTankPlan
        $plan.NetworkAccess | Should -BeFalse
        $plan.ValidatedDetectors | Should -Be 0
        $plan.LiveValidatedDetectors | Should -Be 0
        $plan.SyntheticTestedDetectors | Should -Be 6
        $plan.CustomCollectorsApproved | Should -BeFalse
    }
    It 'exports planning and offline assessment workflows' {
        $names = @(Get-Command -Module ScubaTank | Select-Object -ExpandProperty Name)
        $names.Count | Should -Be 8
        $names | Should -Contain 'Get-ScubaTankPlan'
        $names | Should -Contain 'Get-ScubaTankProvider'
        $names | Should -Contain 'Get-ScubaTankCheck'
        $names | Should -Contain 'Import-ScubaTankEvidence'
        $names | Should -Contain 'Test-ScubaTankEvidence'
        $names | Should -Contain 'Invoke-ScubaTankAssessment'
        $names | Should -Contain 'Export-ScubaTankReport'
        $names | Should -Contain 'Invoke-ScubaTankDemo'
    }
}
