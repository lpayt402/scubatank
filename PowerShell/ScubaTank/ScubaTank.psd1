@{
    RootModule = 'ScubaTank.psm1'
    ModuleVersion = '0.2.0'
    GUID = '8c6c5f76-2119-4540-933c-b1ee86cc83d0'
    Author = 'ScubaTank contributors'
    Copyright = '(c) 2026 ScubaTank contributors'
    Description = 'ScubaTank - Trust Assurance and Normalization Kit (TANK). Offline hybrid identity evidence import, bounded synthetic-tested correlations, and local reports. No live collectors.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport = @('Get-ScubaTankCheck', 'Get-ScubaTankProvider', 'Get-ScubaTankPlan', 'Import-ScubaTankEvidence', 'Test-ScubaTankEvidence', 'Invoke-ScubaTankAssessment', 'Export-ScubaTankReport', 'Invoke-ScubaTankDemo')
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
