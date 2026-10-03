<# .SYNOPSIS
Run the committed PowerShell workflow tests with an already installed Pester 5.7.1.
#>
[CmdletBinding()]
param([string]$PesterModulePath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($PesterModulePath)) {
    $localPester = Join-Path (Split-Path $PSScriptRoot -Parent) '.build/test-tools/Pester/5.7.1/Pester.psd1'
    if (Test-Path -LiteralPath $localPester -PathType Leaf) { Import-Module $localPester -Force }
    else { Import-Module Pester -RequiredVersion 5.7.1 -Force }
}
else { Import-Module $PesterModulePath -Force }
if ((Get-Module Pester).Version -ne [version]'5.7.1') { throw 'The PowerShell test suite requires Pester 5.7.1.' }
$config = New-PesterConfiguration
$config.Run.Path = (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests/ScubaTank.Tests.ps1'), (Join-Path (Split-Path $PSScriptRoot -Parent) 'tests/ScubaTank.Workflow.Tests.ps1')
$config.Run.Exit = $true
$config.Output.Verbosity = 'Detailed'
# These tests exercise local files and processes. No registry tests are needed.
$config.TestRegistry.Enabled = $false
Invoke-Pester -Configuration $config
