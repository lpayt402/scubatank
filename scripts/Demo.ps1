<# .SYNOPSIS
Set up pinned dependencies, then run the synthetic offline import, assessment, and report demonstration.
#>
[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$PythonPath = 'python',
    [switch]$SkipBootstrap
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) { $OutputDirectory = Join-Path $repoRoot '.build/demo' }
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$toolsDirectory = Join-Path $repoRoot '.build/tools'
$venvPython = Join-Path $repoRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) { $venvPython = Join-Path $repoRoot '.venv/bin/python' }
if (-not $SkipBootstrap) {
    $setup = & (Join-Path $PSScriptRoot 'Bootstrap.ps1') -PythonPath $PythonPath
    $venvPython = $setup.PythonPath
}
elseif (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    throw 'The local Python environment is missing. Run scripts/Bootstrap.ps1 before using -SkipBootstrap.'
}
$opaFile = if ($env:OS -eq 'Windows_NT') { 'opa.exe' } else { 'opa' }
$opaPath = Join-Path $toolsDirectory $opaFile
if (-not (Test-Path -LiteralPath $opaPath -PathType Leaf)) { throw 'The pinned OPA runtime is missing. Run scripts/Bootstrap.ps1 first.' }
Import-Module (Join-Path $repoRoot 'PowerShell/ScubaTank/ScubaTank.psd1') -Force
Invoke-ScubaTankDemo -OutputDirectory $outputPath -PythonPath $venvPython -OpaPath $opaPath
