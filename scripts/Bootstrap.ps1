<#
.SYNOPSIS
Create a repository-local Python environment and verify the pinned OPA runtime.
.DESCRIPTION
This is the explicit dependency setup step. It may download packages and OPA from
the pinned sources. Import, validation, assessment, and reporting never install tools.
#>
[CmdletBinding()]
param(
    [string]$PythonPath = 'python',
    [string]$EnvironmentPath,
    [string]$ToolsDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrWhiteSpace($EnvironmentPath)) { $EnvironmentPath = Join-Path $repoRoot '.venv' }
if ([string]::IsNullOrWhiteSpace($ToolsDirectory)) { $ToolsDirectory = Join-Path $repoRoot '.build/tools' }
$EnvironmentPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($EnvironmentPath)
$ToolsDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ToolsDirectory)
$python = Get-Command -Name $PythonPath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $python) { throw "Python executable was not found: $PythonPath. Install Python 3.12 first." }
$requirements = Join-Path $repoRoot 'requirements.lock'
if (-not (Test-Path -LiteralPath $requirements -PathType Leaf)) { throw 'requirements.lock is missing. Dependency setup cannot use unpinned packages.' }
& $python.Source '-c' 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)'
if ($LASTEXITCODE -ne 0) { throw 'The ScubaTank assessment workflow requires Python 3.12 or newer; Python 3.12 is tested.' }
$venvPython = Join-Path $EnvironmentPath 'Scripts/python.exe'
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) { $venvPython = Join-Path $EnvironmentPath 'bin/python' }
if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
    & $python.Source '-m' 'venv' $EnvironmentPath
    if ($LASTEXITCODE -ne 0) { throw 'Creating the local Python environment failed.' }
    $venvPython = Join-Path $EnvironmentPath 'Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) { $venvPython = Join-Path $EnvironmentPath 'bin/python' }
}
$lockHash = (Get-FileHash -LiteralPath $requirements -Algorithm SHA256).Hash.ToLowerInvariant()
$markerPath = Join-Path $EnvironmentPath 'scubatank-requirements.sha256'
$installedHash = if (Test-Path -LiteralPath $markerPath -PathType Leaf) { (Get-Content -LiteralPath $markerPath -Raw).Trim() } else { '' }
Push-Location -LiteralPath $repoRoot
try {
    if ($installedHash -ne $lockHash) {
        & $venvPython '-m' 'pip' 'install' '--disable-pip-version-check' '--require-hashes' '--only-binary=:all:' '-r' $requirements | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Pinned Python dependency installation failed. No readiness marker was written.' }
    }
    & $venvPython '-m' 'pip' 'check' | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'The local Python environment has inconsistent dependencies.' }
    & $venvPython '-m' 'scubatank.bootstrap' '--output-dir' $ToolsDirectory | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Pinned OPA setup or verification failed.' }
    Set-Content -LiteralPath $markerPath -Value $lockHash -Encoding ASCII
}
finally { Pop-Location }
[pscustomobject]@{ PythonPath = $venvPython; ToolsDirectory = $ToolsDirectory; RequirementsSha256 = $lockHash }
