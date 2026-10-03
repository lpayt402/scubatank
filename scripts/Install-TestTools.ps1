<# .SYNOPSIS
Download and verify Pester 5.7.1 into local build storage for development tests.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
$target = Join-Path $repoRoot '.build/test-tools/Pester/5.7.1'
$package = Join-Path $repoRoot '.build/test-tools/Pester.5.7.1.zip'
$digest = '4a27904c6814a5fbe4758f8e49861f6a1994aee77b71165a5c43c0371ba6c580'
New-Item -ItemType Directory -Path (Split-Path $package -Parent) -Force | Out-Null
if (-not (Test-Path -LiteralPath $package -PathType Leaf)) {
    Invoke-WebRequest -UseBasicParsing -Uri 'https://www.powershellgallery.com/api/v2/package/Pester/5.7.1' -OutFile $package
}
if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant() -ne $digest) {
    throw 'Pester 5.7.1 package hash does not match the pinned official package. The module was not imported.'
}
New-Item -ItemType Directory -Path $target -Force | Out-Null
Expand-Archive -LiteralPath $package -DestinationPath $target -Force
Write-Output (Join-Path $target 'Pester.psd1')
