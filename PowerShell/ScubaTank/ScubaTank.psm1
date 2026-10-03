Set-StrictMode -Version Latest
$script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$script:ImplementedChecks = @(
    'ST.CORR.IDENTITY.001', 'ST.CORR.IDENTITY.003', 'ST.CORR.SYNC.001',
    'ST.CORR.GROUP.001', 'ST.CORR.GROUP.006', 'ST.CORR.APPLICATION.001'
)

function Get-ScubaTankCheck {
    <#
    .SYNOPSIS
    Read check specifications. This does not run an assessment.
    .PARAMETER Kind
    Select correlation, posture, or all specifications.
    #>
    [CmdletBinding()]
    param([ValidateSet('all', 'correlation', 'posture')][string]$Kind = 'all')
    $catalog = Join-Path $script:RepoRoot 'catalog'
    foreach ($folder in @('correlation', 'posture')) {
        if ($Kind -ne 'all' -and $Kind -ne $folder) { continue }
        $prefix = if ($folder -eq 'correlation') { 'CORR' } else { 'POST' }
        $files = Get-ChildItem -LiteralPath (Join-Path $catalog $folder) -Filter '*.psv' -File -ErrorAction Stop | Sort-Object Name
        foreach ($file in $files) {
            $area = $file.BaseName.ToUpperInvariant()
            foreach ($row in (Import-Csv -LiteralPath $file.FullName -Delimiter '|' -Encoding UTF8 -ErrorAction Stop)) {
                if ($row.number -notmatch '^\d{3}$' -or [string]::IsNullOrWhiteSpace($row.title)) {
                    throw "Invalid catalog record in $($file.Name). Run the catalog validation tests."
                }
                $row | Add-Member -NotePropertyName Id -NotePropertyValue "ST.$prefix.$area.$($row.number)"
                $row | Add-Member -NotePropertyName Kind -NotePropertyValue $folder
                $implementation = if ($script:ImplementedChecks -contains $row.Id) { 'synthetic-tested' } else { 'specified' }
                $row | Add-Member -NotePropertyName Implementation -NotePropertyValue $implementation
                $row
            }
        }
    }
}

function Get-ScubaTankProvider {
    <# .SYNOPSIS
    List proposed providers and their implementation state. Nothing is installed or executed.
    #>
    [CmdletBinding()]
    param()
    $path = Join-Path $script:RepoRoot 'config/providers.json'
    $config = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $config.providers
}

function Get-ScubaTankPlan {
    <# .SYNOPSIS
    Show implemented offline scope and remaining specifications without contacting a tenant or domain.
    #>
    [CmdletBinding()]
    param()
    [pscustomobject]@{
        Mode = 'Offline evidence import and six bounded correlations; synthetic validation only'
        CorrelationSpecifications = @(Get-ScubaTankCheck -Kind correlation).Count
        PostureSpecifications = @(Get-ScubaTankCheck -Kind posture).Count
        ValidatedDetectors = 0
        SyntheticTestedDetectors = $script:ImplementedChecks.Count
        ImplementedChecks = $script:ImplementedChecks
        LiveValidatedDetectors = 0
        NetworkAccess = $false
        CustomCollectorsApproved = $false
        Providers = @(Get-ScubaTankProvider)
        NextStep = 'Run scripts/Demo.ps1, then import authorized exports using a versioned manifest.'
    }
}

function Resolve-ScubaTankPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    if ($Path.StartsWith('\\') -or $Path.StartsWith('//') -or $Path -match '^\w+://') {
        throw 'ScubaTank offline workflows require local disk paths. Copy authorized evidence from remote shares before importing it.'
    }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Invoke-ScubaTankPython {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$PythonPath
    )
    if ([string]::IsNullOrWhiteSpace($PythonPath)) {
        $venvPython = Join-Path $script:RepoRoot '.venv/Scripts/python.exe'
        $unixPython = Join-Path $script:RepoRoot '.venv/bin/python'
        $PythonPath = if (Test-Path -LiteralPath $venvPython -PathType Leaf) { $venvPython }
            elseif (Test-Path -LiteralPath $unixPython -PathType Leaf) { $unixPython }
            else { 'python' }
    }
    $python = Get-Command -Name $PythonPath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $python) {
        throw "Python executable was not found: $PythonPath. Run scripts/Bootstrap.ps1 with an installed Python 3.12."
    }
    Push-Location -LiteralPath $script:RepoRoot
    try {
        & $python.Source '-m' 'scubatank' @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "ScubaTank $($Arguments[0]) failed with exit code $LASTEXITCODE. Review the preceding diagnostic."
        }
    }
    finally { Pop-Location }
}

function Import-ScubaTankEvidence {
    <# .SYNOPSIS
    Import a versioned evidence manifest offline. Does not install or run collectors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ManifestPath,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [string]$PythonPath
    )
    Invoke-ScubaTankPython -PythonPath $PythonPath -Arguments @('import', '--manifest', (Resolve-ScubaTankPath $ManifestPath), '--output', (Resolve-ScubaTankPath $OutputPath))
}

function Test-ScubaTankEvidence {
    <# .SYNOPSIS
    Validate a normalized bundle. Supply the original evidence root to recheck hashes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path,
        [string]$EvidenceRoot,
        [string]$PythonPath
    )
    $arguments = @('validate', (Resolve-ScubaTankPath $Path))
    if (-not [string]::IsNullOrWhiteSpace($EvidenceRoot)) { $arguments += @('--evidence-root', (Resolve-ScubaTankPath $EvidenceRoot)) }
    Invoke-ScubaTankPython -PythonPath $PythonPath -Arguments $arguments
}

function Invoke-ScubaTankAssessment {
    <# .SYNOPSIS
    Evaluate the six implemented correlations from imported evidence with pinned OPA. No live collection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$BundlePath,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [string]$EvidenceRoot,
        [string]$AsOf,
        [ValidateRange(1, 8760)][int]$MaxAgeHours = 24,
        [string]$OpaPath,
        [string]$PythonPath
    )
    $arguments = @('assess', '--bundle', (Resolve-ScubaTankPath $BundlePath), '--output', (Resolve-ScubaTankPath $OutputPath), '--max-age-hours', [string]$MaxAgeHours)
    if (-not [string]::IsNullOrWhiteSpace($EvidenceRoot)) { $arguments += @('--evidence-root', (Resolve-ScubaTankPath $EvidenceRoot)) }
    if (-not [string]::IsNullOrWhiteSpace($AsOf)) { $arguments += @('--as-of', $AsOf) }
    if (-not [string]::IsNullOrWhiteSpace($OpaPath)) { $arguments += @('--opa', (Resolve-ScubaTankPath $OpaPath)) }
    Invoke-ScubaTankPython -PythonPath $PythonPath -Arguments $arguments
}

function Export-ScubaTankReport {
    <# .SYNOPSIS
    Write local HTML, JSON, CSV, and Markdown reports from an assessment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$AssessmentPath,
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$OutputDirectory,
        [string]$PythonPath
    )
    Invoke-ScubaTankPython -PythonPath $PythonPath -Arguments @('report', '--assessment', (Resolve-ScubaTankPath $AssessmentPath), '--output-dir', (Resolve-ScubaTankPath $OutputDirectory))
}

function Invoke-ScubaTankDemo {
    <# .SYNOPSIS
    Run the deterministic synthetic evidence demonstration. Bootstrap dependencies separately first.
    #>
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()][string]$OutputDirectory = '.build/demo',
        [string]$OpaPath,
        [string]$PythonPath
    )
    $arguments = @('demo', '--output-dir', (Resolve-ScubaTankPath $OutputDirectory))
    if (-not [string]::IsNullOrWhiteSpace($OpaPath)) { $arguments += @('--opa', (Resolve-ScubaTankPath $OpaPath)) }
    Invoke-ScubaTankPython -PythonPath $PythonPath -Arguments $arguments
}

Export-ModuleMember -Function Get-ScubaTankCheck, Get-ScubaTankProvider, Get-ScubaTankPlan, Import-ScubaTankEvidence, Test-ScubaTankEvidence, Invoke-ScubaTankAssessment, Export-ScubaTankReport, Invoke-ScubaTankDemo
