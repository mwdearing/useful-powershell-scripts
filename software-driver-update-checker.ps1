<#
.SYNOPSIS
Checks for and installs available software and driver updates using common Windows update channels.

.DESCRIPTION
This script can update software/drivers from:
- Winget (if installed)
- Chocolatey (if installed)
- Windows Update / Microsoft Update API (software + driver updates)

By default, the script performs updates. Use -AuditOnly for a read-only report.

If blocked by an execution-policy signing requirement, the script attempts a self-relaunch with Process-scope ExecutionPolicy Bypass.

.PARAMETER IncludePreview
Include updates flagged as preview/beta when querying the Windows Update API.

.PARAMETER ExportPath
Optional path to export a JSON report.

.PARAMETER AuditOnly
Run checks only and do not install updates.

.EXAMPLE
.\software-driver-update-checker.ps1

Checks and installs available updates from all available channels.

.EXAMPLE
.\software-driver-update-checker.ps1 -AuditOnly -ExportPath .\update-report.json

Runs read-only checks and exports a detailed JSON report.
#>
[CmdletBinding()]
param(
    [switch]$IncludePreview,
    [string]$ExportPath,
    [switch]$AuditOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'


function Invoke-WithExecutionPolicyBypassIfNeeded {
    param(
        [switch]$IncludePreview,
        [string]$ExportPath,
        [switch]$AuditOnly
    )

    if ($env:UPDATE_CHECKER_BYPASS_RELAUNCH -eq '1') {
        return
    }

    $effectivePolicy = Get-ExecutionPolicy
    if ($effectivePolicy -notin @('AllSigned', 'Restricted')) {
        return
    }

    $shellCommand = if (Get-Command -Name 'powershell.exe' -ErrorAction SilentlyContinue) {
        'powershell.exe'
    }
    elseif (Get-Command -Name 'pwsh' -ErrorAction SilentlyContinue) {
        'pwsh'
    }
    else {
        return
    }

    Write-Host "Execution policy '$effectivePolicy' detected. Relaunching with Process-scope bypass..." -ForegroundColor Yellow

    $arguments = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        $PSCommandPath
    )

    if ($IncludePreview) {
        $arguments += '-IncludePreview'
    }
    if ($AuditOnly) {
        $arguments += '-AuditOnly'
    }
    if ($ExportPath) {
        $arguments += @('-ExportPath', $ExportPath)
    }

    $env:UPDATE_CHECKER_BYPASS_RELAUNCH = '1'
    try {
        & $shellCommand @arguments
        $exitCode = if ($LASTEXITCODE -ne $null) { $LASTEXITCODE } else { 0 }
        exit $exitCode
    }
    finally {
        Remove-Item Env:UPDATE_CHECKER_BYPASS_RELAUNCH -ErrorAction SilentlyContinue
    }
}

Invoke-WithExecutionPolicyBypassIfNeeded -IncludePreview:$IncludePreview -ExportPath $ExportPath -AuditOnly:$AuditOnly

function Write-Section {
    param([string]$Title)
    Write-Host "`n=== $Title ===" -ForegroundColor Cyan
}

function Test-CommandAvailable {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Invoke-WingetUpdate {
    param([switch]$AuditOnly)

    if (-not (Test-CommandAvailable -Name 'winget')) {
        return [pscustomobject]@{
            Source            = 'winget'
            Available         = $false
            Checked           = $false
            Updated           = $false
            UpdatesDetected   = $null
            ExitCode          = $null
            Notes             = 'winget is not installed or not in PATH.'
            RawOutput         = @()
        }
    }

    if ($AuditOnly) {
        $output = & winget upgrade --disable-interactivity --accept-source-agreements 2>&1
        $text = ($output | Out-String)
        $hasUpdates = -not ($text -match 'No applicable update found|No installed package found matching input criteria')

        return [pscustomobject]@{
            Source            = 'winget'
            Available         = $true
            Checked           = $true
            Updated           = $false
            UpdatesDetected   = $hasUpdates
            ExitCode          = $LASTEXITCODE
            Notes             = if ($hasUpdates) { 'Updates detected (audit mode).' } else { 'No updates detected (audit mode).' }
            RawOutput         = $output
        }
    }

    $output = & winget upgrade --all --silent --disable-interactivity --accept-package-agreements --accept-source-agreements --include-unknown 2>&1
    $exitCode = $LASTEXITCODE

    return [pscustomobject]@{
        Source            = 'winget'
        Available         = $true
        Checked           = $true
        Updated           = ($exitCode -eq 0)
        UpdatesDetected   = $null
        ExitCode          = $exitCode
        Notes             = if ($exitCode -eq 0) { 'Winget upgrade command completed.' } else { "Winget upgrade command failed with exit code $exitCode." }
        RawOutput         = $output
    }
}

function Invoke-ChocolateyUpdate {
    param([switch]$AuditOnly)

    if (-not (Test-CommandAvailable -Name 'choco')) {
        return [pscustomobject]@{
            Source            = 'chocolatey'
            Available         = $false
            Checked           = $false
            Updated           = $false
            UpdatesDetected   = $null
            ExitCode          = $null
            Notes             = 'Chocolatey is not installed or not in PATH.'
            RawOutput         = @()
        }
    }

    if ($AuditOnly) {
        $output = & choco outdated --limit-output 2>&1
        $text = ($output | Out-String)
        $hasUpdates = -not ($text -match '0 package\(s\) are outdated')

        return [pscustomobject]@{
            Source            = 'chocolatey'
            Available         = $true
            Checked           = $true
            Updated           = $false
            UpdatesDetected   = $hasUpdates
            ExitCode          = $LASTEXITCODE
            Notes             = if ($hasUpdates) { 'Outdated packages detected (audit mode).' } else { 'No outdated Chocolatey packages detected (audit mode).' }
            RawOutput         = $output
        }
    }

    $output = & choco upgrade all -y --no-progress 2>&1
    $exitCode = $LASTEXITCODE

    return [pscustomobject]@{
        Source            = 'chocolatey'
        Available         = $true
        Checked           = $true
        Updated           = ($exitCode -eq 0)
        UpdatesDetected   = $null
        ExitCode          = $exitCode
        Notes             = if ($exitCode -eq 0) { 'Chocolatey upgrade command completed.' } else { "Chocolatey upgrade command failed with exit code $exitCode." }
        RawOutput         = $output
    }
}

function Invoke-WindowsUpdate {
    param(
        [switch]$IncludePreview,
        [switch]$AuditOnly
    )

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()

        $softwareResult = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $driverResult = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Driver'")

        $allUpdates = @()

        for ($i = 0; $i -lt $softwareResult.Updates.Count; $i++) {
            $update = $softwareResult.Updates.Item($i)
            if ($IncludePreview -or ($update.Title -notmatch 'Preview|Beta')) {
                $allUpdates += [pscustomobject]@{ Type = 'Software'; Update = $update; Title = $update.Title }
            }
        }

        for ($i = 0; $i -lt $driverResult.Updates.Count; $i++) {
            $update = $driverResult.Updates.Item($i)
            if ($IncludePreview -or ($update.Title -notmatch 'Preview|Beta')) {
                $allUpdates += [pscustomobject]@{ Type = 'Driver'; Update = $update; Title = $update.Title }
            }
        }

        $softwareTitles = @($allUpdates | Where-Object { $_.Type -eq 'Software' } | Select-Object -ExpandProperty Title)
        $driverTitles = @($allUpdates | Where-Object { $_.Type -eq 'Driver' } | Select-Object -ExpandProperty Title)

        if ($allUpdates.Count -eq 0) {
            return [pscustomobject]@{
                Source                = 'windows-update-api'
                Available             = $true
                Checked               = $true
                Updated               = $false
                UpdatesDetected       = $false
                RebootRequired        = $false
                Notes                 = 'No applicable Windows Update software/driver updates found.'
                SoftwareUpdateCount   = 0
                DriverUpdateCount     = 0
                SoftwareUpdates       = @()
                DriverUpdates         = @()
            }
        }

        if ($AuditOnly) {
            return [pscustomobject]@{
                Source                = 'windows-update-api'
                Available             = $true
                Checked               = $true
                Updated               = $false
                UpdatesDetected       = $true
                RebootRequired        = $false
                Notes                 = 'Updates detected via Windows Update API (audit mode).'
                SoftwareUpdateCount   = $softwareTitles.Count
                DriverUpdateCount     = $driverTitles.Count
                SoftwareUpdates       = $softwareTitles
                DriverUpdates         = $driverTitles
            }
        }

        $collection = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($entry in $allUpdates) {
            [void]$collection.Add($entry.Update)
        }

        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $collection
        $downloadResult = $downloader.Download()

        $installer = $session.CreateUpdateInstaller()
        $installer.Updates = $collection
        $installResult = $installer.Install()

        $hResult = $installResult.HResult
        $updatedOk = ($hResult -eq 0)

        return [pscustomobject]@{
            Source                = 'windows-update-api'
            Available             = $true
            Checked               = $true
            Updated               = $updatedOk
            UpdatesDetected       = $true
            RebootRequired        = [bool]$installResult.RebootRequired
            DownloadResultCode    = [int]$downloadResult.ResultCode
            InstallResultCode     = [int]$installResult.ResultCode
            HResult               = $hResult
            Notes                 = if ($updatedOk) { 'Windows Update API installation completed.' } else { "Windows Update API installation returned HRESULT $hResult." }
            SoftwareUpdateCount   = $softwareTitles.Count
            DriverUpdateCount     = $driverTitles.Count
            SoftwareUpdates       = $softwareTitles
            DriverUpdates         = $driverTitles
        }
    }
    catch {
        return [pscustomobject]@{
            Source                = 'windows-update-api'
            Available             = $false
            Checked               = $false
            Updated               = $false
            UpdatesDetected       = $null
            RebootRequired        = $false
            Notes                 = "Unable to process Windows Update API: $($_.Exception.Message)"
            SoftwareUpdateCount   = $null
            DriverUpdateCount     = $null
            SoftwareUpdates       = @()
            DriverUpdates         = @()
        }
    }
}

Write-Section -Title 'Software and Driver Update Tool'

if (-not (Test-IsAdministrator)) {
    Write-Host 'Warning: Not running as Administrator. Some update channels may fail.' -ForegroundColor Yellow
}

if ($AuditOnly) {
    Write-Host 'Running in read-only audit mode...' -ForegroundColor Yellow
}
else {
    Write-Host 'Checking and installing updates from available channels...' -ForegroundColor Yellow
}

$wingetResult = Invoke-WingetUpdate -AuditOnly:$AuditOnly
$chocoResult = Invoke-ChocolateyUpdate -AuditOnly:$AuditOnly
$wuResult = Invoke-WindowsUpdate -IncludePreview:$IncludePreview -AuditOnly:$AuditOnly

$summary = [pscustomobject]@{
    TimestampUtc            = (Get-Date).ToUniversalTime().ToString('o')
    Mode                    = if ($AuditOnly) { 'AuditOnly' } else { 'Install' }
    WingetChecked           = $wingetResult.Checked
    ChocolateyChecked       = $chocoResult.Checked
    WindowsUpdateChecked    = $wuResult.Checked
    WindowsSoftwareUpdates  = $wuResult.SoftwareUpdateCount
    WindowsDriverUpdates    = $wuResult.DriverUpdateCount
    WindowsRebootRequired   = $wuResult.RebootRequired
}

Write-Section -Title 'Summary'
$summary | Format-List

Write-Section -Title 'Channel Details'
@($wingetResult, $chocoResult, $wuResult) | ForEach-Object {
    Write-Host "[$($_.Source)] $($_.Notes)" -ForegroundColor Green
}

Write-Section -Title 'Windows Update API - Software Updates'
if ($wuResult.SoftwareUpdates.Count -gt 0) {
    $wuResult.SoftwareUpdates | Sort-Object -Unique | ForEach-Object { "- $_" }
}
else {
    Write-Host 'No software updates found (or check unavailable).' -ForegroundColor DarkGray
}

Write-Section -Title 'Windows Update API - Driver Updates'
if ($wuResult.DriverUpdates.Count -gt 0) {
    $wuResult.DriverUpdates | Sort-Object -Unique | ForEach-Object { "- $_" }
}
else {
    Write-Host 'No driver updates found (or check unavailable).' -ForegroundColor DarkGray
}

if ($ExportPath) {
    $report = [pscustomobject]@{
        Summary           = $summary
        Winget            = $wingetResult
        Chocolatey        = $chocoResult
        WindowsUpdateApi  = $wuResult
    }

    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $ExportPath -Encoding UTF8
    Write-Host "`nReport exported to: $ExportPath" -ForegroundColor Cyan
}

if ($wuResult.RebootRequired) {
    Write-Host "`nA reboot is required to finish installing some updates." -ForegroundColor Yellow
}

if ($AuditOnly) {
    Write-Host "`nDone. Audit completed without installing updates." -ForegroundColor Yellow
}
else {
    Write-Host "`nDone. Update operations completed for available channels." -ForegroundColor Yellow
}
