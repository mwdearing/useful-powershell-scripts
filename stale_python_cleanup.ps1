<# 
    FULL PYTHON REMOVAL SCRIPT
    Completely removes all Python installations, Python Launcher, Python Manager
    metadata, registry entries, PATH variables, and leftover directories.

    This script is designed for "start fresh" scenarios where Python installations
    are broken, partially removed, or conflicting.
#>

Write-Host "`n=== FULL PYTHON REMOVAL STARTED ===`n" -ForegroundColor Cyan

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session (Administrator)."
}

function Invoke-UninstallCommand {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UninstallString
    )

    if ([string]::IsNullOrWhiteSpace($UninstallString)) { return $false }

    $exePath = $null
    $exeArgs = ""

    if ($UninstallString -match '^\s*"([^"]+)"\s*(.*)$') {
        $exePath = $matches[1]
        $exeArgs = $matches[2]
    } elseif ($UninstallString -match '^\s*([^\s]+)\s*(.*)$') {
        $exePath = $matches[1]
        $exeArgs = $matches[2]
    }

    if ([string]::IsNullOrWhiteSpace($exePath)) { return $false }
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        Write-Host "Uninstaller not found on disk: $exePath" -ForegroundColor DarkYellow
        return $false
    }

    $silentArgs = @()
    if ($exeArgs) { $silentArgs += $exeArgs }
    if ($exePath -like "*.msi" -or $exePath -like "*.msix") {
        $silentArgs += "/qn"
    } else {
        $silentArgs += "/quiet"
    }

    $argumentString = ($silentArgs | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join " "

    try {
        Start-Process -FilePath $exePath -ArgumentList $argumentString -Wait -NoNewWindow -ErrorAction Stop | Out-Null
        return $true
    } catch {
        Write-Host "Uninstall process failed: $exePath" -ForegroundColor Red
        return $false
    }
}

# ------------------------------------------------------------
# 1. ATTEMPT NORMAL UNINSTALLS
# ------------------------------------------------------------
# Windows stores uninstall commands in the registry. If the uninstallers still exist,
# this section runs them silently. If the uninstall executable is missing, we skip
# and remove the registry entry later.
Write-Host "Attempting normal uninstalls..." -ForegroundColor Yellow

$uninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($key in $uninstallKeys) {
    Get-ChildItem $key -ErrorAction SilentlyContinue | ForEach-Object {

        $props = Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue

        if ($props.DisplayName -like "Python*" -or $props.DisplayName -like "Python Launcher*") {

            Write-Host "Found uninstall entry: $($props.DisplayName)" -ForegroundColor Yellow

            if ($props.UninstallString) {
                Write-Host "Running uninstall: $($props.UninstallString)" -ForegroundColor DarkYellow
                $success = Invoke-UninstallCommand -UninstallString $props.UninstallString
                if (-not $success) {
                    Write-Host "Uninstall failed or missing EXE — will remove manually." -ForegroundColor Red
                }
            }
        }
    }
}


# ------------------------------------------------------------
# 2. REMOVE LEFTOVER PYTHON DIRECTORIES
# ------------------------------------------------------------
Write-Host "`nRemoving leftover directories..." -ForegroundColor Yellow

$pythonDirs = @(
    "$env:LOCALAPPDATA\Programs\Python",
    "$env:APPDATA\Python",
    "C:\Python27",
    "C:\Python3*",
    "C:\Program Files\Python*",
    "C:\Program Files (x86)\Python*"
)

foreach ($dir in $pythonDirs) {
    Get-ChildItem -Path $dir -ErrorAction SilentlyContinue | ForEach-Object {
        Write-Host "Deleting directory: $($_.FullName)" -ForegroundColor Red
        Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }
}


# ------------------------------------------------------------
# 3. REMOVE PYTHON LAUNCHER (py.exe)
# ------------------------------------------------------------
Write-Host "`nRemoving Python Launcher..." -ForegroundColor Yellow

$launcherFiles = @(
    "C:\Windows\py.exe",
    "C:\Windows\pyw.exe"
)

foreach ($file in $launcherFiles) {
    if (Test-Path $file) {
        Write-Host "Deleting: $file" -ForegroundColor Red
        Remove-Item $file -Force
    }
}


# ------------------------------------------------------------
# 4. CLEAN PYTHON FROM PATH
# ------------------------------------------------------------
Write-Host "`nCleaning PATH entries..." -ForegroundColor Yellow

$pathsToRemove = @("Python", "Python3", "Python38", "Python39", "Python311", "Scripts")

$envTargets = @(
    [System.EnvironmentVariableTarget]::Machine,
    [System.EnvironmentVariableTarget]::User
)

foreach ($target in $envTargets) {

    $path = [System.Environment]::GetEnvironmentVariable("PATH", $target)

    if ($path) {
        $newPath = $path.Split(";") | Where-Object {
            if ([string]::IsNullOrWhiteSpace($_)) { return $false }
            $keep = $true
            foreach ($remove in $pathsToRemove) {
                if ($_ -like "*$remove*") { $keep = $false }
            }
            $keep
        } | Select-Object -Unique

        $newPath = $newPath -join ";"

        if ($newPath -ne $path) {
            Write-Host "PATH cleaned for $target" -ForegroundColor Green
            [System.Environment]::SetEnvironmentVariable("PATH", $newPath, $target)
        }
    }
}


# ------------------------------------------------------------
# 5. REMOVE PYTHON MANAGER / PYTHONCORE REGISTRY ENTRIES
# ------------------------------------------------------------
# This is the part you asked to integrate.
# These keys are what make "Python Manager" or the launcher think Python is still installed.
Write-Host "`nRemoving Python Manager (PythonCore) metadata..." -ForegroundColor Yellow

$pythonCoreKeys = @(
    "HKCU:\Software\Python\PythonCore",
    "HKLM:\Software\Python\PythonCore",
    "HKLM:\Software\WOW6432Node\Python\PythonCore"
)

foreach ($key in $pythonCoreKeys) {
    if (Test-Path $key) {
        Write-Host "Deleting PythonCore metadata: $key" -ForegroundColor Red
        Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
    }
}


# ------------------------------------------------------------
# 6. REMOVE ANY REMAINING PYTHON REGISTRY ROOTS
# ------------------------------------------------------------
Write-Host "`nCleaning remaining Python registry roots..." -ForegroundColor Yellow

$regPaths = @(
    "HKCU:\Software\Python",
    "HKLM:\Software\Python",
    "HKLM:\Software\WOW6432Node\Python"
)

foreach ($reg in $regPaths) {
    if (Test-Path $reg) {
        Write-Host "Deleting registry key: $reg" -ForegroundColor Red
        Remove-Item $reg -Recurse -Force -ErrorAction SilentlyContinue
    }
}


# ------------------------------------------------------------
# 7. VERIFY PYTHON IS GONE
# ------------------------------------------------------------
Write-Host "`nVerifying removal..." -ForegroundColor Yellow

$commands = @("python", "py", "pip")

foreach ($cmd in $commands) {
    Write-Host "`nChecking: $cmd" -ForegroundColor DarkYellow
    try {
        & $cmd --version
    } catch {
        Write-Host "$cmd not found (expected)" -ForegroundColor Green
    }
}

Write-Host "`n=== PYTHON REMOVAL COMPLETE ===`n" -ForegroundColor Green
