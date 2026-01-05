<# 
    Python Cleanup Script
    Removes stale Python uninstall entries, launcher metadata, and leftover directories.
    Safe for systems with multiple Python versions.
#>

Write-Host "`n=== Python Cleanup Script Starting ===`n" -ForegroundColor Cyan

# --- 1. Remove stale uninstall entries ---
$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($path in $uninstallPaths) {
    Write-Host "Scanning: $path" -ForegroundColor Yellow

    Get-ChildItem $path -ErrorAction SilentlyContinue | ForEach-Object {
        $displayName = (Get-ItemProperty $_.PsPath -ErrorAction SilentlyContinue).DisplayName

        if ($displayName -like "Python 3.*") {
            $uninstallString = (Get-ItemProperty $_.PsPath).UninstallString

            # Check if uninstall executable exists
            if ($uninstallString -and -not (Test-Path $uninstallString)) {
                Write-Host "Removing stale entry: $displayName" -ForegroundColor Red
                Remove-Item $_.PsPath -Recurse -Force
            }
        }
    }
}

# --- 2. Remove Python Launcher stale metadata ---
$launcherKey = "HKCU:\Software\Python\PythonCore"
if (Test-Path $launcherKey) {
    Write-Host "`nCleaning Python Launcher metadata..." -ForegroundColor Yellow

    Get-ChildItem $launcherKey | ForEach-Object {
        $installPath = (Get-ItemProperty $_.PsPath).InstallPath

        if ($installPath -and -not (Test-Path $installPath)) {
            Write-Host "Removing stale launcher entry: $($_.PSChildName)" -ForegroundColor Red
            Remove-Item $_.PsPath -Recurse -Force
        }
    }
}

# --- 3. Remove leftover Python directories ---
$pythonDirs = @(
    "$env:LOCALAPPDATA\Programs\Python",
    "C:\Python38",
    "C:\Python39",
    "C:\Program Files\Python38",
    "C:\Program Files\Python39",
    "C:\Program Files (x86)\Python38",
    "C:\Program Files (x86)\Python39"
)

Write-Host "`nChecking for leftover Python directories..." -ForegroundColor Yellow

foreach ($dir in $pythonDirs) {
    if (Test-Path $dir) {
        Write-Host "Deleting leftover directory: $dir" -ForegroundColor Red
        Remove-Item $dir -Recurse -Force
    }
}

Write-Host "`n=== Python Cleanup Complete ===`n" -ForegroundColor Green