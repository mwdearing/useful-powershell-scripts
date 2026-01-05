# ============================================
#        WINDOWS CLEANUP SUITE (ENHANCED)
# ============================================

# -----------------------------
#  LOGGING SYSTEM
# -----------------------------

$Global:LogPath = "C:\CleanupSuite"
$Global:LogFile = "$LogPath\cleanup.log"

if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp  $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

Write-Log "=== Cleanup Suite Started ==="

# -----------------------------
#  BASIC CLEANUP FUNCTIONS
# -----------------------------

function Clear-TempFiles {
    Write-Host "`n[Temp Cleanup] Removing temporary files..." -ForegroundColor Cyan
    Write-Log "Clearing temporary files"

    $paths = @(
        "$env:TEMP\*",
        "C:\Windows\Temp\*"
    )

    foreach ($p in $paths) {
        try {
            Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Deleted temp path: $p"
        } catch {
            Write-Log "Failed to delete: $p"
        }
    }

    Write-Host "Temporary files cleared.`n" -ForegroundColor Green
}

function Clear-BrowserCaches {
    Write-Host "`n[Browser Cleanup] Clearing browser caches..." -ForegroundColor Cyan
    Write-Log "Clearing browser caches"

    $paths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*",
        "$env:APPDATA\Mozilla\Firefox\Profiles\*\cache2\*"
    )

    foreach ($p in $paths) {
        try {
            Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Deleted browser cache: $p"
        } catch {
            Write-Log "Failed to delete: $p"
        }
    }

    Write-Host "Browser caches cleared.`n" -ForegroundColor Green
}

function Run-ComponentCleanup {
    Write-Host "`n[Windows Update Cleanup] Running DISM cleanup..." -ForegroundColor Cyan
    Write-Log "Running DISM component cleanup"

    Dism.exe /online /Cleanup-Image /StartComponentCleanup | Out-Null

    Write-Host "Component cleanup complete.`n" -ForegroundColor Green
    Write-Log "DISM cleanup completed"
}

# -----------------------------
#  LARGE FILE SCANNER
# -----------------------------

function Find-LargeFiles {
    Write-Host "`n[Large File Scanner] Searching for large files..." -ForegroundColor Cyan
    Write-Log "Scanning for large files"

    $ExcludedDirs = @(
        "C:\Windows",
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\ProgramData",
        "C:\$Recycle.Bin",
        "C:\Recovery",
        "C:\System Volume Information"
    )

    $results = Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            -not ($_.Attributes -match "System") -and
            -not ($_.Attributes -match "Hidden") -and
            ($ExcludedDirs -notcontains $_.DirectoryName)
        } |
        Select-Object FullName,
                      @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}},
                      LastWriteTime |
        Sort-Object SizeMB -Descending |
        Select-Object -First 50

    $results | Format-Table -AutoSize

    Write-Host "`nLarge file scan complete.`n" -ForegroundColor Green
    Write-Log "Large file scan completed"
}

# -----------------------------
#  FULL SYSTEM CLEANUP
# -----------------------------

function Full-SystemCleanup {
    Write-Host "`n[Full Cleanup] Running full system cleanup..." -ForegroundColor Cyan
    Write-Log "Running full system cleanup"

    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\SoftwareDistribution\DeliveryOptimization\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue

    Clear-RecycleBin -Force -ErrorAction SilentlyContinue

    Write-Host "Full system cleanup completed.`n" -ForegroundColor Green
    Write-Log "Full system cleanup completed"
}

# -----------------------------
#  JUNK FILE PATTERN SCANNER
# -----------------------------

function Junk-FileScanner {
    Write-Host "`n[Junk Scanner] Searching for junk files..." -ForegroundColor Cyan
    Write-Log "Running junk file pattern scan"

    $patterns = @("*.tmp","*.bak","*.old","*.log","*.dmp","*.err","*.chk","*.gid","*.~*","*.temp")

    $results = foreach ($pattern in $patterns) {
        Get-ChildItem -Path "C:\" -Recurse -Include $pattern -File -ErrorAction SilentlyContinue
    }

    if ($results) {
        Write-Host "`nFound junk files:" -ForegroundColor Yellow
        $results | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize

        Write-Log "Junk files found: $($results.Count)"

        $confirm = Read-Host "Delete ALL junk files? (Y/N)"
        if ($confirm -in @('Y','y')) {
            foreach ($file in $results) {
                try {
                    Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                    Write-Log "Deleted junk file: $($file.FullName)"
                } catch {
                    Write-Log "Failed to delete junk file: $($file.FullName)"
                }
            }
        }
    } else {
        Write-Host "No junk files found." -ForegroundColor Green
        Write-Log "No junk files found"
    }
}

# -----------------------------
#  STARTUP ANALYZER
# -----------------------------

function Startup-Analyzer {
    Write-Host "`n[Startup Analyzer] Collecting startup entries..." -ForegroundColor Cyan
    Write-Log "Running startup analyzer"

    Write-Host "`n--- Registry Startup Items ---" -ForegroundColor Yellow
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            Get-ItemProperty $path | Select-Object * | Format-List
        }
    }

    Write-Host "`n--- Startup Folder Items ---" -ForegroundColor Yellow
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"

    Write-Host "`n--- Scheduled Tasks (Non-Microsoft) ---" -ForegroundColor Yellow
    Get-ScheduledTask | Where-Object { $_.TaskName -notlike "Microsoft*" } |
        Select-Object TaskName, TaskPath, State | Format-Table -AutoSize

    Write-Host "`n--- Auto-Start Services ---" -ForegroundColor Yellow
    Get-Service | Where-Object { $_.StartType -eq "Automatic" } |
        Select-Object Name, DisplayName, Status | Format-Table -AutoSize

    Write-Log "Startup analyzer completed"
}

# -----------------------------
#  REGISTRY CLEANUP
# -----------------------------

function Registry-Cleanup {
    $name = Read-Host "Enter software name for registry cleanup"
    if (-not $name) { return }

    Write-Log "Registry cleanup for: $name"

    $paths = @(
        "HKCU:\Software",
        "HKLM:\Software",
        "HKLM:\Software\WOW6432Node"
    )

    $keys = @()

    foreach ($path in $paths) {
        try {
            Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -like "*$name*") { $keys += $_.PSPath }
            }
        } catch {}
    }

    if (-not $keys) {
        Write-Host "No registry keys found for '$name'." -ForegroundColor Yellow
        Write-Log "No registry keys found for $name"
        return
    }

    Write-Host "`nFound registry keys:" -ForegroundColor Green
    $keys | ForEach-Object { Write-Host $_ }

    $confirm = Read-Host "Delete ALL these keys? (Y/N)"
    if ($confirm -notin @('Y','y')) { return }

    foreach ($key in $keys) {
        try {
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Deleted registry key: $key"
        } catch {
            Write-Log "Failed to delete registry key: $key"
        }
    }
}

# -----------------------------
#  DEEP UNINSTALL (UPDATED)
# -----------------------------

function Deep-Uninstall {
    $name = Read-Host "Enter software name for deep uninstall"
    if (-not $name) { return }

    Write-Host "`n[Deep Uninstall] Searching for uninstallers..." -ForegroundColor Cyan
    Write-Log "Deep uninstall initiated for: $name"

    # -----------------------------
    # 1. RUN OFFICIAL UNINSTALLER
    # -----------------------------

    $uninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $uninstallEntries = foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem $path -ErrorAction SilentlyContinue |
                Get-ItemProperty |
                Where-Object { $_.DisplayName -like "*$name*" }
        }
    }

    $appxEntries = Get-AppxPackage | Where-Object { $_.Name -like "*$name*" }

    if ($uninstallEntries -or $appxEntries) {
        Write-Host "`nFound uninstallable programs:" -ForegroundColor Green

        foreach ($entry in $uninstallEntries) {
            Write-Host "Win32: $($entry.DisplayName)"
        }
        foreach ($app in $appxEntries) {
            Write-Host "Appx:  $($app.Name)"
        }

        $confirmUninstall = Read-Host "Run official uninstallers first? (Y/N)"
        if ($confirmUninstall -in @('Y','y')) {

            foreach ($entry in $uninstallEntries) {
                $quiet = $entry.QuietUninstallString
                $normal = $entry.UninstallString

                if ($quiet) {
                    Write-Host "Running quiet uninstall for $($entry.DisplayName)..." -ForegroundColor Cyan
                    Write-Log "Quiet uninstall: $($entry.DisplayName)"
                    Start-Process "cmd.exe" "/c $quiet" -Wait
                }
                elseif ($normal) {
                    Write-Host "Running uninstall for $($entry.DisplayName)..." -ForegroundColor Cyan
                    Write-Log "Uninstall: $($entry.DisplayName)"
                    Start-Process "cmd.exe" "/c $normal" -Wait
                }
            }

            foreach ($app in $appxEntries) {
                Write-Host "Removing Appx package: $($app.Name)" -ForegroundColor Cyan
                Write-Log "Appx uninstall: $($app.Name)"
                Remove-AppxPackage $app.PackageFullName -ErrorAction SilentlyContinue
            }
        }
    }
    else {
        Write-Host "No official uninstallers found." -ForegroundColor Yellow
        Write-Log "No uninstallers found for $name"
    }

    # -----------------------------
    # 2. REMOVE SERVICES
    # -----------------------------

    Write-Host "`n[Deep Uninstall] Searching for services..." -ForegroundColor Cyan

    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -like "*$name*" -or $_.Name -like "*$name*"
    }

    if ($services) {
        Write-Host "Found services:" -ForegroundColor Green
        $services | Format-Table Name,DisplayName,Status -AutoSize

        $confirmSvc = Read-Host "Disable and delete these services? (Y/N)"
        if ($confirmSvc -in @('Y','y')) {
            foreach ($svc in $services) {
                try { Stop-Service $svc.Name -Force -ErrorAction SilentlyContinue } catch {}
                Set-Service $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
                sc.exe delete $svc.Name | Out-Null
                Write-Log "Deleted service: $($svc.Name)"
            }
        }
    }
    else {
        Write-Host "No services found." -ForegroundColor Yellow
    }

    # -----------------------------
    # 3. REMOVE LEFTOVER FOLDERS
    # -----------------------------

    Write-Host "`n[Deep Uninstall] Searching for leftover folders..." -ForegroundColor Cyan

    $paths = @(
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\ProgramData",
        "C:\Users\$env:USERNAME\AppData\Local",
        "C:\Users\$env:USERNAME\AppData\LocalLow",
        "C:\Users\$env:USERNAME\AppData\Roaming"
    )

    $folders = foreach ($path in $paths) {
        Get-ChildItem $path -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*$name*" }
    }

    if ($folders) {
        Write-Host "Found leftover folders:" -ForegroundColor Green
        $folders | ForEach-Object { Write-Host "  $($_.FullName)" }

        $confirmDirs = Read-Host "Delete ALL these folders? (Y/N)"
        if ($confirmDirs -in @('Y','y')) {
            foreach ($folder in $folders) {
                try {
                    Remove-Item $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Deleted folder: $($folder.FullName)"
                } catch {
                    Write-Log "Failed to delete folder: $($folder.FullName)"
                }
            }
        }
    }
    else {
        Write-Host "No leftover folders found." -ForegroundColor Yellow
    }

    Write-Host "`nDeep uninstall completed." -ForegroundColor Green
    Write-Log "Deep uninstall completed for: $name"
}

# -----------------------------
#  MENU SYSTEM
# -----------------------------

function Show-Menu {
    Clear-Host
    Write-Host "========== WINDOWS CLEANUP SUITE ==========" -ForegroundColor Cyan
    Write-Host "1. Full System Cleanup"
    Write-Host "2. Temp File Cleanup"
    Write-Host "3. Browser Cache Cleanup"
    Write-Host "4. Windows Update Component Cleanup"
    Write-Host "5. Find Large Files"
    Write-Host "6. Junk File Pattern Scanner"
    Write-Host "7. Startup Analyzer"
    Write-Host "8. Registry Cleanup (by software name)"
    Write-Host "9. Deep Uninstall (services + folders + official uninstall)"
    Write-Host "10. Exit"
    Write-Host "==========================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option (1-10)"

    switch ($choice) {
        '1' { Full-SystemCleanup; Pause }
        '2' { Clear-TempFiles; Pause }
        '3' { Clear-BrowserCaches; Pause }
        '4' { Run-ComponentCleanup; Pause }
        '5' { Find-LargeFiles; Pause }
        '6' { Junk-FileScanner; Pause }
        '7' { Startup-Analyzer; Pause }
        '8' { Registry-Cleanup; Pause }
        '9' { Deep-Uninstall; Pause }
        '10' { Write-Host "Exiting..."; Write-Log "Cleanup Suite exited"; break }
        default { Write-Host "Invalid selection."; Pause }
    }
} while ($true)