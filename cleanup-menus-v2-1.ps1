<# 
    WindowsCleanupSuite.ps1
    -----------------------------------------------------------
    A menu-driven Windows maintenance and cleanup suite.

    Features:
      - Logging system
      - Full system cleanup
      - Temp and browser cache cleanup
      - Windows Update component cleanup (DISM)
      - Large file scanner (top 50, avoids system dirs)
      - Junk file pattern scanner
      - Startup analyzer
      - Registry cleanup by software name
      - Deep uninstall helper:
            * Lists installed software
            * Lets you pick one to uninstall
            * Runs official uninstaller
            * Then does deep cleanup of services + folders
      - Hybrid progress system:
            * Write-Progress for measurable loops
            * ASCII bars (including animated) for long/opaque tasks
#>

# ============================================
#  GLOBAL SETTINGS AND LOGGING
# ============================================

# Root folder for logs and future extensions
$Global:SuiteRoot = "C:\CleanupSuite"
$Global:LogFile   = Join-Path $SuiteRoot "cleanup.log"

if (-not (Test-Path $SuiteRoot)) {
    New-Item -ItemType Directory -Path $SuiteRoot | Out-Null
}

function Write-Log {
    <#
        .SYNOPSIS
            Append a timestamped message to the suite log file.

        .PARAMETER Message
            Text to log.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )

    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "$timestamp  $Message" | Out-File -FilePath $LogFile -Append -Encoding utf8
}

Write-Log "=== Cleanup Suite Started ==="

# ============================================
#  PROGRESS UTILITIES (HYBRID SYSTEM)
# ============================================

function Show-AsciiProgress {
    <#
        .SYNOPSIS
            Renders a simple ASCII progress bar in the console.

        .PARAMETER Activity
            Description of the ongoing activity.

        .PARAMETER Percent
            Percentage complete (0-100).
    #>
    param(
        [string]$Activity = "Working",
        [int]$Percent = 0
    )

    if ($Percent -lt 0) { $Percent = 0 }
    if ($Percent -gt 100) { $Percent = 100 }

    $width  = 30
    $filled = [int]([math]::Round($Percent / (100 / $width)))
    $empty  = $width - $filled

    $bar = ('█' * $filled) + ('░' * $empty)
    $line = "[{0}] {1,3}% - {2}" -f $bar, $Percent, $Activity

    # Rewrite the same line
    Write-Host "`r$line" -NoNewline
    if ($Percent -eq 100) {
        Write-Host ""
    }
}

function Show-AnimatedPhase {
    <#
        .SYNOPSIS
            Displays a small animated spinner-style progress indicator.

        .PARAMETER Activity
            Description of current phase.

        .PARAMETER DurationSeconds
            Approximate duration to animate (best-effort).
    #>
    param(
        [string]$Activity = "Processing",
        [int]$DurationSeconds = 10
    )

    $frames = @('|','/','-','\')
    $end = (Get-Date).AddSeconds($DurationSeconds)

    while ((Get-Date) -lt $end) {
        foreach ($f in $frames) {
            $msg = "[ $f ] $Activity"
            Write-Host "`r$msg" -NoNewline
            Start-Sleep -Milliseconds 150
            if ((Get-Date) -ge $end) { break }
        }
    }
    Write-Host "`r[ ✓ ] $Activity`n"
}

# ============================================
#  BASIC CLEANUP FUNCTIONS
# ============================================

function Clear-TempFiles {
    <#
        .SYNOPSIS
            Clears system and user temporary files.

        .DESCRIPTION
            Deletes files from:
                - $env:TEMP
                - C:\Windows\Temp
            Uses Write-Progress to visualize progress through files.
    #>

    Write-Host "`n[Temp Cleanup] Removing temporary files..." -ForegroundColor Cyan
    Write-Log "Clearing temporary files"

    $paths = @(
        "$env:TEMP",
        "C:\Windows\Temp"
    )

    foreach ($basePath in $paths) {
        if (-not (Test-Path $basePath)) { continue }

        $files = Get-ChildItem $basePath -Recurse -File -ErrorAction SilentlyContinue
        $total = $files.Count
        $index = 0

        foreach ($file in $files) {
            $index++
            $percent = if ($total -gt 0) { [int](($index / $total) * 100) } else { 100 }

            Write-Progress -Activity "Clearing temp files" `
                           -Status "Deleting: $($file.FullName)" `
                           -PercentComplete $percent

            try {
                Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                Write-Log "Deleted temp file: $($file.FullName)"
            } catch {
                Write-Log "Failed to delete temp file: $($file.FullName)"
            }
        }
    }

    Write-Progress -Activity "Clearing temp files" -Completed -Status "Done"
    Write-Host "Temporary files cleared.`n" -ForegroundColor Green
}

function Clear-BrowserCaches {
    <#
        .SYNOPSIS
            Clears caches for common browsers.

        .DESCRIPTION
            Targets:
                - Chrome
                - Edge
                - Firefox
            Uses progress based on folder groups.
    #>

    Write-Host "`n[Browser Cleanup] Clearing browser caches..." -ForegroundColor Cyan
    Write-Log "Clearing browser caches"

    $paths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
        "$env:APPDATA\Mozilla\Firefox\Profiles"
    )

    $total = $paths.Count
    $i = 0

    foreach ($p in $paths) {
        $i++
        $percent = [int](($i / $total) * 100)

        Write-Progress -Activity "Clearing browser caches" `
                       -Status "Processing: $p" `
                       -PercentComplete $percent

        if (-not (Test-Path $p)) { continue }

        # Handle Firefox: profiles contain subfolders with cache2
        if ($p -like "*Firefox*Profiles") {
            $profileCaches = Get-ChildItem $p -Directory -ErrorAction SilentlyContinue |
                             ForEach-Object { Join-Path $_.FullName "cache2" }

            foreach ($cachePath in $profileCaches) {
                if (Test-Path $cachePath) {
                    try {
                        Remove-Item (Join-Path $cachePath "*") -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Log "Deleted Firefox cache: $cachePath"
                    } catch {
                        Write-Log "Failed to delete Firefox cache: $cachePath"
                    }
                }
            }
        } else {
            try {
                Remove-Item (Join-Path $p "*") -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Deleted browser cache: $p"
            } catch {
                Write-Log "Failed to delete browser cache: $p"
            }
        }
    }

    Write-Progress -Activity "Clearing browser caches" -Completed -Status "Done"
    Write-Host "Browser caches cleared.`n" -ForegroundColor Green
}

function Run-ComponentCleanup {
    <#
        .SYNOPSIS
            Runs DISM component cleanup for Windows Update.

        .DESCRIPTION
            Uses DISM to reduce WinSxS and component store size.
            Since DISM does not expose detailed progress, we show
            an animated phase indicator while it runs.
    #>

    Write-Host "`n[Windows Update Cleanup] Running DISM cleanup..." -ForegroundColor Cyan
    Write-Log "Running DISM component cleanup"

    # Start DISM in a separate process
    $dism = Start-Process -FilePath "Dism.exe" `
                          -ArgumentList "/online","/Cleanup-Image","/StartComponentCleanup" `
                          -NoNewWindow -PassThru

    # Show animated indicator while DISM runs
    while (-not $dism.HasExited) {
        Show-AsciiProgress -Activity "DISM cleanup in progress..." -Percent 50
        Start-Sleep -Seconds 2
    }

    Show-AsciiProgress -Activity "DISM cleanup" -Percent 100
    Write-Host "Component cleanup complete.`n" -ForegroundColor Green
    Write-Log "DISM cleanup completed"
}

# ============================================
#  LARGE FILE SCANNER
# ============================================

function Find-LargeFiles {
    <#
        .SYNOPSIS
            Lists the top 50 largest non-system files on C:.

        .DESCRIPTION
            Avoids major system and OS directories.
            Uses Write-Progress to show scan progress.
            Output is sorted largest → smallest.
            File sizes are shown in MB or GB depending on size.
    #>

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

    # Enumerate directories first to track progress
    $root = "C:\"
    $dirs = Get-ChildItem $root -Directory -Recurse -ErrorAction SilentlyContinue
    $totalDirs = $dirs.Count
    $dirIndex  = 0
    $files     = @()

    foreach ($dir in $dirs) {
        $dirIndex++
        $percent = if ($totalDirs -gt 0) { [int](($dirIndex / $totalDirs) * 100) } else { 100 }

        Write-Progress -Activity "Scanning for large files" `
                       -Status "Scanning: $($dir.FullName)" `
                       -PercentComplete $percent

        if ($ExcludedDirs -contains $dir.FullName) { continue }

        $files += Get-ChildItem $dir.FullName -File -ErrorAction SilentlyContinue |
                  Where-Object {
                      -not ($_.Attributes -match "System") -and
                      -not ($_.Attributes -match "Hidden")
                  }
    }

    Write-Progress -Activity "Scanning for large files" -Completed -Status "Done"

    # Convert sizes and sort
    $results = $files |
        Select-Object FullName,
            @{Name="SizeBytes";Expression={$_.Length}},
            @{Name="SizeFormatted";Expression={
                if ($_.Length -ge 1GB) {
                    "{0:N2} GB" -f ($_.Length / 1GB)
                } else {
                    "{0:N2} MB" -f ($_.Length / 1MB)
                }
            }},
            LastWriteTime |
        Sort-Object SizeBytes -Descending |
        Select-Object -First 50

    # Display clean table
    $results |
        Select-Object FullName, SizeFormatted, LastWriteTime |
        Format-Table -AutoSize

    Write-Host "`nLarge file scan complete.`n" -ForegroundColor Green
    Write-Log "Large file scan completed (top 50 listed)"
}

# ============================================
#  FULL SYSTEM CLEANUP
# ============================================

function Full-SystemCleanup {
    <#
        .SYNOPSIS
            Performs an aggressive but targeted system cleanup.

        .DESCRIPTION
            Clears:
                - Temp directories
                - SoftwareDistribution downloads
                - DeliveryOptimization cache
                - Explorer thumbnail cache
                - Prefetch data
                - Recycle Bin
            Uses Write-Progress across defined cleanup phases.
    #>

    Write-Host "`n[Full Cleanup] Running full system cleanup..." -ForegroundColor Cyan
    Write-Log "Running full system cleanup"

    $cleanupSteps = @(
        @{ Name = "User temp files";        Path = "$env:TEMP\*"},
        @{ Name = "Windows temp files";     Path = "C:\Windows\Temp\*"},
        @{ Name = "Update downloads";       Path = "C:\Windows\SoftwareDistribution\Download\*"},
        @{ Name = "DeliveryOptimization";   Path = "C:\Windows\SoftwareDistribution\DeliveryOptimization\*"},
        @{ Name = "Explorer thumbnails";    Path = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db"},
        @{ Name = "Prefetch data";          Path = "C:\Windows\Prefetch\*"}
    )

    $totalSteps = $cleanupSteps.Count + 1   # +1 for recycle bin
    $stepIndex  = 0

    foreach ($step in $cleanupSteps) {
        $stepIndex++
        $percent = [int](($stepIndex / $totalSteps) * 100)

        Write-Progress -Activity "Full system cleanup" `
                       -Status $step.Name `
                       -PercentComplete $percent

        try {
            Remove-Item $step.Path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Full cleanup step '${($step.Name)}' completed"
        } catch {
            Write-Log "Full cleanup step '${($step.Name)}' failed: $($_.Exception.Message)"
        }
    }

    # Recycle bin as last step
    $stepIndex++
    $percent = [int](($stepIndex / $totalSteps) * 100)

    Write-Progress -Activity "Full system cleanup" `
                   -Status "Clearing Recycle Bin" `
                   -PercentComplete $percent

    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Log "Recycle Bin cleared"

    Write-Progress -Activity "Full system cleanup" -Completed -Status "Done"
    Write-Host "Full system cleanup completed.`n" -ForegroundColor Green
    Write-Log "Full system cleanup completed"
}

# ============================================
#  JUNK FILE PATTERN SCANNER
# ============================================

function Junk-FileScanner {
    <#
        .SYNOPSIS
            Searches for files that match common "junk" patterns.

        .DESCRIPTION
            Looks for file extensions typically associated with:
                - Temporary files
                - Backups
                - Logs
                - Crash dumps
            Allows optional deletion of all found items.
            Uses Write-Progress over patterns and files.
    #>

    Write-Host "`n[Junk Scanner] Searching for junk files..." -ForegroundColor Cyan
    Write-Log "Running junk file pattern scan"

    $patterns = @("*.tmp","*.bak","*.old","*.log","*.dmp","*.err","*.chk","*.gid","*.~*","*.temp")
    $allResults = @()
    $patternIndex = 0
    $totalPatterns = $patterns.Count

    foreach ($pattern in $patterns) {
        $patternIndex++
        $percent = [int](($patternIndex / $totalPatterns) * 100)

        Write-Progress -Activity "Searching for junk files" `
                       -Status "Pattern: $pattern" `
                       -PercentComplete $percent

        $results = Get-ChildItem -Path "C:\" -Recurse -Include $pattern -File -ErrorAction SilentlyContinue
        if ($results) {
            $allResults += $results
        }
    }

    Write-Progress -Activity "Searching for junk files" -Completed -Status "Done"

    if ($allResults.Count -gt 0) {
        Write-Host "`nFound junk files: $($allResults.Count)" -ForegroundColor Yellow
        $allResults | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize

        Write-Log "Junk files found: $($allResults.Count)"

        $confirm = Read-Host "Delete ALL junk files? (Y/N)"
        if ($confirm -in @('Y','y')) {
            $total = $allResults.Count
            $index = 0

            foreach ($file in $allResults) {
                $index++
                $percent = [int](($index / $total) * 100)

                Write-Progress -Activity "Deleting junk files" `
                               -Status "Deleting: $($file.FullName)" `
                               -PercentComplete $percent

                try {
                    Remove-Item $file.FullName -Force -ErrorAction SilentlyContinue
                    Write-Log "Deleted junk file: $($file.FullName)"
                } catch {
                    Write-Log "Failed to delete junk file: $($file.FullName)"
                }
            }

            Write-Progress -Activity "Deleting junk files" -Completed -Status "Done"
        }
    } else {
        Write-Host "No junk files found." -ForegroundColor Green
        Write-Log "No junk files found"
    }
}

# ============================================
#  STARTUP ANALYZER
# ============================================

function Startup-Analyzer {
    <#
        .SYNOPSIS
            Displays items that run at startup.

        .DESCRIPTION
            Shows:
                - Registry Run entries (HKCU/HKLM, WOW6432Node)
                - Startup folder items
                - Non-Microsoft scheduled tasks
                - Auto-start services
            Uses high-level progress stages (categories).
    #>

    Write-Host "`n[Startup Analyzer] Collecting startup entries..." -ForegroundColor Cyan
    Write-Log "Running startup analyzer"

    $stages = 4
    $stage  = 0

    # Registry Run entries
    $stage++
    Write-Progress -Activity "Startup analyzer" `
                   -Status "Registry startup items" `
                   -PercentComplete ([int](($stage / $stages) * 100))

    Write-Host "`n--- Registry Startup Items ---" -ForegroundColor Yellow
    $regPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($path in $regPaths) {
        if (Test-Path $path) {
            Write-Host "`nPath: $path" -ForegroundColor Cyan
            Get-ItemProperty $path | Select-Object * | Format-List
        }
    }

    # Startup folders
    $stage++
    Write-Progress -Activity "Startup analyzer" `
                   -Status "Startup folder items" `
                   -PercentComplete ([int](($stage / $stages) * 100))

    Write-Host "`n--- Startup Folder Items ---" -ForegroundColor Yellow
    Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue
    Get-ChildItem "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue

    # Scheduled tasks (non-Microsoft)
    $stage++
    Write-Progress -Activity "Startup analyzer" `
                   -Status "Scheduled tasks" `
                   -PercentComplete ([int](($stage / $stages) * 100))

    Write-Host "`n--- Scheduled Tasks (Non-Microsoft) ---" -ForegroundColor Yellow
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notlike "\Microsoft\*" } |
        Select-Object TaskName, TaskPath, State | Format-Table -AutoSize

    # Auto-start services
    $stage++
    Write-Progress -Activity "Startup analyzer" `
                   -Status "Auto-start services" `
                   -PercentComplete ([int](($stage / $stages) * 100))

    Write-Host "`n--- Auto-Start Services ---" -ForegroundColor Yellow
    Get-Service | Where-Object { $_.StartType -eq "Automatic" } |
        Select-Object Name, DisplayName, Status | Format-Table -AutoSize

    Write-Progress -Activity "Startup analyzer" -Completed -Status "Done"
    Write-Log "Startup analyzer completed"
}

# ============================================
#  REGISTRY CLEANUP BY SOFTWARE NAME
# ============================================

function Registry-Cleanup {
    <#
        .SYNOPSIS
            Searches for and optionally deletes registry keys matching a software name.

        .DESCRIPTION
            Recursively scans common software locations in HKCU/HKLM
            for keys whose path contains the provided name.
    #>

    $name = Read-Host "Enter software name for registry cleanup"
    if (-not $name) { return }

    Write-Log "Registry cleanup for: $name"

    $paths = @(
        "HKCU:\Software",
        "HKLM:\Software",
        "HKLM:\Software\WOW6432Node"
    )

    $keys = @()
    $pathIndex = 0
    $totalPaths = $paths.Count

    foreach ($path in $paths) {
        $pathIndex++
        $percent = [int](($pathIndex / $totalPaths) * 100)

        Write-Progress -Activity "Registry cleanup" `
                       -Status "Scanning: $path" `
                       -PercentComplete $percent

        try {
            Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -like "*$name*") {
                    $keys += $_.PSPath
                }
            }
        } catch {}
    }

    Write-Progress -Activity "Registry cleanup" -Completed -Status "Done"

    if (-not $keys -or $keys.Count -eq 0) {
        Write-Host "No registry keys found for '$name'." -ForegroundColor Yellow
        Write-Log "No registry keys found for $name"
        return
    }

    Write-Host "`nFound registry keys:" -ForegroundColor Green
    $keys | ForEach-Object { Write-Host $_ }

    $confirm = Read-Host "Delete ALL these keys? (Y/N)"
    if ($confirm -notin @('Y','y')) { return }

    $total = $keys.Count
    $index = 0

    foreach ($key in $keys) {
        $index++
        $percent = [int](($index / $total) * 100)

        Write-Progress -Activity "Deleting registry keys" `
                       -Status "Deleting: $key" `
                       -PercentComplete $percent

        try {
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Deleted registry key: $key"
        } catch {
            Write-Log "Failed to delete registry key: $key"
        }
    }

    Write-Progress -Activity "Deleting registry keys" -Completed -Status "Done"
}

# ============================================
#  DEEP UNINSTALL WITH SOFTWARE SELECTION
# ============================================

function Deep-Uninstall {
    <#
        .SYNOPSIS
            Performs an in-depth uninstall of a selected program.

        .DESCRIPTION
            - Lists installed Win32 and Appx software
            - Prompts user to pick an entry by number
            - Runs the official uninstaller (quiet if available)
            - Then searches for and optionally removes:
                * Related services
                * Leftover folders in common paths
    #>

    Write-Host "`n[Deep Uninstall] Gathering installed software..." -ForegroundColor Cyan
    Write-Log "Deep uninstall initiated"

    # Collect Win32 uninstallers
    $uninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $win32 = foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Get-ChildItem $path -ErrorAction SilentlyContinue |
                Get-ItemProperty |
                Where-Object { $_.DisplayName -ne $null } |
                Select-Object DisplayName, UninstallString, QuietUninstallString
        }
    }

    # Collect Appx packages
    $appx = Get-AppxPackage | Select-Object Name, PackageFullName

    # Combine lists
    $softwareList = @()

    foreach ($item in $win32) {
        $softwareList += [PSCustomObject]@{
            Name      = $item.DisplayName
            Type      = "Win32"
            Uninstall = $item.UninstallString
            Quiet     = $item.QuietUninstallString
            Package   = $null
        }
    }

    foreach ($item in $appx) {
        $softwareList += [PSCustomObject]@{
            Name      = $item.Name
            Type      = "Appx"
            Uninstall = $null
            Quiet     = $null
            Package   = $item.PackageFullName
        }
    }

    # Sort alphabetically
    $softwareList = $softwareList | Sort-Object Name

    if ($softwareList.Count -eq 0) {
        Write-Host "No installed software found." -ForegroundColor Yellow
        Write-Log "Deep uninstall: no software found"
        return
    }

    # Display numbered list (paged if large)
    Write-Host "`nInstalled Software:" -ForegroundColor Yellow

    $index = 0
    foreach ($app in $softwareList) {
        $index++
        Write-Host ("{0,4}. {1}" -f $index, $app.Name)
    }

    $selection = Read-Host "`nEnter the number of the software to uninstall"
    if (-not $selection -or $selection -notmatch '^\d+$') { return }

    $selectedIndex = [int]$selection - 1
    if ($selectedIndex -lt 0 -or $selectedIndex -ge $softwareList.Count) { return }

    $target = $softwareList[$selectedIndex]

    Write-Host "`nSelected: $($target.Name)" -ForegroundColor Cyan
    Write-Log "Selected uninstall target: $($target.Name)"

    # ----------------------------------------------------
    # 1) RUN OFFICIAL UNINSTALLER
    # ----------------------------------------------------

    if ($target.Type -eq "Win32") {
        if ($target.Quiet) {
            Write-Host "Running quiet uninstall..." -ForegroundColor Cyan
            Write-Log "Quiet uninstall: $($target.Name)"

            Show-AnimatedPhase -Activity "Uninstalling $($target.Name)" -DurationSeconds 5
            Start-Process "cmd.exe" "/c $($target.Quiet)" -Wait
        }
        elseif ($target.Uninstall) {
            Write-Host "Running uninstall..." -ForegroundColor Cyan
            Write-Log "Uninstall: $($target.Name)"

            Show-AnimatedPhase -Activity "Uninstalling $($target.Name)" -DurationSeconds 5
            Start-Process "cmd.exe" "/c $($target.Uninstall)" -Wait
        }
        else {
            Write-Host "No uninstall command found." -ForegroundColor Yellow
            Write-Log "No uninstall command found for $($target.Name)"
        }
    }
    elseif ($target.Type -eq "Appx") {
        Write-Host "Removing Appx package..." -ForegroundColor Cyan
        Write-Log "Appx uninstall: $($target.Name)"

        Show-AnimatedPhase -Activity "Removing $($target.Name)" -DurationSeconds 4
        Remove-AppxPackage $target.Package -ErrorAction SilentlyContinue
    }

    # ----------------------------------------------------
    # 2) DEEP CLEANUP: SERVICES
    # ----------------------------------------------------

    $name = $target.Name
    Write-Host "`n[Deep Cleanup] Searching for related services..." -ForegroundColor Cyan

    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -like "*$name*" -or $_.Name -like "*$name*"
    }

    if ($services) {
        Write-Host "Found services:" -ForegroundColor Green
        $services | Format-Table Name,DisplayName,Status -AutoSize

        $confirmSvc = Read-Host "Disable and delete these services? (Y/N)"
        if ($confirmSvc -in @('Y','y')) {
            $totalSvc = $services.Count
            $svcIndex = 0

            foreach ($svc in $services) {
                $svcIndex++
                $percent = [int](($svcIndex / $totalSvc) * 100)

                Write-Progress -Activity "Removing related services" `
                               -Status "Deleting: $($svc.Name)" `
                               -PercentComplete $percent

                try { Stop-Service $svc.Name -Force -ErrorAction SilentlyContinue } catch {}
                Set-Service $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
                sc.exe delete $svc.Name | Out-Null
                Write-Log "Deleted service: $($svc.Name)"
            }

            Write-Progress -Activity "Removing related services" -Completed -Status "Done"
        }
    }
    else {
        Write-Host "No related services found." -ForegroundColor Yellow
    }

    # ----------------------------------------------------
    # 3) DEEP CLEANUP: LEFTOVER FOLDERS
    # ----------------------------------------------------

    Write-Host "`n[Deep Cleanup] Searching for leftover folders..." -ForegroundColor Cyan

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
            $totalFld = $folders.Count
            $fldIndex = 0

            foreach ($folder in $folders) {
                $fldIndex++
                $percent = [int](($fldIndex / $totalFld) * 100)

                Write-Progress -Activity "Deleting leftover folders" `
                               -Status "Deleting: $($folder.FullName)" `
                               -PercentComplete $percent

                try {
                    Remove-Item $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Deleted folder: $($folder.FullName)"
                } catch {
                    Write-Log "Failed to delete folder: $($folder.FullName)"
                }
            }

            Write-Progress -Activity "Deleting leftover folders" -Completed -Status "Done"
        }
    }
    else {
        Write-Host "No leftover folders found." -ForegroundColor Yellow
    }

    Write-Host "`nDeep uninstall completed." -ForegroundColor Green
    Write-Log "Deep uninstall completed for: $name"
}

# ============================================
#  MENU SYSTEM
# ============================================

function Show-Menu {
    <#
        .SYNOPSIS
            Displays the main menu for the cleanup suite.
    #>

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
    Write-Host "9. Deep Uninstall (with software list)"
    Write-Host "10. Exit"
    Write-Host "==========================================="
}

do {
    Show-Menu
    $choice = Read-Host "Select an option (1-10)"

    switch ($choice) {
        '1'  { Full-SystemCleanup;      Pause }
        '2'  { Clear-TempFiles;         Pause }
        '3'  { Clear-BrowserCaches;     Pause }
        '4'  { Run-ComponentCleanup;    Pause }
        '5'  { Find-LargeFiles;         Pause }
        '6'  { Junk-FileScanner;        Pause }
        '7'  { Startup-Analyzer;        Pause }
        '8'  { Registry-Cleanup;        Pause }
        '9'  { Deep-Uninstall;          Pause }
        '10' { Write-Host "Exiting..."; Write-Log "Cleanup Suite exited"; break }
        default { Write-Host "Invalid selection."; Pause }
    }
} while ($true)