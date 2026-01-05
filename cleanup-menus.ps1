# ============================================
# COMBINED CLEANUP SUITE WITH MENUS
# ============================================

function Full-SystemCleanup {
    Write-Host "Running full system cleanup..." -ForegroundColor Cyan

    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\SoftwareDistribution\DeliveryOptimization\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
    Remove-Item "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction SilentlyContinue
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue

    Write-Host "Full system cleanup completed." -ForegroundColor Green
}

function Registry-Cleanup {
    $name = Read-Host "Enter software name for registry cleanup"
    if (-not $name) { return }

    $paths = @(
        "HKCU:\Software",
        "HKLM:\Software",
        "HKLM:\Software\WOW6432Node"
    )

    $keys = @()

    foreach ($path in $paths) {
        try {
            Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.Name -like "*$name*") {
                    $keys += $_.PSPath
                }
            }
        } catch {}
    }

    if (-not $keys -or $keys.Count -eq 0) {
        Write-Host "No registry keys found for '$name'." -ForegroundColor Yellow
        return
    }

    Write-Host "Found registry keys:" -ForegroundColor Green
    $keys | ForEach-Object { Write-Host $_ }

    $confirm = Read-Host "Delete ALL these keys? (Y/N)"
    if ($confirm -notin @('Y','y')) { return }

    foreach ($key in $keys) {
        try {
            Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Deleted: $key" -ForegroundColor Red
        } catch {
            Write-Host "Failed to delete: $key" -ForegroundColor DarkRed
        }
    }
}

function Deep-Uninstall {
    $name = Read-Host "Enter software name for deep uninstall"
    if (-not $name) { return }

    Write-Host "Deep uninstall helper for '$name'..." -ForegroundColor Cyan

    # Services
    $services = Get-Service -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -like "*$name*" -or $_.Name -like "*$name*"
    }

    if ($services) {
        Write-Host "Found services:" -ForegroundColor Green
        $services | Format-Table Name,DisplayName,Status -AutoSize
        $confirmSvc = Read-Host "Disable and delete these services? (Y/N)"
        if ($confirmSvc -in @('Y','y')) {
            foreach ($svc in $services) {
                try { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue } catch {}
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
                sc.exe delete $svc.Name | Out-Null
                Write-Host "Deleted service: $($svc.Name)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No services found." -ForegroundColor Yellow
    }

    # Folders
    $paths = @(
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\ProgramData",
        "C:\Users\$env:USERNAME\AppData\Local",
        "C:\Users\$env:USERNAME\AppData\LocalLow",
        "C:\Users\$env:USERNAME\AppData\Roaming"
    )

    $folders = @()

    foreach ($path in $paths) {
        $found = Get-ChildItem $path -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like "*$name*" }
        if ($found) {
            $folders += $found
        }
    }

    if ($folders) {
        Write-Host "Found folders:" -ForegroundColor Green
        $folders | ForEach-Object { Write-Host "  $($_.FullName)" }

        $confirmDirs = Read-Host "Delete ALL these folders? (Y/N)"
        if ($confirmDirs -in @('Y','y')) {
            foreach ($folder in $folders) {
                try {
                    Remove-Item $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "Deleted folder: $($folder.FullName)" -ForegroundColor Red
                } catch {
                    Write-Host "Failed to delete: $($folder.FullName)" -ForegroundColor DarkRed
                }
            }
        }
    } else {
        Write-Host "No leftover folders found." -ForegroundColor Yellow
    }
}

function Show-Menu {
    Clear-Host
    Write-Host "===== SYSTEM CLEANUP SUITE =====" -ForegroundColor Cyan
    Write-Host "1. Full system cleanup"
    Write-Host "2. Registry cleanup (by software name)"
    Write-Host "3. Deep uninstall helper (services + folders)"
    Write-Host "4. Exit"
}

do {
    Show-Menu
    $choice = Read-Host "Select an option (1-4)"

    switch ($choice) {
        '1' { Full-SystemCleanup; Pause }
        '2' { Registry-Cleanup; Pause }
        '3' { Deep-Uninstall; Pause }
        '4' { Write-Host "Exiting..."; break }
        default { Write-Host "Invalid selection."; Pause }
    }
} while ($true)