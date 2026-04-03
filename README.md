# Useful PowerShell Scripts for Windows Cleanup & Maintenance

A practical collection of PowerShell scripts for **Windows system cleanup, disk space recovery, startup analysis, uninstall cleanup, and Python environment reset**.

If you landed here looking for “what should I run first?”, start with:

- `larger-file-finder.ps1` for safe, read-only storage analysis.
- `WindowsCleanupSuite.ps1` for an interactive all-in-one cleanup menu.
- `stale_python_cleanup.ps1` only when you intentionally want to fully remove Python from a machine.

---

## Table of Contents

- [What’s in this repo](#whats-in-this-repo)
- [Before You Run Anything](#before-you-run-anything)
- [Quick Start](#quick-start)
- [Script-by-Script Guide](#script-by-script-guide)
  - [`WindowsCleanupSuite.ps1` (recommended interactive suite)](#windowscleanupsuiteps1-recommended-interactive-suite)
  - [`cleanup-menus-v2.ps1` (enhanced legacy variant)](#cleanup-menus-v2ps1-enhanced-legacy-variant)
  - [`cleanup-menus.ps1` (lightweight menu variant)](#cleanup-menusps1-lightweight-menu-variant)
  - [`larger-file-finder.ps1` (read-only large file report)](#larger-file-finderps1-read-only-large-file-report)
  - [`software-driver-update-checker.ps1` (software + driver updater)](#software-driver-update-checkerps1-software--driver-updater)
  - [`stale_python_cleanup.ps1` (full Python removal)](#stale_python_cleanupps1-full-python-removal)
- [Usage Recipes](#usage-recipes)
- [Safety Notes & Best Practices](#safety-notes--best-practices)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## What’s in this repo

This repository currently includes:

1. **`WindowsCleanupSuite.ps1`**
   - Full interactive cleanup toolkit with logging, progress displays, large file scanner, junk scanner, startup analyzer, registry cleanup, and deep uninstall workflow.
2. **`cleanup-menus-v2.ps1`**
   - Enhanced menu-driven cleanup suite similar in spirit to the main suite.
3. **`cleanup-menus.ps1`**
   - Lightweight, focused menu script for full cleanup + registry cleanup + deep uninstall leftovers.
4. **`larger-file-finder.ps1`**
   - Safe reporting script that scans for large files without deleting anything.
5. **`software-driver-update-checker.ps1`**
   - Update script that can install updates through `winget`, Chocolatey, and Windows Update API (software + driver updates), with optional audit-only mode.
6. **`stale_python_cleanup.ps1`**
   - Aggressive “start fresh” script to remove Python installs, launcher, registry metadata, and PATH remnants.
7. **`run-software-driver-update-checker.cmd`**
   - Wrapper launcher that runs the update checker with `ExecutionPolicy Bypass` to avoid script-signing policy blocks.

---

## Before You Run Anything

> These scripts are intended for **Windows PowerShell / PowerShell 7 on Windows** and many operations require **Administrator** rights.

### 1) Open an elevated PowerShell session

- Start Menu → type **PowerShell** → right-click → **Run as Administrator**.

### 2) Optional execution policy setup

If script execution is blocked on your machine:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This applies only to the current PowerShell window.

### 3) Clone/download this repo

```powershell
git clone <your-repo-url>
cd useful-powershell-scripts
```

Or download the ZIP and extract it.

### 4) (Recommended) Create a restore point first

For cleanup/uninstall tasks, a restore point is a smart safety net.

---

## Quick Start

### Option A: Run the main interactive suite

```powershell
.\WindowsCleanupSuite.ps1
```

Then pick actions from the menu.

### Option B: Find large files first (safe/read-only)

```powershell
.\larger-file-finder.ps1 -Path "C:\" -Top 50 -MinSizeMB 500
```

### Option C: Full Python reset (destructive)

```powershell
.\stale_python_cleanup.ps1
```

Use this only if you intentionally want to remove all Python-related installs/config from the machine.

---

## Script-by-Script Guide

## `WindowsCleanupSuite.ps1` (recommended interactive suite)

### What it does

Menu-driven toolkit with:

- Full system cleanup
- Temp cleanup
- Browser cache cleanup (Chrome/Edge/Firefox)
- Windows Update component cleanup via DISM
- Large file scan
- Junk file pattern scanner
- Startup analyzer
- Registry cleanup by software name
- Deep uninstall helper (official uninstaller + services + leftover folders)
- Log output to `C:\CleanupSuite\cleanup.log`

### Run it

```powershell
.\WindowsCleanupSuite.ps1
```

### Typical workflow example

1. Run option **5 (Find Large Files)** to identify space-heavy files.
2. Run option **2/3** for temp and browser cleanup.
3. Run option **4** (DISM component cleanup) if Windows update store has grown.
4. Use option **6** (Junk Scanner) and review results before deleting.
5. If uninstalling an app, use option **9** (Deep Uninstall) and confirm prompts carefully.

### Logs

```powershell
Get-Content C:\CleanupSuite\cleanup.log -Tail 100
```

---

## `cleanup-menus-v2.ps1` (enhanced legacy variant)

A strong alternative menu suite with similar cleanup and uninstall capabilities.

### Run it

```powershell
.\cleanup-menus-v2.ps1
```

### Good use cases

- You want the enhanced menu workflow but prefer this script’s behavior/output.
- You’re comparing script variants before standardizing on one internally.

---

## `cleanup-menus.ps1` (lightweight menu variant)

A smaller interactive script focused on:

- Full system cleanup
- Registry cleanup (by software name)
- Deep uninstall helper (service/folder leftovers)

### Run it

```powershell
.\cleanup-menus.ps1
```

### Good use cases

- You want fewer options and a simpler menu.
- You only need basic cleanup + uninstall artifact removal.

---

## `larger-file-finder.ps1` (read-only large file report)

### What it does

Scans a target path, excludes common system roots, and reports top large files.

- **No deletion** logic.
- Useful for deciding what to clean manually or archive.

### Parameters

- `-Path` (default: `C:\`) — root folder to scan
- `-Top` (default: `50`) — number of largest files to display
- `-MinSizeMB` (default: `10`) — size threshold filter

### Examples

```powershell
# Default scan (C:, top 50, >=10MB)
.\larger-file-finder.ps1

# Scan D: and show top 100 files >=250MB
.\larger-file-finder.ps1 -Path "D:\" -Top 100 -MinSizeMB 250

# Scan user profile for medium-large files
.\larger-file-finder.ps1 -Path "$env:USERPROFILE" -Top 75 -MinSizeMB 100
```

### Export output example

```powershell
.\larger-file-finder.ps1 -Path "C:\" -Top 200 -MinSizeMB 200 |
    Out-File .\large-files-report.txt
```

---

## `software-driver-update-checker.ps1` (software + driver updater)

### What it does

Checks and installs updates across common Windows update channels:

- `winget upgrade --all` (if winget is installed)
- `choco upgrade all` (if Chocolatey is installed)
- Windows Update API via `Microsoft.Update.Session` for:
  - software updates
  - driver updates

By default it performs updates; use audit mode for read-only checks. The script summarizes results and can optionally export a JSON report.

### Parameters

- `-IncludePreview` — include updates with titles containing Preview/Beta.
- `-AuditOnly` — run read-only checks without installing updates.
- `-ExportPath` — optional path for JSON report output.

### Examples

```powershell
# Check and install updates
.\software-driver-update-checker.ps1

# If script-signing policy blocks direct .ps1 execution, use the wrapper
.\run-software-driver-update-checker.cmd

# Read-only audit mode
.\software-driver-update-checker.ps1 -AuditOnly

# Include preview/beta updates in Windows Update API results
.\software-driver-update-checker.ps1 -IncludePreview

# Export detailed report to JSON
.\software-driver-update-checker.ps1 -ExportPath .\update-report.json
```

### Notes

- Run in an elevated PowerShell session for best compatibility; installation actions may fail without Administrator rights.
- If winget/choco are not installed, the script reports that and continues.
- By default the script installs available updates; use `-AuditOnly` for reporting without installation.
- If your system requires signed scripts, run `run-software-driver-update-checker.cmd` (or invoke PowerShell with `-ExecutionPolicy Bypass`) to run this tool without changing machine-wide policy.

---

## `stale_python_cleanup.ps1` (full Python removal)

### What it does

Performs an aggressive, full Python cleanup including:

- Running available uninstallers
- Removing typical Python directories
- Removing `py.exe` / `pyw.exe`
- Cleaning Python-related PATH entries (Machine/User)
- Deleting PythonCore/related registry entries
- Verifying `python`, `py`, `pip` resolution afterward

### Run it (Administrator required)

```powershell
.\stale_python_cleanup.ps1
```

### When to use this

- Python installs are corrupted/conflicting.
- You want to rebuild Python from a clean slate.

### When **not** to use this

- You only need to remove one Python version.
- You rely on existing Python virtual environments.

### Follow-up reinstall example

```powershell
# Example only: reinstall via winget after cleanup
winget install Python.Python.3.12
python --version
pip --version
```

---

## Usage Recipes

### Recipe 1: Recover disk space safely first

1. Run large-file report:
   ```powershell
   .\larger-file-finder.ps1 -Path "C:\" -Top 100 -MinSizeMB 500
   ```
2. Review big files and remove/archive intentionally.
3. Run interactive suite temp/browser cleanup:
   ```powershell
   .\WindowsCleanupSuite.ps1
   ```

### Recipe 2: Remove stubborn app leftovers

1. Launch main suite:
   ```powershell
   .\WindowsCleanupSuite.ps1
   ```
2. Choose **Deep Uninstall**.
3. Enter app name (example: `NVIDIA`, `Docker`, etc.).
4. Confirm official uninstallers, then services/folders only after review.

### Recipe 3: “Factory reset” Python on a workstation

1. Back up scripts/venvs you care about.
2. Run:
   ```powershell
   .\stale_python_cleanup.ps1
   ```
3. Reboot (recommended).
4. Reinstall Python and recreate venvs.

---

## Safety Notes & Best Practices

- **Run as Administrator** for system-level operations.
- **Read prompts carefully** before confirming deletions.
- **Close apps/browsers first** to reduce locked-file issues.
- **Use large-file reporting before deletion-heavy steps**.
- **Keep logs** (`C:\CleanupSuite\cleanup.log`) for auditing/troubleshooting.
- Consider taking a restore point or backup before deep cleanup or registry operations.

---

## Troubleshooting

### “Running scripts is disabled on this system.”

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Access denied / locked files

- Ensure PowerShell is elevated.
- Close related apps (browser, installer, updater, etc.).
- Re-run command.

### Long scan times

- Narrow `-Path` and increase `-MinSizeMB` in `larger-file-finder.ps1`.
- Expect deeper scans to take time on large disks.

### DISM cleanup appears slow

That’s normal on some systems. Let it complete.

---

## Contributing

If you add scripts:

- Include clear comments and safe defaults.
- Document parameters and examples in this README.
- Prefer dry-run/read-only preview modes when feasible.

---

## Disclaimer

These scripts can modify system files, registry keys, services, and environment variables. Use at your own risk and validate in a non-production environment first.
