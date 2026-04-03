<#
    larger-file-finder.ps1
    -----------------------------------------------------------
    Scans a target directory and prints the largest files found.

    Why this script exists:
      - Quickly identify disk-heavy files for cleanup planning.
      - Avoid scanning known Windows/system directories by default.
      - Provide a safe, read-only report (no delete operations).

    Typical usage:
      .\larger-file-finder.ps1
      .\larger-file-finder.ps1 -Path "D:\" -Top 100 -MinSizeMB 250
#>

param(
    # Root directory to scan. Defaults to the system drive.
    [string]$Path = "C:\",
    # Number of largest matching files to display.
    [int]$Top = 50,
    # Minimum file size threshold in megabytes.
    [int]$MinSizeMB = 10
)

# Directories to exclude because they are typically system-managed
# and can significantly slow traversal while adding little cleanup value.
$ExcludedDirs = @(
    "C:\Windows",
    "C:\Program Files",
    "C:\Program Files (x86)",
    "C:\ProgramData",
    "C:\$Recycle.Bin",
    "C:\Recovery",
    "C:\System Volume Information"
)

Write-Host "Scanning $Path for files larger than $MinSizeMB MB (excluding system folders)..." -ForegroundColor Cyan

# Validate the input path early so the script fails fast with a clear message.
if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Path '$Path' does not exist or is not a directory."
}

# Resolve absolute paths once to keep path comparisons reliable and case-insensitive.
$resolvedRoot = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path).TrimEnd('\')
$excludedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($excluded in $ExcludedDirs) {
    [void]$excludedSet.Add([System.IO.Path]::GetFullPath($excluded).TrimEnd('\'))
}

# Convert MB threshold to bytes once to avoid repeated conversion in the filter.
$minBytes = [int64]$MinSizeMB * 1MB

# Pipeline flow:
#   1) Enumerate files recursively.
#   2) Filter out hidden/system and excluded-directory items.
#   3) Keep only files over the configured minimum size.
#   4) Project display columns, sort descending, take top N.
Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File -ErrorAction SilentlyContinue -Force |
    Where-Object {
        $dir = [System.IO.Path]::GetFullPath($_.DirectoryName).TrimEnd('\')
        $isExcluded = $false

        foreach ($excludedRoot in $excludedSet) {
            if ($dir.StartsWith("$excludedRoot\", [System.StringComparison]::OrdinalIgnoreCase) -or $dir.Equals($excludedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                $isExcluded = $true
                break
            }
        }

        -not ($_.Attributes -match "System") -and
        -not ($_.Attributes -match "Hidden") -and
        -not $isExcluded -and
        $_.Length -ge $minBytes
    } |
    Select-Object FullName,
                  @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}},
                  LastWriteTime |
    Sort-Object SizeMB -Descending |   # <-- Sort FIRST
    Select-Object -First $Top |        # <-- Then take the top N
    Format-Table -AutoSize
