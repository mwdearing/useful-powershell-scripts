param(
    [string]$Path = "C:\",
    [int]$Top = 50,
    [int]$MinSizeMB = 10
)

# Directories to exclude
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

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Path '$Path' does not exist or is not a directory."
}

$resolvedRoot = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path).Path).TrimEnd('\')
$excludedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($excluded in $ExcludedDirs) {
    [void]$excludedSet.Add([System.IO.Path]::GetFullPath($excluded).TrimEnd('\'))
}

$minBytes = [int64]$MinSizeMB * 1MB

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
