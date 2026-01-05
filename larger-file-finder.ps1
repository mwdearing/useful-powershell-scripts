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

Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue -Force |
    Where-Object {
        -not ($_.Attributes -match "System") -and
        -not ($_.Attributes -match "Hidden") -and
        ($ExcludedDirs -notcontains $_.DirectoryName) -and
        $_.Length -ge ($MinSizeMB * 1MB)
    } |
    Select-Object FullName,
                  @{Name="SizeMB";Expression={[math]::Round($_.Length / 1MB, 2)}},
                  LastWriteTime |
    Sort-Object SizeMB -Descending |   # <-- Sort FIRST
    Select-Object -First $Top |        # <-- Then take the top N
    Format-Table -AutoSize