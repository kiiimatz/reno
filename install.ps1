# Reno installer for Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/kiiimatz/reno/main/install.ps1 | iex
# Or:    .\install.ps1 station|edge|both

param(
    [string]$Component = ""
)

$Repo = "kiiimatz/reno"
$BaseUrl = "https://github.com/$Repo/releases/latest/download"
$InstallDir = "$env:ProgramFiles\reno"

if (-not $Component) {
    Write-Host "Usage: install.ps1 [station|edge|both]"
    Write-Host "  station  - install reno-station"
    Write-Host "  edge     - install reno-edge"
    Write-Host "  both     - install both"
    exit 1
}

# detect arch
$Arch = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$Arm = (Get-CimInstance Win32_Processor).Architecture
if ($Arm -eq 12) { $Arch = "arm64" }

function Install-Binary {
    param([string]$Name)
    $Url = "$BaseUrl/${Name}-windows-${Arch}.exe"
    $Dest = "$InstallDir\${Name}.exe"

    Write-Host "Downloading $Name (windows/$Arch)..."
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
    Write-Host "Installed: $Dest"
}

if ($Component -eq "station" -or $Component -eq "both") {
    Install-Binary "reno-station"
}
if ($Component -eq "edge" -or $Component -eq "both") {
    Install-Binary "reno-edge"
}

# Add to PATH if not already there
$CurrentPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($CurrentPath -notlike "*$InstallDir*") {
    [System.Environment]::SetEnvironmentVariable("PATH", "$CurrentPath;$InstallDir", "Machine")
    Write-Host "Added $InstallDir to system PATH (restart terminal to apply)"
}

Write-Host ""
Write-Host "Done! Run 'reno-station' or 'reno-edge' to get started."
