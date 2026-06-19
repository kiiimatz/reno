# Reno installer for Windows (PowerShell)
# Run as Administrator:
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/kiiimatz/reno/main/install.ps1)))
#
# Optionally start services after install:
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/kiiimatz/reno/main/install.ps1))) station
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/kiiimatz/reno/main/install.ps1))) edge
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/kiiimatz/reno/main/install.ps1))) both

param(
    [string]$Mode = ""
)

$ErrorActionPreference = "Stop"

$Repo = "kiiimatz/reno"
$BaseUrl = "https://github.com/$Repo/releases/latest/download"
$InstallDir = "$env:ProgramFiles\reno"

# detect arch
$Arch = "amd64"
$CpuArch = (Get-CimInstance Win32_Processor).Architecture
if ($CpuArch -eq 12) { $Arch = "arm64" }

$BinaryName = "reno-windows-${Arch}.exe"
$Url = "$BaseUrl/$BinaryName"
$Dest = "$InstallDir\reno.exe"

Write-Host "Downloading reno (windows/$Arch)..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

try {
    Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
} catch {
    Write-Error "Download failed: $_"
    exit 1
}

Write-Host "Installed: $Dest"

# Add to PATH if not already there
$CurrentPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($CurrentPath -notlike "*$InstallDir*") {
    [System.Environment]::SetEnvironmentVariable("PATH", "$CurrentPath;$InstallDir", "Machine")
    $env:PATH = "$env:PATH;$InstallDir"
    Write-Host "Added $InstallDir to system PATH"
}

# Start services if requested
if ($Mode -eq "station" -or $Mode -eq "both") {
    Write-Host "Starting Station..."
    & "$Dest" station
}
if ($Mode -eq "edge" -or $Mode -eq "both") {
    Write-Host "Starting Edge..."
    & "$Dest" edge
}

if ($Mode -eq "") {
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  reno config    # set up config (%APPDATA%\reno\config.json)"
    Write-Host "  reno station   # start Station server (background, auto-start on boot)"
    Write-Host "  reno edge      # start Edge client (background, auto-start on boot)"
    Write-Host "  reno down      # stop Station and Edge"
    Write-Host "  reno remove    # uninstall reno (stops services, removes binary)"
    Write-Host "  reno version   # show version"
}
