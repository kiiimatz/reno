# Reno installer for Windows (PowerShell)
# Run as Administrator:
#   irm https://raw.githubusercontent.com/kiiimatz/reno/main/install.ps1 | iex

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
Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing
Write-Host "Installed: $Dest"

# Add to PATH if not already there
$CurrentPath = [System.Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($CurrentPath -notlike "*$InstallDir*") {
    [System.Environment]::SetEnvironmentVariable("PATH", "$CurrentPath;$InstallDir", "Machine")
    Write-Host "Added $InstallDir to system PATH"
    Write-Host "Please restart your terminal for PATH changes to take effect."
}

Write-Host ""
Write-Host "Usage:"
Write-Host "  reno config    # set up config (%APPDATA%\reno\config.json)"
Write-Host "  reno station   # start Station server"
Write-Host "  reno edge      # start Edge client"
