# Reno installer for Windows (no admin required)
# Run:
#   irm https://raw.githubusercontent.com/kiiimatz/reno/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "kiiimatz/reno"
$BaseUrl = "https://github.com/$Repo/releases/latest/download"
$InstallDir = "$env:LOCALAPPDATA\reno"

$Arch = "amd64"
if ((Get-CimInstance Win32_Processor).Architecture -eq 12) { $Arch = "arm64" }

$Url = "$BaseUrl/reno-windows-${Arch}.exe"
$Dest = "$InstallDir\reno.exe"

# Stop existing scheduled tasks so the binary is not locked
schtasks /End /TN "RenoStation" 2>$null; $LASTEXITCODE = 0
schtasks /End /TN "RenoEdge"    2>$null; $LASTEXITCODE = 0
Start-Sleep -Seconds 1

Write-Host "Downloading reno (windows/$Arch)..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# Download to temp file then move — avoids "file in use" errors
$Tmp = "$InstallDir\reno-new.exe"
try {
    Invoke-WebRequest -Uri $Url -OutFile $Tmp -UseBasicParsing
} catch {
    Write-Error "Download failed: $_"
    exit 1
}
Move-Item -Force $Tmp $Dest

Write-Host "Installed: $Dest"

# Add to user PATH
$UserPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
if ($UserPath -notlike "*$InstallDir*") {
    [System.Environment]::SetEnvironmentVariable("PATH", "$UserPath;$InstallDir", "User")
    $env:PATH = "$env:PATH;$InstallDir"
    Write-Host "Added $InstallDir to PATH"
}

Write-Host "Starting reno..."
& "$Dest" station
& "$Dest" edge

Write-Host "Done. Run 'reno version' to verify."
