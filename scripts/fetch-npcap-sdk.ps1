# Downloads the Npcap SDK (headers + import libraries) needed to *link* on Windows.
# The Npcap runtime itself must be installed separately by the user: https://npcap.com/#download
param(
    [string]$Version = "1.16",
    [string]$Destination = (Join-Path $PSScriptRoot "..\.deps\npcap-sdk")
)

$ErrorActionPreference = "Stop"
$zipUrl = "https://npcap.com/dist/npcap-sdk-$Version.zip"
$zipPath = Join-Path ([System.IO.Path]::GetTempPath()) "npcap-sdk-$Version.zip"

if (Test-Path (Join-Path $Destination "Lib\x64\wpcap.lib")) {
    Write-Host "Npcap SDK already present at $Destination"
    exit 0
}

Write-Host "Downloading $zipUrl"
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing
New-Item -ItemType Directory -Force -Path $Destination | Out-Null
Expand-Archive -Path $zipPath -DestinationPath $Destination -Force
Remove-Item $zipPath
Write-Host "Npcap SDK extracted to $Destination"
