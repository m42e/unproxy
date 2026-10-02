$ErrorActionPreference = "Stop"
$destination = Join-Path $env:LOCALAPPDATA "Unproxy\bin"
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$binary = Join-Path $destination "unproxy.exe"
Copy-Item (Join-Path $PSScriptRoot "unproxy.exe") $binary -Force
$runKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
New-Item -Path $runKey -Force | Out-Null
New-ItemProperty -Path $runKey -Name Unproxy -Value ('"' + $binary + '"') -PropertyType String -Force | Out-Null
Write-Host "Installed $binary; Unproxy starts at user login. Configure client proxy settings separately."
