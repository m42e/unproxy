param([switch]$DisableLoginStartup)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'Unproxy'
$destination = Join-Path $root 'bin'
New-Item -ItemType Directory -Path $destination -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'unproxy.exe') (Join-Path $destination 'unproxy.exe') -Force
Copy-Item (Join-Path $PSScriptRoot 'UnproxyTray.exe') (Join-Path $destination 'UnproxyTray.exe') -Force
Copy-Item (Join-Path $PSScriptRoot 'unproxy-tray.ps1') (Join-Path $destination 'unproxy-tray.ps1') -Force
$trayIconDirectory = Join-Path $destination 'tray-icons'
New-Item -ItemType Directory -Path $trayIconDirectory -Force | Out-Null
Copy-Item (Join-Path (Join-Path $PSScriptRoot 'tray-icons') '*') $trayIconDirectory -Recurse -Force
Copy-Item (Join-Path $PSScriptRoot 'metadata.json') (Join-Path $destination 'metadata.json') -Force

$prefsFile = Join-Path $root 'preferences.json'
$metadataFile = Join-Path $destination 'metadata.json'
$metadata = if (Test-Path $metadataFile) {
    Get-Content $metadataFile -Raw | ConvertFrom-Json
} else { $null }
if (Test-Path $prefsFile) {
    $preferences = Get-Content $prefsFile -Raw | ConvertFrom-Json
} elseif ($metadata -and $metadata.defaults) {
    $preferences = $metadata.defaults
} else {
    $preferences = [pscustomobject]@{
        port = 3128
        pacFile = Join-Path $root 'proxy.pac'
        proxytunnel = $false
        directFallback = $false
        negotiate = $false
        autostart = $true
    }
}
if (-not $preferences.pacFile) { $preferences.pacFile = Join-Path $root 'proxy.pac' }
if (-not [IO.Path]::IsPathRooted([string]$preferences.pacFile)) {
    $preferences.pacFile = [IO.Path]::GetFullPath((Join-Path $root ([string]$preferences.pacFile)))
}
if ($DisableLoginStartup) { $preferences.autostart = $false }
$preferences | ConvertTo-Json | Set-Content -Encoding UTF8 $prefsFile
$defaultPac = Join-Path $root 'proxy.pac'
if ($preferences.pacFile -eq $defaultPac -and -not (Test-Path -LiteralPath $defaultPac)) {
    'function FindProxyForURL(url, host) { return "DIRECT"; }' |
        Set-Content -Encoding UTF8 $defaultPac
}

$shortcutPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Unproxy.lnk'
$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut($shortcutPath)
$shortcut.TargetPath = Join-Path $destination 'UnproxyTray.exe'
$shortcut.WorkingDirectory = $destination
$shortcut.Save()
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-Item -Path $runKey -Force | Out-Null
if ($preferences.autostart) {
    Set-ItemProperty $runKey -Name Unproxy -Value ('"' + (Join-Path $destination 'UnproxyTray.exe') + '"')
} else {
    Remove-ItemProperty $runKey -Name Unproxy -ErrorAction SilentlyContinue
}
Write-Host "Installed Unproxy to $destination. User data is stored in $root."
Start-Process (Join-Path $destination 'UnproxyTray.exe')
