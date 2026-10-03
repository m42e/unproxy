param([switch]$RemoveUserData)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'Unproxy'
$destination = Join-Path $root 'bin'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Remove-ItemProperty $runKey -Name Unproxy -ErrorAction SilentlyContinue
try { $event = [Threading.EventWaitHandle]::OpenExisting('Local\UnproxyTrayExit'); $event.Set() | Out-Null; $event.Dispose() } catch { }
$installed = Join-Path $destination 'UnproxyTray.exe'
$proxy = Join-Path $destination 'unproxy.exe'
$deadline = (Get-Date).AddSeconds(8)
do { $trayRunning = Get-CimInstance Win32_Process -Filter "Name='UnproxyTray.exe'" | Where-Object { $_.ExecutablePath -eq $installed }; if (-not $trayRunning) { break }; Start-Sleep -Milliseconds 200 } while ((Get-Date) -lt $deadline)
Get-CimInstance Win32_Process -Filter "Name='UnproxyTray.exe'" | Where-Object { $_.ExecutablePath -eq $installed } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*unproxy-tray.ps1*' -and $_.CommandLine -like "*$destination*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Get-CimInstance Win32_Process -Filter "Name='unproxy.exe'" | Where-Object { $_.ExecutablePath -eq $proxy } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Remove-Item (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Unproxy.lnk') -Force -ErrorAction SilentlyContinue
Remove-Item $destination -Recurse -Force -ErrorAction SilentlyContinue
if ($RemoveUserData) { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'Unproxy binaries and login registration removed.'
if (-not $RemoveUserData) { Write-Host "Preferences and logs were preserved in $root." }
