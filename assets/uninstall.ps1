param([switch]$RemoveUserData, [switch]$AsService)
$ErrorActionPreference = 'Stop'

$administrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$serviceData = Join-Path $env:ProgramData 'Unproxy'
if ($AsService) {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $stagePattern = '^' + [regex]::Escape($programFiles) + '\\Unproxy-setup-[0-9a-f]{32}\\payload\z'
    if (-not $administrator -or $PSScriptRoot -notmatch $stagePattern) {
        throw 'Use the verified Windows service setup procedure at https://m42e.github.io/unproxy/docs/installation.html#windows-service'
    }
    $serviceRoot = Join-Path $programFiles 'Unproxy'
    if (Test-Path -LiteralPath $serviceRoot) {
        $service = Get-Service -Name 'Unproxy' -ErrorAction SilentlyContinue
        if ($service) {
            $service.Dispose()
            $serviceRegister = Join-Path $PSScriptRoot 'unproxy-register.exe'
            & $serviceRegister uninstall
            if ($LASTEXITCODE -ne 0) { throw 'Could not remove the Unproxy service registration.' }
        }
        Remove-Item -LiteralPath $serviceRoot -Recurse -Force
        if (-not $RemoveUserData) {
            Write-Host "Service configuration and logs were preserved in $serviceData."
        }
    }
    if ($RemoveUserData) {
        Remove-Item $serviceData -Recurse -Force -ErrorAction SilentlyContinue
    }
    return
}

if ($administrator) { throw 'Run the per-user tray uninstaller in a non-elevated PowerShell session.' }
if (Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Unproxy')) {
    Write-Host 'To remove the Windows service, follow https://m42e.github.io/unproxy/docs/installation.html#windows-service'
}
$root = Join-Path $env:LOCALAPPDATA 'Unproxy'
$destination = Join-Path $root 'bin'
$environmentBackupPath = Join-Path $root 'environment-before-install.json'
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
if (Test-Path -LiteralPath $environmentBackupPath) {
    try {
        $environmentState = Get-Content $environmentBackupPath -Raw | ConvertFrom-Json
        foreach ($name in @('http_proxy', 'https_proxy', 'no_proxy')) {
            $currentValue = [Environment]::GetEnvironmentVariable($name, 'User')
            $installedValue = [string]$environmentState.installed.$name
            if ($currentValue -ceq $installedValue) {
                $previousValue = $environmentState.original.$name
                [Environment]::SetEnvironmentVariable($name, $previousValue, 'User')
                if ($null -eq $previousValue) {
                    Remove-Item -Path ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
                } else {
                    Set-Item -Path ("Env:{0}" -f $name) -Value ([string]$previousValue)
                }
            }
        }
    } catch {
        Write-Warning "Could not restore the original proxy environment variables: $_"
    }
}
Remove-Item (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Unproxy.lnk') -Force -ErrorAction SilentlyContinue
Remove-Item $destination -Recurse -Force -ErrorAction SilentlyContinue
if ($RemoveUserData) { Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host 'Unproxy binaries and login registration removed.'
if (-not $RemoveUserData) {
    Write-Host "Preferences and logs were preserved in $root."
    if (Test-Path -LiteralPath $serviceData) {
        Write-Host "Service configuration and logs were preserved in $serviceData."
    }
}
