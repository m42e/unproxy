param([switch]$RemoveUserData, [switch]$AsService)
$ErrorActionPreference = 'Stop'

function Withdraw-ManagedProxyEnvironment([string]$trackingPath) {
    if (-not (Test-Path -LiteralPath $trackingPath)) { return }
    $tracking = Get-Content -LiteralPath $trackingPath -Raw | ConvertFrom-Json
    foreach ($name in @('http_proxy', 'https_proxy')) {
        $installedProperty = $tracking.installed.PSObject.Properties[$name]
        $pendingProperty = $tracking.installed.PSObject.Properties["${name}_pending"]
        $currentValue = [Environment]::GetEnvironmentVariable($name, 'User')
        $managedMatch = $false
        foreach ($property in @($installedProperty, $pendingProperty)) {
            if ($property -and $null -ne $property.Value -and
                $currentValue -ceq [string]$property.Value) {
                $managedMatch = $true
            }
        }
        if (-not $managedMatch) { continue }
        $previousValue = $tracking.original.$name
        if ($null -ne $previousValue -and $currentValue -ceq [string]$previousValue) {
            if ($installedProperty -and $null -ne $installedProperty.Value -and
                $currentValue -ceq [string]$installedProperty.Value) {
                throw "Cannot safely withdraw the original $name value while it names Unproxy's managed endpoint."
            }
            continue
        }
        [Environment]::SetEnvironmentVariable($name, $previousValue, 'User')
        if ($null -eq $previousValue) {
            Remove-Item -Path ("Env:{0}" -f $name) -ErrorAction SilentlyContinue
        } else {
            Set-Item -Path ("Env:{0}" -f $name) -Value ([string]$previousValue)
        }
    }
}

function Clear-ManagedProxyTracking([string]$trackingPath) {
    if (-not (Test-Path -LiteralPath $trackingPath)) { return }
    $tracking = Get-Content -LiteralPath $trackingPath -Raw | ConvertFrom-Json
    foreach ($name in @('http_proxy', 'https_proxy')) {
        [void]$tracking.installed.PSObject.Properties.Remove($name)
        [void]$tracking.installed.PSObject.Properties.Remove("${name}_pending")
    }
    $temporaryPath = "$trackingPath.$PID.tmp"
    $tracking | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
    Move-Item -LiteralPath $temporaryPath -Destination $trackingPath -Force
}

function Stop-InstalledProxy([string]$proxyExecutable) {
    Get-CimInstance Win32_Process -Filter "Name='unproxy.exe'" |
        Where-Object { $_.ExecutablePath -eq $proxyExecutable } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $deadline = (Get-Date).AddSeconds(5)
    do {
        $proxy = Get-CimInstance Win32_Process -Filter "Name='unproxy.exe'" |
            Where-Object { $_.ExecutablePath -eq $proxyExecutable }
        if (-not $proxy) { return }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    throw 'The Unproxy proxy did not stop; no files were removed.'
}

$administrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$legacyServiceData = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Unproxy'
if ($AsService) {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $stagePattern = '^' + [regex]::Escape($programFiles) + '\\Unproxy-setup-[0-9a-f]{32}\\payload\z'
    if (-not $administrator -or $PSScriptRoot -notmatch $stagePattern) {
        throw 'Use the verified Windows service setup procedure at https://m42e.github.io/unproxy/docs/installation.html#windows-service'
    }
    $serviceRoot = Join-Path $programFiles 'Unproxy'
    $serviceData = Join-Path $serviceRoot 'data'
    if (Test-Path -LiteralPath $serviceRoot) {
        $service = Get-Service -Name 'Unproxy' -ErrorAction SilentlyContinue
        if ($service) {
            $service.Dispose()
            $serviceRegister = Join-Path $PSScriptRoot 'unproxy-register.exe'
            & $serviceRegister uninstall
            if ($LASTEXITCODE -ne 0) { throw 'Could not remove the Unproxy service registration.' }
        }
        if ($RemoveUserData) {
            Remove-Item -LiteralPath $serviceRoot -Recurse -Force
        } else {
            Get-ChildItem -LiteralPath $serviceRoot -Force |
                Where-Object { $_.FullName -ne $serviceData } |
                Remove-Item -Recurse -Force
            Write-Host "Service configuration and logs were preserved in $serviceData."
        }
    }
    if ($RemoveUserData) {
        Remove-Item $legacyServiceData -Recurse -Force -ErrorAction SilentlyContinue
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
Withdraw-ManagedProxyEnvironment $environmentBackupPath
Clear-ManagedProxyTracking $environmentBackupPath
try { $event = [Threading.EventWaitHandle]::OpenExisting('Local\UnproxyTrayExit'); $event.Set() | Out-Null; $event.Dispose() } catch { }
$installed = Join-Path $destination 'UnproxyTray.exe'
$proxy = Join-Path $destination 'unproxy.exe'
$deadline = (Get-Date).AddSeconds(10)
do { $trayRunning = Get-CimInstance Win32_Process -Filter "Name='UnproxyTray.exe'" | Where-Object { $_.ExecutablePath -eq $installed }; if (-not $trayRunning) { break }; Start-Sleep -Milliseconds 200 } while ((Get-Date) -lt $deadline)
if ($trayRunning) {
    $trayRunning | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $killDeadline = (Get-Date).AddSeconds(5)
    do { $trayRunning = Get-CimInstance Win32_Process -Filter "Name='UnproxyTray.exe'" | Where-Object { $_.ExecutablePath -eq $installed }; if (-not $trayRunning) { break }; Start-Sleep -Milliseconds 200 } while ((Get-Date) -lt $killDeadline)
    if ($trayRunning) {
        Write-Warning 'The tray is still exiting after the force-stop request; waiting before environment reconciliation.'
        do {
            $trayRunning = Get-CimInstance Win32_Process -Filter "Name='UnproxyTray.exe'" |
                Where-Object { $_.ExecutablePath -eq $installed }
            if (-not $trayRunning) { break }
            Start-Sleep -Milliseconds 200
        } while ($true)
    }
}
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*unproxy-tray.ps1*' -and $_.CommandLine -like "*$destination*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Withdraw-ManagedProxyEnvironment $environmentBackupPath
Clear-ManagedProxyTracking $environmentBackupPath
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Stop-InstalledProxy $proxy
Remove-ItemProperty $runKey -Name Unproxy -ErrorAction SilentlyContinue
if (Test-Path -LiteralPath $environmentBackupPath) {
    try {
        $environmentState = Get-Content $environmentBackupPath -Raw | ConvertFrom-Json
        foreach ($name in @('http_proxy', 'https_proxy', 'no_proxy')) {
            $currentValue = [Environment]::GetEnvironmentVariable($name, 'User')
            $installedProperty = $environmentState.installed.PSObject.Properties[$name]
            if ($installedProperty -and $null -ne $installedProperty.Value -and
                $currentValue -ceq [string]$installedProperty.Value) {
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
    if (Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Unproxy\data')) {
        Write-Host 'Windows service configuration and logs are stored under Program Files\Unproxy\data.'
    }
}
