param([switch]$DisableLoginStartup, [switch]$AsService)
$ErrorActionPreference = 'Stop'

if ($AsService) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -AsService'
        $elevated = Start-Process powershell.exe -Verb RunAs -ArgumentList $arguments -Wait -PassThru
        exit $elevated.ExitCode
    }

    $serviceRoot = Join-Path $env:ProgramFiles 'Unproxy'
    $serviceData = Join-Path $env:ProgramData 'Unproxy'
    $serviceExecutable = Join-Path $serviceRoot 'unproxy.exe'
    $serviceRegister = Join-Path $serviceRoot 'unproxy-register.exe'
    $servicePac = Join-Path $serviceData 'proxy.pac'
    $serviceLog = Join-Path $serviceData 'unproxy.log'
    $serviceConfig = Join-Path $serviceData 'unproxyrc'
    New-Item -ItemType Directory -Path $serviceRoot, $serviceData -Force | Out-Null

    $trayExecutable = Join-Path $env:LOCALAPPDATA 'Unproxy\bin\UnproxyTray.exe'
    $tray = Get-CimInstance Win32_Process -Filter "Name='UnproxyTray.exe'" |
        Where-Object { $_.ExecutablePath -eq $trayExecutable }
    if ($tray) {
        try {
            $event = [Threading.EventWaitHandle]::OpenExisting('Local\UnproxyTrayExit')
            $event.Set() | Out-Null
            $event.Dispose()
        } catch { }
        $deadline = (Get-Date).AddSeconds(10)
        do {
            $tray = Get-CimInstance Win32_Process -Filter "Name='UnproxyTray.exe'" |
                Where-Object { $_.ExecutablePath -eq $trayExecutable }
            if (-not $tray) { break }
            Start-Sleep -Milliseconds 200
        } while ((Get-Date) -lt $deadline)
        if ($tray) {
            throw 'Close the Unproxy tray app before installing the Windows service.'
        }
    }

    $existing = Get-Service -Name 'Unproxy' -ErrorAction SilentlyContinue
    if ($existing -and $existing.Status -ne 'Stopped') {
        Stop-Service -Name 'Unproxy'
        $existing.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(45))
    }
    if ($existing) { $existing.Dispose() }

    Copy-Item (Join-Path $PSScriptRoot 'unproxy.exe') $serviceExecutable -Force
    Copy-Item (Join-Path $PSScriptRoot 'unproxy-register.exe') $serviceRegister -Force
    Copy-Item (Join-Path $PSScriptRoot 'unproxyctl.exe') (Join-Path $serviceRoot 'unproxyctl.exe') -Force
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $serviceData /grant '*S-1-5-20:(OI)(CI)M' /T /C | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant the Unproxy service access to its data folder.' }
    if (-not (Test-Path -LiteralPath $servicePac)) {
        Copy-Item (Join-Path $PSScriptRoot 'proxy.pac.sample') $servicePac
    }
    if (-not (Test-Path -LiteralPath $serviceConfig)) {
        $metadata = Get-Content (Join-Path $PSScriptRoot 'metadata.json') -Raw | ConvertFrom-Json
        $authHint = if ($metadata.negotiate) {
            '# Add --negotiate on its own line to use Windows Negotiate authentication.'
        } else {
            '# This build was packaged without Windows Negotiate authentication.'
        }
        @(
            ('--pac-file "' + $servicePac + '"')
            ('--logfile "' + $serviceLog + '"')
            $authHint
        ) | Set-Content -Encoding UTF8 $serviceConfig
    }

    & $serviceRegister install
    if ($LASTEXITCODE -ne 0) { throw 'Could not install and start the Unproxy service.' }
    $service = Get-Service -Name 'Unproxy'
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
    $service.Dispose()

    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    Remove-ItemProperty $runKey -Name Unproxy -ErrorAction SilentlyContinue
    Write-Host "Installed and started the Unproxy Windows service. Configuration and logs are in $serviceData."
    Write-Host 'The service starts automatically at boot and runs as NetworkService.'
    return
}

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
        listeners = @()
        pacFiles = @()
        proxytunnel = $false
        directFallback = $false
        negotiate = $false
        autostart = $true
    }
}
if (-not ($preferences.PSObject.Properties.Name -contains 'listeners')) {
    $preferences | Add-Member -NotePropertyName listeners -NotePropertyValue @()
}
if (-not ($preferences.PSObject.Properties.Name -contains 'pacFiles')) {
    $preferences | Add-Member -NotePropertyName pacFiles -NotePropertyValue @()
}
if (-not $preferences.pacFile) { $preferences.pacFile = Join-Path $root 'proxy.pac' }
$pacUri = $null
$isRemotePac = [Uri]::TryCreate(
    [string]$preferences.pacFile, [UriKind]::Absolute, [ref]$pacUri) -and
    ($pacUri.Scheme -eq [Uri]::UriSchemeHttp -or $pacUri.Scheme -eq [Uri]::UriSchemeHttps) -and
    -not [string]::IsNullOrWhiteSpace($pacUri.Host) -and
    [string]::IsNullOrEmpty($pacUri.UserInfo) -and
    [string]::IsNullOrEmpty($pacUri.Fragment)
if ($isRemotePac) {
    $preferences.pacFile = $pacUri.AbsoluteUri
} elseif (-not [IO.Path]::IsPathRooted([string]$preferences.pacFile)) {
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
