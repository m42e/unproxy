param([switch]$DisableLoginStartup, [switch]$AsService)
$ErrorActionPreference = 'Stop'

function Test-ListenerAddressConflict([string]$configuredAddress, [string]$boundAddress) {
    if ($configuredAddress -eq '*' -or $boundAddress -eq '*') { return $true }
    try {
        $configuredIp = [System.Net.IPAddress]::Parse($configuredAddress.Split('%')[0])
        $boundIp = [System.Net.IPAddress]::Parse($boundAddress.Split('%')[0])
        if ($configuredIp.AddressFamily -ne $boundIp.AddressFamily) { return $false }
        return $configuredIp.Equals($boundIp) -or
            $configuredIp.Equals([System.Net.IPAddress]::Any) -or
            $boundIp.Equals([System.Net.IPAddress]::Any) -or
            $configuredIp.Equals([System.Net.IPAddress]::IPv6Any) -or
            $boundIp.Equals([System.Net.IPAddress]::IPv6Any)
    } catch {
        return $configuredAddress -ieq $boundAddress
    }
}

function Get-ProxyPortOwners([string[]]$listeners) {
    foreach ($listener in $listeners) {
        if ($listener -match '^\[(?<address>[^\]]+)\]:(?<port>\d+)$') {
            $configuredAddress = $Matches.address
            $port = [int]$Matches.port
        } elseif ($listener -match '^(?<address>[^:]+):(?<port>\d+)$') {
            $configuredAddress = $Matches.address
            $port = [int]$Matches.port
        } else {
            continue
        }
        $connections = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue |
            Where-Object { Test-ListenerAddressConflict $configuredAddress $_.LocalAddress })
        $ownerIds = @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
        foreach ($ownerId in $ownerIds) {
            $process = Get-CimInstance Win32_Process -Filter "ProcessId = $ownerId" -ErrorAction SilentlyContinue
            if (-not $process) {
                [pscustomobject]@{ ProcessId = $ownerId; Name = 'unknown'; Path = ''; Port = $port; Address = $configuredAddress; Identity = "PID $ownerId" }
                continue
            }
            $productInfo = ''
            if ($process.ExecutablePath) {
                try {
                    $versionInfo = (Get-Item -LiteralPath $process.ExecutablePath -ErrorAction Stop).VersionInfo
                    $productInfo = "$($versionInfo.ProductName) $($versionInfo.FileDescription)"
                } catch { }
            }
            [pscustomobject]@{
                ProcessId = $ownerId
                Name = $process.Name
                Path = $process.ExecutablePath
                Port = $port
                Address = $configuredAddress
                Identity = "$($process.Name) $($process.ExecutablePath) $productInfo"
            }
        }
    }
}

function Assert-ProxyListenersAvailable([string[]]$listeners) {
    $userProxyPath = Join-Path $env:LOCALAPPDATA 'Unproxy\bin\unproxy.exe'
    $serviceProxyPath = Join-Path $env:ProgramFiles 'Unproxy\unproxy.exe'
    while ($true) {
        $owners = @(Get-ProxyPortOwners $listeners)
        if ($owners.Count -eq 0) { return }

        $proxyDetoxOwners = @($owners | Where-Object {
            $_.Identity -match '(?i)proxy[\s._-]*detox|detox[\s._-]*proxy'
        })
        if ($proxyDetoxOwners.Count -gt 0) {
            $endpoints = ($proxyDetoxOwners | ForEach-Object { "$($_.Address):$($_.Port)" } | Select-Object -Unique) -join ', '
            Write-Warning "Proxy Detox is listening on $endpoints. Uninstall Proxy Detox before installing Unproxy."
            [void](Read-Host "After uninstalling Proxy Detox, press Enter to check $endpoints again")
            continue
        }

        $otherOwners = @($owners | Where-Object {
            $_.Name -ine 'unproxy.exe' -or
            ($_.Path -ine $userProxyPath -and $_.Path -ine $serviceProxyPath)
        })
        if ($otherOwners.Count -eq 0) { return }

        $details = ($otherOwners | ForEach-Object { "$($_.Name) (PID $($_.ProcessId))" }) -join ', '
        $endpoints = ($otherOwners | ForEach-Object { "$($_.Address):$($_.Port)" } | Select-Object -Unique) -join ', '
        throw "Unproxy listener $endpoints is already in use by $details. Stop that program before installing Unproxy."
    }
}

function ConvertFrom-UnproxyConfigLine([string]$line) {
    $tokens = [System.Collections.Generic.List[string]]::new()
    $token = [System.Text.StringBuilder]::new()
    $quoted = $false
    $active = $false
    foreach ($character in $line.ToCharArray()) {
        if ($character -eq '"') {
            $quoted = -not $quoted
            $active = $true
        } elseif ([char]::IsWhiteSpace($character) -and -not $quoted) {
            if ($active) {
                [void]$tokens.Add($token.ToString())
                [void]$token.Clear()
                $active = $false
            }
        } else {
            [void]$token.Append($character)
            $active = $true
        }
    }
    if ($active) { [void]$tokens.Add($token.ToString()) }
    return $tokens.ToArray()
}

function Get-ConfiguredServiceListeners([string]$configPath) {
    $listeners = [System.Collections.Generic.List[string]]::new()
    if (-not (Test-Path -LiteralPath $configPath)) { return $listeners.ToArray() }
    $content = Get-Content -LiteralPath $configPath -Raw
    foreach ($line in ($content -split "`r?`n")) {
        $line = $line.TrimStart([char]0xFEFF).Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        $tokens = @(ConvertFrom-UnproxyConfigLine $line)
        for ($index = 0; $index -lt $tokens.Count; $index++) {
            $token = [string]$tokens[$index]
            if ($token -in @('--listen', '-L')) {
                if ($index + 1 -lt $tokens.Count) {
                    [void]$listeners.Add([string]$tokens[$index + 1])
                    $index++
                }
            } elseif ($token.StartsWith('--listen=', [StringComparison]::Ordinal) -or
                $token.StartsWith('-L=', [StringComparison]::Ordinal)) {
                [void]$listeners.Add($token.Substring($token.IndexOf('=') + 1))
            }
        }
    }
    return $listeners.ToArray()
}

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
    $serviceListeners = @(Get-ConfiguredServiceListeners $serviceConfig)
    if ($serviceListeners.Count -eq 0) { $serviceListeners = @('127.0.0.1:3128', '[::1]:3128') }
    Assert-ProxyListenersAvailable $serviceListeners
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
$prefsFile = Join-Path $root 'preferences.json'
$metadataFile = Join-Path $PSScriptRoot 'metadata.json'
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
$configuredListeners = @($preferences.listeners | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
if ($configuredListeners.Count -eq 0) {
    $configuredPort = [int]$preferences.port
    if ($configuredPort -lt 1024 -or $configuredPort -gt 65534) { $configuredPort = 3128 }
    $configuredListeners = @("127.0.0.1:$configuredPort", "[::1]:$configuredPort")
}
Assert-ProxyListenersAvailable $configuredListeners
$metadataDestination = Join-Path $destination 'metadata.json'
New-Item -ItemType Directory -Path $destination -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'unproxy.exe') (Join-Path $destination 'unproxy.exe') -Force
Copy-Item (Join-Path $PSScriptRoot 'UnproxyTray.exe') (Join-Path $destination 'UnproxyTray.exe') -Force
$legacySettingsHelper = Join-Path $destination 'unproxy-tray.ps1'
if (Test-Path -LiteralPath $legacySettingsHelper) {
    Remove-Item -LiteralPath $legacySettingsHelper -Force
}
$trayIconDirectory = Join-Path $destination 'tray-icons'
New-Item -ItemType Directory -Path $trayIconDirectory -Force | Out-Null
Copy-Item (Join-Path (Join-Path $PSScriptRoot 'tray-icons') '*') $trayIconDirectory -Recurse -Force
Copy-Item $metadataFile $metadataDestination -Force
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

$proxyHost = '127.0.0.1'
$proxyPort = [int]$preferences.port
if ($proxyPort -lt 1024 -or $proxyPort -gt 65534) { $proxyPort = 3128 }
if ($preferences.listeners -and $preferences.listeners.Count -gt 0) {
    $primaryListener = [string]$preferences.listeners[0]
    if ($primaryListener -match '^\[(?<host>[^\]]+)\]:(?<port>\d+)$') {
        $proxyHost = $Matches.host
        if ($proxyHost -eq '::') { $proxyHost = '::1' }
        $proxyHost = "[$proxyHost]"
        $proxyPort = [int]$Matches.port
    } elseif ($primaryListener -match '^(?<host>[^:]+):(?<port>\d+)$') {
        $proxyHost = $Matches.host
        if ($proxyHost -eq '0.0.0.0') { $proxyHost = '127.0.0.1' }
        $proxyPort = [int]$Matches.port
    }
}
$proxyUrl = 'http://{0}:{1}' -f $proxyHost, $proxyPort
$proxyEnvironment = [ordered]@{
    http_proxy = $proxyUrl
    https_proxy = $proxyUrl
    no_proxy = 'localhost,127.0.0.1,::1'
}
$environmentBackupPath = Join-Path $root 'environment-before-install.json'
if (Test-Path -LiteralPath $environmentBackupPath) {
    $environmentState = Get-Content $environmentBackupPath -Raw | ConvertFrom-Json
    $previousEnvironment = $environmentState.original
} else {
    $previousEnvironment = [ordered]@{}
    foreach ($name in $proxyEnvironment.Keys) {
        $previousEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'User')
    }
}
[ordered]@{
    original = $previousEnvironment
    installed = $proxyEnvironment
} | ConvertTo-Json -Depth 3 | Set-Content -Encoding UTF8 $environmentBackupPath
foreach ($name in $proxyEnvironment.Keys) {
    [Environment]::SetEnvironmentVariable($name, $proxyEnvironment[$name], 'User')
    Set-Item -Path ("Env:{0}" -f $name) -Value $proxyEnvironment[$name]
}

Write-Host "Installed Unproxy to $destination. User data is stored in $root."
Start-Process (Join-Path $destination 'UnproxyTray.exe')
