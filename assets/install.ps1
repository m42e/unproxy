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

function Assert-NoServicePathReparsePoints([string]$path) {
    $current = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetFullPath($path))
    while ($null -ne $current) {
        if (Test-Path -LiteralPath $current.FullName) {
            $item = Get-Item -LiteralPath $current.FullName -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "The Unproxy service install path cannot contain a reparse point: $($current.FullName)"
            }
        }
        $parent = $current.Parent
        if ($null -eq $parent -or $parent.FullName -eq $current.FullName) { break }
        $current = $parent
    }
}

function Assert-ServiceFileHasSingleLink([string]$path) {
    $fsutil = Join-Path ([Environment]::GetFolderPath('System')) 'fsutil.exe'
    $links = @(& $fsutil hardlink list $path 2>&1)
    if ($LASTEXITCODE -ne 0 -or $links.Count -ne 1) {
        throw "Could not verify that the Unproxy service file has exactly one hard link: $path"
    }
}

function Protect-ServiceRoot([string]$root) {
    Assert-NoServicePathReparsePoints $root
    $acl = Get-Acl -LiteralPath $root
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleAll($rule) }
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $networkServiceSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-20')
    $usersSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $acl.SetOwner($administratorsSid)
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $none = [System.Security.AccessControl.PropagationFlags]::None
    foreach ($identity in @($systemSid, $administratorsSid)) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'FullControl', $inherit, $none, $allow))
    }
    foreach ($identity in @($networkServiceSid, $usersSid)) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $identity, 'ReadAndExecute', $inherit, $none, $allow))
    }
    Set-Acl -LiteralPath $root -AclObject $acl

    $icacls = Join-Path ([Environment]::GetFolderPath('System')) 'icacls.exe'
    foreach ($path in [System.IO.Directory]::EnumerateFileSystemEntries($root)) {
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The Unproxy service install directory cannot contain a reparse point: $path"
        }
        if (($item.Attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
            Assert-ServiceFileHasSingleLink $item.FullName
        }
        & $icacls $item.FullName /setowner '*S-1-5-32-544' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not set the owner of Unproxy service entry: $($item.FullName)" }
        & $icacls $item.FullName /reset | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Could not secure Unproxy service entry: $($item.FullName)" }
    }
}

function Protect-ServiceData([string]$root) {
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The Unproxy service data directory cannot be a reparse point: $root"
    }
    $acl = Get-Acl -LiteralPath $root
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleAll($rule) }
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administratorsSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $networkServiceSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-20')
    $acl.SetOwner($administratorsSid)
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid, 'FullControl', $inherit, $none, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $administratorsSid, 'FullControl', $inherit, $none, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $networkServiceSid, 'ReadAndExecute', $inherit, $none, $allow))
    Set-Acl -LiteralPath $root -AclObject $acl

    # Secure each parent before inspecting its children. Never run a recursive
    # ACL operation against a tree inventoried while it was still writable.
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    $icacls = Join-Path ([Environment]::GetFolderPath('System')) 'icacls.exe'
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $directoryItem = Get-Item -LiteralPath $directory -Force
        if (($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The Unproxy service data directory cannot contain a reparse point: $directory"
        }
        foreach ($path in [System.IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $entry = Get-Item -LiteralPath $path -Force
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse points are not supported in the Unproxy service data directory: $path"
            }
            if (($entry.Attributes -band [System.IO.FileAttributes]::Directory) -eq 0) {
                Assert-ServiceFileHasSingleLink $entry.FullName
            }
            & $icacls $entry.FullName /setowner '*S-1-5-32-544' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not set the owner of Unproxy service entry: $($entry.FullName)" }
            & $icacls $entry.FullName /reset | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Could not secure Unproxy service data entry: $($entry.FullName)" }
            $entry = Get-Item -LiteralPath $path -Force
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Reparse points are not supported in the Unproxy service data directory: $path"
            }
            if (($entry.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                $pending.Push($entry.FullName)
            }
        }
    }

    $logs = Join-Path $root 'logs'
    New-Item -ItemType Directory -Path $logs -Force | Out-Null
    Grant-ServiceLogAccess $logs $networkServiceSid
}

function Grant-ServiceLogAccess([string]$root, [System.Security.Principal.SecurityIdentifier]$networkServiceSid) {
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($root)
    $directories = [System.Collections.Generic.List[string]]::new()
    $files = [System.Collections.Generic.List[string]]::new()
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $none = [System.Security.AccessControl.PropagationFlags]::None
    while ($pending.Count -gt 0) {
        $path = $pending.Pop()
        $item = Get-Item -LiteralPath $path -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Logs cannot contain a reparse point: $path"
        }
        $isDirectory = ($item.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0
        if ($isDirectory) {
            [void]$directories.Add($path)
            foreach ($child in [System.IO.Directory]::EnumerateFileSystemEntries($path)) {
                $pending.Push($child)
            }
        } else {
            Assert-ServiceFileHasSingleLink $path
            [void]$files.Add($path)
        }
    }

    # Grant existing log files before allowing writes to the log directories.
    # This keeps the checked tree stable against new links during ACL changes.
    foreach ($path in $files) {
        $acl = Get-Acl -LiteralPath $path
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $networkServiceSid, 'Modify', [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow))
        Set-Acl -LiteralPath $path -AclObject $acl
    }

    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rootAcl = Get-Acl -LiteralPath $root
    $rootAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $networkServiceSid, 'Modify', $inherit, $none, $allow))
    Set-Acl -LiteralPath $root -AclObject $rootAcl

    foreach ($directory in $directories) {
        $directoryItem = Get-Item -LiteralPath $directory -Force
        if (($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Logs cannot contain a reparse point: $directory"
        }
    }
}

$administrator = ([Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($AsService) {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $stagePattern = '^' + [regex]::Escape($programFiles) + '\\Unproxy-setup-[0-9a-f]{32}\\payload\z'
    if (-not $administrator -or $PSScriptRoot -notmatch $stagePattern) {
        throw 'Use the verified Windows service setup procedure at https://m42e.github.io/unproxy/docs/installation.html#windows-service'
    }

    $serviceRoot = Join-Path $programFiles 'Unproxy'
    $serviceData = Join-Path $serviceRoot 'data'
    $serviceExecutable = Join-Path $serviceRoot 'unproxy.exe'
    $serviceRegister = Join-Path $serviceRoot 'unproxy-register.exe'
    $servicePac = Join-Path $serviceData 'proxy.pac'
    $serviceLog = Join-Path (Join-Path $serviceData 'logs') 'unproxy.log'
    $serviceConfig = Join-Path $serviceData 'unproxyrc'
    $serviceListeners = @('127.0.0.1:3128', '[::1]:3128')
    Assert-ProxyListenersAvailable $serviceListeners

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
    Assert-NoServicePathReparsePoints $serviceRoot
    New-Item -ItemType Directory -Path $serviceRoot -Force | Out-Null
    Protect-ServiceRoot $serviceRoot
    New-Item -ItemType Directory -Path $serviceData -Force | Out-Null
    Protect-ServiceData $serviceData

    Copy-Item (Join-Path $PSScriptRoot 'unproxy.exe') $serviceExecutable -Force
    Copy-Item (Join-Path $PSScriptRoot 'unproxy-register.exe') $serviceRegister -Force
    Copy-Item (Join-Path $PSScriptRoot 'unproxyctl.exe') (Join-Path $serviceRoot 'unproxyctl.exe') -Force
    # Keep policy from a prior protected install as review material. Legacy
    # ProgramData files remain untouched and are never read by the installer.
    $migrationReview = Join-Path $serviceData 'migration-review'
    New-Item -ItemType Directory -Path $migrationReview -Force | Out-Null
    foreach ($oldFile in @($serviceConfig, $servicePac)) {
        if (Test-Path -LiteralPath $oldFile -PathType Leaf) {
            $oldItem = Get-Item -LiteralPath $oldFile -Force
            if (($oldItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Cannot migrate a reparse point from the prior service data directory: $oldFile"
            }
            $candidate = Join-Path $migrationReview (Split-Path -Leaf $oldFile)
            if (-not (Test-Path -LiteralPath $candidate)) {
                Copy-Item -LiteralPath $oldFile -Destination $candidate -Force
            }
        }
    }
    Copy-Item (Join-Path $PSScriptRoot 'proxy.pac.sample') $servicePac
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

if ($administrator) { throw 'Run the per-user tray installer in a non-elevated PowerShell session.' }
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
