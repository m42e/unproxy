$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$root = Join-Path $env:LOCALAPPDATA 'Unproxy'
$bin = Join-Path $root 'bin'
$settingsFile = Join-Path $root 'preferences.json'
$logFile = Join-Path $root 'unproxy.log'
$metadataFile = Join-Path $bin 'metadata.json'
New-Item -ItemType Directory -Force -Path $root | Out-Null

$metadata = if (Test-Path $metadataFile) {
    Get-Content $metadataFile -Raw | ConvertFrom-Json
} else { $null }
$script:negotiateAvailable = -not $metadata -or [bool]$metadata.negotiate
$hasPreferences = Test-Path $settingsFile

$mutex = [Threading.Mutex]::new($false, 'Local\UnproxyTray')
$activationSignal = [Threading.EventWaitHandle]::new(
    $false, [Threading.EventResetMode]::AutoReset, 'Local\UnproxyTrayActivate')
$exitSignal = [Threading.EventWaitHandle]::new(
    $false, [Threading.EventResetMode]::AutoReset, 'Local\UnproxyTrayExit')
if (-not $mutex.WaitOne(0)) {
    $activationSignal.Set() | Out-Null
    $activationSignal.Dispose()
    $exitSignal.Dispose()
    exit
}

$script:p = if ($hasPreferences) {
    Get-Content $settingsFile -Raw | ConvertFrom-Json
} elseif ($metadata -and $metadata.defaults) {
    $metadata.defaults
} else {
    [pscustomobject]@{
        port = 3128
        pacFile = (Join-Path $root 'proxy.pac')
        proxytunnel = $false
        directFallback = $false
        negotiate = $false
        autostart = $true
    }
}
if (-not ($script:p.PSObject.Properties.Name -contains 'listeners')) {
    $script:p | Add-Member -NotePropertyName listeners -NotePropertyValue @()
}
if (-not $script:p.pacFile) { $script:p.pacFile = Join-Path $root 'proxy.pac' }
if (-not [IO.Path]::IsPathRooted([string]$script:p.pacFile)) {
    $script:p.pacFile = [IO.Path]::GetFullPath((Join-Path $root ([string]$script:p.pacFile)))
}
if (-not $hasPreferences -and $script:p.pacFile -eq (Join-Path $root 'proxy.pac')) {
    'function FindProxyForURL(url, host) { return "DIRECT"; }' |
        Set-Content -Encoding UTF8 $script:p.pacFile
}
$script:child = $null
$script:lastExitCode = $null
$script:runtimeStatus = $null
$script:icon = [Windows.Forms.NotifyIcon]::new()
$script:icon.Icon = [Drawing.Icon]::new(
    (Join-Path $PSScriptRoot 'tray-icons\stopped-unloaded-unknown-disabled.ico'))
$script:icon.Visible = $true
$script:icon.Text = 'Unproxy Off | PAC ? | Up ? | Auth Off'

function Save-Prefs {
    $script:p | ConvertTo-Json | Set-Content -Encoding UTF8 $settingsFile
}

function Log-Line([string]$line) {
    if ((Test-Path $logFile) -and (Get-Item $logFile).Length -gt 1048576) {
        Move-Item $logFile ($logFile + '.1') -Force
    }
    Add-Content -Encoding UTF8 $logFile $line
}

function Get-IconStates {
    $authConfigured = ([bool]$script:p.negotiate -and $script:negotiateAvailable) -or
        (Test-Path (Join-Path $env:USERPROFILE '.netrc'))
    if ($script:child -and $script:runtimeStatus) {
        $authConfigured = [bool]$script:runtimeStatus.authentication_configured
    }
    $service = if ($script:child) { 'running' }
        elseif ($null -ne $script:lastExitCode) { 'failed' }
        else { 'stopped' }
    $pac = if (-not $script:child) { 'unloaded' }
        elseif ($null -eq $script:runtimeStatus -or $null -eq $script:runtimeStatus.pac_loaded) { 'unknown' }
        elseif ($script:runtimeStatus.pac_loaded) { 'loaded' }
        else { 'unloaded' }
    $recent = $false
    if ($script:runtimeStatus -and $null -ne $script:runtimeStatus.upstream_checked_at) {
        $age = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -
            [long]$script:runtimeStatus.upstream_checked_at
        $recent = $age -ge 0 -and $age -le 300
    }
    $upstream = if (-not $recent) { 'unknown' }
        elseif ($script:runtimeStatus.upstream_state -eq 'ok') { 'ok' }
        else { 'error' }
    $auth = if ($recent -and $script:runtimeStatus.authentication_state -eq 'authenticated') {
        'authenticated'
    } elseif ($recent -and $script:runtimeStatus.authentication_state -eq 'rejected') {
        'rejected'
    } elseif ($authConfigured) {
        'configured'
    } else {
        'disabled'
    }
    return @($service, $pac, $upstream, $auth)
}

function Update-TrayIcon {
    $states = Get-IconStates
    $key = $states -join '-'
    if ($script:currentIconKey -ne $key) {
        $path = Join-Path $PSScriptRoot "tray-icons\$key.ico"
        if (Test-Path -LiteralPath $path) {
            $next = [Drawing.Icon]::new($path)
            $previous = $script:icon.Icon
            $script:icon.Icon = $next
            if ($previous) { $previous.Dispose() }
            $script:currentIconKey = $key
        }
    }
    $labels = switch ($states[0]) {
        'running' { 'On' }
        'failed' { 'Error' }
        default { 'Off' }
    }
    $pacLabel = switch ($states[1]) {
        'loaded' { 'Ready' }
        'unloaded' { 'No' }
        default { '?' }
    }
    $upstreamLabel = switch ($states[2]) {
        'ok' { 'OK' }
        'error' { 'Fail' }
        default { '?' }
    }
    $authLabel = switch ($states[3]) {
        'authenticated' { 'OK' }
        'rejected' { '407' }
        'configured' { 'Set' }
        default { 'Off' }
    }
    $script:icon.Text = "Unproxy $labels | PAC $pacLabel | Up $upstreamLabel | Auth $authLabel"
}

function Read-RuntimeStatus {
    if (-not $script:child) { return }
    $listeners = @(Get-ListenerAddresses)
    $listener = if ($listeners.Count -gt 0) { Parse-ListenerAddress ([string]$listeners[0]) } else { $null }
    if (-not $listener) { return }
    $hostHeader = if ($listener.IPAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        "[$($listener.IPAddress.ToString())]:$($listener.Port)"
    } else { "$($listener.IPAddress.ToString()):$($listener.Port)" }
    $client = if ($listener.IPAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
    } else { [Net.Sockets.TcpClient]::new() }
    try {
        $client.ReceiveTimeout = 250
        $client.SendTimeout = 250
        $client.Connect($listener.IPAddress, [int]$listener.Port)
        $stream = $client.GetStream()
        $request = [Text.Encoding]::ASCII.GetBytes(
            "GET /status.json HTTP/1.1`r`nHost: $hostHeader`r`nConnection: close`r`n`r`n")
        $stream.Write($request, 0, $request.Length)
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8)
        $response = $reader.ReadToEnd()
        $bodyStart = $response.IndexOf("`r`n`r`n")
        if ($bodyStart -lt 0 -or -not $response.StartsWith('HTTP/1.1 200')) {
            throw 'Status endpoint did not return HTTP 200.'
        }
        $script:runtimeStatus = $response.Substring($bodyStart + 4) | ConvertFrom-Json
    } catch {
        if ($script:runtimeStatus) { $script:runtimeStatus.pac_loaded = $null }
    } finally {
        $client.Dispose()
    }
}

function Refresh-State {
    if ($script:child -and $script:child.HasExited) {
        $code = $script:child.ExitCode
        $script:lastExitCode = $code
        Log-Line "$(Get-Date -Format o) proxy exited with code $code"
        $script:icon.ShowBalloonTip(
            5000, 'Unproxy',
            "Proxy stopped unexpectedly (exit $code). Open the Unproxy log for details.",
            [Windows.Forms.ToolTipIcon]::Warning)
        $script:child = $null
    }
    if ($script:child) {
        Read-RuntimeStatus
        $listeners = @(Get-ListenerAddresses)
        if ($listeners.Count -gt 0) { $script:icon.Text = "Unproxy running on $($listeners[0])" }
    }
    Update-TrayIcon
}

function Stop-Proxy {
    if ($script:child) {
        try {
            # A hidden console child may not have a window; force it only after the wait.
            [void]$script:child.CloseMainWindow()
            if (-not $script:child.WaitForExit(5000)) {
                Log-Line "$(Get-Date -Format o) graceful stop timed out; forcing termination"
                $script:child.Kill()
                $script:child.WaitForExit()
            }
        } finally {
            $script:child = $null
            $script:lastExitCode = $null
        }
    }
    Refresh-State
}

function Test-PortValid {
    $value = [long]0
    return [long]::TryParse([string]$script:p.port, [ref]$value) -and $value -ge 1024 -and $value -le 65534
}

function Parse-ListenerAddress([string]$value) {
    $text = $value.Trim()
    if ($text -match '^\[(?<address>[^\]]+)\]:(?<port>\d+)$') {
        $addressText = $Matches.address
        $portText = $Matches.port
    } elseif ($text -match '^(?<address>[^:]+):(?<port>\d+)$') {
        $addressText = $Matches.address
        $portText = $Matches.port
    } else {
        return $null
    }
    $port = [long]0
    $address = $null
    if (-not [long]::TryParse($portText, [ref]$port) -or
        $port -lt 1024 -or $port -gt 65534 -or
        -not [Net.IPAddress]::TryParse($addressText, [ref]$address)) {
        return $null
    }
    if ($address.Equals([Net.IPAddress]::Any) -or
        $address.Equals([Net.IPAddress]::IPv6Any)) {
        return $null
    }
    $normalizedAddress = if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        "[$($address.ToString())]:$port"
    } else { "$($address.ToString()):$port" }
    return [pscustomobject]@{
        Address = $normalizedAddress
        Port = $port
        IPAddress = $address
    }
}

function Get-ListenerAddresses {
    if ($script:p.listeners -and @($script:p.listeners).Count -gt 0) {
        return @($script:p.listeners | ForEach-Object { [string]$_ })
    }
    $port = if (Test-PortValid) { [long]$script:p.port } else { 3128 }
    return @("127.0.0.1:$port", "[::1]:$port")
}

function Start-Proxy {
    Refresh-State
    if ($script:child) { return }
    $script:lastExitCode = $null
    $script:runtimeStatus = $null
    $listenerAddresses = @(Get-ListenerAddresses)
    if ($listenerAddresses.Count -eq 0) {
        [Windows.Forms.MessageBox]::Show(
            'At least one listener is required. Choose Settings… to add one.', 'Unproxy') | Out-Null
        return
    }
    foreach ($listener in $listenerAddresses) {
        if (-not (Parse-ListenerAddress ([string]$listener))) {
            [Windows.Forms.MessageBox]::Show(
                "Invalid listener address: $listener`nUse a numeric IP address and a port from 1024 through 65534.",
                'Unproxy') | Out-Null
            return
        }
    }
    if (-not [IO.Path]::IsPathRooted([string]$script:p.pacFile)) {
        [Windows.Forms.MessageBox]::Show('PAC path must be absolute.', 'Unproxy') | Out-Null
        return
    }
    if (-not (Test-Path -LiteralPath $script:p.pacFile -PathType Leaf)) {
        [Windows.Forms.MessageBox]::Show(
            "PAC file not found: $($script:p.pacFile)", 'Unproxy') | Out-Null
        return
    }

    $exe = Join-Path $bin 'unproxy.exe'
    $arguments = @()
    foreach ($listener in $listenerAddresses) {
        $arguments += @('--listen', [string]$listener)
    }
    $arguments += @(
        '--pac-file', $script:p.pacFile,
        '--graceful-shutdown-timeout', '0'
    )
    if ($script:p.proxytunnel) { $arguments += '--proxytunnel' }
    if ($script:p.directFallback) { $arguments += '--direct-fallback' }
    if ($script:p.negotiate -and $script:negotiateAvailable) { $arguments += '--negotiate' }

    try {
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $exe
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.EnvironmentVariables['UNPROXY_NORC'] = '1'
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.Arguments = (($arguments | ForEach-Object {
            '"' + ([string]$_).Replace('"', '\"') + '"'
        }) -join ' ')

        $script:child = [Diagnostics.Process]::new()
        $script:child.StartInfo = $startInfo
        $script:child.EnableRaisingEvents = $true
        $script:child.add_OutputDataReceived({ param($sender, $event) if ($event.Data) { Log-Line $event.Data } })
        $script:child.add_ErrorDataReceived({ param($sender, $event) if ($event.Data) { Log-Line $event.Data } })
        [void]$script:child.Start()
        $script:child.BeginOutputReadLine()
        $script:child.BeginErrorReadLine()
        Start-Sleep -Milliseconds 250
        if ($script:child.HasExited) {
            $code = $script:child.ExitCode
            $script:lastExitCode = $code
            $script:child = $null
            throw "Proxy exited during startup (code $code). See $logFile"
        }
    } catch {
        $script:lastExitCode = -1
        Log-Line "$(Get-Date -Format o) start failed: $_"
        [Windows.Forms.MessageBox]::Show(
            "Could not start proxy: $_`nLog: $logFile", 'Unproxy') | Out-Null
        $script:child = $null
    }
    Refresh-State
}

function Show-Settings {
    $form = [Windows.Forms.Form]::new()
    $form.Text = 'Unproxy Settings'
    $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ShowInTaskbar = $false
    $form.ClientSize = [Drawing.Size]::new(700, 525)

    $listenersLabel = [Windows.Forms.Label]::new()
    $listenersLabel.Text = 'Listeners (numeric IP address and port; IPv6 in brackets)'
    $listenersLabel.Location = [Drawing.Point]::new(20, 18)
    $listenersLabel.AutoSize = $true
    [void]$form.Controls.Add($listenersLabel)

    $listenersPanel = [Windows.Forms.Panel]::new()
    $listenersPanel.Location = [Drawing.Point]::new(20, 42)
    $listenersPanel.Size = [Drawing.Size]::new(660, 180)
    $listenersPanel.AutoScroll = $true
    $listenersPanel.BorderStyle = [Windows.Forms.BorderStyle]::FixedSingle
    [void]$form.Controls.Add($listenersPanel)
    $listenerRows = [Collections.ArrayList]::new()
    $renderListenerRows = ({
        $listenersPanel.Controls.Clear()
        for ($index = 0; $index -lt $listenerRows.Count; $index++) {
            $entry = $listenerRows[$index]
            $entry.Panel.Location = [Drawing.Point]::new(0, $index * 34)
            [void]$listenersPanel.Controls.Add($entry.Panel)
        }
        $listenersPanel.AutoScrollMinSize = [Drawing.Size]::new(0, $listenerRows.Count * 34)
    }).GetNewClosure()
    $addListenerRow = ({
        param([string]$value)
        $row = [Windows.Forms.Panel]::new()
        $row.Size = [Drawing.Size]::new(635, 32)
        $addressBox = [Windows.Forms.TextBox]::new()
        $addressBox.Location = [Drawing.Point]::new(5, 4)
        $addressBox.Size = [Drawing.Size]::new(555, 24)
        $addressBox.Text = $value
        [void]$row.Controls.Add($addressBox)
        $remove = [Windows.Forms.Button]::new()
        $remove.Text = 'Remove'
        $remove.Location = [Drawing.Point]::new(570, 2)
        $remove.Size = [Drawing.Size]::new(58, 27)
        [void]$row.Controls.Add($remove)
        $entry = [pscustomobject]@{ Panel = $row; Address = $addressBox }
        $remove.add_Click(({
            [void]$listenerRows.Remove($entry)
            & $renderListenerRows
        }).GetNewClosure())
        [void]$listenerRows.Add($entry)
        & $renderListenerRows
    }).GetNewClosure()
    foreach ($listener in @(Get-ListenerAddresses)) { & $addListenerRow ([string]$listener) }

    $addListenerButton = [Windows.Forms.Button]::new()
    $addListenerButton.Text = 'Add Listener'
    $addListenerButton.Location = [Drawing.Point]::new(20, 229)
    $addListenerButton.Size = [Drawing.Size]::new(120, 30)
    [void]$form.Controls.Add($addListenerButton)
    $addListenerButton.add_Click(({
        & $addListenerRow '127.0.0.1:8080'
    }).GetNewClosure())

    $pacLabel = [Windows.Forms.Label]::new()
    $pacLabel.Text = 'PAC file path'
    $pacLabel.Location = [Drawing.Point]::new(20, 278)
    $pacLabel.AutoSize = $true
    [void]$form.Controls.Add($pacLabel)

    $pacBox = [Windows.Forms.TextBox]::new()
    $pacBox.Location = [Drawing.Point]::new(205, 273)
    $pacBox.Size = [Drawing.Size]::new(410, 24)
    $pacBox.Text = [string]$script:p.pacFile
    [void]$form.Controls.Add($pacBox)

    $browseButton = [Windows.Forms.Button]::new()
    $browseButton.Text = 'Browse…'
    $browseButton.Location = [Drawing.Point]::new(625, 271)
    $browseButton.Size = [Drawing.Size]::new(55, 27)
    [void]$form.Controls.Add($browseButton)
    $browseButton.add_Click(({
        $picker = [Windows.Forms.OpenFileDialog]::new()
        $picker.Title = 'Choose a PAC file'
        $picker.Filter = 'PAC files (*.pac)|*.pac|All files (*.*)|*.*'
        $picker.FileName = $pacBox.Text
        if ($picker.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK) {
            $pacBox.Text = $picker.FileName
        }
        $picker.Dispose()
    }).GetNewClosure())

    $tunnel = [Windows.Forms.CheckBox]::new()
    $tunnel.Text = 'Always use CONNECT'
    $tunnel.Location = [Drawing.Point]::new(205, 315)
    $tunnel.AutoSize = $true
    $tunnel.Checked = [bool]$script:p.proxytunnel
    [void]$form.Controls.Add($tunnel)

    $direct = [Windows.Forms.CheckBox]::new()
    $direct.Text = 'DIRECT fallback'
    $direct.Location = [Drawing.Point]::new(205, 345)
    $direct.AutoSize = $true
    $direct.Checked = [bool]$script:p.directFallback
    [void]$form.Controls.Add($direct)

    $negotiate = [Windows.Forms.CheckBox]::new()
    $negotiate.Text = 'Negotiate'
    $negotiate.Location = [Drawing.Point]::new(205, 375)
    $negotiate.AutoSize = $true
    $negotiate.Checked = [bool]$script:p.negotiate
    $negotiate.Enabled = [bool]$script:negotiateAvailable
    [void]$form.Controls.Add($negotiate)

    $autostart = [Windows.Forms.CheckBox]::new()
    $autostart.Text = 'Start Unproxy when I sign in'
    $autostart.Location = [Drawing.Point]::new(205, 405)
    $autostart.AutoSize = $true
    $autostart.Checked = [bool]$script:p.autostart
    [void]$form.Controls.Add($autostart)

    $saveButton = [Windows.Forms.Button]::new()
    $saveButton.Text = 'Save'
    $saveButton.Location = [Drawing.Point]::new(500, 470)
    $saveButton.Size = [Drawing.Size]::new(80, 30)
    $saveButton.DialogResult = [Windows.Forms.DialogResult]::None
    [void]$form.Controls.Add($saveButton)

    $cancelButton = [Windows.Forms.Button]::new()
    $cancelButton.Text = 'Cancel'
    $cancelButton.Location = [Drawing.Point]::new(590, 470)
    $cancelButton.Size = [Drawing.Size]::new(80, 30)
    $cancelButton.DialogResult = [Windows.Forms.DialogResult]::Cancel
    [void]$form.Controls.Add($cancelButton)
    $form.AcceptButton = $saveButton
    $form.CancelButton = $cancelButton

    $saveButton.add_Click(({
        if (-not [IO.Path]::IsPathRooted($pacBox.Text)) {
            [Windows.Forms.MessageBox]::Show(
                'PAC path must be absolute.', 'Unproxy Settings') | Out-Null
            return
        }

        $listenerAddresses = @()
        foreach ($entry in $listenerRows) {
            $parsed = Parse-ListenerAddress $entry.Address.Text
            if (-not $parsed) {
                [Windows.Forms.MessageBox]::Show(
                    "Invalid listener address: $($entry.Address.Text)`nUse a numeric IP address and a port from 1024 through 65534.",
                    'Unproxy Settings') | Out-Null
                return
            }
            if ($listenerAddresses -contains $parsed.Address) {
                [Windows.Forms.MessageBox]::Show(
                    'Listener addresses must be unique.', 'Unproxy Settings') | Out-Null
                return
            }
            $listenerAddresses += $parsed.Address
        }
        if ($listenerAddresses.Count -eq 0) {
            [Windows.Forms.MessageBox]::Show(
                'At least one listener is required.', 'Unproxy Settings') | Out-Null
            return
        }

        $wasRunning = $null -ne $script:child
        $previousAutostart = [bool]$script:p.autostart
        $previousListeners = @(Get-ListenerAddresses)
        $restartRequired = (($previousListeners -join "`n") -cne ($listenerAddresses -join "`n")) -or
            ([string]$script:p.pacFile -cne [string]$pacBox.Text) -or
            ([bool]$script:p.proxytunnel -ne [bool]$tunnel.Checked) -or
            ([bool]$script:p.directFallback -ne [bool]$direct.Checked) -or
            ([bool]$script:negotiateAvailable -and
                ([bool]$script:p.negotiate -ne [bool]$negotiate.Checked))
        $firstListener = Parse-ListenerAddress ([string]$listenerAddresses[0])
        $previous = [pscustomobject]@{
            port = $script:p.port
            listeners = @($script:p.listeners)
            pacFile = $script:p.pacFile
            proxytunnel = $script:p.proxytunnel
            directFallback = $script:p.directFallback
            negotiate = $script:p.negotiate
        }
        $script:p.listeners = $listenerAddresses
        $script:p.port = [long]$firstListener.Port
        $script:p.pacFile = $pacBox.Text
        $script:p.proxytunnel = [bool]$tunnel.Checked
        $script:p.directFallback = [bool]$direct.Checked
        if ($script:negotiateAvailable) {
            $script:p.negotiate = [bool]$negotiate.Checked
        }
        try {
            Save-Prefs
            if ([bool]$autostart.Checked -ne $previousAutostart) {
                Set-Login ([bool]$autostart.Checked)
            }
        } catch {
            if ([bool]$autostart.Checked -ne $previousAutostart) {
                try { Set-Login $previousAutostart } catch { }
            }
            $script:p.port = $previous.port
            $script:p.listeners = $previous.listeners
            $script:p.pacFile = $previous.pacFile
            $script:p.proxytunnel = $previous.proxytunnel
            $script:p.directFallback = $previous.directFallback
            $script:p.negotiate = $previous.negotiate
            try { Save-Prefs } catch { }
            [Windows.Forms.MessageBox]::Show(
                "Could not save Unproxy settings: $_", 'Unproxy Settings') | Out-Null
            return
        }

        $form.DialogResult = [Windows.Forms.DialogResult]::OK
        $form.Close()
        if ($wasRunning -and $restartRequired) { Stop-Proxy; Start-Proxy }
    }).GetNewClosure())

    [void]$form.ShowDialog()
    $form.Dispose()
}

function Set-Login([bool]$enabled) {
    $runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    if ($enabled) {
        Set-ItemProperty $runKey -Name Unproxy -Value (
            '"' + (Join-Path $bin 'UnproxyTray.exe') + '"')
    } else {
        Remove-ItemProperty $runKey -Name Unproxy -ErrorAction SilentlyContinue
    }
    $script:p.autostart = $enabled
    Save-Prefs
}

function Build-Menu {
    Refresh-State
    $menu = [Windows.Forms.ContextMenuStrip]::new()
    $states = Get-IconStates
    $processLabel = switch ($states[0]) {
        'running' { 'Running' }
        'failed' { "Stopped unexpectedly (exit $($script:lastExitCode))" }
        default { 'Stopped' }
    }
    $statusAction = if ($script:child) { 'click to stop' } else { 'click to start' }
    $statusItem = $menu.Items.Add("Proxy: $processLabel ($statusAction)")
    $statusItem.add_Click({
        if ($script:child) { Stop-Proxy } else { Start-Proxy }
    })
    $logItem = $menu.Items.Add('Open Log')
    $logItem.add_Click({ Start-Process notepad.exe $logFile })
    [void]$menu.Items.Add('-')
    $configuredListeners = @(Get-ListenerAddresses)
    $copyAddress = if ($configuredListeners.Count -gt 0) {
        [string]$configuredListeners[0]
    } else { '127.0.0.1:3128' }
    $copyItem = $menu.Items.Add('Copy Proxy Address')
    $copyItem.add_Click(({ [Windows.Forms.Clipboard]::SetText($copyAddress) }).GetNewClosure())
    $settingsItem = $menu.Items.Add('Settings…')
    $settingsItem.add_Click({ Show-Settings })
    [void]$menu.Items.Add('-')
    $exitItem = $menu.Items.Add('Quit Unproxy')
    $exitItem.add_Click({
        Stop-Proxy
        $script:icon.Visible = $false
        $script:icon.Dispose()
        [Windows.Forms.Application]::Exit()
    })
    return $menu
}

$script:icon.add_MouseUp({
    param($sender, $event)
    if ($event.Button -eq [Windows.Forms.MouseButtons]::Right -or
        $event.Button -eq [Windows.Forms.MouseButtons]::Left) {
        $menu = Build-Menu
        $menu.Show([Windows.Forms.Cursor]::Position)
    }
})
$timer = [Windows.Forms.Timer]::new()
$timer.Interval = 1000
$timer.add_Tick({
    Refresh-State
    if ($activationSignal.WaitOne(0)) {
        $script:icon.ShowBalloonTip(
            2500, 'Unproxy',
            'Unproxy is already running in the notification area.',
            [Windows.Forms.ToolTipIcon]::Info)
    }
    if ($exitSignal.WaitOne(0)) {
        Stop-Proxy
        $script:icon.Visible = $false
        $script:icon.Dispose()
        [Windows.Forms.Application]::Exit()
    }
})
$timer.Start()

try {
    Set-Login ([bool]$script:p.autostart)
    Start-Proxy
    [Windows.Forms.Application]::Run()
} finally {
    Stop-Proxy
    $script:icon.Dispose()
    $mutex.ReleaseMutex()
    $mutex.Dispose()
    $activationSignal.Dispose()
    $exitSignal.Dispose()
}
