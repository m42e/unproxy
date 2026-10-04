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
if (-not ($script:p.PSObject.Properties.Name -contains 'pacFiles')) {
    $script:p | Add-Member -NotePropertyName pacFiles -NotePropertyValue @()
}

function Get-PacUri([string]$value) {
    $uri = $null
    if ([Uri]::TryCreate($value.Trim(), [UriKind]::Absolute, [ref]$uri) -and
        ($uri.Scheme -eq [Uri]::UriSchemeHttp -or $uri.Scheme -eq [Uri]::UriSchemeHttps) -and
        -not [string]::IsNullOrWhiteSpace($uri.Host) -and
        [string]::IsNullOrEmpty($uri.UserInfo) -and
        [string]::IsNullOrEmpty($uri.Fragment)) {
        return $uri
    }
    return $null
}

if (-not $script:p.pacFile) { $script:p.pacFile = Join-Path $root 'proxy.pac' }
$initialPacUri = Get-PacUri ([string]$script:p.pacFile)
if ($initialPacUri) {
    $script:p.pacFile = $initialPacUri.AbsoluteUri
} elseif (-not [IO.Path]::IsPathRooted([string]$script:p.pacFile)) {
    $script:p.pacFile = [IO.Path]::GetFullPath((Join-Path $root ([string]$script:p.pacFile)))
}
if ($script:p.pacFiles -and @($script:p.pacFiles).Count -gt 0) {
    $script:p.pacFiles = @($script:p.pacFiles | ForEach-Object {
        $uri = Get-PacUri ([string]$_)
        if ($uri) { $uri.AbsoluteUri } else { [string]$_ }
    })
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

function Get-PacFiles {
    if ($script:p.pacFiles -and @($script:p.pacFiles).Count -gt 0) {
        return @($script:p.pacFiles | ForEach-Object { [string]$_ })
    }
    if ($script:p.pacFile) { return @([string]$script:p.pacFile) }
    return @()
}

function Get-RemotePacContent([Uri]$uri) {
    $current = $uri
    for ($redirect = 0; $redirect -le 9; $redirect++) {
        if ($current.Scheme -ne [Uri]::UriSchemeHttp -and
            $current.Scheme -ne [Uri]::UriSchemeHttps) {
            throw "PAC URL must use HTTP or HTTPS: $current"
        }
        $request = [Net.HttpWebRequest]::Create($current)
        $request.Method = 'GET'
        $request.AllowAutoRedirect = $false
        $request.Timeout = 15000
        $request.ReadWriteTimeout = 15000
        $response = $null
        try {
            $response = [Net.HttpWebResponse]$request.GetResponse()
        } catch [Net.WebException] {
            if (-not $_.Exception.Response) { throw }
            $response = [Net.HttpWebResponse]$_.Exception.Response
        }
        try {
            $status = [int]$response.StatusCode
            if ($status -in @(301, 302, 307, 308)) {
                if ($redirect -eq 9) { throw 'PAC URL redirected too many times.' }
                $location = $response.Headers['Location']
                if ([string]::IsNullOrWhiteSpace($location)) {
                    throw 'PAC redirect did not include a Location header.'
                }
                $next = [Uri]::new($current, $location)
                if (($next.Scheme -ne [Uri]::UriSchemeHttp -and
                    $next.Scheme -ne [Uri]::UriSchemeHttps) -or
                    -not [string]::IsNullOrEmpty($next.UserInfo) -or
                    -not [string]::IsNullOrEmpty($next.Fragment) -or
                    ($current.Scheme -eq [Uri]::UriSchemeHttps -and
                    $next.Scheme -ne [Uri]::UriSchemeHttps)) {
                    throw 'PAC redirect must use HTTP or HTTPS, cannot include credentials or a fragment, and cannot downgrade HTTPS to HTTP.'
                }
                $current = $next
                continue
            }
            if ($status -ne 200) { throw "Remote PAC returned HTTP $status." }
            if ($response.ContentLength -gt 8388608) {
                throw 'PAC response exceeds 8 MiB.'
            }
            $stream = $response.GetResponseStream()
            $memory = [IO.MemoryStream]::new()
            try {
                $buffer = New-Object byte[] 8192
                while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    if ($memory.Length + $count -gt 8388608) {
                        throw 'PAC response exceeds 8 MiB.'
                    }
                    $memory.Write($buffer, 0, $count)
                }
                $utf8 = [Text.UTF8Encoding]::new($false, $true)
                return $utf8.GetString($memory.ToArray())
            } finally {
                $memory.Dispose()
                $stream.Dispose()
            }
        } finally {
            $response.Dispose()
        }
    }
    throw 'PAC URL redirected too many times.'
}

function Show-PacContent([string]$source, [string]$content, $owner) {
    $viewer = [Windows.Forms.Form]::new()
    $viewer.Text = "PAC content — $source"
    $viewer.StartPosition = [Windows.Forms.FormStartPosition]::CenterParent
    $viewer.Size = [Drawing.Size]::new(900, 650)
    $viewer.MinimizeBox = $false
    $viewer.MaximizeBox = $true
    $text = [Windows.Forms.RichTextBox]::new()
    $text.Dock = [Windows.Forms.DockStyle]::Fill
    $text.ReadOnly = $true
    $text.WordWrap = $false
    $text.DetectUrls = $false
    $text.Font = [Drawing.Font]::new('Consolas', 10)
    $text.Text = $content
    [void]$viewer.Controls.Add($text)
    [void]$viewer.ShowDialog($owner)
    $viewer.Dispose()
}

function Prompt-PacUrl($owner) {
    $dialog = [Windows.Forms.Form]::new()
    $dialog.Text = 'Add PAC URL'
    $dialog.StartPosition = [Windows.Forms.FormStartPosition]::CenterParent
    $dialog.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $dialog.ClientSize = [Drawing.Size]::new(520, 125)
    $dialog.MinimizeBox = $false
    $dialog.MaximizeBox = $false
    $label = [Windows.Forms.Label]::new()
    $label.Text = 'HTTP or HTTPS URL'
    $label.Location = [Drawing.Point]::new(12, 12)
    $label.AutoSize = $true
    [void]$dialog.Controls.Add($label)
    $urlBox = [Windows.Forms.TextBox]::new()
    $urlBox.Location = [Drawing.Point]::new(12, 34)
    $urlBox.Size = [Drawing.Size]::new(496, 24)
    [void]$dialog.Controls.Add($urlBox)
    $add = [Windows.Forms.Button]::new()
    $add.Text = 'Add'
    $add.Location = [Drawing.Point]::new(338, 78)
    $add.Size = [Drawing.Size]::new(80, 30)
    [void]$dialog.Controls.Add($add)
    $cancel = [Windows.Forms.Button]::new()
    $cancel.Text = 'Cancel'
    $cancel.Location = [Drawing.Point]::new(428, 78)
    $cancel.Size = [Drawing.Size]::new(80, 30)
    $cancel.DialogResult = [Windows.Forms.DialogResult]::Cancel
    [void]$dialog.Controls.Add($cancel)
    $dialog.AcceptButton = $add
    $dialog.CancelButton = $cancel
    $add.add_Click(({
        $uri = Get-PacUri $urlBox.Text
        if (-not $uri) {
            [Windows.Forms.MessageBox]::Show(
                'Enter a valid HTTP or HTTPS URL without embedded credentials or a fragment.',
                'Unproxy Settings') | Out-Null
            return
        }
        $dialog.Tag = $uri.AbsoluteUri
        $dialog.DialogResult = [Windows.Forms.DialogResult]::OK
        $dialog.Close()
    }).GetNewClosure())
    $result = $dialog.ShowDialog($owner)
    $value = if ($result -eq [Windows.Forms.DialogResult]::OK) {
        [string]$dialog.Tag
    } else { $null }
    $dialog.Dispose()
    return $value
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
    $pacFiles = @(Get-PacFiles)
    if ($pacFiles.Count -eq 0) {
        [Windows.Forms.MessageBox]::Show('At least one PAC file is required.', 'Unproxy') | Out-Null
        return
    }
    foreach ($pacFile in $pacFiles) {
        $uri = Get-PacUri ([string]$pacFile)
        if ($uri) { continue }
        if ([string]$pacFile -match '^(?i:https?)://') {
            [Windows.Forms.MessageBox]::Show(
                "Enter a valid HTTP or HTTPS PAC URL: $pacFile", 'Unproxy') | Out-Null
            return
        }
        if (-not [IO.Path]::IsPathRooted([string]$pacFile)) {
            [Windows.Forms.MessageBox]::Show('PAC paths must be absolute.', 'Unproxy') | Out-Null
            return
        }
        if (-not (Test-Path -LiteralPath $pacFile -PathType Leaf)) {
            [Windows.Forms.MessageBox]::Show(
                "PAC file not found: $pacFile", 'Unproxy') | Out-Null
            return
        }
    }

    $exe = Join-Path $bin 'unproxy.exe'
    $arguments = @()
    foreach ($listener in $listenerAddresses) {
        $arguments += @('--listen', [string]$listener)
    }
    foreach ($pacFile in $pacFiles) { $arguments += @('--pac-file', [string]$pacFile) }
    $arguments += @('--graceful-shutdown-timeout', '0')
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
    $form.ClientSize = [Drawing.Size]::new(700, 690)

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
    $pacLabel.Text = 'PAC files or URLs (top to bottom; first non-DIRECT result wins)'
    $pacLabel.Location = [Drawing.Point]::new(20, 278)
    $pacLabel.AutoSize = $true
    [void]$form.Controls.Add($pacLabel)

    $pacPanel = [Windows.Forms.Panel]::new()
    $pacPanel.Location = [Drawing.Point]::new(20, 302)
    $pacPanel.Size = [Drawing.Size]::new(660, 130)
    $pacPanel.AutoScroll = $true
    $pacPanel.BorderStyle = [Windows.Forms.BorderStyle]::FixedSingle
    [void]$form.Controls.Add($pacPanel)
    $pacRows = [Collections.ArrayList]::new()
    $renderPacRows = ({
        $pacPanel.Controls.Clear()
        for ($index = 0; $index -lt $pacRows.Count; $index++) {
            $entry = $pacRows[$index]
            $entry.Panel.Location = [Drawing.Point]::new(0, $index * 34)
            $entry.Up.Enabled = $index -gt 0
            $entry.Down.Enabled = $index -lt ($pacRows.Count - 1)
            [void]$pacPanel.Controls.Add($entry.Panel)
        }
        $pacPanel.AutoScrollMinSize = [Drawing.Size]::new(0, $pacRows.Count * 34)
    }).GetNewClosure()
    $addPacRow = ({
        param([string]$value)
        $row = [Windows.Forms.Panel]::new()
        $row.Size = [Drawing.Size]::new(635, 32)
        $pathBox = [Windows.Forms.TextBox]::new()
        $pathBox.Location = [Drawing.Point]::new(5, 4)
        $pathBox.Size = [Drawing.Size]::new(275, 24)
        $pathBox.Text = $value
        [void]$row.Controls.Add($pathBox)
        $open = [Windows.Forms.Button]::new()
        $open.Location = [Drawing.Point]::new(285, 2)
        $open.Size = [Drawing.Size]::new(65, 27)
        [void]$row.Controls.Add($open)
        $browse = [Windows.Forms.Button]::new()
        $browse.Text = 'Browse…'
        $browse.Location = [Drawing.Point]::new(355, 2)
        $browse.Size = [Drawing.Size]::new(72, 27)
        [void]$row.Controls.Add($browse)
        $up = [Windows.Forms.Button]::new()
        $up.Text = 'Up'
        $up.Location = [Drawing.Point]::new(432, 2)
        $up.Size = [Drawing.Size]::new(44, 27)
        [void]$row.Controls.Add($up)
        $down = [Windows.Forms.Button]::new()
        $down.Text = 'Down'
        $down.Location = [Drawing.Point]::new(480, 2)
        $down.Size = [Drawing.Size]::new(50, 27)
        [void]$row.Controls.Add($down)
        $remove = [Windows.Forms.Button]::new()
        $remove.Text = 'Remove'
        $remove.Location = [Drawing.Point]::new(534, 2)
        $remove.Size = [Drawing.Size]::new(88, 27)
        [void]$row.Controls.Add($remove)
        $entry = [pscustomobject]@{
            Panel = $row; Path = $pathBox; Open = $open; Up = $up; Down = $down
        }
        $setOpenLabel = ({
            $entry.Open.Text = if (Get-PacUri $entry.Path.Text) { 'View' } else { 'Open' }
        }).GetNewClosure()
        & $setOpenLabel
        $pathBox.add_TextChanged(({
            & $setOpenLabel
        }).GetNewClosure())
        $open.add_Click(({
            $source = $entry.Path.Text.Trim()
            $uri = Get-PacUri $source
            try {
                if ($uri) {
                    $content = Get-RemotePacContent $uri
                    Show-PacContent $uri.AbsoluteUri $content $form
                } elseif ($source -match '^(?i:https?)://') {
                    throw 'Enter a valid HTTP or HTTPS PAC URL.'
                } else {
                    if (-not [IO.Path]::IsPathRooted($source)) {
                        throw 'PAC path must be absolute.'
                    }
                    $path = [IO.Path]::GetFullPath($source)
                    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                        throw "PAC file not found: $path"
                    }
                    Start-Process -FilePath $path -ErrorAction Stop
                }
            } catch {
                [Windows.Forms.MessageBox]::Show(
                    "Could not open PAC source:`n$_", 'Unproxy Settings') | Out-Null
            }
        }).GetNewClosure())
        $browse.add_Click(({
            $picker = [Windows.Forms.OpenFileDialog]::new()
            $picker.Title = 'Choose a PAC file'
            $picker.Filter = 'PAC files (*.pac)|*.pac|All files (*.*)|*.*'
            if (Test-Path -LiteralPath $entry.Path.Text -PathType Leaf) {
                $picker.FileName = $entry.Path.Text
            }
            if ($picker.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK) {
                $entry.Path.Text = $picker.FileName
            }
            $picker.Dispose()
        }).GetNewClosure())
        $up.add_Click(({
            $index = $pacRows.IndexOf($entry)
            if ($index -gt 0) {
                $previous = $pacRows[$index - 1]
                $pacRows[$index - 1] = $entry
                $pacRows[$index] = $previous
                & $renderPacRows
            }
        }).GetNewClosure())
        $down.add_Click(({
            $index = $pacRows.IndexOf($entry)
            if ($index -lt ($pacRows.Count - 1)) {
                $next = $pacRows[$index + 1]
                $pacRows[$index + 1] = $entry
                $pacRows[$index] = $next
                & $renderPacRows
            }
        }).GetNewClosure())
        $remove.add_Click(({
            [void]$pacRows.Remove($entry)
            & $renderPacRows
        }).GetNewClosure())
        [void]$pacRows.Add($entry)
        & $renderPacRows
    }).GetNewClosure()
    foreach ($pacFile in @(Get-PacFiles)) { & $addPacRow ([string]$pacFile) }

    $addPacButton = [Windows.Forms.Button]::new()
    $addPacButton.Text = 'Add PAC File…'
    $addPacButton.Location = [Drawing.Point]::new(20, 440)
    $addPacButton.Size = [Drawing.Size]::new(120, 30)
    [void]$form.Controls.Add($addPacButton)
    $addPacButton.add_Click(({
        $picker = [Windows.Forms.OpenFileDialog]::new()
        $picker.Title = 'Choose a PAC file'
        $picker.Filter = 'PAC files (*.pac)|*.pac|All files (*.*)|*.*'
        if ($picker.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK) {
            & $addPacRow $picker.FileName
        }
        $picker.Dispose()
    }).GetNewClosure())

    $addPacUrlButton = [Windows.Forms.Button]::new()
    $addPacUrlButton.Text = 'Add PAC URL…'
    $addPacUrlButton.Location = [Drawing.Point]::new(150, 440)
    $addPacUrlButton.Size = [Drawing.Size]::new(120, 30)
    [void]$form.Controls.Add($addPacUrlButton)
    $addPacUrlButton.add_Click(({
        $url = Prompt-PacUrl $form
        if ($url) { & $addPacRow $url }
    }).GetNewClosure())

    $tunnel = [Windows.Forms.CheckBox]::new()
    $tunnel.Text = 'Always use CONNECT'
    $tunnel.Location = [Drawing.Point]::new(205, 490)
    $tunnel.AutoSize = $true
    $tunnel.Checked = [bool]$script:p.proxytunnel
    [void]$form.Controls.Add($tunnel)
    $settingsToolTip = [Windows.Forms.ToolTip]::new()
    $settingsToolTip.SetToolTip($tunnel, 'Tunnel proxied HTTP requests with CONNECT, even when the request does not use CONNECT.')

    $direct = [Windows.Forms.CheckBox]::new()
    $direct.Text = 'DIRECT fallback'
    $direct.Location = [Drawing.Point]::new(205, 520)
    $direct.AutoSize = $true
    $direct.Checked = [bool]$script:p.directFallback
    [void]$form.Controls.Add($direct)
    $settingsToolTip.SetToolTip($direct, 'Add a direct connection after the PAC routes, so requests can bypass the proxy if those routes fail.')

    $negotiate = [Windows.Forms.CheckBox]::new()
    $negotiate.Text = 'Negotiate'
    $negotiate.Location = [Drawing.Point]::new(205, 550)
    $negotiate.AutoSize = $true
    $negotiate.Checked = [bool]$script:p.negotiate
    $negotiate.Enabled = [bool]$script:negotiateAvailable
    [void]$form.Controls.Add($negotiate)
    $settingsToolTip.SetToolTip($negotiate, 'Use integrated Negotiate authentication with the proxy, using your operating system credentials.')

    $autostart = [Windows.Forms.CheckBox]::new()
    $autostart.Text = 'Start Unproxy when I sign in'
    $autostart.Location = [Drawing.Point]::new(205, 580)
    $autostart.AutoSize = $true
    $autostart.Checked = [bool]$script:p.autostart
    [void]$form.Controls.Add($autostart)

    $saveButton = [Windows.Forms.Button]::new()
    $saveButton.Text = 'Save'
    $saveButton.Location = [Drawing.Point]::new(500, 635)
    $saveButton.Size = [Drawing.Size]::new(80, 30)
    $saveButton.DialogResult = [Windows.Forms.DialogResult]::None
    [void]$form.Controls.Add($saveButton)

    $cancelButton = [Windows.Forms.Button]::new()
    $cancelButton.Text = 'Cancel'
    $cancelButton.Location = [Drawing.Point]::new(590, 635)
    $cancelButton.Size = [Drawing.Size]::new(80, 30)
    $cancelButton.DialogResult = [Windows.Forms.DialogResult]::Cancel
    [void]$form.Controls.Add($cancelButton)
    $form.AcceptButton = $saveButton
    $form.CancelButton = $cancelButton

    $saveButton.add_Click(({
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

        $pacFiles = @()
        foreach ($entry in $pacRows) {
            $source = $entry.Path.Text.Trim()
            $uri = Get-PacUri $source
            if ($uri) {
                $source = $uri.AbsoluteUri
            } elseif ($source -match '^(?i:https?)://') {
                [Windows.Forms.MessageBox]::Show(
                    "Enter a valid HTTP or HTTPS PAC URL: $source", 'Unproxy Settings') | Out-Null
                return
            } else {
                if (-not [IO.Path]::IsPathRooted($source)) {
                    [Windows.Forms.MessageBox]::Show(
                        "PAC paths must be absolute: $source", 'Unproxy Settings') | Out-Null
                    return
                }
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                    [Windows.Forms.MessageBox]::Show(
                        "PAC file not found: $source", 'Unproxy Settings') | Out-Null
                    return
                }
                $source = [IO.Path]::GetFullPath($source)
            }
            if ($pacFiles -contains $source) {
                [Windows.Forms.MessageBox]::Show(
                    "PAC source is listed more than once: $source", 'Unproxy Settings') | Out-Null
                return
            }
            $pacFiles += $source
        }
        if ($pacFiles.Count -eq 0) {
            [Windows.Forms.MessageBox]::Show(
                'At least one PAC file is required.', 'Unproxy Settings') | Out-Null
            return
        }

        $wasRunning = $null -ne $script:child
        $previousAutostart = [bool]$script:p.autostart
        $previousListeners = @(Get-ListenerAddresses)
        $previousPacFiles = @(Get-PacFiles)
        $restartRequired = (($previousListeners -join "`n") -cne ($listenerAddresses -join "`n")) -or
            (($previousPacFiles -join "`n") -cne ($pacFiles -join "`n")) -or
            ([bool]$script:p.proxytunnel -ne [bool]$tunnel.Checked) -or
            ([bool]$script:p.directFallback -ne [bool]$direct.Checked) -or
            ([bool]$script:negotiateAvailable -and
                ([bool]$script:p.negotiate -ne [bool]$negotiate.Checked))
        $firstListener = Parse-ListenerAddress ([string]$listenerAddresses[0])
        $previous = [pscustomobject]@{
            port = $script:p.port
            listeners = @($script:p.listeners)
            pacFiles = @($script:p.pacFiles)
            pacFile = $script:p.pacFile
            proxytunnel = $script:p.proxytunnel
            directFallback = $script:p.directFallback
            negotiate = $script:p.negotiate
        }
        $script:p.listeners = $listenerAddresses
        $script:p.port = [long]$firstListener.Port
        $script:p.pacFiles = $pacFiles
        $script:p.pacFile = $pacFiles[0]
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
            $script:p.pacFiles = $previous.pacFiles
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
