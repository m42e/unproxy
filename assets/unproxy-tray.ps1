$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic

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

$script:p = if (Test-Path $settingsFile) {
    Get-Content $settingsFile -Raw | ConvertFrom-Json
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
if (-not [IO.Path]::IsPathRooted([string]$script:p.pacFile)) {
    $script:p.pacFile = [IO.Path]::GetFullPath((Join-Path $root ([string]$script:p.pacFile)))
}
if (-not (Test-Path $settingsFile)) {
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
    $port = if (Test-PortValid) { [long]$script:p.port } else { 3128 }
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.ReceiveTimeout = 250
        $client.SendTimeout = 250
        $client.Connect('127.0.0.1', $port)
        $stream = $client.GetStream()
        $request = [Text.Encoding]::ASCII.GetBytes(
            "GET /status.json HTTP/1.1`r`nHost: 127.0.0.1:$port`r`nConnection: close`r`n`r`n")
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
        $script:icon.Text = "Unproxy running on 127.0.0.1:$(if(Test-PortValid){$script:p.port}else{3128})"
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

function Start-Proxy {
    Refresh-State
    if ($script:child) { return }
    $script:lastExitCode = $null
    $script:runtimeStatus = $null
    $listenerPort = if (Test-PortValid) { [long]$script:p.port } else { 3128 }
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
    $arguments = @(
        '--listen', "127.0.0.1:$listenerPort",
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

function Edit-Setting([string]$name, [string]$label, [string]$value) {
    $newValue = [Microsoft.VisualBasic.Interaction]::InputBox(
        $label, 'Unproxy Settings', $value)
    if ($newValue -eq '') { return }
    if ($name -eq 'port') {
        $port = [long]0
        if (-not [long]::TryParse($newValue, [ref]$port) -or
            $port -lt 1024 -or $port -gt 65534) {
            [Windows.Forms.MessageBox]::Show(
                'Port must be an integer from 1024 through 65534.', 'Unproxy') | Out-Null
            return
        }
        $script:p.port = $port
    } else {
        if (-not [IO.Path]::IsPathRooted($newValue)) {
            [Windows.Forms.MessageBox]::Show(
                'PAC path must be absolute.', 'Unproxy') | Out-Null
            return
        }
        $script:p.pacFile = $newValue
    }
    Save-Prefs
    if ($script:child) { Stop-Proxy; Start-Proxy }
}

function Toggle-Setting([string]$key) {
    $script:p.$key = -not $script:p.$key
    Save-Prefs
    if ($script:child) { Stop-Proxy; Start-Proxy }
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
    $pacLabel = switch ($states[1]) {
        'loaded' { 'Loaded' }
        'unloaded' { 'Not loaded' }
        default { 'Unknown' }
    }
    $upstreamLabel = switch ($states[2]) {
        'ok' { 'Last proxy request succeeded' }
        'error' { 'Last proxy request failed' }
        default { 'No recent proxy request' }
    }
    $authLabel = switch ($states[3]) {
        'authenticated' { 'Accepted on last request' }
        'rejected' { 'Rejected by upstream (407)' }
        'configured' { 'Configured; not verified yet' }
        default { 'Not configured' }
    }
    foreach ($line in @(
        "Proxy: $processLabel",
        "PAC: $pacLabel",
        "Upstream: $upstreamLabel",
        "Authentication: $authLabel"
    )) { [void]$menu.Items.Add($line) }
    [void]$menu.Items.Add('-')
    $startLabel = if ($script:child) { 'Stop' } else { 'Start' }
    $startItem = $menu.Items.Add($startLabel)
    $startItem.add_Click({
        if ($script:child) { Stop-Proxy } else { Start-Proxy }
    })
    if ($script:child) {
        [void]$menu.Items.Add("Listener: 127.0.0.1:$(if(Test-PortValid){$script:p.port}else{3128})")
        [void]$menu.Items.Add("PAC: $($script:p.pacFile)")
    }
    [void]$menu.Items.Add('-')

    $portLabel = if (-not (Test-PortValid)) {
        'Listener port (invalid saved value)'
    } else { 'Listener port' }
    foreach ($entry in @(
        @($portLabel, 'port', [string]$script:p.port),
        @('PAC file', 'pacFile', [string]$script:p.pacFile)
    )) {
        $item = $menu.Items.Add("Edit $($entry[0])…")
        $name = [string]$entry[1]
        $label = [string]$entry[0]
        $value = [string]$entry[2]
        $item.add_Click(({ Edit-Setting $name $label $value }).GetNewClosure())
    }

    foreach ($entry in @(
        @('Always tunnel HTTP through CONNECT', 'proxytunnel'),
        @('DIRECT fallback', 'directFallback'),
        @('Negotiate', 'negotiate')
    )) {
        $item = $menu.Items.Add([string]$entry[0])
        $key = [string]$entry[1]
        $item.CheckOnClick = $true
        $item.Checked = [bool]$script:p.$key
        if ($key -eq 'negotiate' -and -not $script:negotiateAvailable) {
            $item.Text = 'Negotiate (unavailable)'
            $item.Enabled = $false
        } else {
            $item.add_Click(({ Toggle-Setting $key }).GetNewClosure())
        }
    }

    $loginItem = $menu.Items.Add('Start at login')
    $loginItem.CheckOnClick = $true
    $loginItem.Checked = [bool]$script:p.autostart
    $loginItem.add_Click(({ Set-Login $loginItem.Checked }).GetNewClosure())
    $logItem = $menu.Items.Add('Open log')
    $logItem.add_Click({ Start-Process notepad.exe $logFile })
    [void]$menu.Items.Add('-')
    $exitItem = $menu.Items.Add('Exit Unproxy')
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
