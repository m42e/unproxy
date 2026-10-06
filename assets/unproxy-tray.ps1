param([switch]$SettingsOnly)
$ErrorActionPreference = 'Stop'
if (-not $SettingsOnly) {
    throw 'The tray runs in UnproxyTray.exe. Use -SettingsOnly to open preferences.'
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$root = Join-Path $env:LOCALAPPDATA 'Unproxy'
$bin = Join-Path $root 'bin'
$settingsFile = Join-Path $root 'preferences.json'
$metadataFile = Join-Path $bin 'metadata.json'
New-Item -ItemType Directory -Force -Path $root | Out-Null

$metadata = if (Test-Path $metadataFile) {
    Get-Content $metadataFile -Raw | ConvertFrom-Json
} else { $null }
$script:negotiateAvailable = -not $metadata -or [bool]$metadata.negotiate
$hasPreferences = Test-Path $settingsFile

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
        filterLists = @()
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
if (-not ($script:p.PSObject.Properties.Name -contains 'filterLists')) {
    $script:p | Add-Member -NotePropertyName filterLists -NotePropertyValue @()
}
if (-not ($script:p.PSObject.Properties.Name -contains 'pacFile')) {
    $defaultPacFile = Join-Path $root 'proxy.pac'
    if ($script:p.pacFiles -and @($script:p.pacFiles).Count -gt 0) {
        $defaultPacFile = [string]$script:p.pacFiles[0]
    }
    $script:p | Add-Member -NotePropertyName pacFile -NotePropertyValue $defaultPacFile
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
if ($script:p.filterLists -and @($script:p.filterLists).Count -gt 0) {
    $script:p.filterLists = @($script:p.filterLists | ForEach-Object {
        $uri = Get-PacUri ([string]$_)
        if ($uri) { $uri.AbsoluteUri } elseif ([IO.Path]::IsPathRooted([string]$_)) {
            [IO.Path]::GetFullPath([string]$_)
        } else { [IO.Path]::GetFullPath((Join-Path $root ([string]$_))) }
    })
}
if (-not $hasPreferences -and $script:p.pacFile -eq (Join-Path $root 'proxy.pac')) {
    'function FindProxyForURL(url, host) { return "DIRECT"; }' |
        Set-Content -Encoding UTF8 $script:p.pacFile
}
function Save-Prefs {
    $script:p | ConvertTo-Json | Set-Content -Encoding UTF8 $settingsFile
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

function Get-FilterLists {
    if ($script:p.filterLists) {
        return @($script:p.filterLists | ForEach-Object { [string]$_ })
    }
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
    $viewer.Text = "PAC content - $source"
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

function Prompt-RemoteUrl([string]$title, $owner) {
    $dialog = [Windows.Forms.Form]::new()
    $dialog.Text = $title
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

function Show-Settings {
    $preferences = $script:p
    $form = [Windows.Forms.Form]::new()
    $form.Text = 'Unproxy Settings'
    $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ShowInTaskbar = $false
    $form.ClientSize = [Drawing.Size]::new(700, 880)

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
        $browse.Text = 'Browse...'
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
    $addPacButton.Text = 'Add PAC File...'
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
    $addPacUrlButton.Text = 'Add PAC URL...'
    $addPacUrlButton.Location = [Drawing.Point]::new(150, 440)
    $addPacUrlButton.Size = [Drawing.Size]::new(120, 30)
    [void]$form.Controls.Add($addPacUrlButton)
    $addPacUrlButton.add_Click(({
        $url = Prompt-RemoteUrl 'Add PAC URL' $form
        if ($url) { & $addPacRow $url }
    }).GetNewClosure())

    $filterLabel = [Windows.Forms.Label]::new()
    $filterLabel.Text = 'Optional ad blocking lists (Pi-hole / hosts format)'
    $filterLabel.Location = [Drawing.Point]::new(20, 480)
    $filterLabel.AutoSize = $true
    [void]$form.Controls.Add($filterLabel)
    $filterPanel = [Windows.Forms.Panel]::new()
    $filterPanel.Location = [Drawing.Point]::new(20, 504)
    $filterPanel.Size = [Drawing.Size]::new(660, 130)
    $filterPanel.AutoScroll = $true
    $filterPanel.BorderStyle = [Windows.Forms.BorderStyle]::FixedSingle
    [void]$form.Controls.Add($filterPanel)
    $filterRows = [Collections.ArrayList]::new()
    $renderFilterRows = ({
        $filterPanel.Controls.Clear()
        for ($index = 0; $index -lt $filterRows.Count; $index++) {
            $entry = $filterRows[$index]
            $entry.Panel.Location = [Drawing.Point]::new(0, $index * 34)
            [void]$filterPanel.Controls.Add($entry.Panel)
        }
        $filterPanel.AutoScrollMinSize = [Drawing.Size]::new(0, $filterRows.Count * 34)
    }).GetNewClosure()
    $addFilterRow = ({
        param([string]$value)
        $filterRowCollection = $filterRows
        $filterRowRenderer = $renderFilterRows
        $row = [Windows.Forms.Panel]::new()
        $row.Size = [Drawing.Size]::new(635, 32)
        $sourceBox = [Windows.Forms.TextBox]::new()
        $sourceBox.Location = [Drawing.Point]::new(5, 4)
        $sourceBox.Size = [Drawing.Size]::new(480, 24)
        $sourceBox.Text = $value
        [void]$row.Controls.Add($sourceBox)
        $browse = [Windows.Forms.Button]::new()
        $browse.Text = 'Browse...'
        $browse.Location = [Drawing.Point]::new(490, 2)
        $browse.Size = [Drawing.Size]::new(72, 27)
        [void]$row.Controls.Add($browse)
        $remove = [Windows.Forms.Button]::new()
        $remove.Text = 'Remove'
        $remove.Location = [Drawing.Point]::new(570, 2)
        $remove.Size = [Drawing.Size]::new(58, 27)
        [void]$row.Controls.Add($remove)
        $entry = [pscustomobject]@{ Panel = $row; Source = $sourceBox }
        $browse.add_Click(({
            $picker = [Windows.Forms.OpenFileDialog]::new()
            $picker.Title = 'Choose a filter list'
            $picker.Filter = 'Text files (*.txt;*.hosts)|*.txt;*.hosts|All files (*.*)|*.*'
            if (Test-Path -LiteralPath $entry.Source.Text -PathType Leaf) {
                $picker.FileName = $entry.Source.Text
            }
            if ($picker.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK) {
                $entry.Source.Text = $picker.FileName
            }
            $picker.Dispose()
        }).GetNewClosure())
        $remove.add_Click(({
            [void]$filterRowCollection.Remove($entry)
            & $filterRowRenderer
        }).GetNewClosure())
        [void]$filterRows.Add($entry)
        & $renderFilterRows
    }).GetNewClosure()
    foreach ($filterList in @(Get-FilterLists)) { & $addFilterRow ([string]$filterList) }

    $addFilterFileButton = [Windows.Forms.Button]::new()
    $addFilterFileButton.Text = 'Add Local List...'
    $addFilterFileButton.Location = [Drawing.Point]::new(20, 642)
    $addFilterFileButton.Size = [Drawing.Size]::new(130, 30)
    [void]$form.Controls.Add($addFilterFileButton)
    $addFilterFileButton.add_Click(({
        $picker = [Windows.Forms.OpenFileDialog]::new()
        $picker.Title = 'Choose a filter list'
        $picker.Filter = 'Text files (*.txt;*.hosts)|*.txt;*.hosts|All files (*.*)|*.*'
        if ($picker.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK) {
            & $addFilterRow $picker.FileName
        }
        $picker.Dispose()
    }).GetNewClosure())
    $addFilterUrlButton = [Windows.Forms.Button]::new()
    $addFilterUrlButton.Text = 'Add Remote URL...'
    $addFilterUrlButton.Location = [Drawing.Point]::new(160, 642)
    $addFilterUrlButton.Size = [Drawing.Size]::new(140, 30)
    [void]$form.Controls.Add($addFilterUrlButton)
    $addFilterUrlButton.add_Click(({
        $url = Prompt-RemoteUrl 'Add Filter List URL' $form
        if ($url) { & $addFilterRow $url }
    }).GetNewClosure())

    $tunnel = [Windows.Forms.CheckBox]::new()
    $tunnel.Text = 'Always use CONNECT'
    $tunnel.Location = [Drawing.Point]::new(205, 690)
    $tunnel.AutoSize = $true
    $tunnel.Checked = [bool]$script:p.proxytunnel
    [void]$form.Controls.Add($tunnel)
    $settingsToolTip = [Windows.Forms.ToolTip]::new()
    # Keep the component alive for as long as the settings form is open.
    $form.Tag = $settingsToolTip
    $settingsToolTip.SetToolTip($tunnel, 'Tunnel proxied HTTP requests with CONNECT, even when the request does not use CONNECT.')

    $direct = [Windows.Forms.CheckBox]::new()
    $direct.Text = 'DIRECT fallback'
    $direct.Location = [Drawing.Point]::new(205, 720)
    $direct.AutoSize = $true
    $direct.Checked = [bool]$script:p.directFallback
    [void]$form.Controls.Add($direct)
    $settingsToolTip.SetToolTip($direct, 'Add a direct connection after the PAC routes, so requests can bypass the proxy if those routes fail.')

    $negotiate = [Windows.Forms.CheckBox]::new()
    $negotiate.Text = 'Negotiate'
    $negotiate.Location = [Drawing.Point]::new(205, 750)
    $negotiate.AutoSize = $true
    $negotiate.Checked = [bool]$script:p.negotiate
    $negotiate.Enabled = [bool]$script:negotiateAvailable
    [void]$form.Controls.Add($negotiate)
    $settingsToolTip.SetToolTip($negotiate, 'Use integrated Negotiate authentication with the proxy, using your operating system credentials.')

    $autostart = [Windows.Forms.CheckBox]::new()
    $autostart.Text = 'Start Unproxy when I sign in'
    $autostart.Location = [Drawing.Point]::new(205, 780)
    $autostart.AutoSize = $true
    $autostart.Checked = [bool]$script:p.autostart
    [void]$form.Controls.Add($autostart)

    $saveButton = [Windows.Forms.Button]::new()
    $saveButton.Text = 'Save'
    $saveButton.Location = [Drawing.Point]::new(500, 830)
    $saveButton.Size = [Drawing.Size]::new(80, 30)
    $saveButton.DialogResult = [Windows.Forms.DialogResult]::None
    [void]$form.Controls.Add($saveButton)

    $cancelButton = [Windows.Forms.Button]::new()
    $cancelButton.Text = 'Cancel'
    $cancelButton.Location = [Drawing.Point]::new(590, 830)
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

        $filterLists = @()
        foreach ($entry in $filterRows) {
            $source = $entry.Source.Text.Trim()
            $uri = Get-PacUri $source
            if ($uri) {
                $source = $uri.AbsoluteUri
            } elseif ($source -match '^(?i:https?)://') {
                [Windows.Forms.MessageBox]::Show(
                    "Enter a valid HTTP or HTTPS filter-list URL: $source", 'Unproxy Settings') | Out-Null
                return
            } else {
                if (-not [IO.Path]::IsPathRooted($source)) {
                    [Windows.Forms.MessageBox]::Show(
                        "Filter-list paths must be absolute: $source", 'Unproxy Settings') | Out-Null
                    return
                }
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                    [Windows.Forms.MessageBox]::Show(
                        "Filter-list file not found: $source", 'Unproxy Settings') | Out-Null
                    return
                }
                $source = [IO.Path]::GetFullPath($source)
            }
            if ($filterLists -contains $source) {
                [Windows.Forms.MessageBox]::Show(
                    "Filter-list source is listed more than once: $source", 'Unproxy Settings') | Out-Null
                return
            }
            $filterLists += $source
        }

        $previousAutostart = [bool]$preferences.autostart
        $firstListener = Parse-ListenerAddress ([string]$listenerAddresses[0])
        $previous = [pscustomobject]@{
            port = $preferences.port
            listeners = @($preferences.listeners)
            pacFiles = @($preferences.pacFiles)
            pacFile = $preferences.pacFile
            filterLists = @($preferences.filterLists)
            proxytunnel = $preferences.proxytunnel
            directFallback = $preferences.directFallback
            negotiate = $preferences.negotiate
        }
        $preferences.listeners = $listenerAddresses
        $preferences.port = [long]$firstListener.Port
        $preferences.pacFiles = $pacFiles
        $preferences.pacFile = $pacFiles[0]
        $preferences.filterLists = $filterLists
        $preferences.proxytunnel = [bool]$tunnel.Checked
        $preferences.directFallback = [bool]$direct.Checked
        if ($script:negotiateAvailable) {
            $preferences.negotiate = [bool]$negotiate.Checked
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
            $preferences.port = $previous.port
            $preferences.listeners = $previous.listeners
            $preferences.pacFiles = $previous.pacFiles
            $preferences.pacFile = $previous.pacFile
            $preferences.filterLists = $previous.filterLists
            $preferences.proxytunnel = $previous.proxytunnel
            $preferences.directFallback = $previous.directFallback
            $preferences.negotiate = $previous.negotiate
            try { Save-Prefs } catch { }
            [Windows.Forms.MessageBox]::Show(
                "Could not save Unproxy settings: $_", 'Unproxy Settings') | Out-Null
            return
        }

        $form.DialogResult = [Windows.Forms.DialogResult]::OK
        $form.Close()
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

Show-Settings
