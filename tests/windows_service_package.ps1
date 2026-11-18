# Exercise the administrator procedure with harmless package contents and a private staging root.
param([Parameter(Mandatory)][string]$WorkDir)
$ErrorActionPreference = 'Stop'
$docs = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../docs/windows-service-setup.md') -Raw
$commands = [regex]::Match($docs, '(?s)```powershell\r?\n(.*?)\r?\n```').Groups[1].Value
if (-not $commands.Contains("[Environment]::GetFolderPath('ProgramFiles')")) { throw 'Missing protected staging root.' }
$setup = [scriptblock]::Create($commands.Replace("[Environment]::GetFolderPath('ProgramFiles')", '$WorkDir'))
$source = (New-Item -ItemType Directory -Path (Join-Path $WorkDir 'download')).FullName
$zip = Join-Path $WorkDir 'package.zip'
$marker = Join-Path $WorkDir 'invocation.txt'
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Write-FixtureArchive {
    if ([IO.File]::Exists($zip)) { [IO.File]::Delete($zip) }
    [IO.Compression.ZipFile]::CreateFromDirectory($source, $zip)
}

$scriptBody = @'
param([switch]$AsService, [switch]$RemoveUserData)
if (-not $AsService) { throw 'Expected a service operation.' }
$bytes = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'unproxy-register.exe'))
[IO.File]::WriteAllText($marker, "$($MyInvocation.MyCommand.Name) $RemoveUserData $bytes")
'@
foreach ($name in @('install.ps1', 'uninstall.ps1')) {
    [IO.File]::WriteAllText((Join-Path $source $name), $scriptBody)
}
$helper = Join-Path $source 'unproxy-register.exe'
[IO.File]::WriteAllText($helper, 'release')
Write-FixtureArchive
$trustedHash = (Get-FileHash -LiteralPath $zip).Hash

function Read-Host($prompt) {
    switch -Wildcard ($prompt) {
        'Full path*' { return $zip }
        'SHA-256*' { return $trustedHash }
        'Service operation*' { return $operation }
        default { throw "Unexpected prompt: $prompt" }
    }
}

foreach ($operation in @('install', 'uninstall', 'purge')) {
    & $setup
    $expected = switch ($operation) {
        'install'   { 'install.ps1 False release' }
        'uninstall' { 'uninstall.ps1 False release' }
        'purge'     { 'uninstall.ps1 True release' }
    }
    if ([IO.File]::ReadAllText($marker) -cne $expected) { throw "Wrong invocation for $operation." }
    [IO.File]::Delete($marker)
}

foreach ($changed in @('install.ps1', 'uninstall.ps1', 'unproxy-register.exe')) {
    $path = Join-Path $source $changed
    $original = [IO.File]::ReadAllBytes($path)
    [IO.File]::AppendAllText($path, ' ')
    # A replacement ZIP may even include a matching manifest supplied by its author.
    [IO.File]::WriteAllText((Join-Path $source 'SHA256SUMS'), (Get-FileHash -LiteralPath $path).Hash)
    Write-FixtureArchive
    $operation = if ($changed -eq 'uninstall.ps1') { 'uninstall' } else { 'install' }
    try {
        & $setup
        throw "Accepted modified $changed"
    } catch {
        if ($_.Exception.Message -notlike '*does not match the trusted SHA-256*') { throw }
    }
    if ([IO.File]::Exists($marker)) { throw "Invoked setup for modified $changed" }
    [IO.File]::WriteAllBytes($path, $original)
    [IO.File]::Delete((Join-Path $source 'SHA256SUMS'))
}

if (@(Get-ChildItem -LiteralPath $WorkDir -Filter 'Unproxy-setup-*').Count) { throw 'Staging was left behind.' }
