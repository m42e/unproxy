# Windows service setup

Open the [official Unproxy GitHub repository](https://github.com/m42e/unproxy)
in a trusted browser and navigate to this guide and the release from there. Do
not rely on links or instructions in the extracted ZIP before verifying it.

For service installation, upgrade, or removal, press **Win+R**, enter
`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy RemoteSigned`,
and press **Ctrl+Shift+Enter** to open a dedicated administrator session. Display
`SHA256SUMS` from the matching [GitHub release](https://github.com/m42e/unproxy/releases)
over HTTPS on a trusted machine or session. Do not use a checksum file from the
same writable download directory as the ZIP. For a locally built ZIP, obtain
its digest from the trusted build machine. Use the current release ZIP, including
when removing a service installed by an earlier release.

Paste this block into the administrator session. Enter the full path to the
ZIP, the independently obtained digest, and the service operation. Each run
creates a fresh directory under Program Files, checks the staged ZIP before
extracting it, and removes staging when the operation ends.

```powershell
& {
    $ErrorActionPreference = 'Stop'
    $env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')

    function Get-UnproxySha256([string]$Path) {
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try {
            $stream = [IO.File]::OpenRead($Path)
            try {
                return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
            } finally {
                $stream.Dispose()
            }
        } finally {
            $algorithm.Dispose()
        }
    }

    $zip = Read-Host 'Full path to the Windows ZIP'
    $expected = Read-Host 'SHA-256 from the trusted release or build'
    if ($expected -notmatch '\A[0-9a-f]{64}\z') { throw 'Expected a 64-character SHA-256 digest.' }
    $action = Read-Host 'Service operation (install, uninstall, or purge)'
    if ($action -notin @('install', 'uninstall', 'purge')) { throw 'Unknown service operation.' }

    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $stage = Join-Path $programFiles ('Unproxy-setup-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage | Out-Null
    try {
        $archive = Join-Path $stage 'release.zip'
        [IO.File]::WriteAllBytes($archive, [IO.File]::ReadAllBytes($zip))
        if ((Get-UnproxySha256 $archive) -cne $expected) {
            throw 'The staged ZIP does not match the trusted SHA-256 digest.'
        }
        $payload = Join-Path $stage 'payload'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($archive, $payload)
        Push-Location -LiteralPath $payload
        try {
            if ($action -eq 'install') { .\install.ps1 -AsService }
            else { .\uninstall.ps1 -AsService -RemoveUserData:($action -eq 'purge') }
        } finally { Pop-Location }
    } finally { Remove-Item -LiteralPath $stage -Recurse -Force }
}
```

Choose `install` for a new installation or an upgrade. The service starts at
boot and runs without the tray app. Its executable is under
`C:\Program Files\Unproxy`; active settings, PAC file, and logs are under
`C:\Program Files\Unproxy\data`. Existing files under
`C:\ProgramData\Unproxy` remain untouched and inactive; review and migrate
trusted settings manually. See the [installation overview](installation.md#windows-service)
for service configuration, status, and removal behavior. Service removal does
not remove a separate per-user tray installation. If that account still has one,
run the per-user uninstaller in a non-elevated PowerShell session to remove its
binaries and restore its proxy environment settings.
