# Release signing and notarization

The tagged release workflow signs Windows executables and signs and notarizes
the macOS app when the required GitHub Actions secrets are configured. Signing
is optional, so releases can still be built before credentials are added.

Add these secrets in the Unproxy GitHub repository under **Settings → Secrets
and variables → Actions**. Secrets configured in another repository are not
available to this workflow automatically.

## Windows

To sign the executables in the Windows release ZIP, configure:

- `WINDOWS_CERT_BASE64`: Base64-encoded code-signing certificate in `.pfx`
  format.
- `WINDOWS_CERT_PASSWORD`: Password used to export the `.pfx` certificate.

The workflow signs each `.exe` with SHA-256 and a public timestamp, verifies
the signatures, then recreates the ZIP. If either secret is missing, the ZIP
is published unsigned.

## macOS app

The app ZIP is signed and notarized when all of these secrets are configured:

- `APPLE_CERT_BASE64`: Base64-encoded `.p12` Developer ID Application
  certificate.
- `APPLE_CERT_PASSWORD`: Password used to export the `.p12` certificate.
- `APPLE_SIGNING_IDENTITY`: Full Developer ID Application identity, as shown
  by `security find-identity -v -p codesigning`.
- `APPLE_ID`: Apple ID email used for notarization.
- `APPLE_APP_PASSWORD`: App-specific password for that Apple ID.
- `APPLE_TEAM_ID`: Apple Developer Team ID.

The app and its login helper are signed before packaging. The workflow submits
the app ZIP to Apple, waits for acceptance, staples the ticket to `Unproxy.app`,
and recreates the ZIP with the stapled app. If signing secrets are missing, the
app ZIP is unsigned. If only notarization secrets are missing, it is signed but
not notarized.

## macOS installer packages

Signing and notarizing `.pkg` files additionally requires a Developer ID
Installer certificate. Configure these secrets to enable that step:

- `APPLE_INSTALLER_CERT_BASE64`: Base64-encoded `.p12` Developer ID Installer
  certificate.
- `APPLE_INSTALLER_CERT_PASSWORD`: Password used to export that certificate.
- `APPLE_INSTALLER_SIGNING_IDENTITY`: Full Developer ID Installer identity.

When these secrets and the Apple notarization secrets are present, the workflow
signs each installer package, submits it to Apple, waits for acceptance, and
staples the ticket. Without the Installer certificate, `.pkg` files are still
built and published, but are not signed or notarized.
