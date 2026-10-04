# Install Unproxy

Download the release package for your operating system from the project's
Releases page. Choose a file for your operating system and processor. If you
are unsure, use the normal 64-bit Intel/AMD package for Windows or Linux, or
the macOS package for your Mac.

## Windows

1. Download and extract the Windows ZIP.
2. Open the extracted folder in File Explorer.
3. Right-click the folder background and choose **Open in Terminal**.
4. In PowerShell, run:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\install.ps1
   ```

5. The Unproxy tray icon appears near the clock. Click its status row to start
   or stop the proxy. Choose **Settings…** to edit listeners, the PAC file, and
   proxy behavior. The installer adds Unproxy to your Start menu and starts it
   when you sign in; you can change that in Settings.

To remove Unproxy, open the extracted ZIP folder in PowerShell and run:

```powershell
.\uninstall.ps1
```

Add `-RemoveUserData` to also delete Unproxy preferences and logs.

## macOS

1. Download the macOS app installer (`*-app.pkg`) and open it.
2. Follow the installer prompts, then open **Unproxy** from Applications.
3. Click the Unproxy icon in the menu bar. Its status row starts or stops the
   proxy.

Choose **Settings…** to set listeners, the PAC file, and proxy behavior. Use
**Start with Login** to control whether the app opens when you sign in. The menu
also has actions to open the log and copy the proxy address.

## Debian or Ubuntu

Open a terminal in the folder containing the downloaded `.deb` package and run:

```sh
sudo apt install ./unproxy-VERSION-TARGET.deb
systemctl --user enable --now unproxy
systemctl --user status unproxy
```

Replace `VERSION-TARGET` with the version and architecture in the downloaded
filename. The last command should show the service as active. To stop it, run
`systemctl --user stop unproxy`. To start it again, run
`systemctl --user start unproxy`.

## Build from source

Use this if you have the source checkout and Rust installed. On Linux, install
the compiler and TLS build dependencies first (Debian/Ubuntu: `build-essential`,
`pkg-config`, and `libssl-dev`). Then, from the project folder, run:

```sh
cargo build --release --locked --bins
```

Start the built proxy with `./target/release/unproxy` on macOS/Linux or
`target\release\unproxy.exe` on Windows. See [Use Unproxy](user-guide.md) to
connect an application and configure a PAC file.

### Build a company distributable with first-run defaults

Create a TOML profile with the preferences you want new desktop installs to
start with:

```toml
port = 3128
pac_file = "proxy.pac"
negotiate = true
proxytunnel = false
direct_fallback = false
autostart = true
```

Then pass it when packaging a Windows tray ZIP or macOS menu bar app:

```sh
cargo xtask package --format windows --defaults company-defaults.toml
cargo xtask package --format app --defaults company-defaults.toml
```

Run the Windows command on Windows (or specify a Windows `--target` when
cross-compiling) and the app command on macOS.

The same option is available on `cargo xtask build` to embed defaults in a
custom build. Omitted profile fields keep their normal defaults. Relative PAC
paths are resolved under the user's Unproxy data folder (`%LOCALAPPDATA%\Unproxy`
on Windows and `~/Library/Application Support/Unproxy` on macOS); deploy the
company PAC file at that path separately. The profile seeds new preferences
only, so an existing user's choices are preserved when the app is updated.

## Remove Unproxy

- **Windows:** Run `uninstall.ps1` from the extracted Windows ZIP. Add
  `-RemoveUserData` if you also want to delete preferences and logs.
- **macOS:** For the menu bar app, turn off **Start with Login**, quit Unproxy,
  then move it from Applications to the Trash.
- **Debian/Ubuntu:** Run `sudo apt remove unproxy`.
