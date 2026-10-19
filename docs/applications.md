# Connect applications

Point each application at Unproxy’s local HTTP listener. Applications can use their own proxy settings, environment variables, or system settings, depending on what they support.

## Browsers and graphical apps

Choose a manual HTTP proxy and use `127.0.0.1`, port `3128`, for both HTTP and HTTPS. If the app expects a single URL, enter `http://127.0.0.1:3128`. Use your custom listener instead if you changed it.

Configure local destinations in the app’s bypass list, such as `localhost`, `127.0.0.1`, and `::1`. Applications that use operating system proxy settings may need to be configured there. Installing Unproxy does not make every app use it.

Do not select a SOCKS listener in the application: Unproxy exposes an HTTP proxy even when its upstream route uses SOCKS.

## Terminal setup

The following commands set proxy variables and load argument completion in the current shell. Run the command that matches your shell.

### Bash

```sh
source <(unproxy shell-setup bash)
```

### Zsh

```sh
source <(unproxy shell-setup zsh)
```

### Fish

```fish
unproxy shell-setup fish | source
```

### PowerShell

```powershell
Invoke-Expression (unproxy shell-setup powershell | Out-String)
```

### Windows Command Prompt

```bat
for /f "delims=" %i in ('unproxy shell-setup cmd') do @%i
```

In a `.bat` file, use `%%i` instead of `%i`. Command Prompt has no native argument completion.

These commands set lowercase and uppercase HTTP, HTTPS, and bypass variables. The proxy address comes from the first listener in the **CLI settings file**, or defaults to `127.0.0.1:3128`. It does not come from desktop preferences. If you changed the desktop listener, set variables explicitly to that address.

## Keep shell settings across sessions

For Bash or Zsh, add the matching `shell-setup` command to your shell profile if `unproxy` is on your PATH. Alternatively, add explicit exports, adjusting the address to match your listener:

```sh
export http_proxy=http://127.0.0.1:3128
export https_proxy=http://127.0.0.1:3128
export no_proxy=localhost,127.0.0.1,::1
```

On macOS, the default shell uses `~/.zshrc`. Open a new shell after editing it. Variables apply to programs started from that shell; apps opened from Finder do not inherit them.

The Windows per-user installer persists proxy variables for the installing account. Reopen existing terminals after installation. On uninstall, previous values are restored if you have not changed them since installation.

## Test one request

Use an explicit proxy to test independently of shell variables:

```sh
curl --noproxy "" --proxy http://127.0.0.1:3128 https://example.com/
```

Use `curl.exe` in Windows PowerShell. `--noproxy ""` clears bypass rules for this request. Replace the destination with a company URL to exercise a corporate route.

## Stop using proxy variables

Remove any persistent setup from your shell profile too.

### Bash

Clear both cases in the current terminal:

```sh
unset http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY
```

### Zsh

Clear both cases in the current terminal:

```sh
unset http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY
```

### Fish

Clear the proxy variables in the current terminal:

```fish
set -e http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY
```

### PowerShell

Clear the proxy variables in the current terminal:

```powershell
Remove-Item Env:http_proxy, Env:https_proxy, Env:no_proxy -ErrorAction SilentlyContinue
```

### Windows Command Prompt

Clear the proxy variables in the current terminal:

```bat
set http_proxy=
set https_proxy=
set no_proxy=
```

Stopping Unproxy does not remove an application’s proxy settings. Remove those settings when you want the app to connect without Unproxy.
