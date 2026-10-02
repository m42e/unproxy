# Linux and macOS services

Linux packages install a user unit. Source installations may copy
assets/unproxy.service to ~/.config/systemd/user and adjust ExecStart.

```sh
systemctl --user daemon-reload
systemctl --user enable --now unproxy
systemctl --user reload unproxy
systemctl --user disable --now unproxy
```

The service restarts failures after five seconds, starts after/wants
network-online, kills the main process and permits 65536 open files. Debian
hooks preserve enablement, update helper state, mask removal and clear state on
purge. Installing a package does not guarantee automatic startup in every user
session already running.

macOS uses launch agent de.m42e.unproxy and a named Listeners socket at
127.0.0.1:3128. Native packages install it under /Library/LaunchAgents.
unproxyctl defaults to status and supports start, restart, stop, enable and
disable. Commands target gui/UID, not the system domain. The registration helper
supports install/uninstall/status and also persists enable/disable state.

```sh
unproxy-register install
unproxyctl status
unproxyctl restart
unproxy-register uninstall
```

Source registration can use launchctl bootstrap gui/UID PLIST and
launchctl bootout gui/UID/de.m42e.unproxy. Ensure the agent's absolute
executable path matches your installation. Native installers unload the current
and legacy com.github.m42e.unproxy agents and enable the replacement for
the current console user when a GUI session exists.

Systemd activation uses LISTEN_FDS, LISTEN_FDNAMES and optional LISTEN_PID.
Descriptors start at 3; every matching name is adopted with ownership transfer.
No match is a diagnosed error. macOS uses launch_activate_socket. Windows does
not support this option.
