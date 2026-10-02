# Desktop and platform controls

unproxy-system-proxy PORT is a macOS utility. Zero disables HTTP/HTTPS proxies;
other unsigned 16-bit values enable 127.0.0.1:PORT. It obtains native interactive
authorization and changes only Ethernet and Wi-Fi services. Their proxy
dictionaries are replaced; PAC/autodiscovery/SOCKS/Gopher are disabled, with
exceptions ::1, 127.0.0.1, localhost and *.local. Previous settings are not restored.

The macOS menu bar app starts a packaged child and waits for its termination
when stopped. Start/Stop and informational Port/PAC entries reflect its state.
CONNECT, DIRECT fallback and Negotiate toggles persist and restart the child.
Port defaults to 8080; accepted stored ports are 1024..65534, otherwise 3128.
The PAC preference defaults to the user support directory's Unproxy/proxy.pac.
Port and PAC preferences can be changed with native defaults, without editing UI.
The child receives supported --listen, --pac-file and --proxytunnel options and
graceful shutdown timeout zero.

The app enables its login item at launch. The stored Autostart preference has
no control effect. The login helper checks for duplicate main apps, launches
when absent and exits on the main app's distributed notification. Kerberos
InternalNetworkAvailable/NotAvailable notifications only change the availability
indicator; they do not change routing or restart the child. Sign app/helper/child
with your distribution identity and the supplied entitlements before distribution.

Windows release binaries have the windows subsystem. --attach-console runs
before argument parsing so help/version output can reach the invoking console.
Portable unproxyrc/unproxyrc.txt and proxy.pac may live beside the executable.
The per-user installer creates a Run entry; Unix signals and activation are absent.
