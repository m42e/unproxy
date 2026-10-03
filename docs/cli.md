# Command-line reference

Generated with settings-file reading disabled.

```text
Usage: unproxy [OPTIONS]

Options:
  -v, --verbose...
          Increase log verbosity; repeat to enable DEBUG and TRACE output
  -q, --quiet...
          Decrease log verbosity; repeat to disable logging
      --logfile <LOGFILE>
          Write diagnostic logs to this file, truncating it at startup
  -L, --listen <LISTEN>
          Listen on this numeric IP address and port; may be repeated (default: 127.0.0.1:3128)
      --activate-socket <ACTIVATE_SOCKET>
          Accept connections from a named socket-activation listener
  -p, --pac-file <PAC_FILE>
          Load a PAC script from a local path or HTTP(S) URL; may be repeated
      --my-ip-address <MY_IP_ADDRESS>
          Override the IP address returned by PAC's myIpAddress() function
      --netrc-file <NETRC_FILE>
          Read upstream proxy credentials from this netrc file (default: ~/.netrc)
  -n, --negotiate [<NEGOTIATE>]
          Use Negotiate authentication; optionally restrict it to a host, repeatable
      --proxytunnel
          Use an upstream HTTP CONNECT tunnel for every request
      --direct-fallback
          Try a direct connection after all selected proxy routes fail
      --strict-policy
          Fail closed until a routing script loads and on PAC evaluation errors
      --header-timeout <HEADER_TIMEOUT>
          Maximum time in seconds to receive request headers [default: 15]
      --idle-timeout <IDLE_TIMEOUT>
          Maximum idle time in seconds for frontend and upstream HTTP connections [default: 60]
      --exchange-timeout <EXCHANGE_TIMEOUT>
          Maximum time in seconds for an upstream HTTP exchange [default: 30]
      --max-sessions <MAX_SESSIONS>
          Maximum number of simultaneous client sessions, including CONNECT tunnels [default: 256]
  -c, --connect-timeout <CONNECT_TIMEOUT>
          Timeout in seconds for each upstream connection attempt [default: 10]
      --race-connect
          Race concurrent upstream connection attempts and use the first success
      --parallel-connect <PARALLEL_CONNECT>
          Maximum number of upstream connection attempts to run concurrently [default: 1]
      --client-tcp-keepalive-time <CLIENT_TCP_KEEPALIVE_TIME>
          Set the client-side TCP keepalive idle time in seconds
      --client-tcp-keepalive-interval <CLIENT_TCP_KEEPALIVE_INTERVAL>
          Set the client-side TCP keepalive probe interval in seconds
      --client-tcp-keepalive-retries <CLIENT_TCP_KEEPALIVE_RETRIES>
          Set the number of unacknowledged client-side TCP keepalive probes
      --server-tcp-keepalive-time <SERVER_TCP_KEEPALIVE_TIME>
          Set the server-side TCP keepalive idle time in seconds
      --server-tcp-keepalive-interval <SERVER_TCP_KEEPALIVE_INTERVAL>
          Set the server-side TCP keepalive probe interval in seconds
      --server-tcp-keepalive-retries <SERVER_TCP_KEEPALIVE_RETRIES>
          Set the number of unacknowledged server-side TCP keepalive probes
      --graceful-shutdown-timeout <GRACEFUL_SHUTDOWN_TIMEOUT>
          Wait this many seconds for active sessions to finish during shutdown [default: 30]
  -h, --help
          Print help
  -V, --version
          Print version
```
