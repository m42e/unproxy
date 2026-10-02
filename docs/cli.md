# Command-line reference

Generated with settings-file reading disabled.

```text
Usage: unproxy [OPTIONS]

Options:
  -v, --verbose...
  -q, --quiet...
      --logfile <LOGFILE>
  -L, --listen <LISTEN>
      --activate-socket <ACTIVATE_SOCKET>
  -p, --pac-file <PAC_FILE>
      --my-ip-address <MY_IP_ADDRESS>
      --netrc-file <NETRC_FILE>
  -n, --negotiate [<NEGOTIATE>]
      --proxytunnel
      --direct-fallback
      --strict-policy
      --header-timeout <HEADER_TIMEOUT>                                [default: 15]
      --idle-timeout <IDLE_TIMEOUT>                                    [default: 60]
      --exchange-timeout <EXCHANGE_TIMEOUT>                            [default: 30]
      --max-sessions <MAX_SESSIONS>                                    [default: 256]
  -c, --connect-timeout <CONNECT_TIMEOUT>                              [default: 10]
      --race-connect
      --parallel-connect <PARALLEL_CONNECT>                            [default: 1]
      --client-tcp-keepalive-time <CLIENT_TCP_KEEPALIVE_TIME>
      --client-tcp-keepalive-interval <CLIENT_TCP_KEEPALIVE_INTERVAL>
      --client-tcp-keepalive-retries <CLIENT_TCP_KEEPALIVE_RETRIES>
      --server-tcp-keepalive-time <SERVER_TCP_KEEPALIVE_TIME>
      --server-tcp-keepalive-interval <SERVER_TCP_KEEPALIVE_INTERVAL>
      --server-tcp-keepalive-retries <SERVER_TCP_KEEPALIVE_RETRIES>
      --graceful-shutdown-timeout <GRACEFUL_SHUTDOWN_TIMEOUT>          [default: 30]
  -h, --help                                                           Print help
  -V, --version                                                        Print version
```
