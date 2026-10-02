# Experimental Linux redirection context

The historical setup recipe enables IP forwarding and redirects outbound TCP
port 80 to local port 3125 with a proxy-process group exemption. This is external
OS configuration. For example, in a disposable network namespace:

```sh
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner ! --gid-owner unproxy -j REDIRECT --to-ports 3125
```

The listener would have to use --listen 127.0.0.1:3125, matching the rule.
This product treats origin-form traffic as local management and does not recover
the original NAT destination. The recipe therefore does not provide working
transparent forwarding. Transparent HTTPS, NAT setup and firewall management
are outside feature parity. Use explicitly configured clients instead.
