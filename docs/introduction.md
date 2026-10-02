# Introduction

Unproxy gives applications one local proxy while evaluating the administrator's
PAC script for each destination. Direct, HTTP proxy and HTTPS proxy routes can
appear in the same ordered policy. Corporate proxy authentication belongs to
Unproxy; applications retain control of destination authentication and TLS.

The HTTP frontend is plain HTTP/1. HTTPS clients use CONNECT and conduct their
own TLS handshake through an opaque TCP tunnel. Unproxy does not intercept
TLS, install certificates, cache responses, or provide a SOCKS service.

The default listener is 127.0.0.1:3128. Management pages at /, /proxy.pac,
/access.html and /access.log share this listener. Only origin-form GET requests
select these resources. Access events are live and bounded, without history.

The separate dnsdetox companion asks a primary UDP resolver first and sends the
original query to a secondary DoH resolver only when the primary response has
questions and no answers. Primary timeout and malformed responses do not trigger
secondary fallback. This service does not automatically replace system DNS.
