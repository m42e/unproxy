# Local TLS fixture

localhost.pem and localhost.key are a self-signed test-only certificate/key pair.
They authorize no real service and are never used by runtime executables.
The certificate includes localhost, 127.0.0.1 and ::1 subject alternative names.
localhost.p12 contains the same certificate and key for native TLS server tests.
Its test-only password is `unproxy-test`. Tests explicitly trust localhost.pem
to verify successful and failing native TLS. Replace the pair and identity when
the certificate expires, preserving these names and the PKCS#8 key format. Use
PBE-SHA1-3DES for both PKCS#12 bags and SHA-256 for its MAC so OpenSSL 3 can
load the identity without enabling legacy ciphers.
