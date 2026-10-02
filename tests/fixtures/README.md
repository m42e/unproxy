# Local TLS fixture

localhost.pem and localhost.key are a self-signed test-only certificate/key pair.
They authorize no real service and are never used by runtime executables.
The certificate includes localhost, 127.0.0.1 and ::1 subject alternative names.
Tests explicitly trust this root to verify successful and failing native TLS.
Replace the pair when it expires, preserving these names and PKCS#8 key format.
