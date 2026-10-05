//! TCP CONNECT handshakes for SOCKS4a and SOCKS5 upstreams.
use anyhow::{Context, Result, bail, ensure};
use std::net::IpAddr;
#[cfg(feature = "negotiate")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "negotiate")]
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    auth::AuthFactory,
    net::{AsyncIo, BoxedIo},
    route::Endpoint,
};

pub(crate) async fn handshake(
    stream: BoxedIo,
    destination: &Endpoint,
    proxy_host: &str,
    version5: bool,
    auth: &AuthFactory,
) -> Result<(BoxedIo, bool)> {
    if version5 {
        socks5(stream, destination, proxy_host, auth).await
    } else {
        let mut stream = stream;
        socks4(&mut stream, destination).await?;
        Ok((stream, false))
    }
}

async fn socks4(stream: &mut impl AsyncIo, destination: &Endpoint) -> Result<()> {
    let mut request = vec![4, 1];
    request.extend_from_slice(&destination.port.to_be_bytes());
    let hostname = match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.extend_from_slice(&ip.octets());
            false
        }
        Ok(IpAddr::V6(_)) => bail!("SOCKS4 does not support IPv6 destinations"),
        Err(_) => {
            ensure!(
                !destination.host.is_empty()
                    && destination.host.len() <= 255
                    && !destination.host.contains('\0'),
                "invalid SOCKS4a destination hostname"
            );
            request.extend_from_slice(&[0, 0, 0, 1]);
            true
        }
    };
    request.push(0); // Empty USERID; netrc passwords are only used with SOCKS5.
    if hostname {
        request.extend_from_slice(destination.host.as_bytes());
        request.push(0);
    }
    stream.write_all(&request).await.context("SOCKS4 request")?;
    let mut reply = [0; 8];
    stream
        .read_exact(&mut reply)
        .await
        .context("SOCKS4 reply")?;
    ensure!(reply[0] == 0, "invalid SOCKS4 reply version");
    ensure!(
        reply[1] == 90,
        "SOCKS4 CONNECT rejected (status {})",
        reply[1]
    );
    Ok(())
}

async fn socks5(
    mut stream: BoxedIo,
    destination: &Endpoint,
    proxy_host: &str,
    auth: &AuthFactory,
) -> Result<(BoxedIo, bool)> {
    let credentials = auth.socks_credentials(proxy_host);
    let gss_enabled = auth.socks_gss_enabled(proxy_host);
    let mut methods = vec![0];
    if credentials.is_some() {
        methods.push(2);
    }
    if gss_enabled {
        methods.push(1);
    }
    let mut greeting = vec![5, methods.len() as u8];
    greeting.extend(methods);
    stream
        .write_all(&greeting)
        .await
        .context("SOCKS5 greeting")?;
    let mut selection = [0; 2];
    stream
        .read_exact(&mut selection)
        .await
        .context("SOCKS5 method selection")?;
    ensure!(selection[0] == 5, "invalid SOCKS5 method version");
    let authenticated = match selection[1] {
        0 => false,
        1 => {
            ensure!(
                gss_enabled,
                "SOCKS5 selected unoffered GSSAPI authentication"
            );
            #[cfg(feature = "negotiate")]
            {
                let auth = auth.clone();
                let host = proxy_host.to_owned();
                let context = tokio::task::spawn_blocking(move || auth.socks_gss_context(&host))
                    .await
                    .context("starting SOCKS5 GSSAPI worker")??
                    .context("SOCKS5 GSSAPI is not enabled for this proxy host")?;
                let context: SharedGss = Arc::new(Mutex::new(Box::new(context)));
                socks5_gss_authenticate(&mut stream, context.clone()).await?;
                stream = protected_stream(stream, context)?;
                true
            }
            #[cfg(not(feature = "negotiate"))]
            {
                bail!("SOCKS5 GSSAPI requires the negotiate feature")
            }
        }
        2 => {
            let (username, password) = credentials
                .context("SOCKS5 selected unoffered username/password authentication")?;
            ensure!(
                (1..=255).contains(&username.len()) && (1..=255).contains(&password.len()),
                "SOCKS5 username and password must each contain 1–255 bytes"
            );
            let mut auth = vec![1, username.len() as u8];
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream
                .write_all(&auth)
                .await
                .context("SOCKS5 authentication")?;
            let mut reply = [0; 2];
            stream
                .read_exact(&mut reply)
                .await
                .context("SOCKS5 authentication reply")?;
            ensure!(reply == [1, 0], "SOCKS5 authentication rejected");
            true
        }
        method => bail!("SOCKS5 unsupported authentication method {method}"),
    };

    socks5_connect(&mut stream, destination).await?;
    Ok((stream, authenticated))
}

async fn socks5_connect(stream: &mut impl AsyncIo, destination: &Endpoint) -> Result<()> {
    let mut request = vec![5, 1, 0];
    match destination.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            ensure!(
                !destination.host.is_empty()
                    && destination.host.len() <= 255
                    && !destination.host.contains('\0'),
                "invalid SOCKS5 destination hostname"
            );
            request.extend_from_slice(&[3, destination.host.len() as u8]);
            request.extend_from_slice(destination.host.as_bytes());
        }
    }
    request.extend_from_slice(&destination.port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .context("SOCKS5 CONNECT request")?;
    let mut reply = [0; 4];
    stream
        .read_exact(&mut reply)
        .await
        .context("SOCKS5 CONNECT reply")?;
    ensure!(
        reply[0] == 5 && reply[2] == 0,
        "invalid SOCKS5 CONNECT reply"
    );
    ensure!(
        reply[1] == 0,
        "SOCKS5 CONNECT rejected (status {})",
        reply[1]
    );
    let address_len = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let len = stream
                .read_u8()
                .await
                .context("SOCKS5 bound hostname length")?;
            ensure!(len > 0, "invalid SOCKS5 bound hostname length");
            usize::from(len)
        }
        kind => bail!("invalid SOCKS5 reply address type {kind}"),
    };
    let mut bound = vec![0; address_len + 2];
    stream
        .read_exact(&mut bound)
        .await
        .context("SOCKS5 bound address")?;
    Ok(())
}

#[cfg(feature = "negotiate")]
trait GssSession: Send {
    fn step(&mut self, input: Option<&[u8]>) -> Result<(Option<Vec<u8>>, bool)>;
    fn is_complete(&self) -> bool;
    fn wrap(&mut self, message: &[u8], confidential: bool) -> Result<Vec<u8>>;
    fn unwrap(&mut self, message: &[u8], require_confidentiality: bool) -> Result<Vec<u8>>;
}
#[cfg(feature = "negotiate")]
impl GssSession for crate::auth::NegotiateContext {
    fn step(&mut self, input: Option<&[u8]>) -> Result<(Option<Vec<u8>>, bool)> {
        self.step_with_status(input)
    }
    fn is_complete(&self) -> bool {
        crate::auth::NegotiateContext::is_complete(self)
    }
    fn wrap(&mut self, message: &[u8], confidential: bool) -> Result<Vec<u8>> {
        crate::auth::NegotiateContext::wrap(self, message, confidential)
    }
    fn unwrap(&mut self, message: &[u8], require_confidentiality: bool) -> Result<Vec<u8>> {
        crate::auth::NegotiateContext::unwrap(self, message, require_confidentiality)
    }
}

#[cfg(feature = "negotiate")]
type SharedGss = Arc<Mutex<Box<dyn GssSession>>>;

#[cfg(feature = "negotiate")]
async fn gss_call<T, F>(context: &SharedGss, action: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&mut dyn GssSession) -> Result<T> + Send + 'static,
{
    let context = context.clone();
    tokio::task::spawn_blocking(move || {
        let mut context = context
            .lock()
            .map_err(|_| anyhow::anyhow!("SOCKS5 GSSAPI context lock poisoned"))?;
        action(&mut **context)
    })
    .await
    .context("SOCKS5 GSSAPI worker failed")?
}

#[cfg(feature = "negotiate")]
async fn socks5_gss_authenticate(stream: &mut impl AsyncIo, context: SharedGss) -> Result<()> {
    let (mut token, mut complete) = gss_call(&context, |context| context.step(None)).await?;
    loop {
        write_subnegotiation(stream, 1, token.as_deref().unwrap_or(&[])).await?;
        let (kind, server_token) = read_subnegotiation(stream).await?;
        ensure!(kind == 1, "unexpected SOCKS5 GSSAPI message type {kind}");
        if server_token.is_empty() {
            let locally_complete = if complete {
                true
            } else {
                gss_call(&context, |context| Ok(context.is_complete())).await?
            };
            ensure!(
                locally_complete,
                "SOCKS5 GSSAPI server completed before the security context"
            );
            break;
        }
        (token, complete) =
            gss_call(&context, move |context| context.step(Some(&server_token))).await?;
    }

    // Request level 2: integrity and confidentiality for all proxied bytes.
    let protection = gss_call(&context, |context| context.wrap(&[2], false)).await?;
    ensure!(
        !protection.is_empty(),
        "SOCKS5 GSSAPI produced an empty protection token"
    );
    write_subnegotiation(stream, 2, &protection).await?;
    let (kind, server_protection) = read_subnegotiation(stream).await?;
    ensure!(
        kind == 2,
        "unexpected SOCKS5 GSSAPI protection message type {kind}"
    );
    let agreed = gss_call(&context, move |context| {
        context.unwrap(&server_protection, false)
    })
    .await?;
    ensure!(
        agreed == [2],
        "SOCKS5 server did not accept integrity and confidentiality protection"
    );
    Ok(())
}

#[cfg(feature = "negotiate")]
async fn write_subnegotiation<S: AsyncWrite + Unpin>(
    stream: &mut S,
    kind: u8,
    token: &[u8],
) -> Result<()> {
    ensure!(
        token.len() <= u16::MAX as usize,
        "SOCKS5 GSSAPI token exceeds 65535 bytes"
    );
    let mut header = [1, kind, 0, 0];
    header[2..].copy_from_slice(&(token.len() as u16).to_be_bytes());
    stream
        .write_all(&header)
        .await
        .context("SOCKS5 GSSAPI message header")?;
    stream
        .write_all(token)
        .await
        .context("SOCKS5 GSSAPI message token")?;
    Ok(())
}

#[cfg(feature = "negotiate")]
async fn read_subnegotiation<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u8, Vec<u8>)> {
    let mut prefix = [0; 2];
    stream
        .read_exact(&mut prefix)
        .await
        .context("SOCKS5 GSSAPI message header")?;
    ensure!(prefix[0] == 1, "invalid SOCKS5 GSSAPI message version");
    ensure!(prefix[1] != 0xff, "SOCKS5 GSSAPI authentication rejected");
    let mut encoded_len = [0; 2];
    stream
        .read_exact(&mut encoded_len)
        .await
        .context("SOCKS5 GSSAPI message length")?;
    let len = u16::from_be_bytes(encoded_len) as usize;
    let mut token = vec![0; len];
    stream
        .read_exact(&mut token)
        .await
        .context("SOCKS5 GSSAPI message token")?;
    Ok((prefix[1], token))
}

#[cfg(feature = "negotiate")]
fn protected_stream(stream: BoxedIo, context: SharedGss) -> Result<BoxedIo> {
    let (application, relay) = tokio::io::duplex(128 * 1024);
    tokio::spawn(async move {
        let (mut app_read, mut app_write) = tokio::io::split(application);
        let (mut net_read, mut net_write) = tokio::io::split(stream);
        let outbound_context = context.clone();
        let outbound = async {
            let mut buffer = vec![0; 16 * 1024];
            loop {
                let count = app_read
                    .read(&mut buffer)
                    .await
                    .context("reading SOCKS5 GSSAPI application data")?;
                if count == 0 {
                    net_write
                        .shutdown()
                        .await
                        .context("shutting down SOCKS5 GSSAPI write side")?;
                    return Ok::<_, anyhow::Error>(());
                }
                let message = buffer[..count].to_vec();
                let token = gss_call(&outbound_context, move |context| {
                    context.wrap(&message, true)
                })
                .await?;
                write_subnegotiation(&mut net_write, 3, &token).await?;
            }
        };
        let inbound_context = context;
        let inbound = async {
            loop {
                let (kind, token) = read_subnegotiation(&mut net_read).await?;
                ensure!(
                    kind == 3,
                    "unexpected SOCKS5 GSSAPI data message type {kind}"
                );
                let data = gss_call(&inbound_context, move |context| {
                    context.unwrap(&token, true)
                })
                .await?;
                app_write
                    .write_all(&data)
                    .await
                    .context("writing SOCKS5 GSSAPI application data")?;
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        };
        if let Err(error) = tokio::try_join!(outbound, inbound) {
            tracing::debug!(%error, "SOCKS5 GSSAPI stream ended");
        }
    });
    Ok(Box::new(relay))
}

#[cfg(all(test, feature = "negotiate"))]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    struct FixtureContext {
        steps: usize,
    }

    #[test]
    fn negotiate_auth_enables_socks_gss_only_for_allowed_proxy_hosts() {
        let auth = AuthFactory::negotiate(vec!["proxy.corp.test".into()]);
        assert!(auth.socks_gss_enabled("proxy.corp.test"));
        assert!(!auth.socks_gss_enabled("proxy.public.test"));
        assert!(AuthFactory::negotiate(Vec::new()).socks_gss_enabled("any.proxy.test"));
        assert!(!AuthFactory::no_auth().socks_gss_enabled("proxy.corp.test"));
    }
    impl GssSession for FixtureContext {
        fn step(&mut self, input: Option<&[u8]>) -> Result<(Option<Vec<u8>>, bool)> {
            let token = match (self.steps, input) {
                (0, None) => b"client-first".to_vec(),
                (1, Some(b"server-challenge")) => b"client-final".to_vec(),
                _ => bail!("unexpected fixture GSS step"),
            };
            self.steps += 1;
            Ok((Some(token), self.steps == 2))
        }
        fn is_complete(&self) -> bool {
            self.steps == 2
        }
        fn wrap(&mut self, message: &[u8], confidential: bool) -> Result<Vec<u8>> {
            Ok([
                vec![if confidential { 0xcc } else { 0xaa }],
                message.to_vec(),
            ]
            .concat())
        }
        fn unwrap(&mut self, message: &[u8], require_confidentiality: bool) -> Result<Vec<u8>> {
            let prefix = if require_confidentiality { 0xcc } else { 0xaa };
            ensure!(
                message.first() == Some(&prefix),
                "fixture GSS protection mismatch"
            );
            Ok(message[1..].to_vec())
        }
    }

    #[tokio::test]
    async fn gssapi_auth_negotiates_context_protection_and_wraps_the_tunnel() {
        let (mut client, mut proxy) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            assert_eq!(
                read_subnegotiation(&mut proxy).await.unwrap(),
                (1, b"client-first".to_vec())
            );
            write_subnegotiation(&mut proxy, 1, b"server-challenge")
                .await
                .unwrap();
            assert_eq!(
                read_subnegotiation(&mut proxy).await.unwrap(),
                (1, b"client-final".to_vec())
            );
            write_subnegotiation(&mut proxy, 1, b"").await.unwrap();
            assert_eq!(
                read_subnegotiation(&mut proxy).await.unwrap(),
                (2, b"\xaa\x02".to_vec())
            );
            write_subnegotiation(&mut proxy, 2, b"\xaa\x02")
                .await
                .unwrap();
            let (kind, command) = read_subnegotiation(&mut proxy).await.unwrap();
            assert_eq!(kind, 3);
            assert_eq!(
                command,
                [
                    b"\xcc".to_vec(),
                    vec![5, 1, 0, 3, 11],
                    b"target.test".to_vec(),
                    [0, 80].to_vec()
                ]
                .concat()
            );
            write_subnegotiation(
                &mut proxy,
                3,
                &[b"\xcc".to_vec(), [5, 0, 0, 1, 0, 0, 0, 0, 0, 0].to_vec()].concat(),
            )
            .await
            .unwrap();
            write_subnegotiation(&mut proxy, 3, b"\xccready")
                .await
                .unwrap();
        });
        let context: SharedGss = Arc::new(Mutex::new(Box::new(FixtureContext { steps: 0 })));
        socks5_gss_authenticate(&mut client, context.clone())
            .await
            .unwrap();
        let mut client = protected_stream(Box::new(client), context).unwrap();
        socks5_connect(&mut client, &"target.test:80".parse().unwrap())
            .await
            .unwrap();
        let mut response = [0; 5];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ready");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn gssapi_rejects_a_server_that_downgrades_message_protection() {
        let (mut client, mut proxy) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            read_subnegotiation(&mut proxy).await.unwrap();
            write_subnegotiation(&mut proxy, 1, b"server-challenge")
                .await
                .unwrap();
            read_subnegotiation(&mut proxy).await.unwrap();
            write_subnegotiation(&mut proxy, 1, b"").await.unwrap();
            read_subnegotiation(&mut proxy).await.unwrap();
            write_subnegotiation(&mut proxy, 2, b"\xaa\x01")
                .await
                .unwrap();
        });
        let context: SharedGss = Arc::new(Mutex::new(Box::new(FixtureContext { steps: 0 })));
        let error = socks5_gss_authenticate(&mut client, context)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("did not accept integrity and confidentiality")
        );
        server.await.unwrap();
    }
}
