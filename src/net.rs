//! Outbound connection and stream utilities shared by the proxy and embedders.

use std::{
    future::Future,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::{self, Instant, Sleep},
};

/// A stream wrapper that closes inactive HTTP exchanges. An owner may disable
/// the deadline after protocol upgrade, for example when CONNECT takes over.
pub struct IdleIo<S> {
    inner: S,
    timeout: Duration,
    disabled: Arc<AtomicBool>,
    read_deadline: Pin<Box<Sleep>>,
    write_deadline: Pin<Box<Sleep>>,
}
impl<S> IdleIo<S> {
    pub fn new(inner: S, timeout: Duration, disabled: Arc<AtomicBool>) -> Self {
        let deadline = Instant::now() + timeout;
        Self {
            inner,
            timeout,
            disabled,
            read_deadline: Box::pin(time::sleep_until(deadline)),
            write_deadline: Box::pin(time::sleep_until(deadline)),
        }
    }
    fn reset_read(&mut self) {
        self.read_deadline
            .as_mut()
            .reset(Instant::now() + self.timeout);
    }
    fn reset_write(&mut self) {
        self.write_deadline
            .as_mut()
            .reset(Instant::now() + self.timeout);
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for IdleIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if buf.filled().len() > before => {
                self.reset_read();
                self.reset_write();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(value) => Poll::Ready(value),
            Poll::Pending if self.disabled.load(Ordering::Relaxed) => Poll::Pending,
            Poll::Pending => match self.read_deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP read idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for IdleIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, data) {
            Poll::Ready(Ok(n)) if n > 0 => {
                self.reset_write();
                self.reset_read();
                Poll::Ready(Ok(n))
            }
            Poll::Ready(value) => Poll::Ready(value),
            Poll::Pending if self.disabled.load(Ordering::Relaxed) => Poll::Pending,
            Poll::Pending => match self.write_deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP write idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.reset_write();
                self.reset_read();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(value) => Poll::Ready(value),
            Poll::Pending if self.disabled.load(Ordering::Relaxed) => Poll::Pending,
            Poll::Pending => match self.write_deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP flush idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.inner).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                self.reset_write();
                self.reset_read();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(value) => Poll::Ready(value),
            Poll::Pending if self.disabled.load(Ordering::Relaxed) => Poll::Pending,
            Poll::Pending => match self.write_deadline.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "HTTP shutdown idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}
use tokio_native_tls::TlsConnector;

use crate::{
    auth::AuthFactory,
    route::{Endpoint, Route},
};

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncIo for T {}
pub type BoxedIo = Box<dyn AsyncIo>;

#[derive(Clone, Debug, Default)]
pub struct Keepalive {
    pub time: Option<Duration>,
    pub interval: Option<Duration>,
    pub retries: Option<u32>,
}

#[derive(Clone)]
pub struct ConnectionOptions {
    pub tls: TlsConnector,
    pub auth: AuthFactory,
    pub keepalive: Keepalive,
}

impl Default for ConnectionOptions {
    fn default() -> Self {
        let tls = native_tls::TlsConnector::builder()
            .build()
            .expect("native TLS connector");
        Self {
            tls: TlsConnector::from(tls),
            auth: AuthFactory::default(),
            keepalive: Keepalive::default(),
        }
    }
}

pub fn configure_keepalive(stream: &TcpStream, keepalive: &Keepalive) -> Result<()> {
    stream.set_nodelay(true)?;
    let socket = socket2::SockRef::from(stream);
    let mut ka = socket2::TcpKeepalive::new();
    if let Some(time) = keepalive.time {
        ka = ka.with_time(time);
    }
    if let Some(interval) = keepalive.interval {
        ka = ka.with_interval(interval);
    }
    #[cfg(unix)]
    if let Some(retries) = keepalive.retries {
        ka = ka.with_retries(retries);
    }
    socket.set_tcp_keepalive(&ka)?;
    Ok(())
}

async fn tcp(
    endpoint: &Endpoint,
    options: &ConnectionOptions,
    timeout: Duration,
) -> Result<TcpStream> {
    let stream = time::timeout(
        timeout,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .context("TCP connection timed out")?
    .with_context(|| format!("connecting to {endpoint}"))?;
    configure_keepalive(&stream, &options.keepalive)?;
    Ok(stream)
}

async fn secure(stream: BoxedIo, host: &str, connector: &TlsConnector) -> Result<BoxedIo> {
    let stream = connector
        .connect(host, stream)
        .await
        .with_context(|| format!("TLS to {host}"))?;
    Ok(Box::new(stream))
}

/// Apply a deadline to an operation and retain the operation's cause chain.
pub async fn with_timeout<T, F>(duration: Duration, operation: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    time::timeout(duration, operation)
        .await
        .context("operation timed out")?
}

/// Establish a directly connected, TLS-protected destination stream.
pub async fn connect_direct_tls(
    destination: &Endpoint,
    options: &ConnectionOptions,
    timeout: Duration,
) -> Result<BoxedIo> {
    let stream: BoxedIo = Box::new(tcp(destination, options, timeout).await?);
    time::timeout(timeout, secure(stream, &destination.host, &options.tls))
        .await
        .context("TLS handshake timed out")?
}

/// Establish the selected route. For proxy routes, `tunnel` performs CONNECT
/// through the proxy before returning the stream.
pub async fn connect(
    route: &Route,
    destination: &Endpoint,
    tunnel: bool,
    options: &ConnectionOptions,
    timeout: Duration,
) -> Result<BoxedIo> {
    time::timeout(timeout, async {
        match route {
            Route::Direct => Ok(Box::new(tcp(destination, options, timeout).await?) as BoxedIo),
            Route::Http(proxy) => {
                proxy_connect(proxy, destination, tunnel, options, timeout, false).await
            }
            Route::Https(proxy) => {
                proxy_connect(proxy, destination, tunnel, options, timeout, true).await
            }
        }
    })
    .await
    .context("outbound route connection timed out")?
}

async fn proxy_connect(
    proxy: &Endpoint,
    destination: &Endpoint,
    tunnel: bool,
    options: &ConnectionOptions,
    timeout: Duration,
    tls: bool,
) -> Result<BoxedIo> {
    let stream: BoxedIo = Box::new(tcp(proxy, options, timeout).await?);
    let mut stream = if tls {
        secure(stream, &proxy.host, &options.tls).await?
    } else {
        stream
    };
    if tunnel {
        let authorization = time::timeout(
            Duration::from_secs(2),
            options.auth.authorization(&proxy.host),
        )
        .await
        .context("upstream authorization timed out")??;
        let authority = destination.authority();
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(value) = authorization {
            request.push_str("Proxy-Authorization: ");
            request.push_str(
                value
                    .to_str()
                    .context("invalid proxy authorization header")?,
            );
            request.push_str("\r\n");
        }
        request.push_str("Connection: keep-alive\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .context("writing upstream CONNECT")?;
        let mut response = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            let n = time::timeout(timeout, stream.read(&mut byte))
                .await
                .context("upstream CONNECT response timed out")??;
            if n == 0 {
                bail!("upstream proxy closed during CONNECT");
            }
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
            if response.len() > 64 * 1024 {
                bail!("upstream CONNECT headers too large");
            }
        }
        let head = std::str::from_utf8(&response).context("invalid upstream CONNECT response")?;
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| anyhow!("invalid upstream CONNECT status"))?;
        if !(200..300).contains(&status) {
            bail!("upstream proxy {proxy} rejected CONNECT with HTTP {status}");
        }
    }
    Ok(stream)
}

const MAX_PAC_BYTES: usize = 8 * 1024 * 1024;

async fn read_http_head(io: &mut BoxedIo) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if io.read(&mut byte).await? == 0 {
            bail!("connection closed before HTTP headers completed");
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() > 64 * 1024 {
            bail!("HTTP response headers exceed 64 KiB")
        }
    }
}
async fn read_crlf_line(io: &mut BoxedIo) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let mut b = [0u8; 1];
        if io.read(&mut b).await? == 0 {
            bail!("truncated chunked response")
        }
        line.push(b[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
        if line.len() > 8192 {
            bail!("chunk line too long")
        }
    }
}
async fn read_pac_body(io: &mut BoxedIo, header: &str) -> Result<Vec<u8>> {
    let value = |name: &str| {
        header.lines().skip(1).find_map(|line| {
            let (k, v) = line.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim())
        })
    };
    if let Some(length) = value("content-length")
        && length.parse::<usize>().context("invalid Content-Length")? > MAX_PAC_BYTES
    {
        bail!("PAC response exceeds 8 MiB")
    }
    if value("transfer-encoding").is_some_and(|v| {
        v.split(',')
            .any(|e| e.trim().eq_ignore_ascii_case("chunked"))
    }) {
        let mut body = Vec::new();
        loop {
            let line = read_crlf_line(io).await?;
            let text =
                std::str::from_utf8(&line[..line.len() - 2]).context("invalid chunk size")?;
            let size = usize::from_str_radix(text.split(';').next().unwrap_or("").trim(), 16)
                .context("invalid chunk size")?;
            if size == 0 {
                loop {
                    if read_crlf_line(io).await? == b"\r\n" {
                        break;
                    }
                }
                return Ok(body);
            }
            if body.len().saturating_add(size) > MAX_PAC_BYTES {
                bail!("PAC response exceeds 8 MiB")
            };
            let old = body.len();
            body.resize(old + size, 0);
            io.read_exact(&mut body[old..]).await?;
            let mut crlf = [0u8; 2];
            io.read_exact(&mut crlf).await?;
            if crlf != *b"\r\n" {
                bail!("invalid chunk framing")
            }
        }
    }
    if let Some(length) = value("content-length") {
        let length = length.parse::<usize>().context("invalid Content-Length")?;
        if length > MAX_PAC_BYTES {
            bail!("PAC response exceeds 8 MiB")
        };
        let mut body = vec![0; length];
        io.read_exact(&mut body).await?;
        return Ok(body);
    }
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if body.len().saturating_add(n) > MAX_PAC_BYTES {
            bail!("PAC response exceeds 8 MiB")
        };
        body.extend_from_slice(&chunk[..n])
    }
    Ok(body)
}

/// Download a PAC script directly, following at most nine absolute redirects.
pub async fn fetch_remote_pac(uri: &str) -> Result<String> {
    let requested = uri.to_owned();
    time::timeout(Duration::from_secs(15), async move {
        let mut current = http::Uri::try_from(uri).context("invalid PAC URI")?;
        for redirects in 0..=9 {
            let scheme = current.scheme_str().ok_or_else(|| anyhow!("PAC URI has no scheme"))?;
            if scheme != "http" && scheme != "https" { bail!("unsupported PAC URI scheme {scheme}"); }
            let host = current.host().ok_or_else(|| anyhow!("PAC URI has no host"))?.trim_start_matches('[').trim_end_matches(']').to_owned();
            let port = current.port_u16().unwrap_or(if scheme == "https" { 443 } else { 80 });
            let endpoint = Endpoint { host: host.clone(), port };
            let options = ConnectionOptions::default();
            let stream = tcp(&endpoint, &options, Duration::from_secs(15)).await?;
            let mut io: BoxedIo = Box::new(stream);
            if scheme == "https" { io = secure(io, &host, &options.tls).await?; }
            let path = current.path_and_query().map(|v| v.as_str()).unwrap_or("/");
            let host_header = current.authority().unwrap().as_str();
            let request = format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nAccept: */*\r\n\r\n");
            io.write_all(request.as_bytes()).await?;
            let raw_header=read_http_head(&mut io).await?;
            let header = std::str::from_utf8(&raw_header).context("invalid PAC response headers")?;
            let status = header.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|v| v.parse::<u16>().ok()).ok_or_else(|| anyhow!("invalid PAC response status"))?;
            if matches!(status, 301 | 302 | 307 | 308) {
                if redirects == 9 { bail!("too many PAC redirects"); }
                let location = header.lines().skip(1).find_map(|l| { let (k,v)=l.split_once(':')?; k.eq_ignore_ascii_case("location").then(||v.trim()) }).ok_or_else(|| anyhow!("PAC redirect has no Location"))?;
                let next = http::Uri::try_from(location).context("invalid PAC redirect Location")?;
                validate_pac_redirect(scheme, &next)?;
                current = next;
                continue;
            }
            if status != 200 { bail!("PAC download returned HTTP {status}"); }
            let body=read_pac_body(&mut io,header).await?;
            return String::from_utf8(body).context("PAC response is not UTF-8");
        }
        bail!("too many PAC redirects")
    }).await.context("remote PAC download timed out")?.with_context(||format!("downloading PAC from {requested}"))
}

fn validate_pac_redirect(previous_scheme: &str, next: &http::Uri) -> Result<()> {
    if next.authority().is_none() {
        bail!("PAC redirect Location must have authority");
    }
    match next.scheme_str() {
        Some("http") | Some("https") => {}
        _ => bail!("PAC redirect Location must use HTTP or HTTPS"),
    }
    if previous_scheme == "https" && next.scheme_str() != Some("https") {
        bail!("HTTPS PAC redirect cannot downgrade to HTTP");
    }
    Ok(())
}

#[cfg(test)]
mod pac_redirect_tests {
    use super::*;

    #[test]
    fn https_pac_redirects_cannot_downgrade() {
        let http: http::Uri = "http://pac.example/script.pac".parse().unwrap();
        let https: http::Uri = "https://pac.example/script.pac".parse().unwrap();
        assert!(validate_pac_redirect("https", &http).is_err());
        assert!(validate_pac_redirect("https", &https).is_ok());
        assert!(validate_pac_redirect("http", &https).is_ok());
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ByteCount(pub u64);

/// Bidirectionally relay an opaque stream and return byte counts per direction.
#[derive(Debug)]
pub struct RelayError {
    pub source: std::io::Error,
    pub a_read: u64,
    pub a_written: u64,
    pub b_read: u64,
    pub b_written: u64,
}
impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (a read {}, wrote {}; b read {}, wrote {})",
            self.source, self.a_read, self.a_written, self.b_read, self.b_written
        )
    }
}
impl std::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

pub async fn relay<A, B>(a: A, b: B) -> std::result::Result<(u64, u64), RelayError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut a = Metered::new(a);
    let mut b = Metered::new(b);
    match tokio::io::copy_bidirectional(&mut a, &mut b).await {
        Ok((a_to_b, b_to_a)) => Ok((a_to_b, b_to_a)),
        Err(source) => Err(RelayError {
            source,
            a_read: a.read,
            a_written: a.written,
            b_read: b.read,
            b_written: b.written,
        }),
    }
}

// Adaptors can use this helper to preserve read/write accounting while still
// presenting a normal asynchronous stream.
pub struct Metered<T> {
    inner: T,
    pub read: u64,
    pub written: u64,
}
impl<T> Metered<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            read: 0,
            written: 0,
        }
    }
    pub fn into_inner(self) -> T {
        self.inner
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for Metered<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                self.read += (buf.filled().len() - before) as u64;
                Poll::Ready(Ok(()))
            }
            v => v,
        }
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Metered<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                self.written += n as u64;
                Poll::Ready(Ok(n))
            }
            v => v,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Parse a numeric host as an IP address, useful to callers that need to avoid DNS.
pub fn parse_ip(host: &str) -> Option<IpAddr> {
    host.parse().ok()
}
