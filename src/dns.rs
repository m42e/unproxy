//! DNS wire parsing, primary resolver exchange and loopback UDP service.
use anyhow::{Context, Result, anyhow};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsCounts {
    pub questions: u16,
    pub answers: u16,
}
/// Read DNS header counts after checking the full fixed header is present.
pub fn counts(packet: &[u8]) -> Result<DnsCounts> {
    if packet.len() < 12 {
        return Err(anyhow!("DNS packet shorter than header"));
    }
    Ok(DnsCounts {
        questions: u16::from_be_bytes([packet[4], packet[5]]),
        answers: u16::from_be_bytes([packet[6], packet[7]]),
    })
}
/// Validate the declared question and answer sections, including compressed names and RR bounds.
pub fn parse_counts(packet: &[u8]) -> Result<DnsCounts> {
    let c = counts(packet)?;
    let mut p = 12;
    for _ in 0..c.questions {
        p = skip_name(packet, p)?;
        need(packet, p, 4)?;
        p += 4
    }
    for count in [
        c.answers,
        u16::from_be_bytes([packet[8], packet[9]]),
        u16::from_be_bytes([packet[10], packet[11]]),
    ] {
        for _ in 0..count {
            p = skip_name(packet, p)?;
            need(packet, p, 10)?;
            let n = u16::from_be_bytes([packet[p + 8], packet[p + 9]]) as usize;
            p += 10;
            need(packet, p, n)?;
            p += n;
        }
    }
    Ok(c)
}
fn need(b: &[u8], p: usize, n: usize) -> Result<()> {
    if p.checked_add(n).is_none_or(|e| e > b.len()) {
        Err(anyhow!("truncated DNS packet"))
    } else {
        Ok(())
    }
}
fn skip_name(b: &[u8], mut p: usize) -> Result<usize> {
    let mut steps = 0;
    loop {
        need(b, p, 1)?;
        let n = b[p];
        if n & 0xc0 == 0xc0 {
            need(b, p, 2)?;
            let off = ((n as usize & 0x3f) << 8) | b[p + 1] as usize;
            if off >= b.len() {
                return Err(anyhow!("DNS compression pointer out of bounds"));
            }
            return Ok(p + 2);
        }
        if n & 0xc0 != 0 {
            return Err(anyhow!("invalid DNS label tag"));
        }
        p += 1;
        if n == 0 {
            return Ok(p);
        }
        if n > 63 {
            return Err(anyhow!("invalid DNS label length"));
        }
        need(b, p, n as usize)?;
        p += n as usize;
        steps += 1;
        if steps > 127 {
            return Err(anyhow!("too many DNS labels"));
        }
    }
}
async fn primary(query: &[u8], server: SocketAddr) -> Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(server).await?;
    let n = timeout(Duration::from_millis(500), sock.send(query))
        .await
        .context("primary DNS send timeout")??;
    if n != query.len() {
        tracing::warn!(sent = n, expected = query.len(), "short primary DNS send")
    }
    let mut b = vec![0; 65507];
    let n = timeout(Duration::from_millis(500), sock.recv(&mut b))
        .await
        .context("primary DNS receive timeout")??;
    b.truncate(n);
    parse_counts(&b).context("invalid primary DNS response")?;
    Ok(b)
}
/// HTTP-over-TLS DNS POST over a stream already connected to the secondary endpoint.
pub async fn doh_on_stream(
    stream: crate::net::BoxedIo,
    host: &str,
    path: &str,
    query: &[u8],
) -> Result<Vec<u8>> {
    use bytes::Bytes;
    use http::{Request, header};
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::TokioIo;
    let cx = tokio_native_tls::TlsConnector::from(native_tls::TlsConnector::new()?);
    let tls = timeout(Duration::from_millis(1500), cx.connect(host, stream))
        .await
        .context("DoH TLS timeout")??;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .context("DoH HTTP handshake")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let uri: http::Uri = format!("https://{host}{path}").parse()?;
    let request = Request::post(uri)
        .header(header::HOST, host)
        .header(header::ACCEPT, "application/dns-message")
        .header(header::CONTENT_TYPE, "application/dns-message")
        .body(Full::new(Bytes::copy_from_slice(query)))?;
    let response = timeout(Duration::from_millis(1500), sender.send_request(request))
        .await
        .context("DoH exchange timeout")??;
    if response.status() != http::StatusCode::OK {
        return Err(anyhow!("DoH response status {}", response.status()));
    }
    Ok(response.into_body().collect().await?.to_bytes().to_vec())
}

async fn secondary(
    query: &[u8],
    uri: &http::Uri,
    proxy: &crate::route::Route,
    options: &crate::net::ConnectionOptions,
) -> Result<Vec<u8>> {
    if uri.scheme_str() != Some("https") {
        return Err(anyhow!("secondary DNS URI must use HTTPS"));
    }
    let dest = crate::route::Destination::from_uri(uri)?;
    let stream = timeout(
        Duration::from_millis(1500),
        crate::net::connect(
            proxy,
            &dest.endpoint,
            true,
            options,
            Duration::from_millis(1500),
        ),
    )
    .await
    .context("DoH proxy tunnel timeout")??;
    doh_on_stream(
        stream,
        &dest.endpoint.host,
        if dest.path.is_empty() {
            "/"
        } else {
            &dest.path
        },
        query,
    )
    .await
}

/// Start the loopback DNS listener with primary-to-DoH fallback.
pub async fn serve(
    port: u16,
    primary_addr: SocketAddr,
    secondary_uri: http::Uri,
    proxy: crate::route::Route,
    options: crate::net::ConnectionOptions,
) -> Result<()> {
    let socket = UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        port,
    ))
    .await?;
    tracing::info!(address=%socket.local_addr()?, "dnsdetox listening");
    let s = std::sync::Arc::new(socket);
    let mut buf = vec![0; 65507];
    loop {
        let (n, peer) = s.recv_from(&mut buf).await?;
        let q = buf[..n].to_vec();
        let socket = s.clone();
        let secondary_uri = secondary_uri.clone();
        let proxy = proxy.clone();
        let options = options.clone();
        tokio::spawn(async move {
            let answer = async {
                let primary = primary(&q, primary_addr).await?;
                let c = parse_counts(&primary)?;
                if c.questions > 0 && c.answers == 0 {
                    secondary(&q, &secondary_uri, &proxy, &options).await
                } else {
                    Ok(primary)
                }
            }
            .await;
            match answer {
                Ok(ans) => {
                    if let Err(e) = socket.send_to(&ans, peer).await {
                        tracing::warn!(%e,"DNS reply failed")
                    }
                }
                Err(e) => tracing::warn!(%e,"DNS query failed"),
            }
        });
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_counts() {
        let mut b = vec![0; 12];
        b[5] = 1;
        assert_eq!(parse_counts(&b).unwrap().questions, 1);
        b.truncate(12);
        assert!(parse_counts(&b).is_err());
        assert!(parse_counts(&[]).is_err())
    }
}
