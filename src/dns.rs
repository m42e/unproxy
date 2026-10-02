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
fn skip_name(b: &[u8], start: usize) -> Result<usize> {
    fn validate(
        b: &[u8],
        mut p: usize,
        seen: &mut std::collections::HashSet<usize>,
        depth: u8,
    ) -> Result<()> {
        if depth > 32 {
            return Err(anyhow!("DNS compression chain too deep"));
        }
        let mut wire_len = 0usize;
        loop {
            need(b, p, 1)?;
            let n = b[p];
            if n & 0xc0 == 0xc0 {
                need(b, p, 2)?;
                let off = ((n as usize & 0x3f) << 8) | b[p + 1] as usize;
                if off >= p {
                    return Err(anyhow!("invalid DNS compression pointer"));
                }
                if !seen.insert(off) {
                    return Err(anyhow!("DNS compression pointer loop"));
                }
                validate(b, off, seen, depth + 1)?;
                return Ok(());
            }
            if n & 0xc0 != 0 {
                return Err(anyhow!("invalid DNS label tag"));
            }
            p += 1;
            if n == 0 {
                return Ok(());
            }
            if n > 63 {
                return Err(anyhow!("invalid DNS label length"));
            }
            wire_len += n as usize + 1;
            if wire_len > 255 {
                return Err(anyhow!("DNS name exceeds 255 bytes"));
            }
            need(b, p, n as usize)?;
            p += n as usize;
        }
    }
    let mut p = start;
    let mut steps = 0;
    loop {
        need(b, p, 1)?;
        let n = b[p];
        if n & 0xc0 == 0xc0 {
            need(b, p, 2)?;
            let off = ((n as usize & 0x3f) << 8) | b[p + 1] as usize;
            if off >= p {
                return Err(anyhow!("invalid DNS compression pointer"));
            }
            let mut seen = std::collections::HashSet::new();
            seen.insert(off);
            validate(b, off, &mut seen, 0)?;
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
pub async fn exchange_primary(query: &[u8], server: SocketAddr) -> Result<Vec<u8>> {
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
    host_header: &str,
    path: &str,
    query: &[u8],
    tls_connector: &tokio_native_tls::TlsConnector,
) -> Result<Vec<u8>> {
    use bytes::Bytes;
    use http::{Request, header};
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::TokioIo;
    let tls = timeout(
        Duration::from_millis(1500),
        tls_connector.connect(host, stream),
    )
    .await
    .context("DoH TLS timeout")??;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .context("DoH HTTP handshake")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::post(path)
        .header(header::HOST, host_header)
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

/// Tell whether an authority spells an explicit port, including malformed ports.
pub fn authority_has_explicit_port(authority: &str) -> bool {
    let a = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(rest) = a.strip_prefix('[') {
        return rest
            .find(']')
            .is_some_and(|i| rest[i + 1..].starts_with(':'));
    }
    a.rsplit_once(':').is_some()
}

/// Validate an HTTPS DNS endpoint URI and all explicitly supplied ports.
pub fn validate_secondary_uri(uri: &http::Uri) -> Result<()> {
    if uri.scheme_str() != Some("https") {
        return Err(anyhow!("secondary DNS URI must use HTTPS"));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow!("secondary DNS URI requires a host"))?;
    if authority.host().is_empty() || authority.as_str().contains('@') {
        return Err(anyhow!(
            "secondary DNS URI requires a host and cannot contain user information"
        ));
    }
    if authority_has_explicit_port(authority.as_str()) && authority.port_u16().is_none() {
        return Err(anyhow!("invalid secondary DNS port"));
    }
    if authority.port_u16() == Some(0) {
        return Err(anyhow!("secondary DNS port must be nonzero"));
    }
    crate::route::Destination::from_uri(uri)?;
    Ok(())
}

async fn secondary(
    query: &[u8],
    uri: &http::Uri,
    proxy: &crate::route::Route,
    options: &crate::net::ConnectionOptions,
) -> Result<Vec<u8>> {
    validate_secondary_uri(uri)?;
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
    let host_header = uri
        .authority()
        .ok_or_else(|| anyhow!("DoH URI authority missing"))?
        .as_str()
        .to_owned();
    doh_on_stream(
        stream,
        &dest.endpoint.host,
        &host_header,
        if dest.path.is_empty() {
            "/"
        } else {
            &dest.path
        },
        query,
        &options.tls,
    )
    .await
}

/// Apply the specified primary response fallback test, after validating all declared sections.
pub fn needs_fallback(response: &[u8]) -> Result<bool> {
    let c = parse_counts(response)?;
    Ok(c.questions > 0 && c.answers == 0)
}

/// Exchange one wire-format query through the primary resolver and apply conditional DoH fallback.
pub async fn exchange(
    query: &[u8],
    primary_addr: SocketAddr,
    secondary_uri: &http::Uri,
    proxy: &crate::route::Route,
    options: &crate::net::ConnectionOptions,
) -> Result<Vec<u8>> {
    let answer = exchange_primary(query, primary_addr).await?;
    if needs_fallback(&answer)? {
        secondary(query, secondary_uri, proxy, options).await
    } else {
        Ok(answer)
    }
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
            let answer =
                async { exchange(&q, primary_addr, &secondary_uri, &proxy, &options).await }.await;
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
        let mut b = vec![0; 17];
        b[5] = 1;
        assert_eq!(parse_counts(&b).unwrap().questions, 1);
        b.truncate(12);
        assert!(parse_counts(&b).is_err());
        assert!(parse_counts(&[]).is_err())
    }
}
