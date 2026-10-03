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
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind).await?;
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
    timeout(Duration::from_millis(1500), async {
        let tls = tls_connector.connect(host, stream).await?;
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
        let response = sender.send_request(request).await?;
        if response.status() != http::StatusCode::OK {
            return Err(anyhow!("DoH response status {}", response.status()));
        }
        let mut body = response.into_body();
        let mut bytes = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            if let Ok(data) = frame.into_data() {
                append_doh_chunk(&mut bytes, &data)?;
            }
        }
        parse_counts(&bytes).context("invalid DoH DNS response")?;
        Ok(bytes)
    })
    .await
    .context("DoH exchange timed out")?
}

fn append_doh_chunk(output: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    if output.len().saturating_add(data.len()) > 65_507 {
        return Err(anyhow!("DoH response exceeds maximum DNS UDP payload"));
    }
    output.extend_from_slice(data);
    Ok(())
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
    serve_until(
        port,
        primary_addr,
        secondary_uri,
        proxy,
        options,
        std::future::pending::<()>(),
    )
    .await
}

async fn serve_until(
    port: u16,
    primary_addr: SocketAddr,
    secondary_uri: http::Uri,
    proxy: crate::route::Route,
    options: crate::net::ConnectionOptions,
    shutdown: impl std::future::Future + Unpin,
) -> Result<()> {
    let socket = UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        port,
    ))
    .await?;
    serve_socket(
        socket,
        primary_addr,
        secondary_uri,
        proxy,
        options,
        shutdown,
    )
    .await
}

async fn serve_socket(
    socket: UdpSocket,
    primary_addr: SocketAddr,
    secondary_uri: http::Uri,
    proxy: crate::route::Route,
    options: crate::net::ConnectionOptions,
    mut shutdown: impl std::future::Future + Unpin,
) -> Result<()> {
    tracing::info!(address=%socket.local_addr()?, "undns listening");
    let s = std::sync::Arc::new(socket);
    let mut buf = vec![0; 65507];
    loop {
        let (n, peer) = tokio::select! {
            received = s.recv_from(&mut buf) => received?,
            _ = &mut shutdown => return Ok(()),
        };
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
    #[test]
    fn doh_body_enforces_udp_payload_size_across_chunks() {
        let mut body = vec![0; 65_506];
        append_doh_chunk(&mut body, &[0]).unwrap();
        assert_eq!(body.len(), 65_507);
        assert!(append_doh_chunk(&mut body, &[0]).is_err());
    }

    #[test]
    fn dns_questions_accept_backward_compression_and_reject_malformed_names() {
        let mut compressed = vec![0u8; 12];
        compressed[5] = 2;
        compressed.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        let name_offset = compressed.len();
        compressed.extend_from_slice(&[0xc0 | ((12 >> 8) as u8), 12]);
        compressed.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(parse_counts(&compressed).unwrap().questions, 2);
        assert_eq!(name_offset, 19);

        for name in [
            vec![0x40],
            vec![0x80],
            vec![0xc0],
            vec![0xc0, 0xff],
            vec![0x03, b'a'],
        ] {
            let mut packet = vec![0u8; 12];
            packet[5] = 1;
            packet.extend_from_slice(&name);
            assert!(parse_counts(&packet).is_err(), "accepted name {name:?}");
        }

        let mut too_many_labels = vec![0u8; 12];
        too_many_labels[5] = 1;
        for _ in 0..128 {
            too_many_labels.extend_from_slice(&[1, b'x']);
        }
        too_many_labels.push(0);
        too_many_labels.extend_from_slice(&[0, 1, 0, 1]);
        assert!(
            parse_counts(&too_many_labels)
                .unwrap_err()
                .to_string()
                .contains("too many DNS labels")
        );
    }

    #[test]
    fn dns_compression_chain_depth_and_resource_record_bounds_are_checked() {
        fn question_chain(pointer_count: usize) -> Vec<u8> {
            let mut packet = vec![0u8; 12];
            let count = u16::try_from(pointer_count + 1).unwrap();
            packet[4..6].copy_from_slice(&count.to_be_bytes());
            packet.extend_from_slice(&[0, 0, 1, 0, 1]);
            let mut previous = 12usize;
            for _ in 0..pointer_count {
                let current = packet.len();
                packet.extend_from_slice(&[0xc0 | ((previous >> 8) as u8), previous as u8]);
                packet.extend_from_slice(&[0, 1, 0, 1]);
                previous = current;
            }
            packet
        }
        assert!(parse_counts(&question_chain(32)).is_ok());
        assert!(
            parse_counts(&question_chain(35))
                .unwrap_err()
                .to_string()
                .contains("too deep")
        );

        for section in [6, 8, 10] {
            let mut packet = vec![0u8; 12];
            packet[section + 1] = 1;
            packet.push(0); // root owner name
            assert!(parse_counts(&packet).is_err()); // truncated fixed RR

            packet.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 1, 0, 1]);
            assert!(parse_counts(&packet).is_err()); // declared RDATA byte is absent

            packet.push(42);
            assert!(parse_counts(&packet).is_ok());
        }

        let mut short_question = vec![0u8; 12];
        short_question[5] = 1;
        short_question.push(0);
        short_question.extend_from_slice(&[0, 1]);
        assert!(parse_counts(&short_question).is_err());
        assert!(counts(&[0; 11]).is_err());
        assert_eq!(
            counts(&[0; 12]).unwrap(),
            DnsCounts {
                questions: 0,
                answers: 0
            }
        );
    }

    #[test]
    fn compressed_dns_name_cannot_expand_past_wire_limit() {
        let mut packet = vec![0u8; 12];
        packet[5] = 2;
        for _ in 0..4 {
            packet.push(63);
            packet.extend(std::iter::repeat_n(b'x', 63));
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]);
        packet.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);

        let error = parse_counts(&packet).unwrap_err().to_string();
        assert!(error.contains("255 bytes"), "{error}");
    }

    #[tokio::test]
    async fn primary_dns_timeout_has_receive_context() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let mut query = vec![0u8; 17];
        query[5] = 1;
        query[12..].copy_from_slice(&[0, 0, 1, 0, 1]);
        let server_task = tokio::spawn(async move {
            let mut buffer = [0u8; 64];
            server.recv_from(&mut buffer).await.unwrap();
        });

        let error = exchange_primary(&query, address).await.unwrap_err();
        assert!(error.to_string().contains("primary DNS receive timeout"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn public_dns_service_binds_ephemerally_and_stops_cleanly() {
        let reserved = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let occupied_port = reserved.local_addr().unwrap().port();
        assert!(
            serve(
                occupied_port,
                "127.0.0.1:53".parse().unwrap(),
                "https://dns.example.test/dns-query".parse().unwrap(),
                crate::route::Route::Direct,
                crate::net::ConnectionOptions::default(),
            )
            .await
            .is_err()
        );

        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve_until(
            0,
            "127.0.0.1:53".parse().unwrap(),
            "https://dns.example.test/dns-query".parse().unwrap(),
            crate::route::Route::Direct,
            crate::net::ConnectionOptions::default(),
            shutdown,
        ));
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[test]
    fn secondary_authority_and_fallback_inputs_cover_uri_edges() {
        assert!(!authority_has_explicit_port("resolver.example"));
        assert!(authority_has_explicit_port(
            "user:secret@resolver.example:bad"
        ));
        assert!(authority_has_explicit_port("[2001:db8::1]:bad"));
        assert!(!authority_has_explicit_port("[2001:db8::1]"));

        for text in [
            "http://resolver.example/dns-query",
            "https:///dns-query",
            "https://user@resolver.example/dns-query",
            "https://resolver.example:bad/dns-query",
            "https://resolver.example:0/dns-query",
            "https://resolver.example:443/dns-query",
        ] {
            if let Ok(uri) = text.parse::<http::Uri>() {
                let valid = text.ends_with(":443/dns-query");
                assert_eq!(validate_secondary_uri(&uri).is_ok(), valid, "{text}");
            }
        }

        assert!(!needs_fallback(&[0; 12]).unwrap());
        let mut unanswered = vec![0u8; 17];
        unanswered[5] = 1;
        assert!(needs_fallback(&unanswered).unwrap());
        unanswered[7] = 1;
        assert!(needs_fallback(&unanswered).is_err());
    }

    #[tokio::test]
    async fn udp_service_drops_bad_upstream_reply_then_serves_the_next_query() {
        let primary = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let primary_address = primary.local_addr().unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_address = server.local_addr().unwrap();
        let (stop, shutdown) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(serve_socket(
            server,
            primary_address,
            "https://dns.example.test/dns-query".parse().unwrap(),
            crate::route::Route::Http(crate::route::Endpoint {
                host: "proxy.example.test".into(),
                port: 8080,
            }),
            crate::net::ConnectionOptions::default(),
            shutdown,
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&[1, 2], server_address).await.unwrap();
        let mut upstream = [0u8; 128];
        let (size, peer) =
            tokio::time::timeout(Duration::from_secs(2), primary.recv_from(&mut upstream))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&upstream[..size], &[1, 2]);
        primary.send_to(&[0], peer).await.unwrap();

        let mut response = [0u8; 128];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut response))
                .await
                .is_err()
        );

        let query = test_query(0x1234);
        client.send_to(&query, server_address).await.unwrap();
        let (size, peer) =
            tokio::time::timeout(Duration::from_secs(2), primary.recv_from(&mut upstream))
                .await
                .unwrap()
                .unwrap();
        let mut answer = upstream[..size].to_vec();
        answer[6..8].copy_from_slice(&1u16.to_be_bytes());
        answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 7]);
        primary.send_to(&answer, peer).await.unwrap();
        let (size, _) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&response[..size], answer);
        assert_eq!(parse_counts(&response[..size]).unwrap().answers, 1);

        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    fn test_query(id: u16) -> Vec<u8> {
        let mut query = vec![0; 12];
        query[..2].copy_from_slice(&id.to_be_bytes());
        query[5] = 1;
        query.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        query
    }
}
