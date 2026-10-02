use unproxy::dns::{exchange, exchange_primary, needs_fallback, parse_counts};
use unproxy::{net::ConnectionOptions, route::Route};
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;

#[test]
fn dns_wire_parser_checks_all_declared_sections() {
    let mut packet = vec![0u8; 17];
    assert_eq!(parse_counts(&packet).unwrap().answers, 0);
    packet[5] = 1;
    assert!(needs_fallback(&packet).unwrap());
    packet[5] = 0;
    assert!(!needs_fallback(&packet).unwrap());
    let mut truncated = vec![0u8; 12];
    truncated[5] = 1;
    assert!(parse_counts(&truncated).is_err());
    packet[11] = 1; // one additional record with no body
    assert!(parse_counts(&packet).is_err());
}

#[test]
fn dns_parser_rejects_bad_compression_and_trailing_sections() {
    let mut packet = vec![0u8; 18];
    packet[5] = 1;
    packet[12] = 0xc0;
    packet[13] = 0xff;
    assert!(parse_counts(&packet).is_err());

    let mut cyclic = vec![0u8; 18];
    cyclic[5] = 1;
    cyclic[12] = 0xc0;
    cyclic[13] = 12;
    assert!(parse_counts(&cyclic).is_err());
}

#[tokio::test]
async fn primary_exchange_uses_a_fresh_connected_udp_socket() {
    // This exchange validates primary wire processing, so use a complete empty DNS header.
    let responder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = responder.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0; 64];
        let (_, peer) = responder.recv_from(&mut buf).await.unwrap();
        let response = [0u8; 12];
        responder.send_to(&response, peer).await.unwrap();
    });
    let response = exchange_primary(&[0u8; 12], addr).await.unwrap();
    assert_eq!(response, vec![0; 12]);
    task.await.unwrap();
    let _ = addr;
}

#[tokio::test]
async fn exchange_returns_primary_without_fallback_when_it_has_answers() {
    let responder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = responder.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut query = [0u8; 512];
        let (_, peer) = responder.recv_from(&mut query).await.unwrap();
        // Valid response with one root-name A record (empty answer body is invalid, so use a
        // complete question and answer RR).
        let mut response = vec![0u8; 12];
        response[5] = 1;
        response[7] = 1;
        response.extend_from_slice(&[0, 0, 1, 0, 1]);
        response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 127, 0, 0, 1]);
        responder.send_to(&response, peer).await.unwrap();
    });
    let uri: http::Uri = "https://127.0.0.1/dns-query".parse().unwrap();
    let response = exchange(
        &[0; 12],
        addr,
        &uri,
        &Route::Direct,
        &ConnectionOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(parse_counts(&response).unwrap().answers, 1);
    task.await.unwrap();
}
