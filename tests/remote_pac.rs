use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use unproxy::net::fetch_remote_pac;

const LIMIT: usize = 8 * 1024 * 1024;
const TEST_DEADLINE: Duration = Duration::from_secs(4);

async fn request_head(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    loop {
        let mut b = [0u8; 1];
        if stream.read_exact(&mut b).await.is_err() {
            break;
        }
        bytes.push(b[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break;
        }
        assert!(
            bytes.len() < 64 * 1024,
            "request headers unexpectedly large"
        );
    }
    String::from_utf8(bytes).unwrap()
}

async fn one_shot(response: Vec<u8>) -> (SocketAddr, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = timeout(TEST_DEADLINE, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let head = request_head(&mut stream).await;
        let _ = stream.write_all(&response).await;
        head
    });
    (addr, task)
}

fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {status}\r\n{headers}\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

async fn fetch(uri: String) -> anyhow::Result<String> {
    timeout(TEST_DEADLINE, fetch_remote_pac(&uri))
        .await
        .expect("PAC fetch exceeded test deadline")
}

async fn fetch_error(uri: String) -> String {
    let original = uri.clone();
    let err = fetch(uri).await.expect_err("download should fail");
    let chain = format!("{err:#}");
    assert!(
        chain.contains(&original),
        "requested URI missing from error: {chain}"
    );
    chain
}

#[tokio::test]
async fn fetches_utf8_pac_with_get_and_requested_target() {
    let body = b"function FindProxyForURL";
    let (addr, task) = one_shot(response(
        "200 OK",
        &format!("Content-Length: {}\r\nConnection: close\r\n", body.len()),
        body,
    ))
    .await;
    let uri = format!("http://{addr}/policy.pac?rev=3");
    assert_eq!(fetch(uri).await.unwrap(), "function FindProxyForURL");
    let request = task.await.unwrap().to_ascii_lowercase();
    assert!(request.starts_with("get /policy.pac?rev=3 http/1.1\r\n"));
    assert!(request.contains(&format!("host: {addr}\r\n").to_ascii_lowercase()));
    assert!(request.contains("connection: close\r\n"));
}

#[tokio::test]
async fn decodes_chunked_response_without_content_length() {
    let body = b"function FindProxyForURL(){return 'DIRECT';}";
    let mut chunks = Vec::new();
    chunks.extend_from_slice(b"a\r\nfunction F\r\n");
    chunks.extend_from_slice(format!("{:x}\r\n", body.len() - 10).as_bytes());
    chunks.extend_from_slice(&body[10..]);
    chunks.extend_from_slice(b"\r\n0\r\n\r\n");
    let (addr, task) = one_shot(response(
        "200 OK",
        "Transfer-Encoding: chunked\r\nConnection: close\r\n",
        &chunks,
    ))
    .await;
    assert_eq!(
        fetch(format!("http://{addr}/chunks")).await.unwrap(),
        std::str::from_utf8(body).unwrap()
    );
    task.await.unwrap();
}

#[tokio::test]
async fn every_supported_absolute_redirect_status_is_followed() {
    for status in [
        "301 Moved Permanently",
        "302 Found",
        "307 Temporary Redirect",
        "308 Permanent Redirect",
    ] {
        let (destination, final_task) = one_shot(response(
            "200 OK",
            "Content-Length: 2\r\nConnection: close\r\n",
            b"ok",
        ))
        .await;
        let location = format!("http://{destination}/final");
        let (source, redirect_task) = one_shot(response(
            status,
            &format!("Location: {location}\r\nConnection: close\r\n"),
            b"",
        ))
        .await;
        assert_eq!(
            fetch(format!("http://{source}/start")).await.unwrap(),
            "ok",
            "{status}"
        );
        assert!(redirect_task.await.unwrap().starts_with("GET /start "));
        assert!(final_task.await.unwrap().starts_with("GET /final "));
    }
}

async fn redirect_chain(redirect_count: usize, succeed: bool) -> (String, JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let requests = if succeed {
            redirect_count + 1
        } else {
            redirect_count
        };
        for index in 0..requests {
            let (mut stream, _) = timeout(TEST_DEADLINE, listener.accept())
                .await
                .unwrap()
                .unwrap();
            let _ = request_head(&mut stream).await;
            if succeed && index == redirect_count {
                let _ = stream
                    .write_all(&response(
                        "200 OK",
                        "Content-Length: 2\r\nConnection: close\r\n",
                        b"ok",
                    ))
                    .await;
            } else {
                let next = format!("http://{addr}/redirect/{}", index + 1);
                let reply = response(
                    "302 Found",
                    &format!("Location: {next}\r\nConnection: close\r\n"),
                    b"",
                );
                let _ = stream.write_all(&reply).await;
            }
        }
        requests
    });
    (format!("http://{addr}/redirect/0"), task)
}

#[tokio::test]
async fn follows_nine_redirects_but_rejects_the_tenth() {
    let (uri, task) = redirect_chain(9, true).await;
    assert_eq!(fetch(uri).await.unwrap(), "ok");
    assert_eq!(task.await.unwrap(), 10);

    let (uri, task) = redirect_chain(10, false).await;
    let error = fetch_error(uri).await;
    assert!(error.contains("too many PAC redirects"), "{error}");
    assert_eq!(task.await.unwrap(), 10);
}

#[tokio::test]
async fn redirect_location_must_be_absolute_and_have_authority() {
    for location in [
        Some("/relative"),
        Some("http:/missing-authority"),
        Some("http://[broken"),
        None,
    ] {
        let headers = location
            .map(|v| format!("Location: {v}\r\nConnection: close\r\n"))
            .unwrap_or_else(|| "Connection: close\r\n".into());
        let (addr, task) = one_shot(response("301 Moved Permanently", &headers, b"")).await;
        let error = fetch_error(format!("http://{addr}/original")).await;
        assert!(error.contains("Location"), "{error}");
        task.await.unwrap();
    }
}

#[tokio::test]
async fn only_http_200_is_accepted_and_errors_keep_causes() {
    for (status, expected) in [
        ("303 See Other", "HTTP 303"),
        ("404 Not Found", "HTTP 404"),
        ("407 Proxy Authentication Required", "HTTP 407"),
    ] {
        let (addr, task) = one_shot(response(
            status,
            "Content-Length: 0\r\nConnection: close\r\n",
            b"",
        ))
        .await;
        let error = fetch_error(format!("http://{addr}/status")).await;
        assert!(error.contains(expected), "{error}");
        task.await.unwrap();
    }
    let (addr, task) = one_shot(response(
        "200 OK",
        "Content-Length: 2\r\nConnection: close\r\n",
        &[0xff, 0xfe],
    ))
    .await;
    let error = fetch_error(format!("http://{addr}/utf8")).await;
    assert!(error.contains("UTF-8"), "{error}");
    task.await.unwrap();
}

#[tokio::test]
async fn rejects_declared_and_actual_bodies_over_eight_mib() {
    let (addr, task) = one_shot(response(
        "200 OK",
        &format!("Content-Length: {}\r\nConnection: close\r\n", LIMIT + 1),
        b"",
    ))
    .await;
    let error = fetch_error(format!("http://{addr}/declared-large")).await;
    assert!(error.contains("8 MiB"), "{error}");
    task.await.unwrap();

    let mut no_length = response("200 OK", "Connection: close\r\n", &[]);
    no_length.resize(no_length.len() + LIMIT + 1, b'x');
    let (addr, task) = one_shot(no_length).await;
    let error = fetch_error(format!("http://{addr}/actual-large")).await;
    assert!(error.contains("8 MiB"), "{error}");
    task.await.unwrap();

    // Each chunk is within the limit; the aggregate crosses it by one byte.
    let mut chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
    for (size, byte) in [(LIMIT / 2, b'a'), (LIMIT / 2, b'b'), (1, b'c')] {
        chunked.extend_from_slice(format!("{size:x}\r\n").as_bytes());
        chunked.resize(chunked.len() + size, byte);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let (addr, task) = one_shot(chunked).await;
    let error = fetch_error(format!("http://{addr}/chunked-large")).await;
    assert!(error.contains("8 MiB"), "{error}");
    task.await.unwrap();
}

#[tokio::test]
async fn accepts_a_body_at_the_exact_eight_mib_limit() {
    let body = vec![b'x'; LIMIT];
    let (addr, task) = one_shot(response(
        "200 OK",
        &format!("Content-Length: {LIMIT}\r\nConnection: close\r\n"),
        &body,
    ))
    .await;
    let result = fetch(format!("http://{addr}/limit")).await.unwrap();
    assert_eq!(result.len(), LIMIT);
    task.await.unwrap();
}

#[tokio::test]
async fn rejects_malformed_and_truncated_http_responses() {
    for raw in [
        b"not an HTTP response\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxX\r\n0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nab".to_vec(),
    ] {
        let (addr, task) = one_shot(raw).await;
        let error = fetch_error(format!("http://{addr}/bad-response")).await;
        assert!(!error.is_empty());
        task.await.unwrap();
    }
}

#[tokio::test]
async fn https_fetch_uses_default_certificate_verification() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let identity = native_tls::Identity::from_pkcs8(
        include_bytes!("fixtures/localhost.pem"),
        include_bytes!("fixtures/localhost.key"),
    )
    .unwrap();
    let acceptor: tokio_native_tls::TlsAcceptor =
        native_tls::TlsAcceptor::new(identity).unwrap().into();
    let server = tokio::spawn(async move {
        let (stream, _) = timeout(TEST_DEADLINE, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let _ = timeout(TEST_DEADLINE, acceptor.accept(stream)).await;
    });
    let uri = format!("https://{address}/policy.pac");
    let error = fetch_error(uri).await;
    assert!(error.to_ascii_lowercase().contains("tls"), "{error}");
    server.await.unwrap();
}
