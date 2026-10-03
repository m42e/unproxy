use std::time::Duration;
use unproxy::{
    access::{AccessEntry, AccessOutcome},
    route::{Endpoint, Route},
};
#[test]
fn access_records_use_real_seconds_and_omit_size_for_errors() {
    let request = http::Request::get("http://example.test/a?q=1")
        .header("user-agent", "fixture")
        .body(())
        .unwrap();
    let mut entry = AccessEntry::for_request(
        "127.0.0.1:1234".parse().unwrap(),
        Some(Route::Direct),
        &request,
        Duration::from_millis(1234),
        AccessOutcome::Response {
            status: http::StatusCode::OK,
            content_length: Some(42),
        },
    );
    entry.timestamp = chrono::DateTime::parse_from_rfc3339("2026-10-02T12:34:56+02:00").unwrap();
    assert_eq!(
        entry.to_string(),
        "2026-10-02T12:34:56+02:00 127.0.0.1:1234 DIRECT \"GET http://example.test/a?q=1 HTTP/1.1\" 1.234s 200 42b \"fixture\""
    );
    entry.outcome = AccessOutcome::Error("refused\nby upstream".into());
    entry.user_agent = None;
    assert!(
        entry
            .to_string()
            .ends_with("1.234s error: \"refused\\nby upstream\" \"-\"")
    );
    assert!(entry.event().ends_with("\n\n"));
}

#[test]
fn successful_proxy_access_records_show_endpoint_size_and_agent() {
    let request = http::Request::get("http://example.test/resource")
        .header("user-agent", "fixture-agent")
        .body(())
        .unwrap();
    let mut entry = AccessEntry::for_request(
        "127.0.0.1:4567".parse().unwrap(),
        Some(Route::Http(Endpoint {
            host: "proxy.example".into(),
            port: 8080,
        })),
        &request,
        Duration::from_millis(12),
        AccessOutcome::Response {
            status: http::StatusCode::OK,
            content_length: Some(4096),
        },
    );
    entry.timestamp = chrono::DateTime::parse_from_rfc3339("2026-10-02T12:34:56+02:00").unwrap();
    let output = entry.to_string();
    assert!(output.contains("HTTP proxy.example:8080"));
    assert!(output.contains("GET http://example.test/resource HTTP/1.1"));
    assert!(output.contains("200 4096b \"fixture-agent\""));
    assert!(!output.contains("\"-\""));
}

#[test]
fn successful_access_records_mark_missing_size_and_agent() {
    let request = http::Request::get("http://example.test/resource")
        .body(())
        .unwrap();
    let entry = AccessEntry::for_request(
        "127.0.0.1:4567".parse().unwrap(),
        Some(Route::Direct),
        &request,
        Duration::ZERO,
        AccessOutcome::Response {
            status: http::StatusCode::OK,
            content_length: None,
        },
    );
    assert!(entry.to_string().contains("200 -b \"-\""));
}

#[test]
fn failed_access_records_quote_untrusted_error_text_and_missing_agent() {
    let request = http::Request::get("http://example.test/resource")
        .body(())
        .unwrap();
    let entry = AccessEntry::for_request(
        "127.0.0.1:9876".parse().unwrap(),
        None,
        &request,
        Duration::from_millis(5),
        AccessOutcome::Error("bad \"header\"\\path\r\nnext".into()),
    );
    let text = entry.to_string();
    assert!(text.contains("- \"GET http://example.test/resource HTTP/1.1\""));
    assert!(text.contains("error: \"bad \\\"header\\\"\\\\path\\r\\nnext\" \"-\""));
}
