use unproxy::{
    access::{AccessEntry, AccessOutcome},
    route::Route,
};
use std::time::Duration;
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
