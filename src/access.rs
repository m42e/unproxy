//! Completed response-establishment records and compatibility text formatting.
use crate::route::Route;
use chrono::{DateTime, FixedOffset, SecondsFormat};
use http::{Method, StatusCode, Uri, Version};
use std::{fmt, net::SocketAddr, time::Duration};

#[derive(Clone, Debug)]
pub enum AccessOutcome {
    Response {
        status: StatusCode,
        content_length: Option<u64>,
    },
    Error(String),
}
#[derive(Clone, Debug)]
pub struct AccessEntry {
    pub timestamp: DateTime<FixedOffset>,
    pub peer: SocketAddr,
    pub route: Option<Route>,
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub elapsed: Duration,
    pub outcome: AccessOutcome,
    pub user_agent: Option<String>,
}
impl AccessEntry {
    pub fn for_request<B>(
        peer: SocketAddr,
        route: Option<Route>,
        request: &http::Request<B>,
        elapsed: Duration,
        outcome: AccessOutcome,
    ) -> Self {
        Self {
            timestamp: chrono::Local::now().fixed_offset(),
            peer,
            route,
            method: request.method().clone(),
            uri: request.uri().clone(),
            version: request.version(),
            elapsed,
            outcome,
            user_agent: request
                .headers()
                .get(http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        }
    }
    pub fn event(&self) -> String {
        format!("data:{self}\n\n")
    }
}
fn quoted(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}
impl fmt::Display for AccessEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} \"{} {} {:?}\" {:.3}s ",
            self.timestamp.to_rfc3339_opts(SecondsFormat::Secs, false),
            self.peer,
            self.route
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "-".into()),
            self.method,
            self.uri,
            self.version,
            self.elapsed.as_secs_f64()
        )?;
        match &self.outcome {
            AccessOutcome::Response {
                status,
                content_length,
            } => write!(
                f,
                "{} {}b",
                status.as_u16(),
                content_length
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".into())
            )?,
            AccessOutcome::Error(error) => write!(f, "error: \"{}\"", quoted(error))?,
        }
        write!(
            f,
            " \"{}\"",
            self.user_agent
                .as_deref()
                .map(quoted)
                .unwrap_or_else(|| "-".into())
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_without_content_length_formats_as_unknown() {
        let request = http::Request::builder()
            .method(Method::GET)
            .uri("http://example.test/resource")
            .body(())
            .unwrap();
        let entry = AccessEntry::for_request(
            "127.0.0.1:1234".parse().unwrap(),
            None,
            &request,
            Duration::from_millis(12),
            AccessOutcome::Response {
                status: StatusCode::NO_CONTENT,
                content_length: None,
            },
        );

        let formatted = entry.to_string();
        assert!(formatted.contains("GET http://example.test/resource HTTP/1.1"));
        assert!(formatted.contains("204 -b"));
    }

    #[test]
    fn errors_escape_control_characters_and_user_agents() {
        let request = http::Request::builder()
            .method(Method::POST)
            .uri("http://example.test/upload")
            .header(http::header::USER_AGENT, "agent\\name\"quoted")
            .body(())
            .unwrap();
        let entry = AccessEntry::for_request(
            "127.0.0.1:1234".parse().unwrap(),
            Some(Route::Direct),
            &request,
            Duration::from_millis(4),
            AccessOutcome::Error("bad\\request\"\nnext\rline".into()),
        );

        let formatted = entry.to_string();
        assert!(formatted.contains("DIRECT"));
        assert!(formatted.contains("error: \"bad\\\\request\\\"\\nnext\\rline\""));
        assert!(formatted.ends_with("\"agent\\\\name\\\"quoted\""));
        assert!(entry.event().starts_with("data:"));
    }
}
