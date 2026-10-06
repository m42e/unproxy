//! Fast parser and matcher for hosts-format ad blocking lists (including Pi-hole lists).
use anyhow::{Context, Result, bail};
use std::{collections::HashSet, net::SocketAddr, path::Path, sync::Arc};

const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct FilterList(Arc<HashSet<String>>);

impl FilterList {
    pub fn parse(text: &str) -> Self {
        let mut domains = HashSet::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_ascii_whitespace();
            let first = fields.next().unwrap();
            // Hosts files map an IP address to one or more names. Plain domain
            // lines are also accepted, as are common adblock URL rules.
            if first.parse::<std::net::IpAddr>().is_ok() {
                for domain in fields {
                    insert_domain(&mut domains, domain);
                }
            } else if !first.starts_with("||") && !first.starts_with('!') && !first.contains('/') {
                insert_domain(&mut domains, first);
            } else if let Some(domain) = first
                .strip_prefix("||")
                .and_then(|s| s.split(['^', '/', '*']).next())
            {
                insert_domain(&mut domains, domain);
            }
        }
        Self(Arc::new(domains))
    }

    pub fn contains(&self, host: &str) -> bool {
        let host = host
            .trim_end_matches('.')
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        let mut candidate = host.as_str();
        loop {
            if self.0.contains(candidate) {
                return true;
            }
            match candidate.find('.') {
                Some(i) => candidate = &candidate[i + 1..],
                None => return false,
            }
        }
    }

    pub fn domain_count(&self) -> usize {
        self.0.len()
    }

    pub async fn load(sources: &[String]) -> Result<Self> {
        let mut joined = String::new();
        for source in sources {
            let text = Self::read_source(source, None).await?;
            if text.len() > MAX_LIST_BYTES
                || joined.len().saturating_add(text.len()) > MAX_LIST_BYTES
            {
                bail!("filter lists exceed 64 MiB");
            }
            joined.push_str(&text);
            joined.push('\n');
        }
        Ok(Self::parse(&joined))
    }

    pub async fn load_best_effort(sources: &[String]) -> Self {
        Self::load_best_effort_with_proxy(sources, None).await.0
    }

    pub(crate) async fn load_best_effort_with_status(sources: &[String]) -> (Self, bool) {
        Self::load_best_effort_with_proxy(sources, None).await
    }

    pub(crate) async fn load_best_effort_via_proxy(
        sources: &[String],
        proxy: SocketAddr,
    ) -> (Self, bool) {
        Self::load_best_effort_with_proxy(sources, Some(proxy)).await
    }

    async fn load_best_effort_with_proxy(
        sources: &[String],
        proxy: Option<SocketAddr>,
    ) -> (Self, bool) {
        let mut joined = String::new();
        let mut complete = true;
        for source in sources {
            let text = match Self::read_source(source, proxy).await {
                Ok(text) => text,
                Err(error) => {
                    complete = false;
                    tracing::warn!(
                        source = %source,
                        error = %format!("{error:#}"),
                        "filter list unavailable; skipping it for this attempt"
                    );
                    continue;
                }
            };
            if joined.len().saturating_add(text.len()) > MAX_LIST_BYTES {
                complete = false;
                tracing::warn!(
                    source = %source,
                    "filter list skipped because configured lists exceed 64 MiB"
                );
                continue;
            }
            joined.push_str(&text);
            joined.push('\n');
        }
        (Self::parse(&joined), complete)
    }

    pub(crate) fn union(&self, other: &Self) -> Self {
        let mut domains = (*self.0).clone();
        domains.extend(other.0.iter().cloned());
        Self(Arc::new(domains))
    }

    async fn read_source(source: &str, proxy: Option<SocketAddr>) -> Result<String> {
        let text = if source.starts_with("http://") || source.starts_with("https://") {
            let result = match proxy {
                Some(proxy) => crate::net::fetch_remote_text_via_proxy(source, proxy).await,
                None => crate::net::fetch_remote_text(source).await,
            };
            result.with_context(|| format!("downloading filter list from {source}"))?
        } else {
            tokio::fs::read_to_string(Path::new(source))
                .await
                .with_context(|| format!("reading filter list {source}"))?
        };
        if text.len() > MAX_LIST_BYTES {
            bail!("filter list exceeds 64 MiB");
        }
        Ok(text)
    }
}

fn insert_domain(set: &mut HashSet<String>, raw: &str) {
    let domain = raw
        .trim_matches('.')
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if !domain.is_empty() && domain.len() <= 253 && domain.contains('.') && !domain.contains(' ') {
        set.insert(domain);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_hosts_and_pihole_domain_lists_and_matches_subdomains() {
        let list = FilterList::parse(
            "127.0.0.1 ads.example.test tracker.example.test # comment\n0.0.0.0 metrics.example.test\n||banner.test^\n! comment\n",
        );
        assert!(list.contains("ads.example.test"));
        assert!(list.contains("sub.ads.example.test"));
        assert!(list.contains("metrics.example.test"));
        assert!(list.contains("banner.test"));
        assert!(!list.contains("example.test"));
        assert!(!list.contains("safe.test"));
    }

    #[test]
    fn matches_entries_in_a_hundred_thousand_domain_list() {
        let text = (0..100_000)
            .map(|index| format!("0.0.0.0 blocked-{index}.example.test\n"))
            .collect::<String>();
        let list = FilterList::parse(&text);
        assert_eq!(list.0.len(), 100_000);
        assert!(list.contains("BLOCKED-99999.EXAMPLE.TEST."));
        assert!(list.contains("sub.blocked-99999.example.test"));
        assert!(!list.contains("safe.example.test"));
    }

    #[tokio::test]
    async fn delayed_retry_uses_pac_route_and_updates_the_live_filter() {
        use crate::{net::ConnectionOptions, pac::Policy, proxy::ContextBuilder};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, TcpStream},
        };

        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = upstream.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let count = stream.read(&mut chunk).await.unwrap();
                        if count == 0 {
                            return;
                        }
                        request.extend_from_slice(&chunk[..count]);
                    }
                    let body = if request.windows(9).any(|window| window == b"hosts.txt") {
                        "blocked.example.test\n"
                    } else {
                        ""
                    };
                    stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                            .as_bytes(),
                        )
                        .await
                        .unwrap();
                });
            }
        });

        let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unavailable_addr = unavailable.local_addr().unwrap();
        drop(unavailable);
        let sources = vec![format!("http://{unavailable_addr}/hosts.txt")];
        let (initial, complete) = FilterList::load_best_effort_with_status(&sources).await;
        assert!(!complete);

        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        drop(proxy);
        let policy = Policy::new(Some(format!(
            "function FindProxyForURL() {{ return 'PROXY {upstream_addr}'; }}"
        )))
        .unwrap();
        let context = ContextBuilder::new(Arc::new(policy), ConnectionOptions::default())
            .listen(proxy_addr)
            .filter_list(initial)
            .bind()
            .await
            .unwrap();
        context.retry_filter_lists_after(sources, std::time::Duration::from_millis(5));

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let mut client = TcpStream::connect(proxy_addr).await.unwrap();
            client
                .write_all(
                    b"GET http://blocked.example.test/check HTTP/1.1\r\nHost: blocked.example.test\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client.read_to_end(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            if response.starts_with(b"HTTP/1.1 403") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "retry did not install the fetched filter list"
            );
        }

        context.shutdown();
        context.wait().await;
        upstream_task.abort();
    }
}
