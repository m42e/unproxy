//! Fast parser and matcher for hosts-format ad blocking lists (including Pi-hole lists).
use anyhow::{Context, Result, bail};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};

const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct FilterList(Arc<HashSet<String>>);

/// Last-good, source-scoped snapshots retained while incomplete loads retry.
#[derive(Clone, Default)]
pub(crate) struct FilterListSnapshots {
    sources: HashMap<String, (FilterList, usize)>,
}

impl FilterList {
    pub fn parse(text: &str) -> Self {
        let mut domains = HashSet::new();
        let mut malformed_entries = 0;
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
                    malformed_entries += usize::from(!insert_domain(&mut domains, domain));
                }
            } else if !first.starts_with("||") && !first.starts_with('!') && !first.contains('/') {
                malformed_entries += usize::from(!insert_domain(&mut domains, first));
            } else if let Some(domain) = first
                .strip_prefix("||")
                .and_then(|s| s.split(['^', '/', '*']).next())
            {
                malformed_entries += usize::from(!insert_domain(&mut domains, domain));
            }
        }
        if malformed_entries > 0 {
            tracing::warn!(
                malformed_entries,
                "ignored malformed filter-list domain entries"
            );
        }
        Self(Arc::new(domains))
    }

    pub fn contains(&self, host: &str) -> bool {
        let host = host
            .trim_end_matches('.')
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        let single_label_request = !host.contains('.');
        let mut candidate = host.as_str();
        loop {
            if (single_label_request || candidate.contains('.')) && self.0.contains(candidate) {
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
        Self::load_best_effort_with_snapshots(sources, None, FilterListSnapshots::default())
            .await
            .0
    }

    #[cfg(test)]
    pub(crate) async fn load_best_effort_with_status(sources: &[String]) -> (Self, bool) {
        let (list, complete, _) =
            Self::load_best_effort_with_snapshots(sources, None, FilterListSnapshots::default())
                .await;
        (list, complete)
    }

    pub(crate) async fn load_best_effort_with_snapshots(
        sources: &[String],
        proxy: Option<SocketAddr>,
        snapshots: FilterListSnapshots,
    ) -> (Self, bool, FilterListSnapshots) {
        Self::load_best_effort_with_snapshots_and_cap(sources, proxy, snapshots, MAX_LIST_BYTES)
            .await
    }

    async fn load_best_effort_with_snapshots_and_cap(
        sources: &[String],
        proxy: Option<SocketAddr>,
        snapshots: FilterListSnapshots,
        max_bytes: usize,
    ) -> (Self, bool, FilterListSnapshots) {
        // Start with last-good entries only for sources still configured. This also makes
        // removal take effect on the next retry attempt.
        let mut next = FilterListSnapshots {
            sources: sources
                .iter()
                .filter_map(|source| {
                    snapshots
                        .sources
                        .get(source)
                        .map(|snapshot| (source.clone(), snapshot.clone()))
                })
                .collect(),
        };
        let mut complete = true;
        let mut seen_sources = HashSet::new();
        for source in sources {
            // Repeated source entries should not multiply retained memory or the aggregate.
            if !seen_sources.insert(source.as_str()) {
                continue;
            }
            match Self::read_source(source, proxy).await {
                Ok(text) => {
                    let replacement = (Self::parse(&text), text.len());
                    let previous = next.sources.insert(source.clone(), replacement);
                    if next.total_bytes() > max_bytes {
                        complete = false;
                        tracing::warn!(
                            source = %source,
                            "filter list snapshot skipped because configured lists exceed 64 MiB"
                        );
                        // Restore the complete last-good source snapshot, or omit a new source.
                        if let Some(previous) = previous {
                            next.sources.insert(source.clone(), previous);
                        } else {
                            next.sources.remove(source);
                        }
                    }
                }
                Err(error) => {
                    complete = false;
                    tracing::warn!(
                        source = %source,
                        error = %format!("{error:#}"),
                        "filter list unavailable; skipping it for this attempt and retaining its last-good snapshot"
                    );
                }
            }
        }
        let list = next.aggregate();
        (list, complete, next)
    }

    async fn read_source(source: &str, proxy: Option<SocketAddr>) -> Result<String> {
        let text = if let Some((scheme, remainder)) = remote_uri_parts(source) {
            let uri = if scheme.eq_ignore_ascii_case("https") {
                format!("https://{remainder}")
            } else {
                bail!("remote filter list URL must use HTTPS: {source}");
            };
            let result = match proxy {
                Some(proxy) => crate::net::fetch_remote_text_via_proxy(&uri, proxy).await,
                None => crate::net::fetch_remote_text(&uri).await,
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

fn remote_uri_parts(source: &str) -> Option<(&str, &str)> {
    let (scheme, remainder) = source.split_once("://")?;
    let mut bytes = scheme.bytes();
    if !bytes.next()?.is_ascii_alphabetic()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return None;
    }
    Some((scheme, remainder))
}

impl FilterListSnapshots {
    fn total_bytes(&self) -> usize {
        self.sources
            .values()
            .fold(0usize, |total, (_, bytes)| total.saturating_add(*bytes))
    }

    fn aggregate(&self) -> FilterList {
        let mut domains = HashSet::new();
        for (list, _) in self.sources.values() {
            domains.extend(list.0.iter().cloned());
        }
        FilterList(Arc::new(domains))
    }
}

fn insert_domain(set: &mut HashSet<String>, raw: &str) -> bool {
    let unbracketed = match (raw.starts_with('['), raw.ends_with(']')) {
        (false, false) if !raw.contains(['[', ']']) => raw,
        (true, true) if !raw[1..raw.len() - 1].contains(['[', ']']) => &raw[1..raw.len() - 1],
        _ => return false,
    };
    let domain = unbracketed.trim_matches('.').to_ascii_lowercase();
    let single_label = unbracketed.strip_suffix('.').unwrap_or(unbracketed);
    let valid_single_label = !unbracketed.starts_with('.')
        && !single_label.contains('.')
        && is_valid_domain(&single_label.to_ascii_lowercase());
    // Keep the parser's existing permissive handling of multi-label entries.
    // DNS label validation is needed for the newly accepted single-label form
    // so arbitrary tokens do not become overly broad suffix matches.
    if (!domain.is_empty() && domain.len() <= 253 && domain.contains('.') && !domain.contains(' '))
        || valid_single_label
    {
        set.insert(domain);
        true
    } else {
        false
    }
}

fn is_valid_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes[0].is_ascii_alphanumeric()
                && bytes[bytes.len() - 1].is_ascii_alphanumeric()
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn best_effort_loaders_preserve_their_empty_and_local_source_status() {
        assert_eq!(FilterList::load_best_effort(&[]).await.domain_count(), 0);
        let (empty, complete) = FilterList::load_best_effort_with_status(&[]).await;
        assert!(complete);
        assert_eq!(empty.domain_count(), 0);
        let (via_proxy, complete, _) = FilterList::load_best_effort_with_snapshots(
            &[],
            Some("127.0.0.1:3128".parse().unwrap()),
            FilterListSnapshots::default(),
        )
        .await;
        assert!(complete);
        assert_eq!(via_proxy.domain_count(), 0);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("hosts.txt");
        std::fs::write(&path, "blocked.example.test\n").unwrap();
        let source = path.to_string_lossy().into_owned();
        let (loaded, complete) = FilterList::load_best_effort_with_status(&[source]).await;
        assert!(complete);
        assert!(loaded.contains("blocked.example.test"));
    }

    #[tokio::test]
    async fn retries_replace_sources_retain_failures_and_drop_removed_sources() {
        let directory = tempfile::tempdir().unwrap();
        let changing = directory.path().join("changing.txt");
        let flaky = directory.path().join("flaky.txt");
        std::fs::write(&changing, "old.example.test\n").unwrap();
        std::fs::write(&flaky, "stable.example.test\n").unwrap();
        let changing = changing.to_string_lossy().into_owned();
        let flaky = flaky.to_string_lossy().into_owned();
        let sources = vec![changing.clone(), flaky.clone()];

        let (mut live, complete, mut snapshots) = FilterList::load_best_effort_with_snapshots(
            &sources,
            None,
            FilterListSnapshots::default(),
        )
        .await;
        assert!(complete);
        assert_eq!(live.domain_count(), 2);

        std::fs::write(&changing, "new-1.example.test\n").unwrap();
        std::fs::remove_file(&flaky).unwrap();
        for version in 1..=8 {
            let (next, complete, next_snapshots) =
                FilterList::load_best_effort_with_snapshots(&sources, None, snapshots).await;
            assert!(!complete, "the unavailable source must keep retrying");
            live = next;
            snapshots = next_snapshots;
            assert_eq!(
                live.domain_count(),
                2,
                "retry {version} grew retained domains"
            );
            assert!(!live.contains("old.example.test"));
            assert!(live.contains(&format!("new-{version}.example.test")));
            assert!(live.contains("stable.example.test"));

            let replacement = format!("new-{}.example.test\n", version + 1);
            std::fs::write(&changing, replacement).unwrap();
        }

        std::fs::write(&flaky, "recovered.example.test\n").unwrap();
        let (recovered, complete, snapshots) =
            FilterList::load_best_effort_with_snapshots(&sources, None, snapshots).await;
        assert!(complete, "a later successful retry should complete");
        assert_eq!(recovered.domain_count(), 2);
        assert!(!recovered.contains("stable.example.test"));
        assert!(recovered.contains("recovered.example.test"));

        let (without_flaky, complete, _) =
            FilterList::load_best_effort_with_snapshots(&[changing], None, snapshots).await;
        assert!(complete);
        assert_eq!(without_flaky.domain_count(), 1);
        assert!(!without_flaky.contains("recovered.example.test"));
    }

    #[tokio::test]
    async fn aggregate_cap_rejects_a_source_replacement_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.txt");
        let second = directory.path().join("second.txt");
        std::fs::write(&first, "old.example.test\n").unwrap();
        std::fs::write(&second, "second.example.test\n").unwrap();
        let first = first.to_string_lossy().into_owned();
        let second = second.to_string_lossy().into_owned();
        let sources = vec![first.clone(), second.clone()];

        let (initial, complete, snapshots) = FilterList::load_best_effort_with_snapshots_and_cap(
            &sources,
            None,
            FilterListSnapshots::default(),
            64,
        )
        .await;
        assert!(complete);
        assert_eq!(initial.domain_count(), 2);

        std::fs::remove_file(&second).unwrap();
        std::fs::write(
            &first,
            format!("{}\n", "replacement.example.test".repeat(4)),
        )
        .unwrap();
        let (after, complete, _) =
            FilterList::load_best_effort_with_snapshots_and_cap(&sources, None, snapshots, 64)
                .await;
        assert!(!complete, "cap rejection must leave the load incomplete");
        assert_eq!(after.domain_count(), 2);
        assert!(after.contains("old.example.test"));
        assert!(!after.contains("replacement.example.test"));
        assert!(after.contains("second.example.test"));
    }

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
    fn parses_and_matches_single_label_hosts_in_all_supported_forms() {
        let list = FilterList::parse(
            "127.0.0.1 localhost. HOSTS-ONLY\nplain-only\n||adblock-only^\n[bracketed]\n",
        );

        assert_eq!(list.domain_count(), 5);
        assert!(list.contains("localhost"));
        assert!(list.contains("LOCALHOST."));
        assert!(list.contains("hosts-only"));
        assert!(list.contains("PLAIN-ONLY"));
        assert!(list.contains("adblock-only"));
        assert!(list.contains("bracketed"));
        assert!(!list.contains("sub.localhost"));
        assert!(!list.contains("localhost.evil"));
        assert!(!list.contains("other"));
    }

    #[test]
    fn ignores_malformed_domain_entries_without_matching_them() {
        let list = FilterList::parse(
            "-leading-hyphen\ntrailing-hyphen-\ninvalid_domain\n.localhost\nlocalhost..\n[localhost\nlocalhost]\n",
        );

        assert_eq!(list.domain_count(), 0);
        assert!(!list.contains("-leading-hyphen"));
        assert!(!list.contains("invalid_domain"));
        assert!(!list.contains("localhost"));
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
    async fn delayed_retry_loads_local_filter_and_updates_the_live_filter() {
        use crate::{net::ConnectionOptions, pac::Policy, proxy::ContextBuilder};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpStream,
        };

        let directory = tempfile::tempdir().unwrap();
        let source_path = directory.path().join("hosts.txt");
        let sources = vec![source_path.to_string_lossy().into_owned()];
        let (initial, complete) = FilterList::load_best_effort_with_status(&sources).await;
        assert!(!complete);

        let proxy_addr = "127.0.0.1:0".parse().unwrap();
        let policy = Policy::new(None).unwrap();
        let context = ContextBuilder::new(Arc::new(policy), ConnectionOptions::default())
            .listen(proxy_addr)
            .filter_list(initial)
            .bind()
            .await
            .unwrap();
        context.retry_filter_lists_after(
            sources,
            FilterListSnapshots::default(),
            std::time::Duration::from_millis(5),
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        std::fs::write(&source_path, "blocked.example.test\n").unwrap();

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let mut client = TcpStream::connect(context.local_addrs()[0]).await.unwrap();
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
    }
}
