//! Fast parser and matcher for hosts-format ad blocking lists (including Pi-hole lists).
use anyhow::{Context, Result, bail};
use std::{collections::HashSet, path::Path, sync::Arc};

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

    pub async fn load(sources: &[String]) -> Result<Self> {
        let mut joined = String::new();
        for source in sources {
            let text = if source.starts_with("http://") || source.starts_with("https://") {
                crate::net::fetch_remote_pac(source)
                    .await
                    .with_context(|| format!("fetching filter list {source}"))?
            } else {
                tokio::fs::read_to_string(Path::new(source))
                    .await
                    .with_context(|| format!("reading filter list {source}"))?
            };
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
}
