use anyhow::{Context, Result, anyhow, bail};
use http::Uri;
use std::{fmt, net::Ipv6Addr, str::FromStr};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn authority(&self) -> String {
        format!("{}:{}", format_host(&self.host), self.port)
    }
}
fn format_host(host: &str) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}
impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", format_host(&self.host), self.port)
    }
}
impl FromStr for Endpoint {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let (host, port) = if let Some(bracketed) = s.strip_prefix('[') {
            let end = bracketed
                .find(']')
                .ok_or_else(|| anyhow!("invalid bracketed IPv6 endpoint"))?;
            let host = &bracketed[..end];
            host.parse::<Ipv6Addr>().context("invalid IPv6 host")?;
            let tail = &bracketed[end + 1..];
            let port = tail
                .strip_prefix(':')
                .ok_or_else(|| anyhow!("missing port"))?;
            (host, port)
        } else {
            let (host, port) = s.rsplit_once(':').ok_or_else(|| anyhow!("missing port"))?;
            if host.contains(':') {
                bail!("IPv6 endpoint must use brackets")
            }
            (host, port)
        };
        if host.is_empty() {
            bail!("host missing")
        }
        if host.bytes().any(|b| b.is_ascii_whitespace()) || host.contains(['@', '/', '?', '#']) {
            bail!("invalid host in endpoint")
        }
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            bail!("invalid numeric port")
        }
        let port = port.parse::<u16>().context("port out of range")?;
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Route {
    Direct,
    Http(Endpoint),
    Https(Endpoint),
}
impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("DIRECT"),
            Self::Http(e) => write!(f, "HTTP {e}"),
            Self::Https(e) => write!(f, "HTTPS {e}"),
        }
    }
}
impl FromStr for Route {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s == "DIRECT" {
            return Ok(Self::Direct);
        }
        let mut tokens = s.split_whitespace();
        let kind = tokens
            .next()
            .ok_or_else(|| anyhow!("invalid PAC directive: {s}"))?;
        let endpoint = tokens
            .next()
            .ok_or_else(|| anyhow!("invalid PAC directive: {s}"))?;
        if tokens.next().is_some() {
            bail!("invalid PAC endpoint")
        }
        let e = endpoint.parse()?;
        match kind {
            "PROXY" | "HTTP" => Ok(Self::Http(e)),
            "HTTPS" => Ok(Self::Https(e)),
            _ => bail!("unknown PAC directive: {kind}"),
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Routes(pub Vec<Route>);
impl fmt::Display for Routes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, r) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?
            }
            write!(f, "{r}")?;
        }
        Ok(())
    }
}
impl FromStr for Routes {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut out = Vec::new();
        for part in s.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            out.push(part.parse()?)
        }
        if out.is_empty() {
            bail!("empty PAC route list")
        }
        Ok(Self(out))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Destination {
    pub endpoint: Endpoint,
    pub pac_url: String,
    pub path: String,
    pub scheme: String,
}
impl Destination {
    pub fn from_uri(uri: &Uri) -> Result<Self> {
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow!("URI authority missing"))?;
        let host = authority.host();
        if host.is_empty() {
            bail!("URI host missing")
        }
        let scheme = match uri.scheme_str() {
            Some(s) => s.to_ascii_lowercase(),
            None if authority.port_u16() == Some(443) => "https".to_owned(),
            None => "http".to_owned(),
        };
        let default = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            _ => 0,
        };
        let port = if authority.port().is_some() {
            authority
                .port_u16()
                .ok_or_else(|| anyhow!("URI port invalid"))?
        } else {
            (default > 0)
                .then_some(default)
                .ok_or_else(|| anyhow!("URI port missing"))?
        };
        let path = match uri.path_and_query() {
            Some(p) if !p.as_str().is_empty() => p.as_str().to_owned(),
            _ => "/".into(),
        };
        let pac_url = if uri.scheme().is_none() {
            format!("{scheme}://{}{path}", authority.as_str())
        } else {
            uri.to_string()
        };
        Ok(Self {
            endpoint: Endpoint {
                host: host
                    .strip_prefix('[')
                    .and_then(|h| h.strip_suffix(']'))
                    .unwrap_or(host)
                    .to_owned(),
                port,
            },
            pac_url,
            path,
            scheme,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PathOrUri {
    Path(std::path::PathBuf),
    Uri(Uri),
}
impl FromStr for PathOrUri {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        if s.starts_with("http://") || s.starts_with("https://") {
            Ok(Self::Uri(s.parse().context("invalid URI")?))
        } else {
            Ok(Self::Path(s.into()))
        }
    }
}
impl fmt::Display for PathOrUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path(p) => write!(f, "{}", p.display()),
            Self::Uri(u) => write!(f, "{u}"),
        }
    }
}
