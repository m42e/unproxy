//! Release metadata lookup and semantic version comparison.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fmt;

pub const DEFAULT_RELEASE_INFO_URL: &str =
    "https://api.github.com/repos/m42e/unproxy/releases/latest";

/// Release details needed to direct the user to an available upgrade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub version: String,
    pub url: String,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpgradeStatus {
    UpToDate { current_version: String },
    UpgradeAvailable(ReleaseInfo),
}

impl fmt::Display for UpgradeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UpToDate { current_version } => {
                write!(formatter, "Unproxy is up to date ({current_version}).")
            }
            Self::UpgradeAvailable(release) => write!(
                formatter,
                "Unproxy {} is available: {}",
                release.version, release.url
            ),
        }
    }
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    body: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomReleaseInfo {
    version: String,
    url: String,
    #[serde(default)]
    notes: Option<String>,
}

/// Validate and normalize a configured HTTPS release metadata URL.
pub fn validate_release_info_url(value: &str) -> Result<String> {
    let value = value.trim();
    let uri = value
        .parse::<http::Uri>()
        .with_context(|| format!("invalid release info URL {value:?}"))?;
    let scheme = uri
        .scheme_str()
        .context("release info URL must use HTTPS")?;
    anyhow::ensure!(
        scheme.eq_ignore_ascii_case("https"),
        "release info URL must use HTTPS"
    );
    anyhow::ensure!(uri.host().is_some(), "release info URL must include a host");
    anyhow::ensure!(
        !uri.authority()
            .is_some_and(|authority| authority.as_str().contains('@')),
        "release info URL must not include embedded credentials"
    );
    let authority = uri
        .authority()
        .context("release info URL must include a host")?;
    let path_and_query = uri.path_and_query().map_or("", |value| value.as_str());
    let normalized = format!("https://{authority}{path_and_query}");
    Ok(normalized)
}

pub fn parse_custom_release_info(json: &str) -> Result<ReleaseInfo> {
    let value: CustomReleaseInfo =
        serde_json::from_str(json).context("invalid custom release info JSON")?;
    let version = normalize_version(&value.version)?;
    let url = validate_release_info_url(&value.url).context("custom release URL must use HTTPS")?;
    Ok(ReleaseInfo {
        version,
        url,
        notes: value.notes.filter(|notes| !notes.trim().is_empty()),
    })
}

pub fn parse_github_release(json: &str) -> Result<ReleaseInfo> {
    let value: GithubRelease = serde_json::from_str(json).context("invalid GitHub release JSON")?;
    let version = normalize_version(&value.tag_name)?;
    let url =
        validate_release_info_url(&value.html_url).context("GitHub release URL must use HTTPS")?;
    Ok(ReleaseInfo {
        version,
        url,
        notes: value.body.filter(|notes| !notes.trim().is_empty()),
    })
}

/// Compare release metadata with an installed semantic version.
pub fn evaluate_release(current_version: &str, mut release: ReleaseInfo) -> Result<UpgradeStatus> {
    let current = parse_version(current_version)
        .with_context(|| format!("invalid installed version {current_version:?}"))?;
    let latest = parse_version(&release.version)
        .with_context(|| format!("invalid release version {:?}", release.version))?;
    release.version = latest.to_string();
    if latest > current {
        Ok(UpgradeStatus::UpgradeAvailable(release))
    } else {
        Ok(UpgradeStatus::UpToDate {
            current_version: current.to_string(),
        })
    }
}

/// Check the configured release info endpoint, or GitHub Releases by default.
pub async fn check_for_upgrade(release_info_url: Option<&str>) -> Result<UpgradeStatus> {
    let release = if let Some(url) = release_info_url.filter(|url| !url.trim().is_empty()) {
        let url = validate_release_info_url(url)?;
        let json = crate::net::fetch_remote_text(&url).await?;
        parse_custom_release_info(&json)?
    } else {
        let json = crate::net::fetch_remote_json(DEFAULT_RELEASE_INFO_URL).await?;
        parse_github_release(&json)?
    };
    evaluate_release(crate::VERSION, release)
}

/// Synchronous wrapper for desktop event handlers.
pub fn check_for_upgrade_blocking(release_info_url: Option<&str>) -> Result<UpgradeStatus> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("create release check runtime")?
        .block_on(check_for_upgrade(release_info_url))
}

fn normalize_version(value: &str) -> Result<String> {
    Ok(parse_version(value)?.to_string())
}

fn parse_version(value: &str) -> Result<semver::Version> {
    let value = value.trim();
    let value = value
        .strip_prefix('v')
        .or_else(|| value.strip_prefix('V'))
        .unwrap_or(value);
    semver::Version::parse(value).with_context(|| format!("invalid semantic version {value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_release_info_uses_documented_fields_and_validates_urls() {
        let release = parse_custom_release_info(
            r#"{"version":"v1.2.0","url":"https://downloads.example.test/unproxy","notes":"Bug fixes"}"#,
        )
        .unwrap();
        assert_eq!(release.version, "1.2.0");
        assert_eq!(release.url, "https://downloads.example.test/unproxy");
        assert_eq!(release.notes.as_deref(), Some("Bug fixes"));

        assert!(
            parse_custom_release_info(r#"{"version":"1.2.0","url":"file:///release"}"#).is_err()
        );
        assert!(
            parse_custom_release_info(
                r#"{"version":"1.2.0","url":"https://u:p@downloads.example.test/unproxy"}"#
            )
            .is_err()
        );
        assert!(
            parse_custom_release_info(
                r#"{"version":"1.2.0","url":"https://downloads.example.test/unproxy","download":"elsewhere"}"#
            )
            .is_err()
        );
        let insecure_json = r#"{"version":"1.2.0","url":"http://downloads.example.test/release"}"#;
        assert!(parse_custom_release_info(insecure_json).is_err());
        let custom_host = parse_custom_release_info(
            r#"{"version":"1.2.0","url":"https://downloads.example.test/unproxy/1.2.0"}"#,
        )
        .unwrap();
        assert_eq!(
            custom_host.url,
            "https://downloads.example.test/unproxy/1.2.0"
        );
    }

    #[test]
    fn github_release_fields_map_to_release_metadata() {
        let release = parse_github_release(
            r#"{"tag_name":"v0.5.0","html_url":"https://github.com/m42e/unproxy/releases/tag/v0.5.0","body":"Release notes"}"#,
        )
        .unwrap();
        assert_eq!(release.version, "0.5.0");
        assert_eq!(
            release.url,
            "https://github.com/m42e/unproxy/releases/tag/v0.5.0"
        );
        assert_eq!(release.notes.as_deref(), Some("Release notes"));
    }

    #[test]
    fn semantic_comparison_reports_only_newer_releases() {
        let release = |version: &str| ReleaseInfo {
            version: version.into(),
            url: "https://example.test/release".into(),
            notes: None,
        };
        assert!(matches!(
            evaluate_release("1.0.0", release("1.1.0")).unwrap(),
            UpgradeStatus::UpgradeAvailable(_)
        ));
        assert_eq!(
            evaluate_release("1.0.0", release("1.0.0")).unwrap(),
            UpgradeStatus::UpToDate {
                current_version: "1.0.0".into()
            }
        );
        assert!(matches!(
            evaluate_release("1.0.0", release("0.9.9")).unwrap(),
            UpgradeStatus::UpToDate { .. }
        ));
        assert!(evaluate_release("not-a-version", release("1.1.0")).is_err());
    }

    #[test]
    fn release_info_urls_normalize_scheme_and_reject_invalid_inputs() {
        assert_eq!(
            validate_release_info_url(" HTTPS://updates.example.test/releases.json ").unwrap(),
            "https://updates.example.test/releases.json"
        );
        for value in [
            "",
            "http://updates.example.test/releases.json",
            "ftp://example.test/releases.json",
            "https:///release",
        ] {
            assert!(
                validate_release_info_url(value).is_err(),
                "accepted {value:?}"
            );
        }
    }
}
