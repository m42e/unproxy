//! Development metadata and nested TOML lookup utilities.
use anyhow::{Context, Result, bail};
use std::path::Path;

pub fn query_toml(input: &str, path: &[String]) -> Result<String> {
    let document: toml::Value = toml::from_str(input).context("invalid TOML input")?;
    let mut value = &document;
    for component in path {
        value = match value {
            toml::Value::Table(table) => table
                .get(component)
                .with_context(|| format!("missing key {component:?}"))?,
            toml::Value::Array(array) => {
                let index: usize = component
                    .parse()
                    .with_context(|| format!("invalid array index {component:?}"))?;
                array
                    .get(index)
                    .with_context(|| format!("array index {index} out of range"))?
            }
            _ => bail!("cannot descend into scalar at {component:?}"),
        };
    }
    Ok(match value {
        toml::Value::String(s) => s.clone(),
        _ => value.to_string(),
    })
}

pub fn product_version(package: &str) -> Result<&'static str> {
    match package {
        "unproxy" => Ok(crate::VERSION),
        "dnsdetox" => Ok(crate::DNS_VERSION),
        _ => bail!("unknown package {package:?}"),
    }
}

/// Bump manifest metadata explicitly; this function never creates a release.
pub fn bump_version(manifest: &Path, part: &str) -> Result<String> {
    let input = std::fs::read_to_string(manifest)?;
    let mut document: toml::Value = toml::from_str(&input)?;
    let old = document["package"]["version"]
        .as_str()
        .context("missing package.version")?;
    let components: Vec<_> = old
        .split('.')
        .map(str::parse::<u64>)
        .collect::<std::result::Result<_, _>>()?;
    anyhow::ensure!(components.len() == 3, "expected major.minor.patch");
    let (a, b, c) = (components[0], components[1], components[2]);
    let next = match part {
        "major" => format!("{}.0.0", a.checked_add(1).context("version overflow")?),
        "minor" => format!("{a}.{}.0", b.checked_add(1).context("version overflow")?),
        "patch" => format!("{a}.{b}.{}", c.checked_add(1).context("version overflow")?),
        _ => bail!("expected patch, minor, or major"),
    };
    document["package"]["version"] = toml::Value::String(next.clone());
    // Preserve hand-written formatting and comments rather than reformatting TOML.
    let mut in_package = false;
    let mut changed = false;
    let mut output = String::new();
    for line in input.lines() {
        if line.trim().starts_with('[') {
            in_package = line.trim() == "[package]";
        }
        if in_package
            && line
                .split_once('=')
                .is_some_and(|(key, _)| key.trim() == "version")
        {
            output.push_str(&format!("version = \"{next}\"\n"));
            changed = true;
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    anyhow::ensure!(changed, "cannot locate package.version assignment");
    std::fs::write(manifest, output)?;
    Ok(next)
}

pub fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), to.join(entry.file_name()))?;
        }
    }
    Ok(())
}

pub fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
