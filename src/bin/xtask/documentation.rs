//! Static documentation built from the same Markdown read on GitHub.
use anyhow::Result;
use pulldown_cmark::{CowStr, Event, Options, Parser, Tag, TagEnd, html};
use std::{collections::HashSet, path::Path};
use unproxy::tools::html_escape;

const USER_PAGES: &[(&str, &str)] = &[
    ("user-guide", "Quick start"),
    ("installation", "Installation"),
    ("desktop", "Desktop app"),
    ("applications", "Connect applications"),
    ("routing", "PAC & routing"),
    ("authentication", "Authentication"),
    ("configuration", "Configuration reference"),
    ("troubleshooting", "Troubleshooting"),
];
const PAC_PERFORMANCE_MARKER: &str = "<!-- PAC_PERFORMANCE_RESULTS -->";

fn slug(text: &str) -> String {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn render(source: &str) -> (String, String) {
    let mut events: Vec<_> = Parser::new_ext(source, Options::ENABLE_TABLES).collect();
    let mut toc = String::new();
    let mut used = HashSet::new();
    for i in 0..events.len() {
        if let Event::Start(Tag::Heading { level, .. }) = &events[i] {
            let level = *level;
            let title = events[i + 1..]
                .iter()
                .take_while(|event| !matches!(event, Event::End(TagEnd::Heading(_))))
                .filter_map(|event| match event {
                    Event::Text(text) | Event::Code(text) => Some(text.as_ref()),
                    _ => None,
                })
                .collect::<String>();
            let base = slug(&title);
            let mut id = base.clone();
            let mut suffix = 1;
            while !used.insert(id.clone()) {
                id = format!("{base}-{suffix}");
                suffix += 1;
            }
            if level == pulldown_cmark::HeadingLevel::H2 {
                toc.push_str(&format!("<a href=\"#{id}\">{}</a>", html_escape(&title)));
            }
            events[i] = Event::Start(Tag::Heading {
                level,
                id: Some(id.into()),
                classes: vec![],
                attrs: vec![],
            });
        }
        if let Event::Start(Tag::Link { dest_url, .. }) = &mut events[i] {
            let url = dest_url.to_string();
            let (path, fragment) = url.split_once('#').unwrap_or((&url, ""));
            if !path.contains(':')
                && let Some(stem) = path.strip_suffix(".md")
            {
                *dest_url = CowStr::from(format!(
                    "{stem}.html{}{}",
                    if fragment.is_empty() { "" } else { "#" },
                    fragment
                ));
            }
        }
        // Treat embedded HTML as text; documentation never needs executable markup.
        if let Event::Html(raw) | Event::InlineHtml(raw) = &events[i] {
            events[i] = Event::Text(raw.clone());
        }
    }
    let mut body = String::new();
    html::push_html(&mut body, events.into_iter());
    (body, toc)
}

fn platform_tab_group(
    body: &str,
    prefix: &str,
    purpose: &str,
    heading_level: u8,
    platforms: &[(&str, &str, &str)],
) -> String {
    let mut output = String::new();
    let mut remainder = body;
    for (index, (heading_id, id, label)) in platforms.iter().enumerate() {
        let heading = format!("<h{heading_level} id=\"{heading_id}\">");
        let (before, section) = remainder.split_once(&heading).expect("platform heading");
        output.push_str(before);
        if index == 0 {
            output.push_str(
                "<div class=platform-tabs role=tablist aria-label=\"Operating system\" hidden>",
            );
            for (_, key, name) in platforms {
                output.push_str(&format!("<button type=button role=tab id=\"tab-{prefix}-{key}\" aria-controls=\"{prefix}-{key}\" aria-selected=false tabindex=-1>{name}</button>"));
            }
            output.push_str("</div>");
        }
        let next_heading = format!("<h{heading_level} ");
        let end = section.find(&next_heading).unwrap_or(section.len());
        output.push_str(&format!("<section class=platform-panel id=\"{prefix}-{id}\" data-platform=\"{id}\" aria-label=\"{label} {purpose}\">{heading}{}</section>", &section[..end]));
        remainder = &section[end..];
    }
    output.push_str(remainder);
    output
}

fn shell_tab_group(body: &str, prefix: &str, purpose: &str) -> String {
    let shells = [
        ("bash", "Bash"),
        ("zsh", "Zsh"),
        ("fish", "Fish"),
        ("powershell", "PowerShell"),
        ("cmd", "Windows Command Prompt"),
    ];
    let mut output = String::new();
    let mut remainder = body;
    for (index, (id, label)) in shells.iter().enumerate() {
        let heading_end = format!(">{label}</h3>");
        let heading_end_index = remainder.find(&heading_end).expect("shell heading");
        let heading_start = remainder[..heading_end_index]
            .rfind("<h3 ")
            .expect("shell heading start");
        let section_end = remainder[heading_end_index + heading_end.len()..]
            .find("<h3 ")
            .map(|relative| heading_end_index + heading_end.len() + relative)
            .unwrap_or(remainder.len());

        output.push_str(&remainder[..heading_start]);
        if index == 0 {
            output.push_str("<div class=shell-tabs role=tablist aria-label=Shell hidden>");
            for (shell_id, shell_label) in &shells {
                output.push_str(&format!("<button type=button role=tab id=\"tab-{prefix}-{shell_id}\" aria-controls=\"{prefix}-{shell_id}\" aria-selected=false tabindex=-1>{shell_label}</button>"));
            }
            output.push_str("</div>");
        }
        let heading_end_index = heading_end_index + heading_end.len();
        let heading = &remainder[heading_start..heading_end_index];
        let content = &remainder[heading_end_index..section_end];
        output.push_str(&format!("<section class=shell-panel id=\"{prefix}-{id}\" data-shell=\"{id}\" aria-label=\"{label} {purpose}\">{heading}{content}</section>"));
        remainder = &remainder[section_end..];
    }
    output.push_str(remainder);
    output
}

fn shell_tabs_in_section(body: &str, section_id: &str, prefix: &str, purpose: &str) -> String {
    let heading = format!("<h2 id=\"{section_id}\">");
    let (before, section) = body.split_once(&heading).expect("shell section heading");
    let (title, section) = section.split_once("</h2>").expect("shell section title");
    let end = section.find("<h2 ").unwrap_or(section.len());
    let section_body = shell_tab_group(&section[..end], prefix, purpose);
    format!(
        "{before}{heading}{title}</h2>{section_body}{}",
        &section[end..]
    )
}

fn platform_tabs(body: &str, prefix: &str, purpose: &str) -> String {
    platform_tab_group(
        body,
        prefix,
        purpose,
        2,
        &[
            ("windows", "windows", "Windows"),
            ("macos", "macos", "macOS"),
            ("debian-or-ubuntu", "debian-or-ubuntu", "Linux"),
        ],
    )
}

fn platform_tabs_in_section(body: &str, section_id: &str, prefix: &str, purpose: &str) -> String {
    let heading = format!("<h2 id=\"{section_id}\">");
    let (before, section) = body.split_once(&heading).expect("platform section heading");
    let (title, section) = section.split_once("</h2>").expect("platform section title");
    let end = section.find("<h2 ").unwrap_or(section.len());
    let section_body = &section[..end];
    let remainder = &section[end..];
    let section_body = platform_tab_group(
        section_body,
        prefix,
        purpose,
        3,
        &[
            ("windows-removal", "windows", "Windows"),
            ("macos-removal", "macos", "macOS"),
            ("debian-ubuntu-removal", "debian-or-ubuntu", "Linux"),
        ],
    );
    format!("{before}{heading}{title}</h2>{section_body}{remainder}")
}

fn user_pages(available: &[std::path::PathBuf]) -> Vec<(String, String, std::path::PathBuf)> {
    USER_PAGES
        .iter()
        .filter_map(|(name, title)| {
            available
                .iter()
                .find(|path| path.file_stem().is_some_and(|stem| stem == *name))
                .map(|path| (name.to_string(), title.to_string(), path.clone()))
        })
        .collect()
}

pub(super) fn generate(output: &Path, pac_performance_results: &str) -> Result<()> {
    std::fs::write(
        output.join("docs.css"),
        include_str!("../../../site/docs.css"),
    )?;
    std::fs::write(
        output.join("docs.js"),
        include_str!("../../../site/docs.js"),
    )?;
    // Keep static files stored with the documentation alongside generated pages.
    for entry in std::fs::read_dir("docs")? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_none_or(|ext| ext != "md") {
            std::fs::copy(&path, output.join(path.file_name().unwrap()))?;
        }
    }
    let available_pages = std::fs::read_dir("docs")?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "md"))
        .collect::<Vec<_>>();
    let links = user_pages(&available_pages);
    for (position, (name, title, path)) in links.iter().enumerate() {
        let mut nav = String::new();
        for (i, (key, label, _)) in links.iter().enumerate() {
            if i == 0 {
                nav.push_str("<p class=nav-label>User guide</p>");
            }
            nav.push_str(&format!(
                "<a href=\"{key}.html\"{}>{}</a>",
                if key == name {
                    " aria-current=\"page\""
                } else {
                    ""
                },
                html_escape(label)
            ));
        }
        let mut source = std::fs::read_to_string(path)?;
        if name == "routing" {
            anyhow::ensure!(
                source.matches(PAC_PERFORMANCE_MARKER).count() == 1,
                "routing guide must contain exactly one PAC performance results marker"
            );
            source = source.replace(PAC_PERFORMANCE_MARKER, pac_performance_results);
        }
        let (body, toc) = render(&source);
        let body = match name.as_ref() {
            "applications" => shell_tabs_in_section(
                &shell_tabs_in_section(&body, "terminal-setup", "shell-setup", "terminal setup"),
                "stop-using-proxy-variables",
                "shell-cleanup",
                "proxy variable cleanup",
            ),
            "installation" => platform_tabs_in_section(
                &platform_tabs(&body, "install", "installation"),
                "remove-unproxy",
                "remove",
                "removal",
            ),
            "troubleshooting" => platform_tabs(&body, "troubleshoot", "troubleshooting"),
            _ => body,
        };
        let mut pager = String::new();
        for (label, index) in [
            ("Previous", position.checked_sub(1)),
            ("Next", (position + 1 < links.len()).then_some(position + 1)),
        ] {
            if let Some(index) = index {
                let (key, title, _) = &links[index];
                pager.push_str(&format!(
                    "<a href=\"{key}.html\"><span>{label}</span>{}</a>",
                    html_escape(title)
                ));
            }
        }
        let page = include_str!("../../../site/docs.html")
            .replace("@TITLE@", &html_escape(title))
            .replace("@VERSION@", &html_escape(unproxy::VERSION))
            .replace("@NAV@", &nav)
            .replace("@TOC@", &toc)
            .replace("@BODY@", &body)
            .replace("@PAGER@", &pager);
        std::fs::write(output.join(format!("{name}.html")), page)?;
    }
    std::fs::write(
        output.join("index.html"),
        "<!doctype html><html lang=en><meta charset=utf-8><link rel=icon type=image/png href=../unproxy-icon.png><title>Unproxy documentation</title><meta http-equiv=refresh content='0;url=user-guide.html'><a href=user-guide.html>Read the Unproxy user guide</a></html>",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_preserves_structure_links_code_and_unique_anchors() {
        let (body, toc) = render(
            "# Guide\n\n## Set `HTTP` & HTTPS\n\n[Install](installation.md#macos) and **start**.\n\n1. One\n2. Two\n\n| Key | Value |\n| --- | --- |\n| Port | `3128` |\n\n## Set HTTP & HTTPS\n\n```sh\necho '<safe>'\n```\n\n<script>alert(1)</script>",
        );
        for expected in [
            "<ol>",
            "<table>",
            "<strong>start</strong>",
            "href=\"installation.html#macos\"",
            "id=\"set-http-https\"",
            "id=\"set-http-https-1\"",
            "class=\"language-sh\"",
            "&lt;safe&gt;",
        ] {
            assert!(body.contains(expected), "missing {expected}: {body}");
        }
        assert!(!body.contains("<script>"));
        assert!(toc.contains("href=\"#set-http-https-1\""));
    }

    #[test]
    fn generated_docs_include_user_pages_only() {
        let output = tempfile::tempdir().unwrap();
        generate(output.path(), "PAC performance: unit test result").unwrap();

        for page in [
            "user-guide",
            "installation",
            "desktop",
            "applications",
            "routing",
            "authentication",
            "configuration",
            "troubleshooting",
        ] {
            assert!(output.path().join(format!("{page}.html")).exists());
        }
        for page in [
            "corporate-auth-tests",
            "coverage-test-plan",
            "pac-performance",
            "release-signing",
        ] {
            assert!(!output.path().join(format!("{page}.html")).exists());
        }

        let user_guide = std::fs::read_to_string(output.path().join("user-guide.html")).unwrap();
        assert!(!user_guide.contains("<p class=nav-label>Contributors</p>"));
        let routing = std::fs::read_to_string(output.path().join("routing.html")).unwrap();
        assert!(routing.contains("PAC performance: unit test result"));
        assert!(!routing.contains("PAC_PERFORMANCE_RESULTS"));
    }
}
