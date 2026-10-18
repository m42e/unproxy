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

fn platform_tabs(body: &str, prefix: &str, purpose: &str) -> String {
    let platforms = [
        ("windows", "Windows"),
        ("macos", "macOS"),
        ("debian-or-ubuntu", "Linux"),
    ];
    let mut output = String::new();
    let mut remainder = body;
    for (index, (id, label)) in platforms.iter().enumerate() {
        let heading = format!("<h2 id=\"{id}\">");
        let (before, section) = remainder.split_once(&heading).expect("platform heading");
        output.push_str(before);
        if index == 0 {
            output.push_str(
                "<div class=platform-tabs role=tablist aria-label=\"Operating system\" hidden>",
            );
            for (key, name) in platforms {
                output.push_str(&format!("<button type=button role=tab id=\"tab-{key}\" aria-controls=\"{prefix}-{key}\" aria-selected=false tabindex=-1>{name}</button>"));
            }
            output.push_str("</div>");
        }
        let end = section.find("<h2 ").unwrap_or(section.len());
        output.push_str(&format!("<section class=platform-panel id=\"{prefix}-{id}\" data-platform=\"{id}\" aria-label=\"{label} {purpose}\">{heading}{}</section>", &section[..end]));
        remainder = &section[end..];
    }
    output.push_str(remainder);
    output
}

pub(super) fn generate(output: &Path) -> Result<()> {
    std::fs::write(
        output.join("docs.css"),
        include_str!("../../../site/docs.css"),
    )?;
    std::fs::write(
        output.join("docs.js"),
        include_str!("../../../site/docs.js"),
    )?;
    // Preserve downloads linked by contributor pages as well as rendered Markdown.
    for entry in std::fs::read_dir("docs")? {
        let path = entry?.path();
        if path.is_file() && path.extension().is_none_or(|ext| ext != "md") {
            std::fs::copy(&path, output.join(path.file_name().unwrap()))?;
        }
    }
    let mut pages = std::fs::read_dir("docs")?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|ext| ext == "md"))
        .collect::<Vec<_>>();
    pages.sort();
    let mut links = USER_PAGES
        .iter()
        .filter(|(name, _)| {
            pages
                .iter()
                .any(|path| path.file_stem().is_some_and(|stem| stem == *name))
        })
        .map(|(name, title)| (name.to_string(), title.to_string()))
        .collect::<Vec<_>>();
    let user_count = links.len();
    for path in &pages {
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        if !links.iter().any(|(key, _)| key == &name) {
            let source = std::fs::read_to_string(path)?;
            let title = source
                .lines()
                .find_map(|line| line.strip_prefix("# "))
                .unwrap_or(&name)
                .to_string();
            links.push((name, title));
        }
    }
    for path in &pages {
        let name = path.file_stem().unwrap().to_string_lossy();
        let position = links.iter().position(|(key, _)| key == &name).unwrap();
        let title = &links[position].1;
        let mut nav = String::new();
        for (i, (key, label)) in links.iter().enumerate() {
            if i == 0 && user_count > 0 {
                nav.push_str("<p class=nav-label>User guide</p>");
            }
            if i == user_count {
                nav.push_str("<p class=nav-label>Contributors</p>");
            }
            nav.push_str(&format!(
                "<a href=\"{key}.html\"{}>{}</a>",
                if key == &name {
                    " aria-current=\"page\""
                } else {
                    ""
                },
                html_escape(label)
            ));
        }
        let (body, toc) = render(&std::fs::read_to_string(path)?);
        let body = match name.as_ref() {
            "installation" => platform_tabs(&body, "install", "installation"),
            "troubleshooting" => platform_tabs(&body, "troubleshoot", "troubleshooting"),
            _ => body,
        };
        let mut pager = String::new();
        for (label, index) in [
            ("Previous", position.checked_sub(1)),
            ("Next", (position + 1 < links.len()).then_some(position + 1)),
        ] {
            if let Some(index) = index {
                let (key, title) = &links[index];
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
        "<!doctype html><html lang=en><meta charset=utf-8><title>Unproxy documentation</title><meta http-equiv=refresh content='0;url=user-guide.html'><a href=user-guide.html>Read the Unproxy user guide</a></html>",
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
}
