//! AppStream is untrusted: bounded XML, no DTD/entities, and text-only descriptions.
use crate::{CATEGORIES, CatalogMetadata, CatalogPermissions, CatalogScreenshot};
use anyhow::{bail, ensure};
use quick_xml::{Reader, events::Event};
use std::{collections::BTreeSet, net::IpAddr};
use url::{Host, Url};
pub const MAX_XML: usize = 256 * 1024;
#[derive(Default)]
struct Node {
    tag: String,
    content: Vec<Content>,
    attrs: Vec<(String, String)>,
    children: Vec<Node>,
}
enum Content {
    Text(String),
    Child(usize),
}
impl Node {
    fn add(&mut self, child: Node) {
        self.content.push(Content::Child(self.children.len()));
        self.children.push(child);
    }
    fn add_text(&mut self, value: &str) {
        if let Some(Content::Text(last)) = self.content.last_mut() {
            last.push_str(value);
        } else {
            self.content.push(Content::Text(value.to_owned()));
        }
    }
    fn child(&self, tag: &str) -> Option<&Node> {
        self.children
            .iter()
            .find(|n| n.tag == tag && !n.attrs.iter().any(|(k, _)| k == "xml:lang"))
    }
    fn value(&self, tag: &str, limit: usize) -> String {
        self.child(tag).map(|n| text(n, limit)).unwrap_or_default()
    }
    fn attr(&self, key: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}
fn text(node: &Node, limit: usize) -> String {
    // Unknown executable markup and all its contents are discarded. No HTML reaches a DTO.
    if ["script", "style", "iframe", "object", "svg"].contains(&node.tag.as_str()) {
        return String::new();
    }
    let mut result = String::new();
    for part in &node.content {
        match part {
            Content::Text(value) => result.push_str(value),
            Content::Child(index) => {
                let child = &node.children[*index];
                let block = ["p", "li", "ul", "ol"].contains(&child.tag.as_str());
                if block && !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(&text(child, limit));
                if block {
                    result.push('\n');
                }
            }
        }
    }
    bounded_text(&result, limit)
}
pub fn bounded_text(s: &str, limit: usize) -> String {
    let filtered: String = s
        .chars()
        .filter(|c| !c.is_control() || ['\n', '\t'].contains(c))
        .collect();
    let mut end = filtered.len().min(limit);
    while !filtered.is_char_boundary(end) {
        end -= 1;
    }
    filtered[..end].trim().to_owned()
}
/// Public display URLs only; never fetched/proxied by LibreHub. DNS checked by the worker below.
pub fn public_url(s: &str) -> Option<String> {
    if s.len() > 2048 || s.chars().any(char::is_control) {
        return None;
    }
    let u = Url::parse(s).ok()?;
    if u.scheme() != "https"
        || !u.username().is_empty()
        || u.password().is_some()
        || u.port().is_some_and(|p| p != 443)
    {
        return None;
    }
    match u.host()? {
        Host::Ipv4(ip) if !librehub_source::public_ip(IpAddr::V4(ip)) => return None,
        Host::Ipv6(ip) if !librehub_source::public_ip(IpAddr::V6(ip)) => return None,
        Host::Domain(h) => {
            let h = h.trim_end_matches('.').to_ascii_lowercase();
            if !h.contains('.')
                || [
                    "localhost",
                    "local",
                    "internal",
                    "lan",
                    "test",
                    "invalid",
                    "example",
                ]
                .iter()
                .any(|suffix| h == *suffix || h.ends_with(&format!(".{suffix}")))
            {
                return None;
            }
        }
        _ => {}
    }
    Some(u.to_string())
}
pub fn categories(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|s| {
            let s = if s == "Game" { "Games" } else { s.trim() };
            CATEGORIES.iter().find(|v| **v == s).map(|v| v.to_string())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(12)
        .collect()
}
pub fn fallback(app_id: &str) -> CatalogMetadata {
    CatalogMetadata {
        name: app_id.into(),
        summary: String::new(),
        description: String::new(),
        developer_name: None,
        homepage: None,
        license: None,
        categories: vec![],
        keywords: vec![],
        screenshots: vec![],
        icon_url: None,
        version: None,
        release_notes: String::new(),
        content_rating: vec![],
    }
}
pub fn appstream(xml: &str, app_id: &str) -> anyhow::Result<CatalogMetadata> {
    ensure!(xml.len() <= MAX_XML, "Metadata size limit");
    let mut reader = Reader::from_str(xml);
    let mut stack = vec![Node::default()];
    let mut nodes = 0;
    loop {
        match reader.read_event()? {
            Event::DocType(_) => bail!("DTD forbidden"),
            Event::Start(e) | Event::Empty(e) => {
                nodes += 1;
                ensure!(nodes <= 4096 && stack.len() <= 32, "XML structural limit");
                let empty =
                    xml.as_bytes().get(reader.buffer_position() as usize - 2) == Some(&b'/');
                let mut node = Node {
                    tag: String::from_utf8(e.name().as_ref().to_vec())?,
                    ..Node::default()
                };
                for a in e.attributes() {
                    let a = a?;
                    ensure!(node.attrs.len() < 16, "Attribute limit");
                    node.attrs.push((
                        String::from_utf8(a.key.as_ref().to_vec())?,
                        a.decode_and_unescape_value(reader.decoder())?.into_owned(),
                    ));
                }
                if empty {
                    stack.last_mut().unwrap().add(node);
                } else {
                    stack.push(node);
                }
            }
            Event::End(_) => {
                ensure!(stack.len() > 1, "Unbalanced XML");
                let node = stack.pop().unwrap();
                stack.last_mut().unwrap().add(node);
            }
            Event::Text(e) => stack.last_mut().unwrap().add_text(&e.xml_content()?),
            Event::CData(e) => stack.last_mut().unwrap().add_text(&e.xml_content()?),
            Event::GeneralRef(e) => {
                // Only predefined/numeric references; no arbitrary expansion.
                let value = format!("&{};", e.decode()?);
                stack
                    .last_mut()
                    .unwrap()
                    .add_text(&quick_xml::escape::unescape(&value)?);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    ensure!(stack.len() == 1, "Unbalanced XML");
    let root = stack.pop().unwrap();
    ensure!(
        root.children.len() == 1
            && root.content.iter().all(|part| match part {
                Content::Text(t) => t.trim().is_empty(),
                Content::Child(_) => true,
            }),
        "XML must have exactly one document element"
    );
    let components = root.child("components").unwrap_or(&root);
    let component = components
        .children
        .iter()
        .find(|n| {
            ["component", "application"].contains(&n.tag.as_str())
                && n.value("id", 255).trim_end_matches(".desktop") == app_id
        })
        .ok_or_else(|| anyhow::anyhow!("Application identity mismatch"))?;
    let mut m = fallback(app_id);
    let name = component.value("name", 120);
    if !name.is_empty() {
        m.name = name;
    }
    m.summary = component.value("summary", 240);
    m.description = component.value("description", 16_384);
    let developer = component.value("developer_name", 120);
    let developer = if developer.is_empty() {
        component
            .child("developer")
            .map(|n| n.value("name", 120))
            .unwrap_or_default()
    } else {
        developer
    };
    m.developer_name = (!developer.is_empty()).then_some(developer);
    let license = component.value("project_license", 160);
    m.license = (!license.is_empty()).then_some(license);
    m.homepage = component
        .children
        .iter()
        .find(|n| n.tag == "url" && n.attr("type") == Some("homepage"))
        .and_then(|n| public_url(&text(n, 2048)));
    if let Some(c) = component.child("categories") {
        ensure!(c.children.len() <= 32, "Category limit");
        m.categories = categories(c.children.iter().map(|n| text(n, 64)));
    }
    if let Some(k) = component.child("keywords") {
        ensure!(k.children.len() <= 32, "Keyword limit");
        m.keywords = k
            .children
            .iter()
            .map(|n| text(n, 64))
            .filter(|s| !s.is_empty())
            .collect();
    }
    if let Some(s) = component.child("screenshots") {
        ensure!(s.children.len() <= 8, "Screenshot limit");
        for shot in &s.children {
            let image = shot
                .children
                .iter()
                .find(|n| n.tag == "image" && n.attr("type") != Some("thumbnail"));
            if let Some(url) = image.and_then(|n| public_url(&text(n, 2048))) {
                m.screenshots.push(CatalogScreenshot {
                    url,
                    caption: shot.value("caption", 240),
                });
            }
        }
    }
    m.icon_url = component
        .children
        .iter()
        .find(|n| n.tag == "icon" && n.attr("type") == Some("remote"))
        .and_then(|n| public_url(&text(n, 2048)));
    if let Some(r) = component.child("releases") {
        ensure!(r.children.len() <= 64, "Release limit");
        // AppStream is conventionally newest first; prefer newest ISO date, stable on ties.
        let mut releases: Vec<_> = r.children.iter().filter(|n| n.tag == "release").collect();
        releases.sort_by_key(|n| std::cmp::Reverse(n.attr("date").unwrap_or("")));
        if let Some(release) = releases.iter().find(|n| {
            n.attr("version").is_some_and(|v| {
                !v.trim().is_empty() && v.len() <= 120 && !v.chars().any(char::is_control)
            })
        }) {
            m.version = release.attr("version").map(str::to_owned);
            m.release_notes = release.value("description", 4096);
        }
    }
    if let Some(r) = component.child("content_rating") {
        m.content_rating = r
            .children
            .iter()
            .take(32)
            .map(|n| {
                format!(
                    "{}: {}",
                    bounded_text(n.attr("id").unwrap_or(""), 64),
                    text(n, 64)
                )
            })
            .collect();
    }
    Ok(m)
}
pub fn desktop(text: &str, app_id: &str) -> anyhow::Result<CatalogMetadata> {
    ensure!(text.len() <= 65536, "Desktop size limit");
    let mut m = fallback(app_id);
    let mut section = "";
    for line in text.lines() {
        if line.starts_with('[') {
            section = line;
        }
        if section != "[Desktop Entry]" {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            match k {
                "Name" => m.name = bounded_text(v, 120),
                "Comment" => m.summary = bounded_text(v, 240),
                "Categories" => m.categories = categories(v.split(';').map(str::to_owned)),
                "Keywords" => {
                    m.keywords = v
                        .split(';')
                        .take(32)
                        .map(|v| bounded_text(v, 64))
                        .filter(|s| !s.is_empty())
                        .collect()
                }
                _ => {}
            }
        }
    }
    Ok(m)
}
pub fn permissions(text: &str) -> anyhow::Result<CatalogPermissions> {
    ensure!(text.len() <= 65536, "Permission metadata size limit");
    let mut p = CatalogPermissions::default();
    let mut section = "";
    let mut count = 0;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            section = line;
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if ["[Session Bus Policy]", "[System Bus Policy]"].contains(&section) {
                p.dbus.push(format!(
                    "{}: {}={}",
                    section.trim_matches(['[', ']']),
                    bounded_text(key, 160),
                    bounded_text(value, 80)
                ));
                count += 1;
            } else if section == "[Context]" {
                for v in value.split(';').filter(|s| !s.is_empty()) {
                    count += 1;
                    ensure!(
                        count <= 256 && v.len() <= 256,
                        "Permission count/length limit"
                    );
                    match key {
                        "shared" => {
                            if v == "network" {
                                p.network = true;
                            }
                            p.shared.push(v.into());
                        }
                        "filesystems" => p.filesystem.push(v.into()),
                        "devices" => p.devices.push(v.into()),
                        "sockets" => p.sockets.push(v.into()),
                        _ => p.other.push(format!("{key}={v}")),
                    }
                }
            }
            ensure!(count <= 256, "Permission count limit");
        }
    }
    Ok(p)
}
/// Check DNS without fetching assets. No credentials, redirect or HTTP proxy boundary exists.
pub async fn validate_urls(m: &mut CatalogMetadata) {
    async fn allowed(value: &str) -> bool {
        let Ok(u) = Url::parse(value) else {
            return false;
        };
        let Some(host) = u.host_str() else {
            return false;
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::lookup_host((host, 443)),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .is_some_and(|addresses| {
            let ips: Vec<_> = addresses.take(32).collect();
            !ips.is_empty() && ips.iter().all(|a| librehub_source::public_ip(a.ip()))
        })
    }
    let mut screenshots = vec![];
    for s in m.screenshots.drain(..) {
        if allowed(&s.url).await {
            screenshots.push(s);
        }
    }
    m.screenshots = screenshots;
    for value in [&mut m.homepage, &mut m.icon_url] {
        if let Some(url) = value.as_ref()
            && !allowed(url).await
        {
            *value = None;
        }
    }
}
