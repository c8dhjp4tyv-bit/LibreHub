use crate::{extract::validate_png, metadata::*, search_expression};
fn xml(body: &str) -> String {
    format!("<component type='desktop-application'><id>org.example.Test</id>{body}</component>")
}
#[test]
fn appstream_extracts_standard_fields() {
    let m=appstream(&xml("<name>Editor</name><summary>Write code</summary><description><p>A small <em>tool</em>.</p></description><developer_name>Dev</developer_name><project_license>MIT</project_license><categories><category>Development</category><category>Game</category><category>Bad</category></categories><keywords><keyword>code</keyword></keywords><releases><release version='2.4' date='2026-02-01'><description><p>Notes</p></description></release></releases>"),"org.example.Test").unwrap();
    assert_eq!(m.name, "Editor");
    assert_eq!(m.version.as_deref(), Some("2.4"));
    assert_eq!(m.categories, vec!["Development", "Games"]);
    assert!(m.description.contains("tool"));
    assert_eq!(m.license.as_deref(), Some("MIT"));
}
#[test]
fn markup_cannot_inject_browser_dom() {
    let m=appstream(&xml("<name>&lt;img onerror=alert(1)&gt;</name><description><p onclick='alert(1)'>Hello</p><script>alert(2)</script><svg onload='bad'><script>bad</script></svg></description>"),"org.example.Test").unwrap();
    assert!(!m.description.contains("script"));
    assert!(!m.description.contains("onclick"));
    assert!(!m.description.contains("alert"));
    assert!(m.name.contains("<img"));
}
#[test]
fn dtd_and_external_entities_rejected() {
    assert!(appstream("<!DOCTYPE component [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><component><id>org.example.Test</id><name>&x;</name></component>","org.example.Test").is_err());
}
#[test]
fn wrong_identity_rejected() {
    assert!(appstream(&xml("<name>Editor</name>"), "org.example.Other").is_err());
}
#[test]
fn malformed_xml_rejected() {
    assert!(appstream("<component><id>org.example.Test</id>", "org.example.Test").is_err());
}
#[test]
fn size_and_depth_bounded() {
    assert!(appstream(&"x".repeat(MAX_XML + 1), "org.example.Test").is_err());
    let deep = format!("{}{}", "<a>".repeat(40), "</a>".repeat(40));
    assert!(appstream(&xml(&deep), "org.example.Test").is_err());
}
#[test]
fn screenshot_count_bounded() {
    let shots = format!("<screenshots>{}</screenshots>", "<screenshot/>".repeat(9));
    assert!(appstream(&xml(&shots), "org.example.Test").is_err());
}
#[test]
fn unsafe_urls_rejected() {
    for url in [
        "javascript:alert(1)",
        "data:image/png;base64,foo",
        "file:///tmp/x",
        "ftp://example.com/x",
        "http://example.com/x",
        "https://localhost/x",
        "https://localhost./x",
        "https://127.0.0.1/x",
        "https://2130706433/x",
        "https://10.0.0.1/x",
        "https://[::1]/x",
        "https://192.168.1.1/x",
        "https://foo.local/x",
        "https://user:pass@example.com/x",
    ] {
        assert!(public_url(url).is_none(), "{url}");
    }
    assert!(public_url("https://example.com/image.png").is_some());
}
#[test]
fn screenshot_and_icon_urls_are_validated() {
    let m=appstream(&xml("<screenshots><screenshot><image>javascript:alert(1)</image></screenshot><screenshot><image>https://10.0.0.1/image.png</image></screenshot></screenshots><icon type='remote'>file:///x</icon>"),"org.example.Test").unwrap();
    assert!(m.screenshots.is_empty());
    assert!(m.icon_url.is_none());
}
#[test]
fn svg_cannot_be_served_as_an_icon() {
    assert!(!validate_png(b"<svg onload='alert(1)'/>"));
    assert!(!validate_png(b"<html>bad</html>"));
}
#[test]
fn permissions_come_from_deployed_context() {
    let p=permissions("[Application]\nname=org.example.Test\n[Context]\nshared=network;ipc;\nsockets=wayland;\nfilesystems=xdg-download:ro;\ndevices=dri;\n[Session Bus Policy]\norg.example.Service=talk\n").unwrap();
    assert!(p.network);
    assert_eq!(p.filesystem, vec!["xdg-download:ro"]);
    assert_eq!(p.sockets, vec!["wayland"]);
    assert_eq!(p.devices, vec!["dri"]);
    assert!(p.dbus[0].contains("org.example.Service=talk"));
}
#[test]
fn categories_normalize_and_deduplicate() {
    assert_eq!(
        categories(["Game", "Games", "Unknown", "Utility"].map(str::to_owned)),
        vec!["Games", "Utility"]
    );
}
#[test]
fn search_tokens_are_literal_and_bounded() {
    assert_eq!(
        search_expression("foo OR \"bar\":*").unwrap(),
        "\"foo\"* AND \"OR\"* AND \"bar\"*"
    );
    assert!(search_expression(&"a".repeat(201)).is_err());
    assert!(search_expression(&"a ".repeat(17)).is_err());
    assert_eq!(search_expression("").unwrap(), "");
}
#[test]
fn desktop_fallback_uses_standard_keys() {
    let m=desktop("[Desktop Entry]\nName=Tool\nComment=Useful\nCategories=Utility;Unknown;\nKeywords=work;tool;\nExec=evil\nIcon=../../evil.svg","org.example.Test").unwrap();
    assert_eq!(m.name, "Tool");
    assert_eq!(m.categories, vec!["Utility"]);
    assert!(m.icon_url.is_none());
}
#[test]
fn unicode_truncation_is_safe() {
    assert_eq!(bounded_text("ééé", 3), "é");
}

#[test]
fn mixed_description_text_keeps_document_order() {
    let m = appstream(
        &xml("<description><p>First <em>middle</em> last.</p></description>"),
        "org.example.Test",
    )
    .unwrap();
    assert_eq!(m.description, "First middle last.");
}
#[test]
fn multiple_document_roots_are_rejected() {
    assert!(
        appstream(
            &format!("{}{}", xml("<name>One</name>"), xml("<name>Two</name>")),
            "org.example.Test"
        )
        .is_err()
    );
}
