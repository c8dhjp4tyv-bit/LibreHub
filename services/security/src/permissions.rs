//! Flatpak permission snapshotting and release-to-release permission diffing.
//! Neutral severity heuristics categorize changes without claiming malicious intent.
use librehub_common::{
    NetworkChange, PermissionDiff, PermissionSeverity, PermissionSnapshot, Timestamp,
};
use std::collections::BTreeSet;

/// Parse Flatpak permissions from deployed /metadata file content.
pub fn parse_permission_snapshot(text: &str) -> anyhow::Result<PermissionSnapshot> {
    anyhow::ensure!(
        text.len() <= 128 * 1024,
        "Metadata file size limit exceeded"
    );
    let mut snapshot = PermissionSnapshot::default();
    let mut section = "";
    let mut count = 0;

    for line in text.lines().map(str::trim) {
        if line.starts_with('[') && line.ends_with(']') {
            section = line;
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if ["[Session Bus Policy]", "[System Bus Policy]"].contains(&section) {
                count += 1;
                anyhow::ensure!(count <= 512, "Permission entry limit exceeded");
                snapshot.dbus.push(format!(
                    "{}: {}={}",
                    section.trim_matches(['[', ']']),
                    key,
                    value
                ));
            } else if section == "[Context]" {
                for v in value.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                    count += 1;
                    anyhow::ensure!(count <= 512, "Permission entry limit exceeded");
                    match key {
                        "shared" => {
                            if v == "network" {
                                snapshot.network = true;
                            }
                            if !snapshot.shared.contains(&v.to_string()) {
                                snapshot.shared.push(v.to_string());
                            }
                        }
                        "filesystems" => {
                            if !snapshot.filesystem.contains(&v.to_string()) {
                                snapshot.filesystem.push(v.to_string());
                            }
                        }
                        "devices" => {
                            if !snapshot.devices.contains(&v.to_string()) {
                                snapshot.devices.push(v.to_string());
                            }
                        }
                        "sockets" => {
                            if !snapshot.sockets.contains(&v.to_string()) {
                                snapshot.sockets.push(v.to_string());
                            }
                        }
                        _ => {
                            let entry = format!("{key}={v}");
                            if !snapshot.other.contains(&entry) {
                                snapshot.other.push(entry);
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort vectors for deterministic comparison
    snapshot.filesystem.sort();
    snapshot.devices.sort();
    snapshot.sockets.sort();
    snapshot.dbus.sort();
    snapshot.shared.sort();
    snapshot.other.sort();

    Ok(snapshot)
}

/// Compute structured permission diff between previous release and current release.
pub fn diff_permissions(
    from_publication_id: Option<String>,
    to_publication_id: String,
    prev: Option<&PermissionSnapshot>,
    curr: &PermissionSnapshot,
    now: Timestamp,
) -> PermissionDiff {
    let empty = PermissionSnapshot::default();
    let old = prev.unwrap_or(&empty);

    let mut added = PermissionSnapshot::default();
    let mut removed = PermissionSnapshot::default();
    let mut notes = Vec::new();

    let net_change = if old.network != curr.network {
        let change = NetworkChange {
            from: old.network,
            to: curr.network,
        };
        if curr.network {
            added.network = true;
            notes.push("Network access was added.".into());
        } else {
            removed.network = true;
            notes.push("Network access was removed.".into());
        }
        Some(change)
    } else {
        None
    };

    diff_list(
        &old.filesystem,
        &curr.filesystem,
        &mut added.filesystem,
        &mut removed.filesystem,
    );
    diff_list(
        &old.devices,
        &curr.devices,
        &mut added.devices,
        &mut removed.devices,
    );
    diff_list(
        &old.sockets,
        &curr.sockets,
        &mut added.sockets,
        &mut removed.sockets,
    );
    diff_list(&old.dbus, &curr.dbus, &mut added.dbus, &mut removed.dbus);
    diff_list(
        &old.shared,
        &curr.shared,
        &mut added.shared,
        &mut removed.shared,
    );
    diff_list(
        &old.other,
        &curr.other,
        &mut added.other,
        &mut removed.other,
    );

    // Build human-readable neutral notes
    for fs in &added.filesystem {
        if ["host", "host-os", "host-etc", "home"]
            .iter()
            .any(|b| fs.starts_with(b))
        {
            notes.push(format!("Broad filesystem access added: '{fs}'."));
        } else {
            notes.push(format!("Filesystem access added: '{fs}'."));
        }
    }
    for fs in &removed.filesystem {
        notes.push(format!("Filesystem access removed: '{fs}'."));
    }
    for dev in &added.devices {
        notes.push(format!("Device access added: '{dev}'."));
    }
    for dev in &removed.devices {
        notes.push(format!("Device access removed: '{dev}'."));
    }
    for sock in &added.sockets {
        notes.push(format!("Socket access added: '{sock}'."));
    }
    for sock in &removed.sockets {
        notes.push(format!("Socket access removed: '{sock}'."));
    }
    for dbus in &added.dbus {
        notes.push(format!("D-Bus policy added: '{dbus}'."));
    }
    for dbus in &removed.dbus {
        notes.push(format!("D-Bus policy removed: '{dbus}'."));
    }

    let severity = categorize_severity(prev.is_some(), &added, net_change.as_ref(), &removed);

    PermissionDiff {
        from_publication_id,
        to_publication_id,
        severity,
        added,
        removed,
        changed_network: net_change,
        summary_notes: notes,
        generated_at: now,
    }
}

fn diff_list(old: &[String], new: &[String], added: &mut Vec<String>, removed: &mut Vec<String>) {
    let old_set: BTreeSet<&str> = old.iter().map(String::as_str).collect();
    let new_set: BTreeSet<&str> = new.iter().map(String::as_str).collect();

    for item in new_set.difference(&old_set) {
        added.push((*item).to_string());
    }
    for item in old_set.difference(&new_set) {
        removed.push((*item).to_string());
    }
}

/// Categorize severity into neutral levels: none, low, moderate, significant.
///
/// Significant: Broad access introductions (e.g. broad filesystem access like home/host,
/// device access, or new network enablement).
/// Moderate: Specific folder access (xdg-*), desktop display sockets, session D-Bus.
/// Low: Minor flag additions or permission restrictions/removals.
/// None: No permission changes.
fn categorize_severity(
    has_previous: bool,
    added: &PermissionSnapshot,
    net_change: Option<&NetworkChange>,
    removed: &PermissionSnapshot,
) -> PermissionSeverity {
    if !has_previous {
        return PermissionSeverity::None;
    }

    let has_any_addition = added.network
        || !added.filesystem.is_empty()
        || !added.devices.is_empty()
        || !added.sockets.is_empty()
        || !added.dbus.is_empty()
        || !added.shared.is_empty()
        || !added.other.is_empty();

    let has_any_removal = removed.network
        || !removed.filesystem.is_empty()
        || !removed.devices.is_empty()
        || !removed.sockets.is_empty()
        || !removed.dbus.is_empty()
        || !removed.shared.is_empty()
        || !removed.other.is_empty();

    if !has_any_addition && !has_any_removal {
        return PermissionSeverity::None;
    }

    // Significant:
    // 1. Network access turned ON
    if let Some(net) = net_change
        && !net.from
        && net.to
    {
        return PermissionSeverity::Significant;
    }

    // 2. Broad filesystem access
    for fs in &added.filesystem {
        if ["host", "host-os", "host-etc", "home"]
            .iter()
            .any(|b| fs.starts_with(b))
        {
            return PermissionSeverity::Significant;
        }
    }

    // 3. Device access (all, dri, kvm, etc)
    if !added.devices.is_empty() {
        return PermissionSeverity::Significant;
    }

    // 4. System bus policy
    for dbus in &added.dbus {
        if dbus.starts_with("System Bus Policy") {
            return PermissionSeverity::Significant;
        }
    }

    // Moderate:
    // 1. Specific filesystems (xdg-*)
    if !added.filesystem.is_empty() {
        return PermissionSeverity::Moderate;
    }

    // 2. Sockets (x11, wayland, pulseaudio)
    if !added.sockets.is_empty() {
        return PermissionSeverity::Moderate;
    }

    // 3. Session bus
    if !added.dbus.is_empty() {
        return PermissionSeverity::Moderate;
    }

    // Low:
    // Other additions or only removals
    PermissionSeverity::Low
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    const SAMPLE_METADATA: &str = r#"
[Application]
name=org.librehub.Hello
runtime=runtime/org.freedesktop.Platform/x86_64/25.08
sdk=runtime/org.freedesktop.Sdk/x86_64/25.08
command=hello

[Context]
shared=network;ipc;
sockets=wayland;x11;
devices=dri;
filesystems=xdg-download;~/Documents;

[Session Bus Policy]
org.freedesktop.Notifications=talk

[System Bus Policy]
org.freedesktop.NetworkManager=see
"#;

    #[test]
    fn parses_metadata_into_snapshot() {
        let snap = parse_permission_snapshot(SAMPLE_METADATA).expect("Valid metadata");
        assert!(snap.network);
        assert_eq!(snap.devices, vec!["dri"]);
        assert_eq!(snap.sockets, vec!["wayland", "x11"]);
        assert_eq!(snap.filesystem, vec!["xdg-download", "~/Documents"]);
        assert_eq!(snap.shared, vec!["ipc", "network"]);
        assert_eq!(
            snap.dbus,
            vec![
                "Session Bus Policy: org.freedesktop.Notifications=talk",
                "System Bus Policy: org.freedesktop.NetworkManager=see"
            ]
        );
    }

    #[test]
    fn diffs_significant_filesystem_addition() {
        let now = Utc::now();
        let prev = PermissionSnapshot {
            network: false,
            filesystem: vec!["xdg-download".into()],
            ..Default::default()
        };
        let curr = PermissionSnapshot {
            network: false,
            filesystem: vec!["home".into(), "xdg-download".into()],
            ..Default::default()
        };

        let diff = diff_permissions(
            Some("pub-1".into()),
            "pub-2".into(),
            Some(&prev),
            &curr,
            now,
        );

        assert_eq!(diff.severity, PermissionSeverity::Significant);
        assert_eq!(diff.added.filesystem, vec!["home"]);
        assert!(diff.removed.filesystem.is_empty());
        assert!(diff.summary_notes.iter().any(|n| n.contains("home")));
    }

    #[test]
    fn diffs_network_enabled() {
        let now = Utc::now();
        let prev = PermissionSnapshot {
            network: false,
            ..Default::default()
        };
        let curr = PermissionSnapshot {
            network: true,
            ..Default::default()
        };

        let diff = diff_permissions(
            Some("pub-1".into()),
            "pub-2".into(),
            Some(&prev),
            &curr,
            now,
        );

        assert_eq!(diff.severity, PermissionSeverity::Significant);
        assert!(diff.added.network);
        assert_eq!(
            diff.changed_network,
            Some(NetworkChange {
                from: false,
                to: true
            })
        );
    }

    #[test]
    fn diffs_moderate_socket_addition() {
        let now = Utc::now();
        let prev = PermissionSnapshot::default();
        let curr = PermissionSnapshot {
            sockets: vec!["wayland".into()],
            ..Default::default()
        };

        let diff = diff_permissions(
            Some("pub-1".into()),
            "pub-2".into(),
            Some(&prev),
            &curr,
            now,
        );

        assert_eq!(diff.severity, PermissionSeverity::Moderate);
        assert_eq!(diff.added.sockets, vec!["wayland"]);
    }

    #[test]
    fn diffs_low_for_removals() {
        let now = Utc::now();
        let prev = PermissionSnapshot {
            network: true,
            filesystem: vec!["home".into()],
            ..Default::default()
        };
        let curr = PermissionSnapshot {
            network: true,
            ..Default::default()
        };

        let diff = diff_permissions(
            Some("pub-1".into()),
            "pub-2".into(),
            Some(&prev),
            &curr,
            now,
        );

        assert_eq!(diff.severity, PermissionSeverity::Low);
        assert_eq!(diff.removed.filesystem, vec!["home"]);
    }
}
