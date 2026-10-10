//! Capability/policy admission must fail before any worker starts, never downgrade.
use librehub_builder::{DockerConfig, DockerExecutor};
use librehub_common::IsolationPolicy;
#[test]
fn hardened_requires_podman() {
    assert!(
        DockerExecutor::new(DockerConfig {
            isolation: IsolationPolicy::Hardened,
            ..Default::default()
        })
        .is_err()
    );
}
#[test]
fn hardened_rejects_egress_and_unbounded_disk() {
    for (network, bytes) in [
        ("bridge", 1024),
        ("host", 1024),
        ("none", 0),
        ("none", u64::MAX),
    ] {
        assert!(
            DockerExecutor::new(DockerConfig {
                binary: "podman".into(),
                isolation: IsolationPolicy::Hardened,
                network: network.into(),
                writable_bytes: bytes,
                ..Default::default()
            })
            .is_err()
        );
    }
}
#[test]
fn compatibility_is_explicit() {
    assert!(
        DockerExecutor::new(DockerConfig {
            isolation: IsolationPolicy::Compatibility,
            ..Default::default()
        })
        .is_ok()
    );
}
