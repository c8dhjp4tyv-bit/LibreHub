use base64::{Engine, engine::general_purpose::STANDARD};
use librehub_common::*;
use librehub_supply_chain::*;
fn fixture() -> ProvenanceStatement {
    serde_json::from_str(include_str!("fixtures/build.json")).unwrap()
}
fn signer() -> (tempfile::TempDir, Attestor, KeyBundle) {
    let tmp = tempfile::tempdir().unwrap();
    let seed = tmp.path().join("seed");
    let bundle = tmp.path().join("keys");
    let keys = provision(&seed, &bundle).unwrap();
    let signer = Attestor::new(seed, bundle).unwrap();
    (tmp, signer, keys)
}
fn release(build: &ProvenanceStatement) -> ProvenanceStatement {
    let ProvenancePredicate::Build(b) = &build.predicate else {
        panic!()
    };
    let e = &b.build_definition.external_parameters;
    ProvenanceStatement {
        statement_type: STATEMENT_V1.into(),
        predicate_type: RELEASE_V1.into(),
        subject: vec![AttestationSubject {
            name: build.subject[0].name.clone(),
            digest: digest("sha256", &"2".repeat(64)),
        }],
        predicate: ProvenancePredicate::Release(Box::new(ReleaseProvenance {
            publication_id: PublishId::new(),
            build_id: e.build_id,
            app_id: e.app_id.clone(),
            architecture: e.architecture,
            channel: "stable".into(),
            repository: "https://repo.example.org/stable".into(),
            flatpak_ref: build.subject[0].name.clone(),
            build_statement_sha256: sha256(&canonical(build).unwrap()),
            build_artifact_sha256: build.subject[0].digest["sha256"].clone(),
            source_ostree_commit: "3".repeat(64),
            sbom_sha256: "4".repeat(64),
            published_on: chrono::Utc::now(),
        })),
    }
}
#[test]
fn pae_uses_utf8_byte_lengths_and_no_trailing_separator() {
    assert_eq!(pae("é", b"hi"), b"DSSEv1 2 \xc3\xa9 2 hi");
    assert_eq!(pae("", b""), b"DSSEv1 0  0 ");
}
#[test]
fn real_ed25519_roundtrip_and_release_link() {
    let (_t, s, k) = signer();
    let b = fixture();
    let r = release(&b);
    let (be, h) = verify(&s.sign(&b).unwrap(), &k).unwrap();
    let (re, _) = verify(&s.sign(&r).unwrap(), &k).unwrap();
    verify_link(&re, &be, &h).unwrap();
    assert_ne!(be.subject[0].digest, re.subject[0].digest);
}
#[test]
fn signature_tampering_rejected() {
    let (_t, s, k) = signer();
    let mut e = s.sign(&fixture()).unwrap();
    e.signatures[0].sig = STANDARD.encode([0u8; 64]);
    assert!(
        verify(&e, &k)
            .unwrap_err()
            .to_string()
            .contains("signature_invalid")
    );
}
#[test]
fn payload_tampering_rejected() {
    let (_t, s, k) = signer();
    let mut e = s.sign(&fixture()).unwrap();
    let mut bytes = STANDARD.decode(&e.payload).unwrap();
    bytes[20] ^= 1;
    e.payload = STANDARD.encode(bytes);
    assert!(verify(&e, &k).is_err());
}
#[test]
fn unknown_and_wrong_keys_rejected() {
    let (_t, s, k) = signer();
    let (_u, _, other) = signer();
    let e = s.sign(&fixture()).unwrap();
    assert!(
        verify(&e, &other)
            .unwrap_err()
            .to_string()
            .contains("unknown_key")
    );
    let mut wrong = k;
    wrong.keys[0].public_key = other.keys[0].public_key.clone();
    assert!(verify(&e, &wrong).is_err());
}
#[test]
fn revoked_rejected_and_retired_preserves_history() {
    let (_t, s, mut k) = signer();
    let e = s.sign(&fixture()).unwrap();
    k.keys[0].state = KeyState::Retired;
    verify(&e, &k).unwrap();
    k.keys[0].state = KeyState::Revoked;
    assert!(
        verify(&e, &k)
            .unwrap_err()
            .to_string()
            .contains("revoked_key")
    );
}
#[test]
fn malformed_and_oversized_envelopes_rejected() {
    let (_t, s, k) = signer();
    let e = s.sign(&fixture()).unwrap();
    for change in 0..5 {
        let mut e = e.clone();
        match change {
            0 => e.payload_type = "application/json".into(),
            1 => e.payload = "!bad".into(),
            2 => e.signatures.clear(),
            3 => e.signatures.push(e.signatures[0].clone()),
            _ => e.payload = "A".repeat(MAX_ENVELOPE),
        }
        assert!(verify(&e, &k).is_err());
    }
}
#[test]
fn unsupported_schema_and_builder_rejected() {
    for path in [
        "/_type",
        "/predicateType",
        "/predicate/runDetails/builder/id",
        "/predicate/buildDefinition/buildType",
    ] {
        let mut value = serde_json::to_value(fixture()).unwrap();
        *value.pointer_mut(path).unwrap() = serde_json::json!("unsupported");
        let s: ProvenanceStatement = serde_json::from_value(value).unwrap();
        assert!(validate_statement(&s).is_err());
    }
}
#[test]
fn substituted_source_manifest_image_and_subject_rejected() {
    for path in [
        "/predicate/buildDefinition/externalParameters/source/revision/commit",
        "/predicate/buildDefinition/externalParameters/source/snapshot/sha256",
        "/predicate/buildDefinition/internalParameters/imageConfigDigest",
        "/subject/0/name",
        "/predicate/runDetails/metadata/invocationId",
    ] {
        let mut value = serde_json::to_value(fixture()).unwrap();
        let old = value.pointer(path).unwrap().as_str().unwrap().to_string();
        *value.pointer_mut(path).unwrap() =
            serde_json::json!(old.replace(['a', 'b', 'c', '1'], "9"));
        let s: ProvenanceStatement = serde_json::from_value(value).unwrap();
        assert!(validate_statement(&s).is_err(), "{path}");
    }
}
#[test]
fn cross_build_release_substitution_rejected() {
    let b = fixture();
    let mut r = release(&b);
    if let ProvenancePredicate::Release(p) = &mut r.predicate {
        p.build_id = BuildId::new();
    }
    assert!(verify_link(&r, &b, &sha256(&canonical(&b).unwrap())).is_err());
}
#[test]
fn changed_link_digests_and_app_rejected() {
    for field in [
        "buildStatementSha256",
        "buildArtifactSha256",
        "appId",
        "flatpakRef",
    ] {
        let b = fixture();
        let r = release(&b);
        let mut value = serde_json::to_value(r).unwrap();
        value["predicate"][field] = serde_json::json!("5".repeat(64));
        let r: ProvenanceStatement = serde_json::from_value(value).unwrap();
        assert!(verify_link(&r, &b, &sha256(&canonical(&b).unwrap())).is_err());
    }
}
#[test]
fn lost_key_never_regenerated() {
    let (t, s, _) = signer();
    std::fs::remove_file(t.path().join("seed")).unwrap();
    assert!(s.sign(&fixture()).is_err());
    assert!(!t.path().join("seed").exists());
}
#[test]
fn provisioning_never_replaces_key() {
    let (t, _, _) = signer();
    assert!(provision(&t.path().join("seed"), &t.path().join("keys")).is_err());
}
#[test]
fn mutable_git_sources_are_separate_from_observed_materials() {
    let mut manifest = librehub_validator::validate(
        include_str!("../../../examples/org.librehub.Hello.json"),
        ManifestFormat::Json,
    )
    .unwrap();
    manifest.modules[0].sources = vec![Source {
        kind: SourceKind::Git,
        options: std::collections::BTreeMap::from([
            (
                "url".into(),
                serde_json::json!("https://example.org/source.git"),
            ),
            ("branch".into(), serde_json::json!("main")),
        ]),
    }];
    assert!(!declared_dependencies(&manifest)[0].immutable);
    manifest.modules[0].sources[0]
        .options
        .insert("commit".into(), serde_json::json!("a".repeat(40)));
    assert!(declared_dependencies(&manifest)[0].immutable);
}
#[test]
fn openssl_independently_verifies_dsse_pae() {
    let (t, s, k) = signer();
    let e = s.sign(&fixture()).unwrap();
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend(STANDARD.decode(&k.keys[0].public_key).unwrap());
    std::fs::write(t.path().join("public.der"), der).unwrap();
    std::fs::write(
        t.path().join("pae"),
        pae(&e.payload_type, &STANDARD.decode(&e.payload).unwrap()),
    )
    .unwrap();
    std::fs::write(
        t.path().join("signature"),
        STANDARD.decode(&e.signatures[0].sig).unwrap(),
    )
    .unwrap();
    let status = std::process::Command::new("openssl")
        .current_dir(t.path())
        .args([
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            "public.der",
            "-keyform",
            "DER",
            "-rawin",
            "-in",
            "pae",
            "-sigfile",
            "signature",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}
