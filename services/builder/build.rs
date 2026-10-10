//! Record the trusted executor implementation revision separately from the worker image.
fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = std::process::Command::new("git")
        .current_dir(&root)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("Git build identity");
    assert!(
        output.status.success(),
        "Cannot determine builder implementation revision"
    );
    let revision = String::from_utf8(output.stdout).expect("Git revision UTF-8");
    println!(
        "cargo:rustc-env=LIBREHUB_BUILDER_REVISION={}",
        revision.trim()
    );
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs");
    println!("cargo:rerun-if-changed=../../.git/index");
}
