//! Conservative standalone-manifest validation. Execution remains a trust boundary.
use librehub_common::{FlatpakManifest, ManifestFormat, ValidationError, ValidationResult};
use serde_json::Value;

pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 32;

fn error(errors: &mut Vec<ValidationError>, field: &str, code: &str, message: &str) {
    if errors.len() >= 100 {
        return;
    }
    errors.push(ValidationError {
        field: field.into(),
        code: code.into(),
        message: message.into(),
    });
}

pub fn validate(input: &str, format: ManifestFormat) -> Result<FlatpakManifest, ValidationResult> {
    let mut errors = Vec::new();
    if input.len() > MAX_MANIFEST_BYTES {
        error(
            &mut errors,
            "$",
            "manifest_too_large",
            "Manifest exceeds 1 MiB",
        );
        return Err(ValidationResult {
            valid: false,
            errors,
        });
    }
    if matches!(format, ManifestFormat::Yaml)
        && let Err((code, message)) = check_yaml_structure(input)
    {
        error(&mut errors, "$", code, &message);
        return Err(ValidationResult {
            valid: false,
            errors,
        });
    }
    let parsed = match format {
        ManifestFormat::Json => serde_json::from_str::<Value>(input).map_err(|e| e.to_string()),
        ManifestFormat::Yaml => serde_yaml_ng::from_str::<Value>(input).map_err(|e| e.to_string()),
    };
    let value = match parsed {
        Ok(value) => value,
        Err(message) => {
            error(&mut errors, "$", "invalid_syntax", &message);
            return Err(ValidationResult {
                valid: false,
                errors,
            });
        }
    };
    let Some(root) = value.as_object() else {
        error(
            &mut errors,
            "$",
            "invalid_manifest",
            "Manifest must be an object",
        );
        return Err(ValidationResult {
            valid: false,
            errors,
        });
    };
    for key in ["app-id", "runtime", "runtime-version", "sdk", "command"] {
        let candidate = if key == "app-id" {
            root.get(key).or_else(|| root.get("id"))
        } else {
            root.get(key)
        };
        match candidate.and_then(Value::as_str) {
            Some(s) if !s.trim().is_empty() => {
                let valid = match key {
                    "app-id" | "runtime" | "sdk" => valid_app_id(s),
                    _ => safe_component(s),
                };
                if !valid {
                    error(
                        &mut errors,
                        key,
                        if key == "app-id" {
                            "invalid_app_id"
                        } else {
                            "invalid_field"
                        },
                        if matches!(key, "app-id" | "runtime" | "sdk") {
                            "Identifier must use reverse-DNS notation (at least three components)"
                        } else {
                            "Value must be a safe, nonempty name without paths or whitespace"
                        },
                    );
                }
            }
            _ => error(
                &mut errors,
                key,
                "required_field",
                "Required nonempty string is missing or has the wrong type",
            ),
        }
    }
    if let Some(branch) = root.get("branch")
        && !branch.as_str().is_some_and(safe_component)
    {
        error(
            &mut errors,
            "branch",
            "invalid_branch",
            "Branch must be a safe name without paths or command flags",
        );
    }
    if root.contains_key("app-id") && root.contains_key("id") {
        error(
            &mut errors,
            "app-id",
            "duplicate_app_id",
            "Specify app-id or id, not both",
        );
    }
    if let Some(branch) = root.get("branch")
        && !branch.as_str().is_some_and(safe_component)
    {
        error(
            &mut errors,
            "branch",
            "invalid_branch",
            "Branch must be a safe name",
        );
    }
    match root.get("modules").and_then(Value::as_array) {
        Some(modules) if !modules.is_empty() => check_modules(modules, "modules", 0, &mut errors),
        _ => error(
            &mut errors,
            "modules",
            "required_field",
            "At least one inline module is required",
        ),
    }
    check_options(&value, "$", 0, &mut errors);
    if errors.is_empty() {
        match serde_json::from_value(value) {
            Ok(manifest) => return Ok(manifest),
            Err(e) => error(&mut errors, "$", "invalid_definition", &e.to_string()),
        }
    }
    // A bounded response even for a manifest with thousands of invalid fields.
    errors.truncate(100);
    Err(ValidationResult {
        valid: false,
        errors,
    })
}

// Scan before deserialization: aliases can expand tiny YAML into unbounded object graphs.
fn check_yaml_structure(input: &str) -> Result<(), (&'static str, String)> {
    use yaml_rust2::scanner::{Scanner, TokenType};
    let mut scanner = Scanner::new(input.chars());
    let mut depth = 0_usize;
    let mut count = 0;
    for token in scanner.by_ref() {
        count += 1;
        if count > 50_000 {
            return Err(("too_complex", "YAML exceeds 50,000 tokens".into()));
        }
        match token.1 {
            TokenType::Alias(_) | TokenType::Anchor(_) => {
                return Err((
                    "yaml_alias_unsupported",
                    "YAML anchors and aliases are unsupported; use inline definitions".into(),
                ));
            }
            TokenType::BlockSequenceStart
            | TokenType::BlockMappingStart
            | TokenType::FlowSequenceStart
            | TokenType::FlowMappingStart => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(("too_deep", "Manifest nesting exceeds 32 levels".into()));
                }
            }
            TokenType::BlockEnd | TokenType::FlowSequenceEnd | TokenType::FlowMappingEnd => {
                depth = depth.saturating_sub(1)
            }
            _ => {}
        }
    }
    if let Some(error) = scanner.get_error() {
        return Err(("invalid_syntax", error.to_string()));
    }
    Ok(())
}

pub fn valid_app_id(id: &str) -> bool {
    if id.len() > 255 {
        return false;
    }
    let parts: Vec<_> = id.split('.').collect();
    parts.len() >= 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.as_bytes()[0].is_ascii_alphabetic()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}
fn safe_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s != "."
        && s != ".."
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn safe_path(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('/')
        && !s.contains(['\\', ':', '\0'])
        && s.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}
fn check_modules(modules: &[Value], field: &str, depth: usize, errors: &mut Vec<ValidationError>) {
    if depth > MAX_DEPTH || errors.len() >= 100 {
        return;
    }
    let mut names = std::collections::HashSet::new();
    for (i, module) in modules.iter().enumerate() {
        if errors.len() >= 100 {
            break;
        }
        let path = format!("{field}[{i}]");
        let Some(module) = module.as_object() else {
            error(
                errors,
                &path,
                "invalid_module",
                "Modules must be inline objects; included files are unsupported",
            );
            continue;
        };
        match module.get("name").and_then(Value::as_str) {
            Some(name) if safe_component(name) => {
                if !names.insert(name) {
                    error(
                        errors,
                        &format!("{path}.name"),
                        "duplicate_module",
                        "Module names must be unique among siblings",
                    );
                }
            }
            _ => error(
                errors,
                &format!("{path}.name"),
                "invalid_module_name",
                "Module requires a safe name",
            ),
        }
        if let Some(nested) = module.get("modules") {
            match nested.as_array() {
                Some(nested) => {
                    check_modules(nested, &format!("{path}.modules"), depth + 1, errors)
                }
                None => error(
                    errors,
                    &path,
                    "invalid_module",
                    "Nested modules must be an array",
                ),
            }
        }
        if let Some(commands) = module.get("build-commands")
            && !commands.as_array().is_some_and(|a| {
                a.iter()
                    .all(|v| v.as_str().is_some_and(|s| !s.trim().is_empty()))
            })
        {
            error(
                errors,
                &format!("{path}.build-commands"),
                "invalid_commands",
                "Build commands must be an array of nonempty strings",
            );
        }
        if let Some(system) = module.get("buildsystem")
            && !system.as_str().is_some_and(|s| {
                [
                    "autotools",
                    "cmake",
                    "cmake-ninja",
                    "meson",
                    "simple",
                    "qmake",
                ]
                .contains(&s)
            })
        {
            error(
                errors,
                &format!("{path}.buildsystem"),
                "unsupported_buildsystem",
                "Unsupported Flatpak build system",
            );
        }
        if let Some(sources) = module.get("sources") {
            match sources.as_array() {
                Some(sources) => {
                    for (j, source) in sources.iter().enumerate() {
                        check_source(source, &format!("{path}.sources[{j}]"), errors);
                    }
                }
                None => error(
                    errors,
                    &format!("{path}.sources"),
                    "invalid_sources",
                    "Sources must be an array",
                ),
            }
        }
    }
}
fn check_source(source: &Value, field: &str, errors: &mut Vec<ValidationError>) {
    let Some(source) = source.as_object() else {
        error(
            errors,
            field,
            "invalid_source",
            "Sources must be inline objects",
        );
        return;
    };
    let kind = source.get("type").and_then(Value::as_str).unwrap_or("");
    if ![
        "archive", "git", "file", "script", "inline", "patch", "shell",
    ]
    .contains(&kind)
    {
        error(
            errors,
            field,
            "unsupported_source",
            "Unsupported or missing source type",
        );
        return;
    }
    if let Some(url) = source.get("url")
        && !url.as_str().is_some_and(|s| {
            s.strip_prefix("https://").is_some_and(|rest| {
                !rest.is_empty()
                    && !rest.starts_with('/')
                    && !rest.contains(['@', '\\', '\n', '\r', ' '])
            })
        })
    {
        error(
            errors,
            &format!("{field}.url"),
            "unsafe_url",
            "Only HTTPS source URLs without embedded credentials are supported",
        );
    }
    match kind {
        "archive" | "git" | "file" | "patch" => {
            if !source.get("url").is_some_and(Value::is_string) {
                error(
                    errors,
                    &format!("{field}.url"),
                    "required_field",
                    "A remote URL is required; local files are not accepted in M1",
                );
            }
            if kind != "git"
                && !source
                    .get("sha256")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                error(
                    errors,
                    &format!("{field}.sha256"),
                    "invalid_checksum",
                    "Remote file sources require a 64-character SHA-256 checksum",
                );
            }
        }
        "inline" => {
            for key in ["contents", "dest-filename"] {
                if !source.get(key).is_some_and(Value::is_string) {
                    error(
                        errors,
                        &format!("{field}.{key}"),
                        "required_field",
                        "Inline source requires contents and dest-filename strings",
                    );
                }
            }
        }
        "script" | "shell"
            if !source
                .get("commands")
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty() && a.iter().all(Value::is_string)) =>
        {
            error(
                errors,
                &format!("{field}.commands"),
                "invalid_commands",
                "Source requires a nonempty commands array",
            );
        }
        _ => {}
    }
}
fn check_options(value: &Value, field: &str, depth: usize, errors: &mut Vec<ValidationError>) {
    if errors.len() >= 100 {
        return;
    }
    if depth > MAX_DEPTH {
        error(
            errors,
            field,
            "too_deep",
            "Manifest nesting exceeds 32 levels",
        );
        return;
    }
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                let path = format!("{field}.{key}");
                if [
                    "build-args",
                    "build-runtime",
                    "build-extension",
                    "base",
                    "base-version",
                    "add-extensions",
                    "inherit-extensions",
                    "extra-data",
                ]
                .contains(&key.as_str())
                {
                    error(
                        errors,
                        &path,
                        "unsupported_option",
                        "Option is unsupported for standalone M1 application builds",
                    );
                }
                if ["path", "paths", "include"].contains(&key.as_str()) {
                    error(
                        errors,
                        &path,
                        "local_path_unsupported",
                        "M1 accepts standalone manifests without local file references",
                    );
                }
                if ["dest", "dest-filename", "subdir"].contains(&key.as_str())
                    && !val.as_str().is_some_and(safe_path)
                {
                    error(
                        errors,
                        &path,
                        "unsafe_path",
                        "Destination must be relative without parent traversal",
                    );
                }
                if key == "finish-args" {
                    match val.as_array() {
                        Some(args) => {
                            for arg in args {
                                if !arg.as_str().is_some_and(|s| {
                                    s.starts_with("--")
                                        && !s.contains(['\n', '\0'])
                                        && !s.starts_with("--filesystem=")
                                }) {
                                    error(
                                        errors,
                                        &path,
                                        "unsafe_finish_arg",
                                        "Finish arguments must be flags; filesystem grants are unsupported in M1",
                                    );
                                }
                            }
                        }
                        None => error(
                            errors,
                            &path,
                            "invalid_finish_args",
                            "Finish arguments must be an array",
                        ),
                    }
                }
                check_options(val, &path, depth + 1, errors);
            }
        }
        Value::Array(values) => {
            for (i, val) in values.iter().enumerate() {
                check_options(val, &format!("{field}[{i}]"), depth + 1, errors);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const MANIFEST: &str = include_str!("../../../examples/org.librehub.Hello.json");
    #[test]
    fn valid_json_and_yaml() {
        let json = validate(MANIFEST, ManifestFormat::Json).unwrap();
        let yaml = serde_yaml_ng::to_string(&json).unwrap();
        assert_eq!(
            validate(&yaml, ManifestFormat::Yaml).unwrap().app_id,
            "org.librehub.Hello"
        );
    }
    #[test]
    fn syntax_errors_are_structured() {
        for (input, format) in [("{", ManifestFormat::Json), ("a: [", ManifestFormat::Yaml)] {
            assert_eq!(
                validate(input, format).unwrap_err().errors[0].code,
                "invalid_syntax"
            );
        }
    }
    #[test]
    fn invalid_ids() {
        for id in [
            "hello",
            "org..Hello",
            "org.test.2bad",
            "../etc/passwd",
            "org.test.Hello;rm",
        ] {
            assert!(!valid_app_id(id));
        }
        assert!(valid_app_id("org.example.Hello"));
    }
    #[test]
    fn collects_missing_fields() {
        let result = validate("{}", ManifestFormat::Json).unwrap_err();
        assert_eq!(result.errors.len(), 6);
        assert!(result.errors.iter().any(|e| e.field == "sdk"));
    }
    #[test]
    fn rejects_malformed_modules_and_unsafe_options() {
        for replacement in [
            serde_json::json!(["external.json"]),
            serde_json::json!([{"name":"../escape"}]),
            serde_json::json!([{"name":"a","sources":[{"type":"file","path":"/etc/passwd"}]}]),
            serde_json::json!([{"name":"a","build-options":{"build-args":["--filesystem=host"]}}]),
        ] {
            let mut value: Value = serde_json::from_str(MANIFEST).unwrap();
            value["modules"] = replacement;
            assert!(validate(&value.to_string(), ManifestFormat::Json).is_err());
        }
    }
    #[test]
    fn rejects_traversal_and_insecure_downloads() {
        for source in [
            serde_json::json!({"type":"inline","contents":"x","dest-filename":"../bad"}),
            serde_json::json!({"type":"git","url":"file:///home/secret"}),
        ] {
            let mut value: Value = serde_json::from_str(MANIFEST).unwrap();
            value["modules"][0]["sources"] = serde_json::json!([source]);
            assert!(validate(&value.to_string(), ManifestFormat::Json).is_err());
        }
    }
    #[test]
    fn rejects_yaml_alias_expansion_and_excessive_nesting() {
        let aliases = "a: &a [x, x]\nb: [*a, *a]\n";
        assert_eq!(
            validate(aliases, ManifestFormat::Yaml).unwrap_err().errors[0].code,
            "yaml_alias_unsupported"
        );
        let deeply_nested = format!("{}0{}", "[".repeat(40), "]".repeat(40));
        assert_eq!(
            validate(&deeply_nested, ManifestFormat::Yaml)
                .unwrap_err()
                .errors[0]
                .code,
            "too_deep"
        );
        // Quoted shell syntax is a scalar, not a YAML alias.
        assert!(check_yaml_structure("commands: ['echo *', 'echo &']").is_ok());
    }
    #[test]
    fn supports_id_alias() {
        assert!(validate(&MANIFEST.replace("app-id", "id"), ManifestFormat::Json).is_ok());
    }
}
