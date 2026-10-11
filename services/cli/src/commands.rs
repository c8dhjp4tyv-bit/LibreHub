//! Command implementations. Each one calls a real LibreHub endpoint.
use crate::{
    ApprovalCommand, AuthCommand, AutomationCommand, BuildCommand, CiArgs, CiOperation, Cli,
    Command, IntegrationCommand, Output, ProjectCommand, Provider, PublishCommand, Toggle,
    VerifyArgs,
    api::{Client, Secret},
    credentials,
    error::CliError,
    wait::{self, Poller},
};
use librehub_automation::workflow;
use reqwest::Method;
use serde_json::{Value, json};
use std::io::Read;

pub struct Context {
    pub client: Client,
    pub json: bool,
    pub timeout: u64,
    pub source: &'static str,
}

fn text(value: &Value, key: &str) -> String {
    match &value[key] {
        Value::String(s) => s.clone(),
        Value::Null => "-".into(),
        other => other.to_string(),
    }
}
fn table(headers: &[&str], rows: Vec<Vec<String>>) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let line = |cells: Vec<String>| {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{c:<w$}", w = widths[i]))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    let mut out = vec![line(headers.iter().map(|h| h.to_uppercase()).collect())];
    out.extend(rows.into_iter().map(line));
    out.join("\n")
}
fn rows(list: &Value, columns: &[&str]) -> Vec<Vec<String>> {
    list.as_array()
        .map(|a| {
            a.iter()
                .map(|item| columns.iter().map(|c| text(item, c)).collect())
                .collect()
        })
        .unwrap_or_default()
}
fn page(p: &crate::Page) -> Vec<(&'static str, String)> {
    vec![
        ("limit", p.limit.to_string()),
        ("offset", p.offset.to_string()),
    ]
}
fn uuid_arg(value: &str, what: &str) -> Result<String, CliError> {
    value
        .parse::<uuid::Uuid>()
        .map(|u| u.to_string())
        .map_err(|_| CliError::usage(format!("{what} must be a UUID")))
}
fn read_file(path: &std::path::Path, limit: u64) -> Result<String, CliError> {
    let meta = std::fs::metadata(path)
        .map_err(|e| CliError::usage(format!("Cannot read {}: {e}", path.display())))?;
    if meta.len() > limit {
        return Err(CliError::usage(format!(
            "{} is larger than {limit} bytes",
            path.display()
        )));
    }
    std::fs::read_to_string(path)
        .map_err(|e| CliError::usage(format!("Cannot read {}: {e}", path.display())))
}

/// Pick credentials: GitHub OIDC when asked for, otherwise a static token.
async fn establish(cli: &Cli, client: Client) -> Result<(Client, &'static str), CliError> {
    if let Some(project) = &cli.oidc_project {
        let audience = cli.oidc_audience.clone().ok_or_else(|| {
            CliError::usage(
                "--oidc-audience (or LIBREHUB_OIDC_AUDIENCE) is required with --oidc-project",
            )
        })?;
        let identity = credentials::github_identity_token(&audience).await?;
        let project = uuid_arg(project, "--oidc-project")?;
        let exchanged = credentials::exchange(&client, &project, &identity).await?;
        // Deliberately not stored: the credential lives only as long as this process.
        return Ok((client.with_token(Some(exchanged.token)), "github-oidc"));
    }
    if let Ok(token) = std::env::var("LIBREHUB_TOKEN")
        && !token.trim().is_empty()
    {
        credentials::mask(token.trim());
        return Ok((
            client.with_token(Some(Secret::new(token.trim()))),
            "environment",
        ));
    }
    if let Some(token) = credentials::load_stored(&client)? {
        return Ok((client.with_token(Some(token)), "stored"));
    }
    Ok((client, "none"))
}
fn need_auth(ctx: &Context) -> Result<(), CliError> {
    if ctx.client.has_token() {
        Ok(())
    } else {
        Err(CliError::Api { status: 401, code: "authentication_required".into(), message: "No credentials: run `librehub auth login`, set LIBREHUB_TOKEN or use --oidc-project in GitHub Actions".into() })
    }
}

pub async fn run(cli: Cli) -> Result<Output, CliError> {
    let client = Client::new(&cli.api_url, None)?;
    let (client, source) = establish(&cli, client).await?;
    let ctx = Context {
        client,
        json: cli.json,
        timeout: cli.timeout,
        source,
    };
    match cli.command {
        Command::Auth(c) => auth(&ctx, c).await,
        Command::Project(c) => project(&ctx, c).await,
        Command::Build(c) => build(&ctx, c).await,
        Command::Publish(c) => publish(&ctx, c).await,
        Command::Automation(c) => automation(&ctx, c).await,
        Command::Approval(c) => approval(&ctx, c).await,
        Command::Integration(c) => integration(&ctx, c).await,
        Command::Verify(a) => verify(&ctx, a).await,
        Command::Ci(a) => ci(&ctx, a).await,
    }
}

// ----------------------------------------------------------------------- auth
async fn auth(ctx: &Context, command: AuthCommand) -> Result<Output, CliError> {
    match command {
        AuthCommand::Login { token_stdin } => {
            let raw = if token_stdin {
                let mut buffer = String::new();
                std::io::stdin()
                    .take(1024)
                    .read_to_string(&mut buffer)
                    .map_err(|e| CliError::usage(e.to_string()))?;
                buffer
            } else {
                std::env::var("LIBREHUB_TOKEN").map_err(|_| CliError::usage("Pass --token-stdin and pipe the token on stdin (tokens are never accepted as arguments)"))?
            };
            let token = raw.trim();
            if !token.starts_with("librehub_")
                || token.len() > 160
                || token.contains(char::is_whitespace)
            {
                return Err(CliError::usage(
                    "That does not look like a LibreHub API token",
                ));
            }
            if credentials::in_github_actions() {
                return Err(CliError::usage(
                    "Refusing to store credentials inside a GitHub Actions job; use --oidc-project",
                ));
            }
            let secret = Secret::new(token);
            let who = ctx
                .client
                .with_token(Some(secret.clone()))
                .get("/api/v1/whoami", &[])
                .await?;
            let path = credentials::store(&ctx.client, &secret)?;
            Ok(Output {
                text: format!(
                    "Logged in to {} as developer {}\nCredentials saved to {} (mode 0600)",
                    credentials::origin_key(&ctx.client),
                    text(&who, "developer_id"),
                    path.display()
                ),
                value: json!({"logged_in":true,"developer_id":who["developer_id"],"scopes":who["scopes"],"credentials_file":path}),
            })
        }
        AuthCommand::Logout => {
            let removed = credentials::forget(&ctx.client)?;
            Ok(Output {
                text: if removed {
                    "Stored credentials removed".into()
                } else {
                    "No stored credentials for this server".into()
                },
                value: json!({"removed":removed}),
            })
        }
        AuthCommand::Status => {
            need_auth(ctx)?;
            let who = ctx.client.get("/api/v1/whoami", &[]).await?;
            let scopes = who["scopes"]
                .as_array()
                .map(|s| {
                    s.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            Ok(Output {
                text: format!(
                    "Authenticated via {}\ndeveloper: {}\nproject binding: {}\nscopes: {scopes}",
                    ctx.source,
                    text(&who, "developer_id"),
                    text(&who, "project_id")
                ),
                value: json!({"authenticated":true,"source":ctx.source,"api_url":credentials::origin_key(&ctx.client),"developer_id":who["developer_id"],"federated":who["federated"],"project_id":who["project_id"],"scopes":who["scopes"]}),
            })
        }
    }
}

// -------------------------------------------------------------------- project
async fn project(ctx: &Context, command: ProjectCommand) -> Result<Output, CliError> {
    need_auth(ctx)?;
    match command {
        ProjectCommand::List(p) => {
            let list = ctx.client.get("/api/v1/projects", &page(&p)).await?;
            Ok(Output {
                text: table(
                    &["id", "slug", "status", "default_branch"],
                    rows(&list, &["id", "slug", "status", "default_branch"]),
                ),
                value: list,
            })
        }
        ProjectCommand::Show { id } => {
            let p = ctx
                .client
                .get(
                    &format!("/api/v1/projects/{}", uuid_arg(&id, "project")?),
                    &[],
                )
                .await?;
            Ok(Output {
                text: serde_json::to_string_pretty(&p).unwrap_or_default(),
                value: p,
            })
        }
        ProjectCommand::Create {
            slug,
            name,
            repository,
            provider,
            default_branch,
            auto_build,
        } => {
            let body = json!({"slug":slug,"display_name":name,"repository":{"provider":match provider { Provider::Github => "github", Provider::Git => "git" },"url":repository},"default_branch":default_branch,"auto_build":auto_build});
            let (_, created) = ctx.client.post("/api/v1/projects", Some(&body)).await?;
            let secret = created["webhook_secret"].as_str().unwrap_or_default();
            credentials::mask(secret);
            Ok(Output {
                text: format!(
                    "Created project {}\nWebhook secret (shown once, configure it in GitHub): {secret}",
                    text(&created["project"], "id")
                ),
                value: created,
            })
        }
    }
}

// ---------------------------------------------------------------------- builds
const BUILD_TERMINAL: [&str; 3] = ["succeeded", "failed", "cancelled"];
async fn wait_build(ctx: &Context, id: &str) -> Result<Value, CliError> {
    let mut poller = Poller::new(ctx.timeout);
    loop {
        let build = ctx.client.get(&format!("/api/v1/builds/{id}"), &[]).await?;
        let status = build["status"].as_str().unwrap_or("");
        if BUILD_TERMINAL.contains(&status) {
            return if status == "succeeded" {
                Ok(build)
            } else {
                Err(CliError::Failed {
                    code: format!("build_{status}"),
                    message: format!("The build {status}"),
                })
            };
        }
        poller
            .tick(&format!("build {id} (currently {status})"))
            .await?;
    }
}
async fn build(ctx: &Context, command: BuildCommand) -> Result<Output, CliError> {
    need_auth(ctx)?;
    match command {
        BuildCommand::Trigger {
            project,
            reference,
            wait,
        } => {
            let project = uuid_arg(&project, "--project")?;
            let body = json!({"ref": reference});
            let body = if reference.is_some() { body } else { json!({}) };
            let (_, started) = ctx
                .client
                .post(&format!("/api/v1/projects/{project}/builds"), Some(&body))
                .await?;
            let build_id = text(&started, "build_id");
            if !wait {
                return Ok(Output {
                    text: format!(
                        "Build {build_id} queued (source event {})",
                        text(&started, "source_event_id")
                    ),
                    value: started,
                });
            }
            let event = text(&started, "source_event_id");
            let mut poller = Poller::new(ctx.timeout);
            loop {
                let e = ctx
                    .client
                    .get(
                        &format!("/api/v1/projects/{project}/source-events/{event}"),
                        &[],
                    )
                    .await?;
                match e["status"].as_str().unwrap_or("") {
                    "completed" => break,
                    "failed" | "ignored" => {
                        return Err(CliError::Failed {
                            code: e["error"]["code"]
                                .as_str()
                                .unwrap_or("source_failed")
                                .into(),
                            message: "Source processing failed".into(),
                        });
                    }
                    s => {
                        poller
                            .tick(&format!("source event {event} (currently {s})"))
                            .await?
                    }
                }
            }
            let finished = wait_build(ctx, &build_id).await?;
            Ok(Output {
                text: format!("Build {build_id} succeeded"),
                value: json!({"source_event":started,"build":finished}),
            })
        }
        BuildCommand::Status { id, wait } => {
            let id = uuid_arg(&id, "build")?;
            let build = if wait {
                wait_build(ctx, &id).await?
            } else {
                ctx.client.get(&format!("/api/v1/builds/{id}"), &[]).await?
            };
            Ok(Output {
                text: format!("build {id}: {}", text(&build, "status")),
                value: build,
            })
        }
        BuildCommand::Logs { id, follow, after } => {
            let id = uuid_arg(&id, "build")?;
            let mut after = after;
            let mut poller = Poller::new(ctx.timeout);
            let mut all = vec![];
            loop {
                let entries = ctx
                    .client
                    .get(
                        &format!("/api/v1/builds/{id}/logs"),
                        &[("after", after.to_string()), ("limit", "200".into())],
                    )
                    .await?;
                let list = entries.as_array().cloned().unwrap_or_default();
                for entry in &list {
                    after = entry["sequence"].as_u64().unwrap_or(after);
                    if ctx.json {
                        all.push(entry.clone());
                    } else {
                        // Log lines are build output; strip terminal control characters before display.
                        let line: String = text(entry, "message")
                            .chars()
                            .filter(|c| !c.is_control() || *c == '\t')
                            .collect();
                        println!("[{}] {line}", text(entry, "stream"));
                    }
                }
                if list.len() == 200 {
                    continue;
                }
                if !follow {
                    break;
                }
                let status = ctx.client.get(&format!("/api/v1/builds/{id}"), &[]).await?["status"]
                    .as_str()
                    .unwrap_or("")
                    .to_owned();
                if BUILD_TERMINAL.contains(&status.as_str()) {
                    // One more page after the terminal state captures the final lines.
                    let tail = ctx
                        .client
                        .get(
                            &format!("/api/v1/builds/{id}/logs"),
                            &[("after", after.to_string()), ("limit", "200".into())],
                        )
                        .await?;
                    if tail.as_array().is_none_or(|t| t.is_empty()) {
                        break;
                    }
                    continue;
                }
                poller.tick(&format!("build {id} logs")).await?;
            }
            Ok(Output {
                text: String::new(),
                value: Value::Array(all),
            })
        }
    }
}

async fn wait_publication(ctx: &Context, id: &str) -> Result<Value, CliError> {
    let mut poller = Poller::new(ctx.timeout);
    loop {
        let record = ctx
            .client
            .get(&format!("/api/v1/publishes/{id}"), &[])
            .await?;
        match record["status"].as_str().unwrap_or("") {
            "succeeded" => return Ok(record),
            s @ ("failed" | "cancelled") => {
                return Err(CliError::Failed {
                    code: format!("publication_{s}"),
                    message: record["error"]["message"]
                        .as_str()
                        .unwrap_or("The publication did not succeed")
                        .into(),
                });
            }
            s => {
                poller
                    .tick(&format!("publication {id} (currently {s})"))
                    .await?
            }
        }
    }
}
async fn publish(ctx: &Context, command: PublishCommand) -> Result<Output, CliError> {
    need_auth(ctx)?;
    let (build, channel, wait) = match command {
        PublishCommand::Beta { build, wait } => (build, "beta", wait),
        PublishCommand::Stable { build, yes, wait } => {
            if !yes {
                return Err(CliError::usage(
                    "Direct stable publication skips the approval workflow; pass --yes to confirm (or use an automation with an approval step)",
                ));
            }
            (build, "stable", wait)
        }
    };
    let build = uuid_arg(&build, "build")?;
    let (_, record) = ctx
        .client
        .post(
            &format!("/api/v1/builds/{build}/publish"),
            Some(&json!({"channel": channel})),
        )
        .await?;
    let id = text(&record, "id");
    let record = if wait {
        wait_publication(ctx, &id).await?
    } else {
        record
    };
    Ok(Output {
        text: format!("publication {id} ({channel}): {}", text(&record, "status")),
        value: record,
    })
}

// ----------------------------------------------------------------- automations
fn local_spec(path: &std::path::Path) -> Result<Value, CliError> {
    let spec = workflow::parse_workflow(&read_file(path, workflow::MAX_SPEC_BYTES as u64)?)
        .map_err(|e| CliError::usage(format!("{}: {e}", path.display())))?;
    serde_json::to_value(spec).map_err(|e| CliError::usage(e.to_string()))
}
fn run_summary(run: &Value) -> String {
    let mut lines = vec![format!(
        "run {}  {}  (automation v{}, trigger {})",
        text(run, "id"),
        text(run, "status"),
        text(run, "definition_version"),
        text(run, "trigger")
    )];
    lines.push(format!(
        "commit {}  build {}",
        text(run, "source_commit"),
        text(run, "build_id")
    ));
    for step in run["steps"].as_array().cloned().unwrap_or_default() {
        let mark = match step["status"].as_str().unwrap_or("") {
            "succeeded" => "✓",
            "failed" => "✗",
            "skipped" => "–",
            "cancelled" => "⊘",
            "waiting" => "…",
            "running" => "▶",
            _ => " ",
        };
        let note = step["error"]["code"]
            .as_str()
            .map(|c| format!("  [{c}]"))
            .unwrap_or_default();
        lines.push(format!(
            "  {mark} {:<16} {:<10}{note}",
            text(&step, "id"),
            text(&step, "status")
        ));
    }
    if let Some(code) = run["error"]["code"].as_str() {
        lines.push(format!("failure: {code}"));
    }
    lines.join("\n")
}
async fn resolve_automation(
    ctx: &Context,
    project: &str,
    automation: &str,
) -> Result<String, CliError> {
    if let Ok(id) = automation.parse::<uuid::Uuid>() {
        return Ok(id.to_string());
    }
    let list = ctx
        .client
        .get(
            &format!("/api/v1/projects/{project}/automations"),
            &[("limit", "100".into())],
        )
        .await?;
    list.as_array()
        .and_then(|a| a.iter().find(|x| x["name"] == automation))
        .map(|x| text(x, "id"))
        .ok_or_else(|| CliError::Api {
            status: 404,
            code: "automation_not_found".into(),
            message: format!("No automation named `{automation}`"),
        })
}
async fn automation(ctx: &Context, command: AutomationCommand) -> Result<Output, CliError> {
    if let AutomationCommand::Validate { file } = &command {
        let spec = local_spec(file)?;
        let steps = spec["steps"].as_array().map_or(0, |s| s.len());
        return Ok(Output {
            text: format!("{} is a valid workflow ({steps} steps)", file.display()),
            value: json!({"valid":true,"workflow":spec}),
        });
    }
    need_auth(ctx)?;
    match command {
        AutomationCommand::Validate { .. } => unreachable!("handled above"),
        AutomationCommand::List { project, page: p } => {
            let project = uuid_arg(&project, "--project")?;
            let list = ctx
                .client
                .get(
                    &format!("/api/v1/projects/{project}/automations"),
                    &page(&p),
                )
                .await?;
            Ok(Output {
                text: table(
                    &["id", "name", "enabled", "current_version"],
                    rows(&list, &["id", "name", "enabled", "current_version"]),
                ),
                value: list,
            })
        }
        AutomationCommand::Show {
            project,
            automation,
        } => {
            let project = uuid_arg(&project, "--project")?;
            let id = resolve_automation(ctx, &project, &automation).await?;
            let a = ctx
                .client
                .get(&format!("/api/v1/projects/{project}/automations/{id}"), &[])
                .await?;
            Ok(Output {
                text: serde_json::to_string_pretty(&a).unwrap_or_default(),
                value: a,
            })
        }
        AutomationCommand::Create { project, file } => {
            let project = uuid_arg(&project, "--project")?;
            let (_, created) = ctx
                .client
                .post(
                    &format!("/api/v1/projects/{project}/automations"),
                    Some(&json!({"spec": local_spec(&file)?})),
                )
                .await?;
            Ok(Output {
                text: format!(
                    "Created automation {} ({})",
                    text(&created, "id"),
                    text(&created, "name")
                ),
                value: created,
            })
        }
        AutomationCommand::Update {
            project,
            automation,
            file,
            enable,
            disable,
            schedules,
        } => {
            let project = uuid_arg(&project, "--project")?;
            let id = resolve_automation(ctx, &project, &automation).await?;
            let mut body = serde_json::Map::new();
            if let Some(file) = file {
                body.insert("spec".into(), local_spec(&file)?);
            }
            if enable || disable {
                body.insert("enabled".into(), json!(enable));
            }
            if let Some(toggle) = schedules {
                body.insert(
                    "schedules_enabled".into(),
                    json!(matches!(toggle, Toggle::On)),
                );
            }
            if body.is_empty() {
                return Err(CliError::usage(
                    "Nothing to update: pass --file, --enable/--disable or --schedules",
                ));
            }
            let (_, updated) = ctx
                .client
                .request(
                    Method::PATCH,
                    &format!("/api/v1/projects/{project}/automations/{id}"),
                    &[],
                    Some(&Value::Object(body)),
                )
                .await?;
            Ok(Output {
                text: format!(
                    "Automation {id} is now version {}",
                    text(&updated, "current_version")
                ),
                value: updated,
            })
        }
        AutomationCommand::Run {
            project,
            automation,
            reference,
            commit,
            fresh_build,
            idempotency_key,
            wait_for,
        } => {
            let project = uuid_arg(&project, "--project")?;
            let id = resolve_automation(ctx, &project, &automation).await?;
            let mut body = serde_json::Map::new();
            if let Some(r) = reference {
                body.insert("ref".into(), json!(r));
            }
            if let Some(c) = commit {
                body.insert("commit".into(), json!(c));
            }
            if fresh_build {
                body.insert("fresh_build".into(), json!(true));
            }
            if let Some(k) = idempotency_key {
                body.insert("idempotency_key".into(), json!(k));
            }
            let (status, started) = ctx
                .client
                .post(
                    &format!("/api/v1/projects/{project}/automations/{id}/run"),
                    Some(&Value::Object(body)),
                )
                .await?;
            let mut run = started["run"].clone();
            let existing = status == 200;
            if let Some(target) = wait_for.as_deref() {
                run = wait::wait_run(
                    &ctx.client,
                    &project,
                    &text(&run, "id"),
                    Some(target),
                    ctx.timeout,
                )
                .await?;
            }
            let heading = if existing {
                "Existing run returned (duplicate trigger)"
            } else {
                "Run started"
            };
            Ok(Output {
                text: format!("{heading}\n{}", run_summary(&run)),
                value: json!({"run":run,"existing":existing}),
            })
        }
        AutomationCommand::Status {
            project,
            run,
            wait_for,
        } => {
            let project = uuid_arg(&project, "--project")?;
            let run = uuid_arg(&run, "run")?;
            let view = match wait_for.as_deref() {
                Some(target) => {
                    wait::wait_run(&ctx.client, &project, &run, Some(target), ctx.timeout).await?
                }
                None => {
                    ctx.client
                        .get(
                            &format!("/api/v1/projects/{project}/automations/runs/{run}"),
                            &[],
                        )
                        .await?
                }
            };
            Ok(Output {
                text: run_summary(&view),
                value: view,
            })
        }
        AutomationCommand::Logs { project, run } => {
            let project = uuid_arg(&project, "--project")?;
            let run = uuid_arg(&run, "run")?;
            let events = ctx
                .client
                .get(
                    &format!("/api/v1/projects/{project}/automations/runs/{run}/events"),
                    &[],
                )
                .await?;
            let lines: Vec<String> = events
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .rev()
                .map(|e| format!("{}  {:<18} {}", text(e, "at"), text(e, "kind"), e["detail"]))
                .collect();
            Ok(Output {
                text: lines.join("\n"),
                value: events,
            })
        }
        AutomationCommand::Cancel { project, run } => {
            let project = uuid_arg(&project, "--project")?;
            let run = uuid_arg(&run, "run")?;
            let (_, view) = ctx
                .client
                .post(
                    &format!("/api/v1/projects/{project}/automations/runs/{run}/cancel"),
                    None,
                )
                .await?;
            Ok(Output {
                text: format!(
                    "Cancellation requested; run is {}. Releases already committed to the repository are not rolled back.",
                    text(&view, "status")
                ),
                value: view,
            })
        }
        AutomationCommand::Runs { project, page: p } => {
            let project = uuid_arg(&project, "--project")?;
            let list = ctx
                .client
                .get(&format!("/api/v1/projects/{project}/runs"), &page(&p))
                .await?;
            Ok(Output {
                text: table(
                    &["id", "status", "trigger", "source_commit"],
                    rows(&list, &["id", "status", "trigger", "source_commit"]),
                ),
                value: list,
            })
        }
    }
}

async fn approval(ctx: &Context, command: ApprovalCommand) -> Result<Output, CliError> {
    need_auth(ctx)?;
    match command {
        ApprovalCommand::List {
            project,
            status,
            page: p,
        } => {
            let mut query = page(&p);
            if let Some(s) = status {
                query.push(("status", s));
            }
            let path = match project {
                Some(p) => format!("/api/v1/projects/{}/approvals", uuid_arg(&p, "--project")?),
                None => "/api/v1/approvals".into(),
            };
            let list = ctx.client.get(&path, &query).await?;
            Ok(Output {
                text: table(
                    &["id", "status", "run_id", "expires_at"],
                    rows(&list, &["id", "status", "run_id", "expires_at"]),
                ),
                value: list,
            })
        }
        ApprovalCommand::Show { id } => {
            let a = ctx
                .client
                .get(
                    &format!("/api/v1/approvals/{}", uuid_arg(&id, "approval")?),
                    &[],
                )
                .await?;
            Ok(Output {
                text: serde_json::to_string_pretty(&a).unwrap_or_default(),
                value: a,
            })
        }
        ApprovalCommand::Approve { id, reason } => decide(ctx, &id, "approve", reason).await,
        ApprovalCommand::Reject { id, reason } => decide(ctx, &id, "reject", reason).await,
    }
}
async fn decide(
    ctx: &Context,
    id: &str,
    action: &str,
    reason: Option<String>,
) -> Result<Output, CliError> {
    let id = uuid_arg(id, "approval")?;
    let body = reason.map(|r| json!({"reason": r}));
    let (_, a) = ctx
        .client
        .post(&format!("/api/v1/approvals/{id}/{action}"), body.as_ref())
        .await?;
    Ok(Output {
        text: format!("Approval {id}: {}", text(&a, "status")),
        value: a,
    })
}

// ---------------------------------------------------------------- integrations
async fn integration(ctx: &Context, command: IntegrationCommand) -> Result<Output, CliError> {
    need_auth(ctx)?;
    match command {
        IntegrationCommand::List { project } => {
            let project = uuid_arg(&project, "--project")?;
            let connections = ctx
                .client
                .get(
                    &format!("/api/v1/projects/{project}/integrations/oidc"),
                    &[],
                )
                .await?;
            let webhooks = ctx
                .client
                .get(
                    &format!("/api/v1/projects/{project}/integrations/webhooks"),
                    &[],
                )
                .await?;
            let conn_rows: Vec<Vec<String>> = connections
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|c| {
                    vec![
                        text(c, "id"),
                        text(c, "name"),
                        text(&c["policy"], "repository_id"),
                        text(c, "enabled"),
                        text(c, "revoked_at"),
                    ]
                })
                .collect();
            let hook_rows: Vec<Vec<String>> = webhooks
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|w| {
                    vec![
                        text(w, "id"),
                        text(w, "url"),
                        text(w, "enabled"),
                        text(&w["last_delivery"], "status"),
                    ]
                })
                .collect();
            Ok(Output {
                text: format!(
                    "GitHub identities\n{}\n\nWebhooks\n{}",
                    table(
                        &["id", "name", "repository_id", "enabled", "revoked"],
                        conn_rows
                    ),
                    table(&["id", "url", "enabled", "last_delivery"], hook_rows)
                ),
                value: json!({"oidc":connections,"webhooks":webhooks}),
            })
        }
        IntegrationCommand::OidcAdd {
            project,
            name,
            policy,
        } => {
            let project = uuid_arg(&project, "--project")?;
            let policy: Value = serde_json::from_str(&read_file(&policy, 32 * 1024)?)
                .map_err(|e| CliError::usage(format!("Invalid policy JSON: {e}")))?;
            let (_, created) = ctx
                .client
                .post(
                    &format!("/api/v1/projects/{project}/integrations/oidc"),
                    Some(&json!({"name":name,"policy":policy})),
                )
                .await?;
            Ok(Output {
                text: format!(
                    "Trusting GitHub repository {} (integration {})",
                    text(&created["policy"], "repository_id"),
                    text(&created, "id")
                ),
                value: created,
            })
        }
        IntegrationCommand::OidcRevoke { project, id } => {
            let project = uuid_arg(&project, "--project")?;
            let id = uuid_arg(&id, "integration")?;
            ctx.client
                .request(
                    Method::DELETE,
                    &format!("/api/v1/projects/{project}/integrations/oidc/{id}"),
                    &[],
                    None,
                )
                .await?;
            Ok(Output {
                text: format!(
                    "Integration {id} revoked together with every credential minted through it"
                ),
                value: json!({"revoked":id}),
            })
        }
        IntegrationCommand::WebhookAdd {
            project,
            url,
            events,
            exclude_origins,
            description,
        } => {
            let project = uuid_arg(&project, "--project")?;
            let (_, created) = ctx.client.post(&format!("/api/v1/projects/{project}/integrations/webhooks"), Some(&json!({"url":url,"event_types":events,"exclude_origins":exclude_origins,"description":description}))).await?;
            let secret = text(&created, "secret");
            credentials::mask(&secret);
            Ok(Output {
                text: format!(
                    "Webhook {} created.\nSigning secret (shown once): {secret}",
                    text(&created["webhook"], "id")
                ),
                value: created,
            })
        }
        IntegrationCommand::WebhookRotate { project, id } => {
            let project = uuid_arg(&project, "--project")?;
            let id = uuid_arg(&id, "webhook")?;
            let (_, rotated) = ctx
                .client
                .post(
                    &format!("/api/v1/projects/{project}/integrations/webhooks/{id}/rotate"),
                    None,
                )
                .await?;
            let secret = text(&rotated, "secret");
            credentials::mask(&secret);
            Ok(Output {
                text: format!(
                    "New signing secret (shown once; the old one stops working immediately): {secret}"
                ),
                value: rotated,
            })
        }
        IntegrationCommand::WebhookDelete { project, id } => {
            let project = uuid_arg(&project, "--project")?;
            let id = uuid_arg(&id, "webhook")?;
            ctx.client
                .request(
                    Method::DELETE,
                    &format!("/api/v1/projects/{project}/integrations/webhooks/{id}"),
                    &[],
                    None,
                )
                .await?;
            Ok(Output {
                text: format!("Webhook {id} deleted"),
                value: json!({"deleted":id}),
            })
        }
        IntegrationCommand::Deliveries {
            project,
            webhook,
            page: p,
        } => {
            let project = uuid_arg(&project, "--project")?;
            let path = match webhook {
                Some(w) => format!(
                    "/api/v1/projects/{project}/integrations/webhooks/{}/deliveries",
                    uuid_arg(&w, "webhook")?
                ),
                None => format!("/api/v1/projects/{project}/integrations/deliveries"),
            };
            let list = ctx.client.get(&path, &page(&p)).await?;
            Ok(Output {
                text: table(
                    &["id", "event_type", "status", "attempts", "last_http_status"],
                    rows(
                        &list,
                        &["id", "event_type", "status", "attempts", "last_http_status"],
                    ),
                ),
                value: list,
            })
        }
        IntegrationCommand::Replay { project, delivery } => {
            let project = uuid_arg(&project, "--project")?;
            let delivery = uuid_arg(&delivery, "delivery")?;
            let (_, replayed) = ctx
                .client
                .post(
                    &format!(
                        "/api/v1/projects/{project}/integrations/deliveries/{delivery}/replay"
                    ),
                    None,
                )
                .await?;
            Ok(Output {
                text: format!("Replay queued as delivery {}", text(&replayed, "id")),
                value: replayed,
            })
        }
    }
}

// ------------------------------------------------------------------- verification
async fn verify(ctx: &Context, args: VerifyArgs) -> Result<Output, CliError> {
    let release = uuid_arg(&args.release, "--release")?;
    if args.app.is_empty()
        || args.app.len() > 255
        || !args
            .app
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(CliError::usage("--app is not a valid application ID"));
    }
    let evidence = ctx
        .client
        .get(
            &format!(
                "/api/v1/catalog/apps/{}/releases/{release}/provenance",
                args.app
            ),
            &[],
        )
        .await?;
    let server_code = text(&evidence["verification"], "code");
    let Some(bundle) = evidence.get("bundle").filter(|b| !b.is_null()) else {
        return Err(CliError::Failed {
            code: server_code,
            message: format!(
                "No attestation bundle is available (status: {})",
                text(&evidence, "status")
            ),
        });
    };
    let (keys, independent) = match &args.trusted_keys {
        Some(path) => (
            serde_json::from_str(&read_file(path, 64 * 1024)?)
                .map_err(|e| CliError::usage(format!("Invalid key file: {e}")))?,
            true,
        ),
        None => (
            serde_json::from_value(ctx.client.get("/api/v1/supply-chain/keys", &[]).await?)
                .map_err(|_| CliError::Network("Unreadable key list".into()))?,
            false,
        ),
    };
    let bundle: librehub_common::AttestationBundle = serde_json::from_value(bundle.clone())
        .map_err(|_| CliError::Network("Unreadable attestation bundle".into()))?;
    let failed = |e: anyhow::Error| CliError::Failed {
        code: "verification_failed".into(),
        message: e.to_string(),
    };
    let (build, digest) = librehub_supply_chain::verify(&bundle.build, &keys).map_err(failed)?;
    let (rel, _) = librehub_supply_chain::verify(&bundle.release, &keys).map_err(failed)?;
    librehub_supply_chain::verify_link(&rel, &build, &digest).map_err(failed)?;
    let subject = rel.subject.first().ok_or_else(|| CliError::Failed {
        code: "verification_failed".into(),
        message: "Release has no subject".into(),
    })?;
    let published = subject.digest.get("sha256").cloned().unwrap_or_default();
    if args.checksum.as_deref().is_some_and(|c| c != published) {
        return Err(CliError::Failed {
            code: "release_subject_mismatch".into(),
            message: "The attested release checksum differs from --checksum".into(),
        });
    }
    Ok(Output {
        text: format!(
            "Release {release} of {} verified: ref {}, checksum {published}{}",
            args.app,
            subject.name,
            if independent {
                ""
            } else {
                "\nnote: trust roots were fetched from the server; pass --trusted-keys for independent verification"
            }
        ),
        value: json!({"verified":true,"ref":subject.name,"checksum":published,"independent_trust_root":independent,"server_verdict":server_code}),
    })
}

// -------------------------------------------------------------------------- CI
fn github_output(path: &std::path::Path, outputs: &[(&str, String)]) -> Result<(), CliError> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
        .map_err(|e| CliError::usage(format!("Cannot write {}: {e}", path.display())))?;
    for (key, value) in outputs {
        // Values are single-line identifiers and statuses; anything else would allow output injection.
        if value.contains(['\n', '\r']) || key.contains(['=', '\n']) {
            continue;
        }
        writeln!(file, "{key}={value}").map_err(|e| CliError::usage(e.to_string()))?;
    }
    Ok(())
}
fn step_output(run: &Value, kind: &str, key: &str) -> String {
    run["steps"]
        .as_array()
        .and_then(|s| s.iter().find(|x| x["kind"] == kind))
        .and_then(|s| s["output"][key].as_str().map(str::to_owned))
        .unwrap_or_default()
}
fn ci_outputs(run: &Value) -> Vec<(&'static str, String)> {
    let s = |v: &Value| v.as_str().unwrap_or_default().to_owned();
    let promoted = step_output(run, "librehub/promote", "publication_id");
    let (kind, key_prefix) = if promoted.is_empty() {
        ("librehub/publish", "")
    } else {
        ("librehub/promote", "")
    };
    let _ = key_prefix;
    let attestation = {
        let release = step_output(run, "librehub/promote", "attestation_status");
        if release.is_empty() {
            step_output(run, "librehub/verify-provenance", "attestation")
        } else {
            release
        }
    };
    vec![
        ("run_id", s(&run["id"])),
        ("run_status", s(&run["status"])),
        ("source_commit", s(&run["source_commit"])),
        ("source_event_id", s(&run["source_event_id"])),
        ("build_id", s(&run["build_id"])),
        (
            "build_status",
            step_output(run, "librehub/build", "build_status"),
        ),
        ("publication_id", step_output(run, kind, "publication_id")),
        (
            "publication_status",
            step_output(run, kind, "publication_status"),
        ),
        ("flatpak_ref", step_output(run, kind, "flatpak_ref")),
        ("attestation_status", attestation),
        (
            "approval_id",
            step_output(run, "librehub/approval", "approval_id"),
        ),
    ]
}
async fn ci(ctx: &Context, args: CiArgs) -> Result<Output, CliError> {
    need_auth(ctx)?;
    let project = uuid_arg(&args.project, "--project")?;
    let automation = resolve_automation(ctx, &project, &args.automation).await?;
    // Triggering is idempotent for a GitHub run attempt, so every operation can start by
    // (re)triggering and receive the same automation run.
    let mut body = serde_json::Map::new();
    if ctx.source != "github-oidc" {
        if let Ok(sha) = std::env::var("GITHUB_SHA") {
            body.insert("commit".into(), json!(sha));
        }
        if let Ok(r) = std::env::var("GITHUB_REF")
            && r.starts_with("refs/heads/")
        {
            body.insert("ref".into(), json!(r.trim_start_matches("refs/heads/")));
        }
        body.insert(
            "idempotency_key".into(),
            json!(format!(
                "gha-{}-{}",
                std::env::var("GITHUB_RUN_ID").unwrap_or_else(|_| "local".into()),
                std::env::var("GITHUB_RUN_ATTEMPT").unwrap_or_else(|_| "1".into())
            )),
        );
    }
    let (_, started) = ctx
        .client
        .post(
            &format!("/api/v1/projects/{project}/automations/{automation}/run"),
            Some(&Value::Object(body)),
        )
        .await?;
    let run_id = text(&started["run"], "id");
    let target = match args.operation {
        CiOperation::Build => None,
        CiOperation::WaitForBuild => Some("build"),
        CiOperation::VerifyProvenance => Some("verify-provenance"),
        CiOperation::PublishBeta | CiOperation::BuildAndPublishBeta => Some("publish-beta"),
        CiOperation::WaitForSecurity => Some("security"),
        CiOperation::RequestPromotion => Some("approval-requested"),
        CiOperation::WaitForPublication => Some("promote"),
    };
    let run = match target {
        Some(target) => {
            wait::wait_run(&ctx.client, &project, &run_id, Some(target), ctx.timeout).await?
        }
        None => started["run"].clone(),
    };
    let outputs = ci_outputs(&run);
    if let Some(path) = &args.output_file {
        github_output(path, &outputs)?;
    }
    let lines: Vec<String> = outputs
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    Ok(Output {
        text: format!("{}\n{}", run_summary(&run), lines.join("\n")),
        value: json!({"operation":format!("{:?}", args.operation),"outputs":outputs.iter().map(|(k, v)| (k.to_string(), json!(v))).collect::<serde_json::Map<_, _>>(),"run":run}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tables_align_and_handle_empty_input() {
        let t = table(
            &["id", "name"],
            vec![
                vec!["1".into(), "alpha".into()],
                vec!["22".into(), "b".into()],
            ],
        );
        assert_eq!(t.lines().count(), 3);
        assert!(t.starts_with("ID"));
        assert_eq!(table(&["id"], vec![]).lines().count(), 1);
    }
    #[test]
    fn ci_outputs_are_extracted_from_step_state() {
        let run = json!({"id":"r","status":"waiting_for_approval","source_commit":"abc","build_id":"b","source_event_id":"e","steps":[
            {"kind":"librehub/build","output":{"build_status":"succeeded"}},
            {"kind":"librehub/verify-provenance","output":{"attestation":"verified"}},
            {"kind":"librehub/publish","output":{"publication_id":"p","publication_status":"succeeded","flatpak_ref":"app/x/x86_64/master"}}]});
        let out: std::collections::BTreeMap<_, _> = ci_outputs(&run).into_iter().collect();
        assert_eq!(out["build_status"], "succeeded");
        assert_eq!(out["publication_id"], "p");
        assert_eq!(out["flatpak_ref"], "app/x/x86_64/master");
        assert_eq!(out["attestation_status"], "verified");
        assert_eq!(out["source_commit"], "abc");
    }
    #[test]
    fn github_output_refuses_multiline_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out");
        github_output(
            &path,
            &[
                ("ok", "v".into()),
                ("evil", "x\nINJECTED=1".into()),
                ("bad=key", "v".into()),
            ],
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "ok=v\n");
    }
    #[test]
    fn ids_must_be_uuids() {
        assert!(uuid_arg("../etc/passwd", "x").is_err());
        assert!(uuid_arg("00000000-0000-0000-0000-000000000000", "x").is_ok());
    }
}
