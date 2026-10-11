//! `librehub`: a developer and CI command line for the LibreHub API.
//!
//! Every command maps to a real API endpoint. Credentials come from `LIBREHUB_TOKEN`, a
//! private credentials file or GitHub Actions OIDC federation (memory only), and are never
//! printed, logged or placed in a URL.
pub mod api;
pub mod commands;
pub mod credentials;
pub mod error;
pub mod wait;

use clap::{Args, Parser, Subcommand, ValueEnum};
use error::CliError;
use serde_json::Value;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "librehub",
    version,
    about = "LibreHub developer and CI command line",
    propagate_version = true
)]
pub struct Cli {
    /// LibreHub API base URL (https, or http for localhost only).
    #[arg(
        long,
        global = true,
        env = "LIBREHUB_URL",
        default_value = "http://127.0.0.1:8080"
    )]
    pub api_url: String,
    /// Machine-readable JSON on stdout; structured JSON errors on stderr.
    #[arg(long, global = true)]
    pub json: bool,
    /// Upper bound, in seconds, for commands that wait.
    #[arg(long, global = true, env = "LIBREHUB_TIMEOUT", default_value_t = 900)]
    pub timeout: u64,
    /// Authenticate as this GitHub Actions workflow via OIDC for the given project ID.
    #[arg(long, global = true, env = "LIBREHUB_OIDC_PROJECT")]
    pub oidc_project: Option<String>,
    /// Audience requested for the GitHub identity token (must match the server's configuration).
    #[arg(long, global = true, env = "LIBREHUB_OIDC_AUDIENCE")]
    pub oidc_audience: Option<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Sign in, sign out and inspect the current credential.
    #[command(subcommand)]
    Auth(AuthCommand),
    /// List, inspect and create projects.
    #[command(subcommand)]
    Project(ProjectCommand),
    /// Trigger builds and read their status and logs.
    #[command(subcommand)]
    Build(BuildCommand),
    /// Publish a successful build to a channel (M2).
    #[command(subcommand)]
    Publish(PublishCommand),
    /// Manage and run durable release automations.
    #[command(subcommand)]
    Automation(AutomationCommand),
    /// Review and decide stable-release approvals.
    #[command(subcommand)]
    Approval(ApprovalCommand),
    /// Manage trusted CI identities and outbound webhooks.
    #[command(subcommand)]
    Integration(IntegrationCommand),
    /// Verify a release's supply-chain attestation with the DSSE trust roots.
    Verify(VerifyArgs),
    /// Operations used by the GitHub Actions integration.
    Ci(CiArgs),
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Store a token read from stdin (or LIBREHUB_TOKEN); tokens are never accepted as arguments.
    Login {
        #[arg(long)]
        token_stdin: bool,
    },
    Logout,
    /// Show who the current credential is.
    Status,
}

#[derive(Args, Debug)]
pub struct Page {
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
}

#[derive(Subcommand, Debug)]
pub enum ProjectCommand {
    List(Page),
    Show {
        id: String,
    },
    Create {
        #[arg(long)]
        slug: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        repository: String,
        #[arg(long, value_enum, default_value = "github")]
        provider: Provider,
        #[arg(long, default_value = "main")]
        default_branch: String,
        /// Let M3 build pushes to the allowed branches automatically.
        #[arg(long)]
        auto_build: bool,
    },
}
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum Provider {
    Github,
    Git,
}

#[derive(Subcommand, Debug)]
pub enum BuildCommand {
    Trigger {
        #[arg(long)]
        project: String,
        /// Branch, tag (`refs/tags/v1`) or full commit.
        #[arg(long = "ref")]
        reference: Option<String>,
        /// Wait until the build finishes.
        #[arg(long)]
        wait: bool,
    },
    Status {
        id: String,
        #[arg(long)]
        wait: bool,
    },
    Logs {
        id: String,
        #[arg(long)]
        follow: bool,
        #[arg(long, default_value_t = 0)]
        after: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum PublishCommand {
    Beta {
        build: String,
        #[arg(long)]
        wait: bool,
    },
    /// Direct stable publication (prefer an automation with an approval step).
    Stable {
        build: String,
        /// Confirm that this skips the automation approval workflow.
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        wait: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum AutomationCommand {
    List {
        #[arg(long)]
        project: String,
        #[command(flatten)]
        page: Page,
    },
    Show {
        #[arg(long)]
        project: String,
        automation: String,
    },
    /// Create an automation from a YAML or JSON workflow file (validated locally first).
    Create {
        #[arg(long)]
        project: String,
        #[arg(long)]
        file: std::path::PathBuf,
    },
    Update {
        #[arg(long)]
        project: String,
        automation: String,
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        #[arg(long)]
        disable: bool,
        /// Turn scheduled triggers on or off without editing the workflow.
        #[arg(long, value_enum)]
        schedules: Option<Toggle>,
    },
    /// Validate a workflow file without contacting the server.
    Validate {
        #[arg(long)]
        file: std::path::PathBuf,
    },
    Run {
        #[arg(long)]
        project: String,
        automation: String,
        #[arg(long = "ref")]
        reference: Option<String>,
        #[arg(long)]
        commit: Option<String>,
        /// Build again even if the commit already has a usable build.
        #[arg(long)]
        fresh_build: bool,
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Block until this step id, `build`, `publish-beta`, `security`, `approval` or `completed`.
        #[arg(long)]
        wait_for: Option<String>,
    },
    Status {
        #[arg(long)]
        project: String,
        run: String,
        #[arg(long)]
        wait_for: Option<String>,
    },
    /// Run history (events), newest first.
    Logs {
        #[arg(long)]
        project: String,
        run: String,
    },
    Cancel {
        #[arg(long)]
        project: String,
        run: String,
    },
    Runs {
        #[arg(long)]
        project: String,
        #[command(flatten)]
        page: Page,
    },
}
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum Toggle {
    On,
    Off,
}

#[derive(Subcommand, Debug)]
pub enum ApprovalCommand {
    List {
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[command(flatten)]
        page: Page,
    },
    Show {
        id: String,
    },
    Approve {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    Reject {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum IntegrationCommand {
    /// Trusted CI identities and webhooks of a project.
    List {
        #[arg(long)]
        project: String,
    },
    /// Trust a GitHub repository identity (policy JSON file).
    OidcAdd {
        #[arg(long)]
        project: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        policy: std::path::PathBuf,
    },
    OidcRevoke {
        #[arg(long)]
        project: String,
        id: String,
    },
    WebhookAdd {
        #[arg(long)]
        project: String,
        #[arg(long)]
        url: String,
        #[arg(long = "event", required = true)]
        events: Vec<String>,
        #[arg(long = "exclude-origin")]
        exclude_origins: Vec<String>,
        #[arg(long, default_value = "")]
        description: String,
    },
    WebhookRotate {
        #[arg(long)]
        project: String,
        id: String,
    },
    WebhookDelete {
        #[arg(long)]
        project: String,
        id: String,
    },
    Deliveries {
        #[arg(long)]
        project: String,
        #[arg(long)]
        webhook: Option<String>,
        #[command(flatten)]
        page: Page,
    },
    Replay {
        #[arg(long)]
        project: String,
        delivery: String,
    },
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Application ID (for example org.example.App).
    #[arg(long)]
    pub app: String,
    /// Publication (release) ID.
    #[arg(long)]
    pub release: String,
    /// Trusted attestor keys (JSON). Without it the server's key list is used, which is not an
    /// independent trust root.
    #[arg(long)]
    pub trusted_keys: Option<std::path::PathBuf>,
    /// Expected OSTree commit checksum of the release.
    #[arg(long)]
    pub checksum: Option<String>,
}

#[derive(Args, Debug)]
pub struct CiArgs {
    #[arg(value_enum)]
    pub operation: CiOperation,
    #[arg(long)]
    pub project: String,
    /// Automation ID or name.
    #[arg(long)]
    pub automation: String,
    /// Append `key=value` outputs to this file (defaults to $GITHUB_OUTPUT when set).
    #[arg(long, env = "GITHUB_OUTPUT")]
    pub output_file: Option<std::path::PathBuf>,
}
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiOperation {
    Build,
    WaitForBuild,
    VerifyProvenance,
    PublishBeta,
    WaitForSecurity,
    RequestPromotion,
    WaitForPublication,
    BuildAndPublishBeta,
}

/// What a command produced: the JSON form and the human-readable form.
pub struct Output {
    pub value: Value,
    pub text: String,
}

pub fn main_entry() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let code = if e.use_stderr() { error::EXIT_USAGE } else { 0 };
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    let json = cli.json;
    credentials::set_json_output(json);
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start runtime: {e}");
            return ExitCode::from(error::EXIT_FAILED);
        }
    };
    let result = runtime.block_on(async {
        tokio::select! {
            result = commands::run(cli) => result,
            _ = tokio::signal::ctrl_c() => Err(CliError::Interrupted),
        }
    });
    match result {
        Ok(output) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output.value).unwrap_or_default()
                );
            } else if !output.text.is_empty() {
                println!("{}", output.text);
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            if json {
                eprintln!("{}", e.to_json());
            } else {
                eprintln!("error: {e}");
            }
            ExitCode::from(e.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("librehub").chain(args.iter().copied()))
    }
    #[test]
    fn every_documented_command_parses() {
        let id = "00000000-0000-0000-0000-000000000000";
        for args in [
            vec!["auth", "login", "--token-stdin"],
            vec!["auth", "status"],
            vec!["project", "list", "--limit", "5"],
            vec!["project", "show", id],
            vec![
                "project",
                "create",
                "--slug",
                "hello",
                "--name",
                "Hello",
                "--repository",
                "https://github.com/o/r",
            ],
            vec![
                "build",
                "trigger",
                "--project",
                id,
                "--ref",
                "main",
                "--wait",
            ],
            vec!["build", "status", id, "--wait"],
            vec!["build", "logs", id, "--follow"],
            vec!["publish", "beta", id],
            vec!["publish", "stable", id, "--yes"],
            vec!["automation", "list", "--project", id],
            vec![
                "automation",
                "run",
                "--project",
                id,
                "release",
                "--wait-for",
                "publish-beta",
                "--fresh-build",
            ],
            vec!["automation", "status", "--project", id, id],
            vec!["automation", "logs", "--project", id, id],
            vec!["automation", "cancel", "--project", id, id],
            vec!["automation", "validate", "--file", "wf.yaml"],
            vec!["approval", "approve", id, "--reason", "ok"],
            vec!["integration", "list", "--project", id],
            vec![
                "integration",
                "webhook-add",
                "--project",
                id,
                "--url",
                "https://x.example/h",
                "--event",
                "build.started",
            ],
            vec!["verify", "--app", "org.example.App", "--release", id],
            vec![
                "ci",
                "wait-for-build",
                "--project",
                id,
                "--automation",
                "release",
            ],
            vec![
                "--json",
                "--timeout",
                "30",
                "--api-url",
                "https://librehub.example",
                "project",
                "list",
            ],
        ] {
            parse(&args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
    }
    #[test]
    fn tokens_are_never_command_line_arguments() {
        assert!(parse(&["auth", "login", "--token", "librehub_secret"]).is_err());
        assert!(parse(&["--token", "librehub_secret", "project", "list"]).is_err());
    }
    #[test]
    fn invalid_usage_is_rejected() {
        assert!(parse(&["build", "trigger"]).is_err());
        assert!(parse(&["publish", "nightly", "id"]).is_err());
        assert!(
            parse(&[
                "ci",
                "deploy-everything",
                "--project",
                "x",
                "--automation",
                "y"
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "integration",
                "webhook-add",
                "--project",
                "x",
                "--url",
                "https://x.example"
            ])
            .is_err(),
            "events are required"
        );
    }
}
