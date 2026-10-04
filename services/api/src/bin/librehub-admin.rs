//! Offline bootstrap and operator moderation CLI, deliberately separate from public HTTP admission.
use librehub_api::store::Store;
use librehub_common::{
    DeveloperId, ModerationAction, ModerationReason, ReportId, ReportStatus, Scope,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let data = std::env::var("LIBREHUB_DATA_DIR").unwrap_or_else(|_| "data".into());
    let database = std::env::var("LIBREHUB_DATABASE_PATH")
        .ok()
        .map(std::path::PathBuf::from);
    let store = Store::open_at(std::path::Path::new(&data), database.as_deref())?;

    if args.is_empty() {
        print_usage();
        anyhow::bail!("No command specified");
    }

    let result = match args[0].as_str() {
        "catalog" if args.len() >= 2 && args[1] == "rebuild" => {
            store.catalog_rebuild().await?;
            serde_json::json!({"catalog": "requeued"})
        }
        "catalog" if args.len() >= 5 && args[1] == "moderate" => {
            let app_id = &args[2];
            let action: ModerationAction = args[3].parse().map_err(|e| anyhow::anyhow!("{e}"))?;
            let reason: ModerationReason = args[4].parse().map_err(|e| anyhow::anyhow!("{e}"))?;

            let mut public_note = None;
            let mut internal_note = None;
            let mut idx = 5;
            while idx < args.len() {
                if args[idx] == "--public-note" && idx + 1 < args.len() {
                    public_note = Some(args[idx + 1].clone());
                    idx += 2;
                } else if args[idx] == "--internal-note" && idx + 1 < args.len() {
                    internal_note = Some(args[idx + 1].clone());
                    idx += 2;
                } else {
                    idx += 1;
                }
            }

            let event = store
                .apply_moderation(
                    app_id,
                    action,
                    reason,
                    public_note,
                    internal_note,
                    "operator:admin-cli",
                )
                .await?;
            serde_json::to_value(event)?
        }
        "create-developer" if args.len() == 2 => {
            serde_json::to_value(store.create_developer(args[1].clone()).await?)?
        }
        "create-token" if args.len() >= 3 => {
            let dev_id: DeveloperId = args[1].parse()?;
            let name = args[2].clone();
            let is_operator = args.iter().any(|a| a == "--operator");
            let mut scopes = Scope::developer_defaults();
            if is_operator {
                scopes.push(Scope::Operator);
            }
            serde_json::to_value(store.issue_token(dev_id, name, scopes).await?)?
        }
        "reports" if args.len() >= 2 && args[1] == "list" => {
            let mut status = None;
            let mut idx = 2;
            while idx < args.len() {
                if args[idx] == "--status" && idx + 1 < args.len() {
                    status = Some(args[idx + 1].parse().map_err(|e| anyhow::anyhow!("{e}"))?);
                    idx += 2;
                } else {
                    idx += 1;
                }
            }
            let reports = store.list_reports(status, None, 100, 0).await?;
            serde_json::to_value(reports)?
        }
        "reports" if args.len() >= 4 && args[1] == "resolve" => {
            let report_id: ReportId = args[2].parse()?;
            let status: ReportStatus = args[3].parse().map_err(|e| anyhow::anyhow!("{e}"))?;

            let mut note = None;
            let mut idx = 4;
            while idx < args.len() {
                if args[idx] == "--note" && idx + 1 < args.len() {
                    note = Some(args[idx + 1].clone());
                    idx += 2;
                } else {
                    idx += 1;
                }
            }

            let record = store
                .resolve_report(&report_id, status, note, "operator:admin-cli")
                .await?;
            serde_json::to_value(record)?
        }
        "security" if args.len() == 3 && args[1] == "status" => {
            let app_id = &args[2];
            let trust = store
                .compute_trust_summary(app_id, "stable", None, None)
                .await?;
            let moderation = store.get_moderation_state(app_id).await?;
            serde_json::json!({
                "app_id": app_id,
                "trust": trust,
                "moderation": moderation,
            })
        }
        _ => {
            print_usage();
            anyhow::bail!("Invalid command: {}", args.join(" "));
        }
    };

    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn print_usage() {
    eprintln!(
        r#"Usage:
  librehub-admin catalog rebuild
  librehub-admin catalog moderate <APP_ID> <ACTION> <REASON> [--public-note NOTE] [--internal-note NOTE]
  librehub-admin create-developer <NAME>
  librehub-admin create-token <DEVELOPER_ID> <NAME> [--operator]
  librehub-admin reports list [--status STATUS]
  librehub-admin reports resolve <REPORT_ID> <STATUS> [--note NOTE]
  librehub-admin security status <APP_ID>
"#
    );
}
