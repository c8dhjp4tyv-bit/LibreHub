//! Offline bootstrap, deliberately separate from public HTTP admission.
use librehub_api::store::Store;
use librehub_common::{DeveloperId, Scope};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let data = std::env::var("LIBREHUB_DATA_DIR").unwrap_or_else(|_| "data".into());
    let database = std::env::var("LIBREHUB_DATABASE_PATH")
        .ok()
        .map(std::path::PathBuf::from);
    let store = Store::open_at(std::path::Path::new(&data), database.as_deref())?;
    let result = match args.as_slice() {
        [command, action] if command == "catalog" && action == "rebuild" => {
            store.catalog_rebuild().await?;
            serde_json::json!({"catalog":"requeued"})
        }
        [command, name] if command == "create-developer" => {
            serde_json::to_value(store.create_developer(name.clone()).await?)?
        }
        [command, developer, name] if command == "create-token" => serde_json::to_value(
            store
                .issue_token(
                    developer.parse::<DeveloperId>()?,
                    name.clone(),
                    Scope::developer_defaults(),
                )
                .await?,
        )?,
        [command, developer, name, flag] if command == "create-token" && flag == "--operator" => {
            let mut scopes = Scope::developer_defaults();
            scopes.push(Scope::Operator);
            serde_json::to_value(
                store
                    .issue_token(developer.parse::<DeveloperId>()?, name.clone(), scopes)
                    .await?,
            )?
        }
        _ => anyhow::bail!(
            "Usage: librehub-admin catalog rebuild | create-developer NAME | create-token DEVELOPER_ID NAME [--operator]. Stop the API before offline bootstrap."
        ),
    };
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
