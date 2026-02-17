use manifest_core::{ManifestError, Storage};

use crate::commands::init::resolve_db_path;

/// Export receipts as JSON or JSONL.
pub fn run(
    session: Option<&str>,
    format: &str,
    output: Option<&str>,
    db: Option<&str>,
) -> Result<(), ManifestError> {
    let db_path = resolve_db_path(db);

    if !db_path.exists() {
        return Err(ManifestError::NotFound(
            "no receipt database found".to_string(),
        ));
    }

    let storage = Storage::open(&db_path)?;

    let receipts = match session {
        Some(sid) => storage.list_by_session(sid, usize::MAX, 0)?,
        None => storage.list_receipts(usize::MAX, 0)?,
    };

    let content = match format {
        "json" => serde_json::to_string_pretty(&receipts)?,
        "jsonl" => receipts
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>()?
            .join("\n"),
        other => {
            return Err(ManifestError::Config(format!(
                "unsupported format: '{other}'. Use 'json' or 'jsonl'."
            )));
        }
    };

    match output {
        Some(path) => {
            std::fs::write(path, &content)?;
            eprintln!(
                "Exported {} receipt(s) to {}",
                receipts.len(),
                path
            );
        }
        None => {
            print!("{content}");
        }
    }

    Ok(())
}
