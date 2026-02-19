use manifest_core::{ManifestError, Storage, StorageBackend};

use crate::commands::init::resolve_db_path;

/// Show the full JSON-LD receipt for a given hash, ID, or the latest receipt.
pub fn run(hash: Option<&str>, latest: bool, db: Option<&str>) -> Result<(), ManifestError> {
    let db_path = resolve_db_path(db);

    if !db_path.exists() {
        return Err(ManifestError::NotFound(
            "no receipt database found".to_string(),
        ));
    }

    let storage = Storage::open(&db_path)?;

    let receipt = if latest {
        // Show most recent receipt
        storage
            .list_receipts(1, 0)?
            .into_iter()
            .next()
            .ok_or_else(|| ManifestError::NotFound("no receipts found".to_string()))?
    } else if let Some(hash) = hash {
        // Try exact match first (by hash, then by ID)
        let exact = storage
            .get_receipt_by_hash(hash)?
            .or(storage.get_receipt_by_id(hash)?);

        match exact {
            Some(r) => r,
            None => {
                // Prefix matching on content_hash
                let all = storage.list_receipts(1000, 0)?;
                let matches: Vec<_> = all
                    .into_iter()
                    .filter(|r| r.content_hash().starts_with(hash))
                    .collect();
                match matches.len() {
                    0 => {
                        return Err(ManifestError::NotFound(format!(
                            "receipt not found: {hash}"
                        )))
                    }
                    1 => matches.into_iter().next().unwrap(),
                    n => {
                        return Err(ManifestError::NotFound(format!(
                            "ambiguous prefix '{hash}' matches {n} receipts — use more characters"
                        )))
                    }
                }
            }
        }
    } else {
        return Err(ManifestError::Config(
            "provide a receipt hash or use --latest".to_string(),
        ));
    };

    let json = serde_json::to_string_pretty(&receipt)?;
    println!("{json}");

    Ok(())
}
