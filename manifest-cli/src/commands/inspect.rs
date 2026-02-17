use manifest_core::{ManifestError, Storage, StorageBackend};

use crate::commands::init::resolve_db_path;

/// Show the full JSON-LD receipt for a given hash or ID.
pub fn run(hash: &str, db: Option<&str>) -> Result<(), ManifestError> {
    let db_path = resolve_db_path(db);

    if !db_path.exists() {
        return Err(ManifestError::NotFound(
            "no receipt database found".to_string(),
        ));
    }

    let storage = Storage::open(&db_path)?;

    // Try by content hash first, then by receipt ID
    let receipt = storage
        .get_receipt_by_hash(hash)?
        .or(storage.get_receipt_by_id(hash)?)
        .ok_or_else(|| ManifestError::NotFound(hash.to_string()))?;

    let json = serde_json::to_string_pretty(&receipt)?;
    println!("{json}");

    Ok(())
}
