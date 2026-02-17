use manifest_core::{ManifestError, Storage, StorageBackend};

use crate::commands::init::resolve_db_path;

/// Display recent receipts in a compact table format.
pub fn run(tail: usize, session: Option<&str>, db: Option<&str>) -> Result<(), ManifestError> {
    let db_path = resolve_db_path(db);

    if !db_path.exists() {
        eprintln!("No receipt database found at: {}", db_path.display());
        eprintln!("Run `manifest proxy --server \"...\"` first to generate receipts.");
        return Ok(());
    }

    let storage = Storage::open(&db_path)?;

    let receipts = match session {
        Some(sid) => storage.list_by_session(sid, tail, 0)?,
        None => storage.list_receipts(tail, 0)?,
    };

    if receipts.is_empty() {
        eprintln!("No receipts found.");
        return Ok(());
    }

    // Header
    println!(
        "{:<24} {:<20} {:<20} {:<16}",
        "TIMESTAMP", "TOOL", "AGENT", "HASH"
    );
    println!("{}", "-".repeat(82));

    for receipt in &receipts {
        let timestamp = receipt.timestamp.format("%Y-%m-%d %H:%M:%S");
        let tool = &receipt.action.tool;
        let agent = &receipt.agent.name;
        let hash = receipt.content_hash();
        // Truncate hash for display: "sha256:abcd1234..."
        let hash_short = if hash.len() > 18 {
            format!("{}...", &hash[..18])
        } else {
            hash.clone()
        };

        println!("{:<24} {:<20} {:<20} {:<16}", timestamp, tool, agent, hash_short);
    }

    println!("\n{} receipt(s)", receipts.len());

    Ok(())
}
