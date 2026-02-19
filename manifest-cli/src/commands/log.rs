use manifest_core::{ManifestError, Storage, StorageBackend};

use crate::commands::init::resolve_db_path;

/// Display recent receipts.
pub fn run(
    tail: usize,
    session: Option<&str>,
    tool_filter: Option<&str>,
    format: &str,
    db: Option<&str>,
) -> Result<(), ManifestError> {
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

    // Apply tool filter
    let receipts: Vec<_> = if let Some(tool) = tool_filter {
        receipts.into_iter().filter(|r| r.action.tool == tool).collect()
    } else {
        receipts
    };

    if receipts.is_empty() {
        eprintln!("No receipts found.");
        return Ok(());
    }

    match format {
        "json" => {
            let json = serde_json::to_string_pretty(&receipts)?;
            println!("{json}");
        }
        "jsonl" => {
            for receipt in &receipts {
                let json = serde_json::to_string(receipt)?;
                println!("{json}");
            }
        }
        _ => {
            // Table format with status column
            println!(
                "{:<24} {:<20} {:<20} {:<12} {}",
                "TIMESTAMP", "TOOL", "AGENT", "STATUS", "HASH"
            );
            println!("{}", "-".repeat(100));

            for receipt in &receipts {
                let timestamp = receipt.timestamp.format("%Y-%m-%d %H:%M:%S");
                let tool = &receipt.action.tool;
                let agent = &receipt.agent.name;
                let hash = receipt.content_hash();
                let hash_short = format!("{}...", &hash[..19]);

                let status = if let Some(ref delta) = receipt.delta {
                    if !delta.violations.is_empty() {
                        "\x1b[31mVIOLATION\x1b[0m"
                    } else if delta.authorized {
                        "\x1b[32mok\x1b[0m"
                    } else {
                        "\x1b[33mdenied\x1b[0m"
                    }
                } else {
                    "-"
                };

                println!(
                    "{:<24} {:<20} {:<20} {:<21} {}",
                    timestamp, tool, agent, status, hash_short
                );
            }

            println!("\n{} receipt(s)", receipts.len());
        }
    }

    Ok(())
}
