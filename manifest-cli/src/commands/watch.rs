use std::time::Duration;

use manifest_core::{ManifestError, Storage, StorageBackend};

use crate::commands::init::resolve_db_path;

/// Live-tail receipts as they are generated.
///
/// Polls the database at a fixed interval and prints any new receipts
/// since the last check. Optionally filters by tool name or session ID.
pub async fn run(
    tool_filter: Option<&str>,
    session_filter: Option<&str>,
    db: Option<&str>,
) -> Result<(), ManifestError> {
    let db_path = resolve_db_path(db);

    if !db_path.exists() {
        eprintln!("No receipt database found at: {}", db_path.display());
        eprintln!("Run `manifest proxy` or `manifest proxy-http` first.");
        return Ok(());
    }

    let storage = Storage::open(&db_path)?;

    // Start from current count so we only show new receipts
    let mut seen = storage.count_receipts()?;

    // Print header
    println!(
        "{:<24} {:<20} {:<20} {:<10} {:<16}",
        "TIMESTAMP", "TOOL", "AGENT", "STATUS", "HASH"
    );
    println!("{}", "-".repeat(92));

    eprintln!("Watching for new receipts... (Ctrl+C to stop)");

    let poll_interval = Duration::from_millis(500);

    loop {
        let current = storage.count_receipts()?;

        if current > seen {
            let new_count = current - seen;
            // Fetch the newest receipts (they come in reverse-chronological order)
            let receipts = match session_filter {
                Some(sid) => storage.list_by_session(sid, new_count, 0)?,
                None => storage.list_receipts(new_count, 0)?,
            };

            // Print in chronological order (reverse the list)
            for receipt in receipts.iter().rev() {
                // Apply tool filter
                if let Some(tool) = tool_filter {
                    if receipt.action.tool != tool {
                        continue;
                    }
                }

                let timestamp = receipt.timestamp.format("%Y-%m-%d %H:%M:%S");
                let tool = &receipt.action.tool;
                let agent = &receipt.agent.name;
                let hash = receipt.content_hash();
                let hash_short = if hash.len() > 18 {
                    format!("{}...", &hash[..18])
                } else {
                    hash.clone()
                };

                // Status: show violations or "ok"
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
                    "{:<24} {:<20} {:<20} {:<10} {:<16}",
                    timestamp, tool, agent, status, hash_short
                );
            }

            seen = current;
        }

        tokio::time::sleep(poll_interval).await;
    }
}
