use manifest_core::{ManifestError, Storage};

use crate::commands::init::resolve_db_path;

/// Parse a human-readable duration string like "90d", "24h", "30m" into seconds.
fn parse_duration(s: &str) -> Result<u64, ManifestError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ManifestError::Config("empty duration".into()));
    }

    let (num_str, suffix) = s.split_at(s.len() - 1);
    let num: u64 = num_str
        .parse()
        .map_err(|_| ManifestError::Config(format!("invalid duration: '{s}'")))?;

    let seconds = match suffix {
        "d" => num * 86400,
        "h" => num * 3600,
        "m" => num * 60,
        "s" => num,
        _ => return Err(ManifestError::Config(format!(
            "unknown duration suffix '{suffix}', use d/h/m/s"
        ))),
    };

    Ok(seconds)
}

/// Prune receipts older than the given duration.
pub fn run(older_than: &str, dry_run: bool, db_path: Option<&str>) -> Result<(), ManifestError> {
    let db_file = resolve_db_path(db_path);

    if !db_file.exists() {
        eprintln!("No database found at {}", db_file.display());
        return Ok(());
    }

    let storage = Storage::open(&db_file)?;
    let total_before = storage.count_receipts()?;

    let seconds = parse_duration(older_than)?;
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(seconds as i64);
    let cutoff_str = cutoff.to_rfc3339();

    if dry_run {
        eprintln!("Dry run: would delete receipts before {cutoff_str}");
        eprintln!("Total receipts in database: {total_before}");
        eprintln!("(Use without --dry-run to actually delete)");
    } else {
        let deleted = storage.prune_before(&cutoff_str)?;
        let total_after = storage.count_receipts()?;

        eprintln!("Pruned {deleted} receipts older than {older_than} (before {cutoff_str})");
        eprintln!("Receipts remaining: {total_after}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_days() {
        assert_eq!(parse_duration("90d").unwrap(), 90 * 86400);
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration("24h").unwrap(), 24 * 3600);
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration("30m").unwrap(), 30 * 60);
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("10x").is_err());
    }
}
