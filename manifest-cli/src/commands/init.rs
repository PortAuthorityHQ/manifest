use manifest_core::{ManifestError, Signer};
use std::path::PathBuf;

/// Generate a new Ed25519 signing keypair.
pub fn run(key_path: Option<&str>) -> Result<(), ManifestError> {
    let path = resolve_key_path(key_path);

    if path.exists() {
        eprintln!("Key already exists at: {}", path.display());
        eprintln!("To generate a new key, remove the existing file first.");
        return Ok(());
    }

    let signer = Signer::generate();
    signer.save(&path)?;

    eprintln!("Generated new signing key: {}", path.display());
    eprintln!(
        "Public key: {}",
        hex::encode(signer.verifying_key().to_bytes())
    );

    Ok(())
}

/// Resolve the key path, expanding `~` and using the default if not specified.
pub fn resolve_key_path(key_path: Option<&str>) -> PathBuf {
    match key_path {
        Some(p) => PathBuf::from(p),
        None => default_dir().join("signing.key"),
    }
}

/// Resolve the database path.
pub fn resolve_db_path(db_path: Option<&str>) -> PathBuf {
    match db_path {
        Some(p) => PathBuf::from(p),
        None => default_dir().join("receipts.db"),
    }
}

/// Default manifest data directory: `~/.manifest/`.
fn default_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".manifest")
}
