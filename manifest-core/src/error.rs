use thiserror::Error;

/// Unified error type for the manifest system.
#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("signing error: {0}")]
    Signing(String),

    #[error("identity error: {0}")]
    Identity(String),

    #[error("policy error: {0}")]
    Policy(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("receipt not found: {0}")]
    NotFound(String),
}
