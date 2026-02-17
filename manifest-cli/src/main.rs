mod commands;

use clap::{Parser, Subcommand};

/// Cryptographic receipts for AI agent tool calls.
#[derive(Parser)]
#[command(name = "manifest", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the proxy, wrapping an MCP server
    Proxy {
        /// The command to spawn as the MCP server
        #[arg(long)]
        server: String,

        /// Path to identity config file
        #[arg(long)]
        identity: Option<String>,

        /// Path to policy config file
        #[arg(long)]
        policy: Option<String>,

        /// Path to the signing key (generated if absent)
        #[arg(long)]
        key: Option<String>,

        /// Path to the SQLite database
        #[arg(long)]
        db: Option<String>,
    },

    /// View recent receipts
    Log {
        /// Number of receipts to show
        #[arg(long, default_value = "20")]
        tail: usize,

        /// Filter by session ID
        #[arg(long)]
        session: Option<String>,

        /// Path to the SQLite database
        #[arg(long)]
        db: Option<String>,
    },

    /// Show full receipt detail
    Inspect {
        /// Receipt content hash or ID
        hash: String,

        /// Path to the SQLite database
        #[arg(long)]
        db: Option<String>,
    },

    /// Export receipts as JSON
    Export {
        /// Filter by session
        #[arg(long)]
        session: Option<String>,

        /// Output format (json, jsonl)
        #[arg(long, default_value = "json")]
        format: String,

        /// Output file path (stdout if omitted)
        #[arg(long)]
        output: Option<String>,

        /// Path to the SQLite database
        #[arg(long)]
        db: Option<String>,
    },

    /// Generate a new signing keypair
    Init {
        /// Path to store the keypair
        #[arg(long)]
        key: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Proxy { server, identity, policy, key, db } => {
            commands::proxy::run(
                &server,
                identity.as_deref(),
                policy.as_deref(),
                key.as_deref(),
                db.as_deref(),
            ).await?;
        }
        Commands::Log { tail, session, db } => {
            commands::log::run(tail, session.as_deref(), db.as_deref())?;
        }
        Commands::Inspect { hash, db } => {
            commands::inspect::run(&hash, db.as_deref())?;
        }
        Commands::Export { session, format, output, db } => {
            commands::export::run(session.as_deref(), &format, output.as_deref(), db.as_deref())?;
        }
        Commands::Init { key } => {
            commands::init::run(key.as_deref())?;
        }
    }

    Ok(())
}
