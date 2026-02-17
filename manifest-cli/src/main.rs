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

        /// Webhook URL for real-time policy violation alerts
        #[arg(long)]
        webhook: Option<String>,
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

        /// Output format (json, jsonl, html)
        #[arg(long, default_value = "json")]
        format: String,

        /// Output file path (stdout if omitted)
        #[arg(long)]
        output: Option<String>,

        /// Path to the SQLite database
        #[arg(long)]
        db: Option<String>,
    },

    /// Verify a receipt's signature and Merkle proof
    Verify {
        /// Receipt content hash or ID
        hash: String,

        /// Path to the public key file (.pub)
        #[arg(long)]
        public_key: String,

        /// Path to the SQLite database
        #[arg(long)]
        db: Option<String>,
    },

    /// Start the HTTP proxy for remote MCP servers (Streamable HTTP transport)
    ProxyHttp {
        /// Upstream MCP server URL (e.g., http://localhost:9090/mcp)
        #[arg(long)]
        upstream: String,

        /// Port to listen on
        #[arg(long, default_value = "8080")]
        port: u16,

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

        /// Bearer token for authentication (rejects unauthenticated requests)
        #[arg(long)]
        token: Option<String>,

        /// Rate limit in requests per second (excess requests get 503)
        #[arg(long)]
        rate_limit: Option<u64>,

        /// Webhook URL for real-time policy violation alerts
        #[arg(long)]
        webhook: Option<String>,
    },

    /// Generate a new signing keypair
    Init {
        /// Path to store the keypair
        #[arg(long)]
        key: Option<String>,
    },

    /// Live-tail receipts as they are generated
    Watch {
        /// Filter by tool name
        #[arg(long)]
        tool: Option<String>,

        /// Filter by session ID
        #[arg(long)]
        session: Option<String>,

        /// Path to the SQLite database
        #[arg(long)]
        db: Option<String>,
    },

    /// Delete receipts older than a given duration
    Prune {
        /// Duration threshold (e.g., "90d", "24h", "30m")
        #[arg(long)]
        older_than: String,

        /// Show what would be deleted without actually deleting
        #[arg(long, default_value = "false")]
        dry_run: bool,

        /// Path to the SQLite database
        #[arg(long)]
        db: Option<String>,
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
        Commands::Proxy { server, identity, policy, key, db, webhook } => {
            commands::proxy::run(
                &server,
                identity.as_deref(),
                policy.as_deref(),
                key.as_deref(),
                db.as_deref(),
                webhook.as_deref(),
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
        Commands::Verify { hash, public_key, db } => {
            commands::verify::run(&hash, &public_key, db.as_deref())?;
        }
        Commands::ProxyHttp { upstream, port, identity, policy, key, db, token, rate_limit, webhook } => {
            commands::proxy_http::run(
                &upstream,
                port,
                identity.as_deref(),
                policy.as_deref(),
                key.as_deref(),
                db.as_deref(),
                token.as_deref(),
                rate_limit,
                webhook.as_deref(),
            ).await?;
        }
        Commands::Init { key } => {
            commands::init::run(key.as_deref())?;
        }
        Commands::Watch { tool, session, db } => {
            commands::watch::run(
                tool.as_deref(),
                session.as_deref(),
                db.as_deref(),
            ).await?;
        }
        Commands::Prune { older_than, dry_run, db } => {
            commands::prune::run(&older_than, dry_run, db.as_deref())?;
        }
    }

    Ok(())
}
