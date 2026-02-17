use std::process::Stdio;
use std::time::Duration;

use manifest_core::ManifestError;
use tokio::io::BufReader;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// A managed child process with captured stdio pipes.
///
/// The child's stderr is inherited by the proxy process so that
/// server diagnostics appear alongside proxy logs.
pub struct ChildProcess {
    child: Child,
}

/// The stdio handles extracted from the child process.
pub struct ChildStdio {
    pub stdin: ChildStdin,
    pub stdout: BufReader<ChildStdout>,
}

impl ChildProcess {
    /// Spawn a child process from a command string.
    ///
    /// The command is parsed using shell word splitting (respects quotes).
    /// stdin and stdout are piped; stderr is inherited.
    pub async fn spawn(command: &str) -> Result<(Self, ChildStdio), ManifestError> {
        let parts = shell_words::split(command).map_err(|e| {
            ManifestError::Config(format!("failed to parse server command: {e}"))
        })?;

        if parts.is_empty() {
            return Err(ManifestError::Config("server command is empty".into()));
        }

        let mut cmd = Command::new(&parts[0]);
        if parts.len() > 1 {
            cmd.args(&parts[1..]);
        }

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().map_err(|e| {
            ManifestError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to spawn '{}': {e}", parts[0]),
            ))
        })?;

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");

        Ok((
            Self { child },
            ChildStdio {
                stdin,
                stdout: BufReader::new(stdout),
            },
        ))
    }

    /// Gracefully shut down the child process.
    ///
    /// Attempts to wait for the process to exit within the timeout,
    /// then kills it if still running.
    pub async fn shutdown(mut self, timeout: Duration) -> Result<(), ManifestError> {
        // Try graceful wait first
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(Ok(_status)) => Ok(()),
            Ok(Err(e)) => Err(ManifestError::Io(e)),
            Err(_) => {
                // Timeout: force kill
                tracing::warn!("child process did not exit within timeout, killing");
                self.child.kill().await?;
                Ok(())
            }
        }
    }
}
