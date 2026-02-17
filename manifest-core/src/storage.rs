use rusqlite::{params, Connection};

use crate::error::ManifestError;
use crate::receipt::Receipt;

/// SQLite-backed storage for receipts and Merkle tree leaves.
pub struct Storage {
    conn: Connection,
}

impl Storage {
    /// Open or create the database at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self, ManifestError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let storage = Self { conn };
        storage.migrate()?;
        Ok(storage)
    }

    /// Open an in-memory database (for testing).
    pub fn in_memory() -> Result<Self, ManifestError> {
        let conn = Connection::open_in_memory()?;
        let storage = Self { conn };
        storage.migrate()?;
        Ok(storage)
    }

    /// Run schema migrations.
    fn migrate(&self) -> Result<(), ManifestError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS receipts (
                id           TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL UNIQUE,
                timestamp    TEXT NOT NULL,
                session_id   TEXT,
                agent_name   TEXT NOT NULL,
                tool_name    TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                created_at   TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_receipts_timestamp
                ON receipts(timestamp DESC);

            CREATE INDEX IF NOT EXISTS idx_receipts_session
                ON receipts(session_id);

            CREATE INDEX IF NOT EXISTS idx_receipts_tool
                ON receipts(tool_name);

            CREATE TABLE IF NOT EXISTS merkle_leaves (
                leaf_index  INTEGER PRIMARY KEY,
                leaf_hash   BLOB NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    /// Insert a receipt into storage.
    pub fn insert_receipt(
        &self,
        receipt: &Receipt,
        session_id: Option<&str>,
    ) -> Result<(), ManifestError> {
        let content_hash = receipt.content_hash();
        let receipt_json = serde_json::to_string(receipt)?;

        self.conn.execute(
            "INSERT INTO receipts (id, content_hash, timestamp, session_id, agent_name, tool_name, receipt_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                receipt.id,
                content_hash,
                receipt.timestamp.to_rfc3339(),
                session_id,
                receipt.agent.name,
                receipt.action.tool,
                receipt_json,
            ],
        )?;
        Ok(())
    }

    /// Get a receipt by its ID (`urn:uuid:...`).
    pub fn get_receipt_by_id(&self, id: &str) -> Result<Option<Receipt>, ManifestError> {
        let mut stmt = self
            .conn
            .prepare("SELECT receipt_json FROM receipts WHERE id = ?1")?;
        let mut rows = stmt.query(params![id])?;

        match rows.next()? {
            Some(row) => {
                let json: String = row.get(0)?;
                let receipt: Receipt = serde_json::from_str(&json)?;
                Ok(Some(receipt))
            }
            None => Ok(None),
        }
    }

    /// Get a receipt by its content hash (`sha256:...`).
    pub fn get_receipt_by_hash(&self, hash: &str) -> Result<Option<Receipt>, ManifestError> {
        let mut stmt = self
            .conn
            .prepare("SELECT receipt_json FROM receipts WHERE content_hash = ?1")?;
        let mut rows = stmt.query(params![hash])?;

        match rows.next()? {
            Some(row) => {
                let json: String = row.get(0)?;
                let receipt: Receipt = serde_json::from_str(&json)?;
                Ok(Some(receipt))
            }
            None => Ok(None),
        }
    }

    /// List receipts with pagination (newest first).
    pub fn list_receipts(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Receipt>, ManifestError> {
        let mut stmt = self.conn.prepare(
            "SELECT receipt_json FROM receipts ORDER BY timestamp DESC LIMIT ?1 OFFSET ?2",
        )?;
        let rows = stmt.query_map(params![limit as i64, offset as i64], |row| {
            row.get::<_, String>(0)
        })?;

        let mut receipts = Vec::new();
        for row in rows {
            let json = row?;
            let receipt: Receipt = serde_json::from_str(&json)?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    /// List receipts filtered by session ID.
    pub fn list_by_session(
        &self,
        session_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Receipt>, ManifestError> {
        let mut stmt = self.conn.prepare(
            "SELECT receipt_json FROM receipts WHERE session_id = ?1 ORDER BY timestamp DESC LIMIT ?2 OFFSET ?3",
        )?;
        let rows = stmt.query_map(params![session_id, limit as i64, offset as i64], |row| {
            row.get::<_, String>(0)
        })?;

        let mut receipts = Vec::new();
        for row in rows {
            let json = row?;
            let receipt: Receipt = serde_json::from_str(&json)?;
            receipts.push(receipt);
        }
        Ok(receipts)
    }

    /// Store a Merkle leaf hash for tree reconstruction on restart.
    pub fn insert_merkle_leaf(
        &self,
        index: u64,
        leaf_hash: &[u8; 32],
    ) -> Result<(), ManifestError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO merkle_leaves (leaf_index, leaf_hash) VALUES (?1, ?2)",
            params![index as i64, &leaf_hash[..]],
        )?;
        Ok(())
    }

    /// Load all Merkle leaves ordered by index (for tree restoration).
    pub fn load_merkle_leaves(&self) -> Result<Vec<[u8; 32]>, ManifestError> {
        let mut stmt = self
            .conn
            .prepare("SELECT leaf_hash FROM merkle_leaves ORDER BY leaf_index ASC")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;

        let mut leaves = Vec::new();
        for row in rows {
            let bytes = row?;
            let hash: [u8; 32] = bytes
                .try_into()
                .map_err(|_| ManifestError::Config("merkle leaf is not 32 bytes".into()))?;
            leaves.push(hash);
        }
        Ok(leaves)
    }

    /// Delete receipts older than the given timestamp.
    ///
    /// Returns the number of receipts deleted. Note: this does NOT prune
    /// Merkle leaves — the Merkle tree is append-only by design.
    pub fn prune_before(&self, cutoff: &str) -> Result<usize, ManifestError> {
        let deleted = self.conn.execute(
            "DELETE FROM receipts WHERE timestamp < ?1",
            params![cutoff],
        )?;
        Ok(deleted)
    }

    /// Count total receipts in the database.
    pub fn count_receipts(&self) -> Result<usize, ManifestError> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM receipts")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get the content hash of the most recent receipt (for chaining).
    pub fn latest_receipt_hash(&self) -> Result<Option<String>, ManifestError> {
        let mut stmt = self
            .conn
            .prepare("SELECT content_hash FROM receipts ORDER BY timestamp DESC LIMIT 1")?;
        let mut rows = stmt.query([])?;

        match rows.next()? {
            Some(row) => {
                let hash: String = row.get(0)?;
                Ok(Some(hash))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Action;
    use crate::identity::{AgentIdentity, IdentitySource};
    use crate::merkle::MerkleTree;
    use crate::signing::Signer;
    use crate::receipt::ReceiptBuilder;

    fn make_receipt(signer: &Signer, merkle: &mut MerkleTree, tool: &str) -> Receipt {
        ReceiptBuilder::new()
            .agent(AgentIdentity {
                name: "test-agent".into(),
                version: None,
                deployer: None,
                environment: None,
                source: IdentitySource::Environment,
                verified: false,
            })
            .action(Action {
                tool: tool.into(),
                input: serde_json::json!({}),
                output: Some(serde_json::json!({"ok": true})),
                error: None,
            })
            .build(signer, merkle)
            .unwrap()
    }

    #[test]
    fn insert_and_get_by_id() {
        let storage = Storage::in_memory().unwrap();
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let receipt = make_receipt(&signer, &mut merkle, "db_query");
        let id = receipt.id.clone();
        storage.insert_receipt(&receipt, None).unwrap();

        let loaded = storage.get_receipt_by_id(&id).unwrap().unwrap();
        assert_eq!(loaded.id, id);
        assert_eq!(loaded.action.tool, "db_query");
    }

    #[test]
    fn get_by_hash() {
        let storage = Storage::in_memory().unwrap();
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let receipt = make_receipt(&signer, &mut merkle, "send_email");
        let hash = receipt.content_hash();
        storage.insert_receipt(&receipt, None).unwrap();

        let loaded = storage.get_receipt_by_hash(&hash).unwrap().unwrap();
        assert_eq!(loaded.action.tool, "send_email");
    }

    #[test]
    fn list_receipts_ordering() {
        let storage = Storage::in_memory().unwrap();
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        for tool in ["a", "b", "c"] {
            let receipt = make_receipt(&signer, &mut merkle, tool);
            storage.insert_receipt(&receipt, None).unwrap();
        }

        let all = storage.list_receipts(10, 0).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn list_receipts_pagination() {
        let storage = Storage::in_memory().unwrap();
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        for i in 0..5 {
            let receipt = make_receipt(&signer, &mut merkle, &format!("tool_{i}"));
            storage.insert_receipt(&receipt, None).unwrap();
        }

        let page1 = storage.list_receipts(2, 0).unwrap();
        assert_eq!(page1.len(), 2);

        let page2 = storage.list_receipts(2, 2).unwrap();
        assert_eq!(page2.len(), 2);
    }

    #[test]
    fn list_by_session() {
        let storage = Storage::in_memory().unwrap();
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        let r1 = make_receipt(&signer, &mut merkle, "a");
        let r2 = make_receipt(&signer, &mut merkle, "b");
        let r3 = make_receipt(&signer, &mut merkle, "c");

        storage.insert_receipt(&r1, Some("session-1")).unwrap();
        storage.insert_receipt(&r2, Some("session-1")).unwrap();
        storage.insert_receipt(&r3, Some("session-2")).unwrap();

        let s1 = storage.list_by_session("session-1", 10, 0).unwrap();
        assert_eq!(s1.len(), 2);

        let s2 = storage.list_by_session("session-2", 10, 0).unwrap();
        assert_eq!(s2.len(), 1);
    }

    #[test]
    fn not_found_returns_none() {
        let storage = Storage::in_memory().unwrap();
        assert!(storage.get_receipt_by_id("nonexistent").unwrap().is_none());
        assert!(storage.get_receipt_by_hash("sha256:abc").unwrap().is_none());
    }

    #[test]
    fn latest_receipt_hash() {
        let storage = Storage::in_memory().unwrap();
        assert!(storage.latest_receipt_hash().unwrap().is_none());

        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();
        let receipt = make_receipt(&signer, &mut merkle, "test");
        let expected_hash = receipt.content_hash();
        storage.insert_receipt(&receipt, None).unwrap();

        let latest = storage.latest_receipt_hash().unwrap().unwrap();
        assert_eq!(latest, expected_hash);
    }

    #[test]
    fn prune_before() {
        let storage = Storage::in_memory().unwrap();
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        for tool in ["a", "b", "c"] {
            let receipt = make_receipt(&signer, &mut merkle, tool);
            storage.insert_receipt(&receipt, None).unwrap();
        }

        assert_eq!(storage.count_receipts().unwrap(), 3);

        // Prune with a future cutoff deletes everything
        let future = "9999-12-31T23:59:59Z";
        let deleted = storage.prune_before(future).unwrap();
        assert_eq!(deleted, 3);
        assert_eq!(storage.count_receipts().unwrap(), 0);
    }

    #[test]
    fn prune_before_keeps_recent() {
        let storage = Storage::in_memory().unwrap();
        let signer = Signer::generate();
        let mut merkle = MerkleTree::new();

        for tool in ["a", "b", "c"] {
            let receipt = make_receipt(&signer, &mut merkle, tool);
            storage.insert_receipt(&receipt, None).unwrap();
        }

        // Prune with a past cutoff deletes nothing
        let past = "2000-01-01T00:00:00Z";
        let deleted = storage.prune_before(past).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(storage.count_receipts().unwrap(), 3);
    }

    #[test]
    fn merkle_leaf_persistence() {
        let storage = Storage::in_memory().unwrap();

        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];

        storage.insert_merkle_leaf(0, &leaf1).unwrap();
        storage.insert_merkle_leaf(1, &leaf2).unwrap();

        let loaded = storage.load_merkle_leaves().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0], leaf1);
        assert_eq!(loaded[1], leaf2);
    }
}
