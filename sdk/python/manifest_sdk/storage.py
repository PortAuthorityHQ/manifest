"""SQLite storage matching manifest-core's Storage schema."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .receipt import Receipt


class Storage:
    """SQLite-backed storage for receipts and Merkle tree leaves."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._migrate()

    @staticmethod
    def open(path: str) -> Storage:
        """Open or create the database at the given path."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(p))
        return Storage(conn)

    @staticmethod
    def in_memory() -> Storage:
        """Open an in-memory database (for testing)."""
        conn = sqlite3.connect(":memory:")
        return Storage(conn)

    def _migrate(self) -> None:
        """Run schema migrations matching Rust's exact schema."""
        self._conn.executescript(
            """
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
            """
        )

    def insert_receipt(self, receipt: Receipt, session_id: str | None = None) -> None:
        """Insert a receipt into the database."""
        content_hash = receipt.content_hash()
        receipt_json = receipt.to_json()
        self._conn.execute(
            """INSERT INTO receipts (id, content_hash, timestamp, session_id, agent_name, tool_name, receipt_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                receipt.id,
                content_hash,
                _format_timestamp(receipt.timestamp),
                session_id,
                receipt.agent.name,
                receipt.action.tool,
                receipt_json,
            ),
        )
        self._conn.commit()

    def get_receipt_by_id(self, id: str) -> Receipt | None:
        """Get a receipt by its URN ID."""
        row = self._conn.execute(
            "SELECT receipt_json FROM receipts WHERE id = ?", (id,)
        ).fetchone()
        if row is None:
            return None
        return Receipt.from_json(row[0])

    def get_receipt_by_hash(self, hash: str) -> Receipt | None:
        """Get a receipt by its content hash."""
        row = self._conn.execute(
            "SELECT receipt_json FROM receipts WHERE content_hash = ?", (hash,)
        ).fetchone()
        if row is None:
            return None
        return Receipt.from_json(row[0])

    def list_receipts(self, limit: int = 50, offset: int = 0) -> list[Receipt]:
        """List receipts ordered by timestamp descending."""
        rows = self._conn.execute(
            "SELECT receipt_json FROM receipts ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [Receipt.from_json(row[0]) for row in rows]

    def list_by_session(
        self, session_id: str, limit: int = 50, offset: int = 0
    ) -> list[Receipt]:
        """List receipts for a specific session."""
        rows = self._conn.execute(
            "SELECT receipt_json FROM receipts WHERE session_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (session_id, limit, offset),
        ).fetchall()
        return [Receipt.from_json(row[0]) for row in rows]

    def latest_receipt_hash(self) -> str | None:
        """Get the content hash of the most recent receipt."""
        row = self._conn.execute(
            "SELECT content_hash FROM receipts ORDER BY timestamp DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None

    def count_receipts(self) -> int:
        """Count total receipts in the database."""
        row = self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()
        return row[0]

    def insert_merkle_leaf(self, index: int, leaf_hash: bytes) -> None:
        """Insert or replace a Merkle tree leaf."""
        self._conn.execute(
            "INSERT OR REPLACE INTO merkle_leaves (leaf_index, leaf_hash) VALUES (?, ?)",
            (index, leaf_hash),
        )
        self._conn.commit()

    def load_merkle_leaves(self) -> list[bytes]:
        """Load all Merkle tree leaves in order."""
        rows = self._conn.execute(
            "SELECT leaf_hash FROM merkle_leaves ORDER BY leaf_index ASC"
        ).fetchall()
        return [bytes(row[0]) for row in rows]

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()


def _format_timestamp(dt) -> str:
    """Format timestamp for storage."""
    s = dt.isoformat()
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"
    return s
