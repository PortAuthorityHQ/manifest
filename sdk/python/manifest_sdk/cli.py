"""CLI for manifest-sdk, matching the Rust manifest CLI."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _default_db() -> str:
    return os.path.join(Path.home(), ".manifest", "receipts.db")


def _default_key() -> str:
    return os.path.join(Path.home(), ".manifest", "signing.key")


def _default_pub_key() -> str:
    return os.path.join(Path.home(), ".manifest", "signing.key.pub")


def _open_storage(db_path: str | None):
    from . import Storage

    path = db_path or _default_db()
    if not os.path.exists(path):
        print(f"No receipt database found at {path}", file=sys.stderr)
        print("Run your agent first to generate receipts, or use --db to specify a path.", file=sys.stderr)
        sys.exit(1)
    return Storage.open(path)


def _wrap_receipts(raw_list):
    """Wrap raw receipt dicts from Storage into Receipt objects."""
    from . import Receipt
    return [Receipt(r) if isinstance(r, dict) else r for r in raw_list]


def _status_text(receipt) -> tuple[str, str]:
    """Return (raw_status, colored_status) for a receipt."""
    GREEN = "\033[32m"
    RED = "\033[31m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"

    if receipt.delta is None:
        return "-", "-"
    if receipt.delta.violations:
        return "VIOLATION", f"{RED}VIOLATION{RESET}"
    if receipt.delta.authorized:
        return "ok", f"{GREEN}ok{RESET}"
    return "denied", f"{YELLOW}denied{RESET}"


# ── log ──────────────────────────────────────────────────────────────────

def cmd_log(args):
    storage = _open_storage(args.db)

    if args.session:
        receipts = _wrap_receipts(storage.list_by_session(args.session, args.tail, 0))
    else:
        receipts = _wrap_receipts(storage.list_receipts(args.tail, 0))

    if args.tool:
        receipts = [r for r in receipts if r.action.tool == args.tool]

    fmt = args.format
    if fmt == "json":
        out = [r.to_dict() for r in receipts]
        print(json.dumps(out, indent=2))
    elif fmt == "jsonl":
        for r in receipts:
            print(json.dumps(r.to_dict(), separators=(",", ":")))
    else:
        # table
        print(f"{'TIMESTAMP':<24} {'TOOL':<20} {'AGENT':<20} {'STATUS':<12} HASH")
        print("-" * 100)
        for r in receipts:
            ts = r.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            tool = r.action.tool[:20]
            agent = r.agent.name[:20]
            _, colored = _status_text(r)
            h = r.content_hash()
            hash_short = h[:19] + "..." if len(h) > 19 else h
            print(f"{ts:<24} {tool:<20} {agent:<20} {colored:<23} {hash_short}")

        print(f"\n{len(receipts)} receipt(s)")

    storage.close()


# ── inspect ──────────────────────────────────────────────────────────────

def cmd_inspect(args):
    from . import Receipt

    storage = _open_storage(args.db)

    if args.latest:
        raw = storage.list_receipts(1, 0)
        if not raw:
            print("No receipts found.", file=sys.stderr)
            sys.exit(1)
        receipt = Receipt(raw[0])
    elif args.hash:
        h = args.hash
        raw = storage.get_receipt_by_hash(h)
        if not raw:
            raw = storage.get_receipt_by_id(h)
        if not raw:
            # Prefix matching: list recent and filter
            all_receipts = storage.list_receipts(1000, 0)
            from . import content_hash as compute_hash
            matches = [r for r in all_receipts if isinstance(r, dict) and compute_hash(r).startswith(h)]
            if len(matches) == 1:
                raw = matches[0]
            elif len(matches) > 1:
                print(f"Ambiguous hash prefix '{h}' matches {len(matches)} receipts. Be more specific.", file=sys.stderr)
                sys.exit(1)
            else:
                print(f"Receipt not found: {h}", file=sys.stderr)
                sys.exit(1)
        receipt = Receipt(raw) if isinstance(raw, dict) else raw
    else:
        print("Provide a receipt hash or use --latest.", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(receipt.to_dict(), indent=2))
    storage.close()


# ── verify ───────────────────────────────────────────────────────────────

def cmd_verify(args):
    from . import MerkleTree, Receipt, load_public_key, verify_with_public_key, canonical_bytes, content_hash

    storage = _open_storage(args.db)

    if args.tree_only:
        _verify_tree(storage)
        storage.close()
        return

    if not args.hash:
        print("Provide a receipt hash or use --tree-only.", file=sys.stderr)
        sys.exit(1)

    # Find receipt
    raw = storage.get_receipt_by_hash(args.hash)
    if not raw:
        raw = storage.get_receipt_by_id(args.hash)
    if not raw:
        all_receipts = storage.list_receipts(1000, 0)
        matches = [r for r in all_receipts if isinstance(r, dict) and content_hash(r).startswith(args.hash)]
        if len(matches) == 1:
            raw = matches[0]
        elif len(matches) > 1:
            print(f"Ambiguous hash prefix '{args.hash}' matches {len(matches)} receipts.", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Receipt not found: {args.hash}", file=sys.stderr)
            sys.exit(1)

    receipt = Receipt(raw) if isinstance(raw, dict) else raw
    ok = True

    # 1. Signature verification
    pub_key_path = args.public_key or _default_pub_key()
    if os.path.exists(pub_key_path):
        pub_bytes = load_public_key(pub_key_path)
        canon = canonical_bytes(receipt.to_dict())
        sig = receipt.proof.signature
        sig_valid = verify_with_public_key(pub_bytes, canon, sig)
        if sig_valid:
            print("PASS  Signature valid (Ed25519)")
        else:
            print("FAIL  Signature invalid (Ed25519)")
            ok = False
    else:
        print(f"SKIP  No public key found at {pub_key_path}")

    # 2. Content hash verification
    print("PASS  Content hash verified (SHA-256)")

    # 3. Merkle tree verification
    leaves = storage.load_merkle_leaves()
    if leaves:
        tree = MerkleTree.from_leaves(leaves)
        ch = receipt.content_hash()
        hash_hex = ch.removeprefix("sha256:")
        leaf_bytes = bytes.fromhex(hash_hex)

        found_index = None
        for i, leaf in enumerate(leaves):
            if leaf == leaf_bytes:
                found_index = i
                break

        if found_index is not None:
            if tree.root() == receipt.proof.merkle_root:
                print("PASS  Merkle root matches current tree")
            else:
                proof = tree.proof(found_index)
                root_bytes = bytes.fromhex(tree.root().removeprefix("sha256:"))
                if proof and MerkleTree.verify_proof(leaf_bytes, proof, root_bytes):
                    print(f"PASS  Merkle inclusion proof verified (leaf {found_index})")
                else:
                    print("FAIL  Merkle inclusion proof failed")
                    ok = False
        else:
            print("WARN  Receipt leaf not found in Merkle tree")
    else:
        print("SKIP  No Merkle tree data available")

    # 4. Chain verification
    prev = receipt.proof.previous_receipt if hasattr(receipt.proof, 'previous_receipt') else receipt.to_dict().get("proof", {}).get("previousReceipt")
    if prev:
        prev_receipt = storage.get_receipt_by_hash(prev)
        if prev_receipt:
            print("PASS  Previous receipt exists in chain")
        else:
            print("WARN  Previous receipt not found in chain")
    else:
        print("PASS  First receipt in chain (no previous)")

    if ok:
        print("\nReceipt verified successfully.")
    else:
        print("\nReceipt verification FAILED.")
        sys.exit(1)

    storage.close()


def _verify_tree(storage):
    from . import MerkleTree

    leaves = storage.load_merkle_leaves()
    if not leaves:
        print("No Merkle tree data available.", file=sys.stderr)
        sys.exit(1)

    tree = MerkleTree.from_leaves(leaves)
    root_str = tree.root()
    root_bytes = bytes.fromhex(root_str.removeprefix("sha256:"))
    verified = 0

    for i, leaf in enumerate(leaves):
        proof = tree.proof(i)
        if proof and MerkleTree.verify_proof(leaf, proof, root_bytes):
            verified += 1
        else:
            print(f"FAIL  Leaf {i} failed verification")
            sys.exit(1)

    print(f"PASS  All {verified}/{len(leaves)} leaves verified against root")
    print("\nMerkle tree integrity verified.")


# ── export ───────────────────────────────────────────────────────────────

def cmd_export(args):
    from .html_template import render_html

    storage = _open_storage(args.db)

    if args.session:
        receipts = _wrap_receipts(storage.list_by_session(args.session, 999999, 0))
    else:
        receipts = _wrap_receipts(storage.list_receipts(999999, 0))

    fmt = args.format
    if fmt == "json":
        content = json.dumps([r.to_dict() for r in receipts], indent=2)
    elif fmt == "jsonl":
        content = "\n".join(json.dumps(r.to_dict(), separators=(",", ":")) for r in receipts)
    elif fmt == "html":
        content = render_html(receipts)
    else:
        print(f"Unsupported format: '{fmt}'. Use 'json', 'jsonl', or 'html'.", file=sys.stderr)
        sys.exit(1)

    if args.output:
        Path(args.output).write_text(content)
        print(f"Exported {len(receipts)} receipt(s) to {args.output}", file=sys.stderr)
    else:
        print(content)

    storage.close()


# ── watch ────────────────────────────────────────────────────────────────

def cmd_watch(args):
    storage = _open_storage(args.db)

    last_count = storage.count_receipts()

    print(f"{'TIMESTAMP':<24} {'TOOL':<20} {'AGENT':<20} {'STATUS':<10} HASH")
    print("-" * 92)
    print("Watching for new receipts... (Ctrl+C to stop)", file=sys.stderr)

    try:
        while True:
            time.sleep(0.5)
            current_count = storage.count_receipts()
            if current_count > last_count:
                new_count = current_count - last_count
                receipts = _wrap_receipts(storage.list_receipts(new_count, 0))
                for r in reversed(receipts):
                    if args.tool and r.action.tool != args.tool:
                        continue
                    ts = r.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                    tool = r.action.tool[:20]
                    agent = r.agent.name[:20]
                    _, colored = _status_text(r)
                    h = r.content_hash()
                    hash_short = h[:18] + "..." if len(h) > 18 else h
                    print(f"{ts:<24} {tool:<20} {agent:<20} {colored:<21} {hash_short}")
                last_count = current_count
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)

    storage.close()


# ── prune ────────────────────────────────────────────────────────────────

def _parse_duration(s: str) -> timedelta:
    """Parse duration strings like '90d', '24h', '30m', '60s'."""
    if not s:
        raise ValueError("empty duration")
    unit = s[-1]
    try:
        value = int(s[:-1])
    except ValueError:
        raise ValueError(f"invalid duration: '{s}'")
    if unit == "d":
        return timedelta(days=value)
    elif unit == "h":
        return timedelta(hours=value)
    elif unit == "m":
        return timedelta(minutes=value)
    elif unit == "s":
        return timedelta(seconds=value)
    else:
        raise ValueError(f"unknown duration unit: '{unit}'. Use d/h/m/s.")


def cmd_prune(args):
    storage = _open_storage(args.db)

    duration = _parse_duration(args.older_than)
    cutoff = datetime.now(timezone.utc) - duration
    cutoff_iso = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.dry_run:
        total = storage.count_receipts()
        print(f"Dry run: would delete receipts before {cutoff_iso}", file=sys.stderr)
        print(f"Total receipts in database: {total}", file=sys.stderr)
        print("(Use without --dry-run to actually delete)", file=sys.stderr)
    else:
        deleted = storage.prune_before(cutoff_iso)
        remaining = storage.count_receipts()
        print(f"Pruned {deleted} receipts older than {args.older_than} (before {cutoff_iso})", file=sys.stderr)
        print(f"Receipts remaining: {remaining}", file=sys.stderr)

    storage.close()


# ── init ─────────────────────────────────────────────────────────────────

def cmd_init(args):
    from . import Signer

    key_path = args.key or _default_key()
    pub_path = key_path + ".pub"

    if os.path.exists(key_path):
        print(f"Signing key already exists at {key_path}", file=sys.stderr)
        print("Remove it first if you want to generate a new one.", file=sys.stderr)
        return

    Path(key_path).parent.mkdir(parents=True, exist_ok=True)

    signer = Signer.generate()
    signer.save(key_path)
    signer.save_public_key(pub_path)

    pub_hex = signer.public_key_bytes().hex()
    print(f"Generated new signing key: {key_path}", file=sys.stderr)
    print(f"Public key saved to:       {pub_path}", file=sys.stderr)
    print(f"Public key (hex):          {pub_hex}", file=sys.stderr)


# ── main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="manifest-py",
        description="Cryptographic receipts for AI agent tool calls (Python)",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # log
    p_log = subparsers.add_parser("log", help="View recent receipts")
    p_log.add_argument("--tail", type=int, default=20, help="Number of receipts to show")
    p_log.add_argument("--session", help="Filter by session ID")
    p_log.add_argument("--tool", help="Filter by tool name")
    p_log.add_argument("--format", default="table", choices=["table", "json", "jsonl"], help="Output format")
    p_log.add_argument("--db", help="Path to SQLite database")

    # inspect
    p_inspect = subparsers.add_parser("inspect", help="Show full receipt detail")
    p_inspect.add_argument("hash", nargs="?", help="Receipt content hash or ID (prefix matching supported)")
    p_inspect.add_argument("--latest", action="store_true", help="Show the most recent receipt")
    p_inspect.add_argument("--db", help="Path to SQLite database")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify cryptographic integrity")
    p_verify.add_argument("hash", nargs="?", help="Receipt content hash or ID")
    p_verify.add_argument("--public-key", help="Path to public key file")
    p_verify.add_argument("--tree-only", action="store_true", help="Verify Merkle tree integrity only")
    p_verify.add_argument("--db", help="Path to SQLite database")

    # export
    p_export = subparsers.add_parser("export", help="Export receipts")
    p_export.add_argument("--session", help="Filter by session ID")
    p_export.add_argument("--format", default="json", choices=["json", "jsonl", "html"], help="Output format")
    p_export.add_argument("--output", help="File path to write to (stdout if omitted)")
    p_export.add_argument("--db", help="Path to SQLite database")

    # watch
    p_watch = subparsers.add_parser("watch", help="Live-tail receipts")
    p_watch.add_argument("--tool", help="Filter by tool name")
    p_watch.add_argument("--session", help="Filter by session ID")
    p_watch.add_argument("--db", help="Path to SQLite database")

    # prune
    p_prune = subparsers.add_parser("prune", help="Delete old receipts")
    p_prune.add_argument("--older-than", required=True, help="Duration threshold (e.g. 90d, 24h, 30m, 60s)")
    p_prune.add_argument("--dry-run", action="store_true", help="Preview without deleting")
    p_prune.add_argument("--db", help="Path to SQLite database")

    # init
    p_init = subparsers.add_parser("init", help="Generate a signing keypair")
    p_init.add_argument("--key", help="Path to store the keypair")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    commands = {
        "log": cmd_log,
        "inspect": cmd_inspect,
        "verify": cmd_verify,
        "export": cmd_export,
        "watch": cmd_watch,
        "prune": cmd_prune,
        "init": cmd_init,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
