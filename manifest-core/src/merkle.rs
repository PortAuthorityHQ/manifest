use crate::hashing::sha256;

/// Append-only Merkle tree for chaining receipts.
///
/// Each leaf is the SHA-256 content hash of a receipt. The tree grows as
/// receipts are appended, and the root provides a single hash that commits
/// to the entire receipt history. Inclusion proofs allow verifying that a
/// specific receipt is part of the chain without replaying all receipts.
pub struct MerkleTree {
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Create an empty tree.
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Restore a tree from previously stored leaves.
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        Self { leaves }
    }

    /// Append a new leaf (receipt content hash).
    pub fn append(&mut self, leaf: [u8; 32]) {
        self.leaves.push(leaf);
    }

    /// Compute the current Merkle root as `"sha256:<hex>"`.
    ///
    /// Returns a hash of the empty byte string if the tree has no leaves.
    pub fn root(&self) -> String {
        let root = compute_root(&self.leaves);
        format!("sha256:{}", hex::encode(root))
    }

    /// Number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Generate an inclusion proof for the leaf at `index`.
    ///
    /// Returns a list of `(sibling_hash, is_left)` pairs along the path from
    /// the leaf to the root. For promoted odd nodes (no sibling), no entry is
    /// added — the node is carried up as-is, matching the tree construction.
    /// Returns `None` if the index is out of bounds.
    pub fn proof(&self, index: usize) -> Option<Vec<(bool, [u8; 32])>> {
        if index >= self.leaves.len() {
            return None;
        }
        Some(compute_proof(&self.leaves, index))
    }

    /// Verify an inclusion proof.
    ///
    /// Each proof element is `(is_left, sibling)`: if `is_left` is true, the
    /// sibling goes on the left side of the hash pair.
    pub fn verify_proof(leaf: [u8; 32], proof: &[(bool, [u8; 32])], root: &[u8; 32]) -> bool {
        let mut hash = leaf;

        for &(is_left, ref sibling) in proof {
            hash = if is_left {
                hash_pair(sibling, &hash)
            } else {
                hash_pair(&hash, sibling)
            };
        }

        hash == *root
    }

    /// Get all leaves (for persistence).
    pub fn leaves(&self) -> &[[u8; 32]] {
        &self.leaves
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash two child nodes together to form a parent.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(left);
    combined.extend_from_slice(right);
    sha256(&combined)
}

/// Compute the Merkle root from a slice of leaves.
fn compute_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256(b"");
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));

        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                // Odd node: promote it to the next level
                next_level.push(chunk[0]);
            }
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Compute an inclusion proof (sibling hashes along the path to root).
///
/// Each element is `(is_left, sibling_hash)` — `is_left` means the sibling
/// should be placed on the left when hashing. Promoted odd nodes (no sibling)
/// produce no proof element, matching how `compute_root` promotes them.
fn compute_proof(leaves: &[[u8; 32]], index: usize) -> Vec<(bool, [u8; 32])> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let mut proof = Vec::new();
    let mut current_level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        if idx.is_multiple_of(2) {
            // Even index: sibling is to the right (idx + 1)
            if idx + 1 < current_level.len() {
                proof.push((false, current_level[idx + 1]));
            }
            // If no right sibling, node is promoted — no proof element
        } else {
            // Odd index: sibling is to the left (idx - 1)
            proof.push((true, current_level[idx - 1]));
        }

        // Build the next level
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(hash_pair(&chunk[0], &chunk[1]));
            } else {
                next_level.push(chunk[0]);
            }
        }

        current_level = next_level;
        idx /= 2;
    }

    proof
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::sha256;

    fn leaf(data: &[u8]) -> [u8; 32] {
        sha256(data)
    }

    #[test]
    fn empty_tree() {
        let tree = MerkleTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
        // Root of empty tree is hash of empty string
        let root = tree.root();
        assert!(root.starts_with("sha256:"));
    }

    #[test]
    fn single_leaf() {
        let mut tree = MerkleTree::new();
        let l = leaf(b"receipt-1");
        tree.append(l);

        assert_eq!(tree.len(), 1);
        // Root of single-leaf tree is the leaf itself
        let expected = format!("sha256:{}", hex::encode(l));
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn two_leaves() {
        let mut tree = MerkleTree::new();
        let l0 = leaf(b"receipt-0");
        let l1 = leaf(b"receipt-1");
        tree.append(l0);
        tree.append(l1);

        let expected_root = hash_pair(&l0, &l1);
        assert_eq!(tree.root(), format!("sha256:{}", hex::encode(expected_root)));
    }

    #[test]
    fn root_is_deterministic() {
        let mut t1 = MerkleTree::new();
        let mut t2 = MerkleTree::new();

        for i in 0..5 {
            let l = leaf(format!("receipt-{i}").as_bytes());
            t1.append(l);
            t2.append(l);
        }

        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn root_changes_on_append() {
        let mut tree = MerkleTree::new();
        tree.append(leaf(b"a"));
        let root1 = tree.root();

        tree.append(leaf(b"b"));
        let root2 = tree.root();

        assert_ne!(root1, root2);
    }

    #[test]
    fn inclusion_proof_two_leaves() {
        let mut tree = MerkleTree::new();
        let l0 = leaf(b"receipt-0");
        let l1 = leaf(b"receipt-1");
        tree.append(l0);
        tree.append(l1);

        let root_bytes = compute_root(&[l0, l1]);

        // Proof for leaf 0
        let proof = tree.proof(0).unwrap();
        assert!(MerkleTree::verify_proof(l0, &proof, &root_bytes));

        // Proof for leaf 1
        let proof = tree.proof(1).unwrap();
        assert!(MerkleTree::verify_proof(l1, &proof, &root_bytes));
    }

    #[test]
    fn inclusion_proof_multiple_leaves() {
        let mut tree = MerkleTree::new();
        let leaves: Vec<[u8; 32]> = (0..7).map(|i| leaf(format!("r-{i}").as_bytes())).collect();

        for &l in &leaves {
            tree.append(l);
        }

        let root_bytes = compute_root(&leaves);

        for (i, &l) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(
                MerkleTree::verify_proof(l, &proof, &root_bytes),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn inclusion_proof_power_of_two_leaves() {
        let mut tree = MerkleTree::new();
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| leaf(format!("r-{i}").as_bytes())).collect();

        for &l in &leaves {
            tree.append(l);
        }

        let root_bytes = compute_root(&leaves);

        for (i, &l) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(
                MerkleTree::verify_proof(l, &proof, &root_bytes),
                "proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn proof_rejects_wrong_leaf() {
        let mut tree = MerkleTree::new();
        let l0 = leaf(b"real");
        let l1 = leaf(b"also-real");
        tree.append(l0);
        tree.append(l1);

        let root_bytes = compute_root(&[l0, l1]);
        let proof = tree.proof(0).unwrap();

        let fake = leaf(b"fake");
        assert!(!MerkleTree::verify_proof(fake, &proof, &root_bytes));
    }

    #[test]
    fn from_leaves_matches_incremental() {
        let leaves: Vec<[u8; 32]> = (0..10).map(|i| leaf(format!("r-{i}").as_bytes())).collect();

        let mut incremental = MerkleTree::new();
        for &l in &leaves {
            incremental.append(l);
        }

        let restored = MerkleTree::from_leaves(leaves);
        assert_eq!(incremental.root(), restored.root());
    }

    #[test]
    fn out_of_bounds_proof() {
        let tree = MerkleTree::new();
        assert!(tree.proof(0).is_none());

        let mut tree = MerkleTree::new();
        tree.append(leaf(b"x"));
        assert!(tree.proof(1).is_none());
    }
}
