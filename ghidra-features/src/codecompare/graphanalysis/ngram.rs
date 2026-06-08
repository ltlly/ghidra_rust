//! N-gram hash structures for data-flow and control-flow graph matching.
//!
//! Ported from Ghidra's `DataNGram` and `CtrlNGram` Java classes in
//! `ghidra.features.codecompare.graphanalysis`.
//!
//! N-grams are the core fingerprinting mechanism of the Pinning algorithm.
//! Each n-gram captures the structural hash of a vertex's neighborhood up to
//! a given depth in either the data-flow or control-flow graph. Matching
//! n-gram hashes across two functions indicates structural similarity.
//!
//! # Key types
//!
//! - [`DataNGram`] -- n-gram hash rooted at a data-flow vertex
//! - [`CtrlNGram`] -- n-gram hash rooted at a control-flow vertex
//! - [`NGramHash`] -- raw hash value with weight and depth metadata

use std::cmp::Ordering;

use super::Side;

/// Raw n-gram hash with structural metadata.
///
/// An n-gram hash captures the structural fingerprint of a vertex's
/// neighborhood. The `weight` indicates how many nodes contribute to
/// the hash, `depth` is the maximum edge traversal distance, and `hash`
/// is the computed fingerprint value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NGramHash {
    /// The number of nodes involved in computing this hash.
    pub weight: u32,
    /// The maximum distance between nodes in this n-gram set.
    pub depth: u32,
    /// The computed hash value.
    pub hash: u64,
}

impl NGramHash {
    /// Create a new n-gram hash.
    pub fn new(weight: u32, depth: u32, hash: u64) -> Self {
        Self {
            weight,
            depth,
            hash,
        }
    }

    /// Check if two n-gram hashes have identical hash data (weight, depth, hash).
    ///
    /// The underlying vertices may differ; only the structural fingerprint
    /// is compared.
    pub fn equal_hash(&self, other: &Self) -> bool {
        self.weight == other.weight && self.depth == other.depth && self.hash == other.hash
    }
}

/// Sortable n-gram hash on the data-flow graph rooted at a specific [`DataVertex`].
///
/// The n-gram depth is the maximum number of backward edge traversals from the
/// root node to any other node involved in the hash. The n-gram weight is the
/// total number of nodes involved in the hash. N-grams sort with bigger weights
/// first so that n-grams involving more nodes are paired first.
///
/// Ported from Ghidra's `DataNGram` Java class.
#[derive(Debug, Clone)]
pub struct DataNGram {
    /// The number of nodes involved in this hash.
    pub weight: u32,
    /// The maximum distance between nodes in this n-gram set.
    pub depth: u32,
    /// The hash value.
    pub hash: u64,
    /// The UID of the root data-flow vertex.
    pub root_uid: u32,
    /// The side of the comparison this n-gram belongs to.
    pub side: Side,
    /// The UID of the data-flow graph this n-gram belongs to (for multi-graph tracking).
    pub graph_id: u32,
}

impl DataNGram {
    /// Create a new data-flow n-gram.
    ///
    /// # Arguments
    ///
    /// * `root_uid` -- the UID of the root data-flow vertex
    /// * `weight` -- the number of data-flow nodes involved in the n-gram
    /// * `depth` -- the maximum distance between nodes in the n-gram
    /// * `hash` -- the hash value for the n-gram
    /// * `side` -- which side of the comparison this n-gram belongs to
    pub fn new(
        root_uid: u32,
        weight: u32,
        depth: u32,
        hash: u64,
        side: Side,
    ) -> Self {
        Self {
            weight,
            depth,
            hash,
            root_uid,
            side,
            graph_id: side.value() as u32,
        }
    }

    /// Check if the hash of this n-gram matches another (weight, depth, and hash must all match).
    ///
    /// The underlying vertices may differ; only the structural fingerprint
    /// is compared.
    pub fn equal_hash(&self, other: &Self) -> bool {
        self.weight == other.weight && self.depth == other.depth && self.hash == other.hash
    }

    /// Check if this n-gram is rooted in a different data-flow graph than the other.
    ///
    /// Returns `true` if the two n-grams come from opposite sides of the comparison.
    pub fn graphs_differ(&self, other: &Self) -> bool {
        self.side != other.side
    }

    /// Convert to an [`NGramHash`] for generic hash operations.
    pub fn to_ngram_hash(&self) -> NGramHash {
        NGramHash::new(self.weight, self.depth, self.hash)
    }
}

impl PartialEq for DataNGram {
    fn eq(&self, other: &Self) -> bool {
        self.weight == other.weight
            && self.depth == other.depth
            && self.hash == other.hash
            && self.root_uid == other.root_uid
            && self.side == other.side
    }
}

impl Eq for DataNGram {}

impl PartialOrd for DataNGram {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DataNGram {
    /// Sort so that bigger weights come first, then bigger depths, then
    /// by hash value, then by root UID, and finally by side.
    ///
    /// This ordering ensures that the most structurally significant
    /// n-grams are processed first by the Pinning algorithm.
    fn cmp(&self, other: &Self) -> Ordering {
        // Bigger weight first
        match self.weight.cmp(&other.weight) {
            Ordering::Less => return Ordering::Greater,
            Ordering::Greater => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Bigger depth first
        match self.depth.cmp(&other.depth) {
            Ordering::Less => return Ordering::Greater,
            Ordering::Greater => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Then by hash
        match self.hash.cmp(&other.hash) {
            Ordering::Less => return Ordering::Less,
            Ordering::Greater => return Ordering::Greater,
            Ordering::Equal => {}
        }

        // For equivalent hashes, sort by node id
        match self.root_uid.cmp(&other.root_uid) {
            Ordering::Less => return Ordering::Greater,
            Ordering::Greater => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Finally, sort on the graph owning the root node
        other.side.value().cmp(&self.side.value())
    }
}

impl std::fmt::Display for DataNGram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "d={} h={} w={} vert={}",
            self.depth, self.hash, self.weight, self.root_uid
        )
    }
}

/// N-gram hash on the control-flow graph rooted at a specific [`CtrlVertex`].
///
/// The n-gram depth is the maximum number of backward edge traversals from the
/// root node to any other node involved in the hash. The n-gram weight is the
/// total number of nodes involved in the hash. N-grams sort with bigger weights
/// first so that n-grams involving more nodes are paired first.
///
/// Ported from Ghidra's `CtrlNGram` Java class.
#[derive(Debug, Clone)]
pub struct CtrlNGram {
    /// The number of nodes involved in this hash.
    pub weight: u32,
    /// The maximum distance between nodes in this n-gram set.
    pub depth: u32,
    /// The hash value.
    pub hash: u64,
    /// The UID of the root control-flow vertex.
    pub root_uid: u32,
    /// The side of the comparison this n-gram belongs to.
    pub side: Side,
}

impl CtrlNGram {
    /// Create a new control-flow n-gram.
    ///
    /// # Arguments
    ///
    /// * `root_uid` -- the UID of the root control-flow vertex
    /// * `weight` -- the number of nodes involved in computing the n-gram
    /// * `depth` -- the maximum distance between nodes in the n-gram
    /// * `hash` -- the hash value for the n-gram
    /// * `side` -- which side of the comparison this n-gram belongs to
    pub fn new(
        root_uid: u32,
        weight: u32,
        depth: u32,
        hash: u64,
        side: Side,
    ) -> Self {
        Self {
            weight,
            depth,
            hash,
            root_uid,
            side,
        }
    }

    /// Check if the hash of this n-gram matches another (weight, depth, and hash must all match).
    ///
    /// The underlying vertices may differ; only the structural fingerprint
    /// is compared.
    pub fn equal_hash(&self, other: &Self) -> bool {
        self.weight == other.weight && self.depth == other.depth && self.hash == other.hash
    }

    /// Check if this n-gram is rooted in a different control-flow graph than the other.
    ///
    /// Returns `true` if the two n-grams come from opposite sides of the comparison.
    pub fn graphs_differ(&self, other: &Self) -> bool {
        self.side != other.side
    }

    /// Convert to an [`NGramHash`] for generic hash operations.
    pub fn to_ngram_hash(&self) -> NGramHash {
        NGramHash::new(self.weight, self.depth, self.hash)
    }
}

impl PartialEq for CtrlNGram {
    fn eq(&self, other: &Self) -> bool {
        self.weight == other.weight
            && self.depth == other.depth
            && self.hash == other.hash
            && self.root_uid == other.root_uid
            && self.side == other.side
    }
}

impl Eq for CtrlNGram {}

impl PartialOrd for CtrlNGram {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CtrlNGram {
    /// Sort so that bigger weights come first, then bigger depths, then
    /// by hash value, then by root UID, and finally by side.
    fn cmp(&self, other: &Self) -> Ordering {
        // Bigger weight first
        match self.weight.cmp(&other.weight) {
            Ordering::Less => return Ordering::Greater,
            Ordering::Greater => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Bigger depth first
        match self.depth.cmp(&other.depth) {
            Ordering::Less => return Ordering::Greater,
            Ordering::Greater => return Ordering::Less,
            Ordering::Equal => {}
        }

        // Then by hash
        match self.hash.cmp(&other.hash) {
            Ordering::Less => return Ordering::Less,
            Ordering::Greater => return Ordering::Greater,
            Ordering::Equal => {}
        }

        // For equivalent hashes, sort by node id
        match self.root_uid.cmp(&other.root_uid) {
            Ordering::Less => return Ordering::Less,
            Ordering::Greater => return Ordering::Greater,
            Ordering::Equal => {}
        }

        // Finally, sort on the side
        self.side.value().cmp(&other.side.value())
    }
}

impl std::fmt::Display for CtrlNGram {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "d={} h={} w={} vert={}",
            self.depth, self.hash, self.weight, self.root_uid
        )
    }
}

/// Utility function to hash two integers into one using CRC32-based mixing.
///
/// Ported from Ghidra's `Pinning.hashTwo` static method.
pub fn hash_two(first: u32, second: u32) -> u32 {
    let mut result: u32 = 0;
    for i in 0..4 {
        result = crc32_one_byte(result, (first >> (i * 8)) & 0xFF);
    }
    for i in 0..4 {
        result = crc32_one_byte(result, (second >> (i * 8)) & 0xFF);
    }
    result
}

/// CRC32 single-byte update.
fn crc32_one_byte(crc: u32, byte: u32) -> u32 {
    let mut c = crc ^ byte;
    for _ in 0..8 {
        if c & 1 != 0 {
            c = (c >> 1) ^ 0xEDB88320;
        } else {
            c >>= 1;
        }
    }
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- DataNGram tests ---

    #[test]
    fn test_data_ngram_new() {
        let ngram = DataNGram::new(42, 10, 3, 0xDEADBEEF, Side::Left);
        assert_eq!(ngram.root_uid, 42);
        assert_eq!(ngram.weight, 10);
        assert_eq!(ngram.depth, 3);
        assert_eq!(ngram.hash, 0xDEADBEEF);
        assert_eq!(ngram.side, Side::Left);
    }

    #[test]
    fn test_data_ngram_equal_hash() {
        let a = DataNGram::new(1, 5, 2, 100, Side::Left);
        let b = DataNGram::new(2, 5, 2, 100, Side::Right);
        assert!(a.equal_hash(&b));

        let c = DataNGram::new(1, 6, 2, 100, Side::Left);
        assert!(!a.equal_hash(&c));
    }

    #[test]
    fn test_data_ngram_graphs_differ() {
        let left = DataNGram::new(1, 5, 2, 100, Side::Left);
        let right = DataNGram::new(2, 5, 2, 100, Side::Right);
        assert!(left.graphs_differ(&right));

        let also_left = DataNGram::new(2, 5, 2, 100, Side::Left);
        assert!(!left.graphs_differ(&also_left));
    }

    #[test]
    fn test_data_ngram_ordering_weight_first() {
        let heavier = DataNGram::new(1, 10, 2, 100, Side::Left);
        let lighter = DataNGram::new(1, 5, 2, 100, Side::Left);
        // Heavier should come first (smaller ordering)
        assert!(heavier < lighter);
    }

    #[test]
    fn test_data_ngram_ordering_depth_second() {
        let deeper = DataNGram::new(1, 5, 3, 100, Side::Left);
        let shallower = DataNGram::new(1, 5, 1, 100, Side::Left);
        // Deeper should come first
        assert!(deeper < shallower);
    }

    #[test]
    fn test_data_ngram_ordering_hash_third() {
        let a = DataNGram::new(1, 5, 2, 50, Side::Left);
        let b = DataNGram::new(1, 5, 2, 200, Side::Left);
        // Lower hash comes first
        assert!(a < b);
    }

    #[test]
    fn test_data_ngram_ordering_root_uid_fourth() {
        let a = DataNGram::new(1, 5, 2, 100, Side::Left);
        let b = DataNGram::new(3, 5, 2, 100, Side::Left);
        // Higher root_uid comes first (reverse ordering per Java)
        assert!(b < a);
    }

    #[test]
    fn test_data_ngram_display() {
        let ngram = DataNGram::new(42, 10, 3, 0xAB, Side::Left);
        let s = format!("{}", ngram);
        assert!(s.contains("d=3"));
        assert!(s.contains("w=10"));
        assert!(s.contains("vert=42"));
    }

    #[test]
    fn test_data_ngram_to_ngram_hash() {
        let ngram = DataNGram::new(1, 5, 3, 100, Side::Left);
        let nh = ngram.to_ngram_hash();
        assert_eq!(nh.weight, 5);
        assert_eq!(nh.depth, 3);
        assert_eq!(nh.hash, 100);
    }

    // --- CtrlNGram tests ---

    #[test]
    fn test_ctrl_ngram_new() {
        let ngram = CtrlNGram::new(100, 8, 4, 0xCAFEBABE, Side::Right);
        assert_eq!(ngram.root_uid, 100);
        assert_eq!(ngram.weight, 8);
        assert_eq!(ngram.depth, 4);
        assert_eq!(ngram.hash, 0xCAFEBABE);
        assert_eq!(ngram.side, Side::Right);
    }

    #[test]
    fn test_ctrl_ngram_equal_hash() {
        let a = CtrlNGram::new(1, 5, 2, 100, Side::Left);
        let b = CtrlNGram::new(2, 5, 2, 100, Side::Right);
        assert!(a.equal_hash(&b));

        let c = CtrlNGram::new(1, 5, 2, 200, Side::Left);
        assert!(!a.equal_hash(&c));
    }

    #[test]
    fn test_ctrl_ngram_graphs_differ() {
        let left = CtrlNGram::new(1, 5, 2, 100, Side::Left);
        let right = CtrlNGram::new(1, 5, 2, 100, Side::Right);
        assert!(left.graphs_differ(&right));
    }

    #[test]
    fn test_ctrl_ngram_ordering_weight() {
        let heavier = CtrlNGram::new(1, 10, 2, 100, Side::Left);
        let lighter = CtrlNGram::new(1, 5, 2, 100, Side::Left);
        assert!(heavier < lighter);
    }

    #[test]
    fn test_ctrl_ngram_display() {
        let ngram = CtrlNGram::new(42, 8, 4, 0xAB, Side::Left);
        let s = format!("{}", ngram);
        assert!(s.contains("d=4"));
        assert!(s.contains("w=8"));
        assert!(s.contains("vert=42"));
    }

    // --- NGramHash tests ---

    #[test]
    fn test_ngram_hash_equal() {
        let a = NGramHash::new(5, 3, 100);
        let b = NGramHash::new(5, 3, 100);
        assert!(a.equal_hash(&b));

        let c = NGramHash::new(5, 3, 200);
        assert!(!a.equal_hash(&c));
    }

    // --- hash_two tests ---

    #[test]
    fn test_hash_two_deterministic() {
        let h1 = hash_two(0x12345678, 0x9ABCDEF0);
        let h2 = hash_two(0x12345678, 0x9ABCDEF0);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_two_different_inputs() {
        let h1 = hash_two(1, 2);
        let h2 = hash_two(2, 1);
        // hash_two(1,2) != hash_two(2,1) in general
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_two_zero() {
        let h = hash_two(0, 0);
        // CRC32 of all-zero input is 0 (identity element)
        assert_eq!(h, 0);
    }
}
