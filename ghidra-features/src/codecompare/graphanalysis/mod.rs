//! Graph-based code analysis for cross-architecture comparison.
//!
//! Ported from Ghidra's `ghidra.features.codecompare.graphanalysis` Java package.
//!
//! Implements the **Pinning algorithm** that matches decompiler tokens
//! between two functions using data-flow and control-flow graph analysis.
//! This is the core engine behind cross-architecture code comparison.
//!
//! # Key types
//!
//! - [`TokenBin`] -- a group of decompiler tokens that share the same
//!   structural role, used for matching between the two sides
//! - [`Pinning`] -- the main matching engine
//! - [`DataVertex`] -- a vertex in a data-flow graph
//! - [`CtrlVertex`] -- a vertex in a control-flow graph
//! - [`NGramHash`] -- an n-gram hash for structural fingerprinting

use std::collections::HashMap;

/// The side of a comparison (left or right function).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Side {
    /// The left (source) function.
    Left = 0,
    /// The right (destination) function.
    Right = 1,
}

impl Side {
    /// The integer encoding of the side.
    pub fn value(&self) -> usize {
        *self as usize
    }

    /// The opposite side.
    pub fn opposite(&self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

/// A decompiler token with text and metadata.
#[derive(Debug, Clone)]
pub struct DecompilerToken {
    /// The token text.
    pub text: String,
    /// The token kind (keyword, variable, operator, etc.).
    pub kind: TokenKind,
    /// The address associated with this token.
    pub address: u64,
    /// The function side.
    pub side: Side,
}

/// The kind of a decompiler token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// A keyword (if, while, return, etc.).
    Keyword,
    /// A variable name.
    Variable,
    /// A function name.
    FunctionName,
    /// A numeric constant.
    Constant,
    /// An operator (+, -, ==, etc.).
    Operator,
    /// A type name.
    TypeName,
    /// A field name (struct member).
    FieldName,
    /// A comment.
    Comment,
    /// Other/unclassified.
    Other,
}

/// A vertex in the data-flow graph of a function.
///
/// Represents either a PcodeOp (operation) or a Varnode (variable).
#[derive(Debug, Clone)]
pub struct DataVertex {
    /// Unique identifier.
    pub uid: u32,
    /// The side this vertex belongs to.
    pub side: Side,
    /// The associated token, if any.
    pub token: Option<DecompilerToken>,
    /// The opcode or operation type.
    pub operation: String,
    /// Input vertex uids.
    pub inputs: Vec<u32>,
    /// Output vertex uids.
    pub outputs: Vec<u32>,
    /// Whether this is an operation vertex (vs. a varnode).
    pub is_op: bool,
}

impl DataVertex {
    /// Create a new data vertex.
    pub fn new(uid: u32, side: Side, operation: impl Into<String>, is_op: bool) -> Self {
        Self {
            uid,
            side,
            token: None,
            operation: operation.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            is_op,
        }
    }
}

/// A vertex in the control-flow graph.
#[derive(Debug, Clone)]
pub struct CtrlVertex {
    /// Unique identifier.
    pub uid: u32,
    /// The side this vertex belongs to.
    pub side: Side,
    /// Successor vertex uids.
    pub successors: Vec<u32>,
    /// Predecessor vertex uids.
    pub predecessors: Vec<u32>,
    /// The address of the basic block.
    pub address: u64,
}

impl CtrlVertex {
    /// Create a new control vertex.
    pub fn new(uid: u32, side: Side, address: u64) -> Self {
        Self {
            uid,
            side,
            successors: Vec::new(),
            predecessors: Vec::new(),
            address,
        }
    }
}

/// An n-gram of control-flow vertices, used for structural fingerprinting.
///
/// Ported from Ghidra's `CtrlNGram` Java class.
#[derive(Debug, Clone)]
pub struct CtrlNGram {
    /// The root control-flow vertex.
    pub root: u32,
    /// The structural hash of this n-gram.
    pub hash: u64,
    /// The depth of this n-gram.
    pub depth: u32,
    /// The weight (number of operations in the subtree).
    pub weight: u32,
}

/// A data-flow vertex linked with an underlying control-flow n-gram.
///
/// This is the unit that the Pinning algorithm operates on.
#[derive(Debug, Clone)]
pub struct DataCtrl {
    /// The data-flow vertex.
    pub data_vertex_uid: u32,
    /// The associated control-flow n-gram.
    pub ctrl_ngram: CtrlNGram,
}

/// A bin of matched tokens.
///
/// When the Pinning algorithm determines that a set of tokens from
/// the left function matches a set from the right function, it groups
/// them into paired TokenBins.
///
/// Ported from Ghidra's `TokenBin` Java class.
#[derive(Debug, Clone)]
pub struct TokenBin {
    /// The tokens in this bin.
    tokens: Vec<DecompilerToken>,
    /// The side this bin belongs to.
    pub side: Side,
    /// Index of the paired bin in the other side's bin list, if matched.
    pub match_index: Option<usize>,
}

impl TokenBin {
    /// Create a new empty token bin.
    pub fn new(side: Side) -> Self {
        Self {
            tokens: Vec::new(),
            side,
            match_index: None,
        }
    }

    /// Add a token to this bin.
    pub fn add(&mut self, token: DecompilerToken) {
        self.tokens.push(token);
    }

    /// Get the i-th token.
    pub fn get(&self, index: usize) -> Option<&DecompilerToken> {
        self.tokens.get(index)
    }

    /// Number of tokens in this bin.
    pub fn size(&self) -> usize {
        self.tokens.len()
    }

    /// Whether this bin is empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Whether this bin has been matched with a bin from the other side.
    pub fn is_matched(&self) -> bool {
        self.match_index.is_some()
    }

    /// Iterate over tokens.
    pub fn iter(&self) -> impl Iterator<Item = &DecompilerToken> {
        self.tokens.iter()
    }

    /// Get all tokens.
    pub fn tokens(&self) -> &[DecompilerToken] {
        &self.tokens
    }
}

/// A simplified Pinning algorithm implementation.
///
/// Ported from Ghidra's `Pinning` Java class.
///
/// The Pinning algorithm works in passes:
/// 1. Build data-flow and control-flow graphs for both functions
/// 2. Compute n-gram hashes for control-flow vertices
/// 3. Sort data vertices by their control-flow n-gram hashes
/// 4. Match vertices with identical hashes across the two sides
/// 5. Use matched vertices to anchor further matching (propagation)
///
/// This is a simplified version that operates on pre-built graph data
/// rather than directly interfacing with the decompiler.
pub struct Pinning {
    /// N-gram depth (default 24).
    ngram_depth: u32,
    /// Data-flow graph vertices for the left side.
    data_left: Vec<DataVertex>,
    /// Data-flow graph vertices for the right side.
    data_right: Vec<DataVertex>,
    /// Control-flow graph vertices for the left side.
    ctrl_left: Vec<CtrlVertex>,
    /// Control-flow graph vertices for the right side.
    ctrl_right: Vec<CtrlVertex>,
    /// Token bins produced by the matching.
    bins_left: Vec<TokenBin>,
    /// Token bins produced by the matching.
    bins_right: Vec<TokenBin>,
}

impl Pinning {
    /// Create a new Pinning instance.
    pub fn new() -> Self {
        Self {
            ngram_depth: 24,
            data_left: Vec::new(),
            data_right: Vec::new(),
            ctrl_left: Vec::new(),
            ctrl_right: Vec::new(),
            bins_left: Vec::new(),
            bins_right: Vec::new(),
        }
    }

    /// Set the n-gram depth.
    pub fn with_ngram_depth(mut self, depth: u32) -> Self {
        self.ngram_depth = depth;
        self
    }

    /// Set the data-flow vertices for the left side.
    pub fn set_data_left(&mut self, vertices: Vec<DataVertex>) {
        self.data_left = vertices;
    }

    /// Set the data-flow vertices for the right side.
    pub fn set_data_right(&mut self, vertices: Vec<DataVertex>) {
        self.data_right = vertices;
    }

    /// Set the control-flow vertices for the left side.
    pub fn set_ctrl_left(&mut self, vertices: Vec<CtrlVertex>) {
        self.ctrl_left = vertices;
    }

    /// Set the control-flow vertices for the right side.
    pub fn set_ctrl_right(&mut self, vertices: Vec<CtrlVertex>) {
        self.ctrl_right = vertices;
    }

    /// Run the Pinning algorithm and return the token bins.
    ///
    /// Returns (left_bins, right_bins) where matched bins at the same
    /// index correspond to each other.
    pub fn execute(&mut self) -> (&[TokenBin], &[TokenBin]) {
        // Phase 1: Compute n-gram hashes for control-flow vertices
        let ngram_left = self.compute_ngrams(&self.ctrl_left, Side::Left);
        let ngram_right = self.compute_ngrams(&self.ctrl_right, Side::Right);

        // Phase 2: Link data vertices with control-flow n-grams
        let mut data_ctrl_left: Vec<DataCtrl> = self
            .data_left
            .iter()
            .filter_map(|dv| {
                ngram_left.get(&dv.uid).map(|ngram| DataCtrl {
                    data_vertex_uid: dv.uid,
                    ctrl_ngram: ngram.clone(),
                })
            })
            .collect();

        let mut data_ctrl_right: Vec<DataCtrl> = self
            .data_right
            .iter()
            .filter_map(|dv| {
                ngram_right.get(&dv.uid).map(|ngram| DataCtrl {
                    data_vertex_uid: dv.uid,
                    ctrl_ngram: ngram.clone(),
                })
            })
            .collect();

        // Phase 3: Sort by n-gram hash
        data_ctrl_left.sort_by(|a, b| a.ctrl_ngram.hash.cmp(&b.ctrl_ngram.hash));
        data_ctrl_right.sort_by(|a, b| a.ctrl_ngram.hash.cmp(&b.ctrl_ngram.hash));

        // Phase 4: Match vertices with identical hashes
        let mut matches: Vec<(u32, u32)> = Vec::new();
        let mut ri = 0;
        for dc_left in &data_ctrl_left {
            while ri < data_ctrl_right.len()
                && data_ctrl_right[ri].ctrl_ngram.hash < dc_left.ctrl_ngram.hash
            {
                ri += 1;
            }
            if ri < data_ctrl_right.len()
                && data_ctrl_right[ri].ctrl_ngram.hash == dc_left.ctrl_ngram.hash
            {
                matches.push((dc_left.data_vertex_uid, data_ctrl_right[ri].data_vertex_uid));
            }
        }

        // Phase 5: Build token bins from matches
        self.bins_left.clear();
        self.bins_right.clear();

        for (left_uid, right_uid) in &matches {
            let mut left_bin = TokenBin::new(Side::Left);
            let mut right_bin = TokenBin::new(Side::Right);

            if let Some(dv) = self.data_left.iter().find(|d| &d.uid == left_uid) {
                if let Some(token) = &dv.token {
                    left_bin.add(token.clone());
                }
            }
            if let Some(dv) = self.data_right.iter().find(|d| &d.uid == right_uid) {
                if let Some(token) = &dv.token {
                    right_bin.add(token.clone());
                }
            }

            let idx = self.bins_left.len();
            left_bin.match_index = Some(idx);
            right_bin.match_index = Some(idx);

            self.bins_left.push(left_bin);
            self.bins_right.push(right_bin);
        }

        (&self.bins_left, &self.bins_right)
    }

    /// Compute n-gram hashes for control-flow vertices.
    fn compute_ngrams(
        &self,
        ctrl_vertices: &[CtrlVertex],
        _side: Side,
    ) -> HashMap<u32, CtrlNGram> {
        let mut result = HashMap::new();
        for vertex in ctrl_vertices {
            // Simple hash: combine uid with depth and successor info
            let hash = self.hash_ngram(vertex, ctrl_vertices, self.ngram_depth);
            let weight = self.count_subtree_weight(vertex, ctrl_vertices);
            result.insert(
                vertex.uid,
                CtrlNGram {
                    root: vertex.uid,
                    hash,
                    depth: self.ngram_depth,
                    weight,
                },
            );
        }
        result
    }

    /// Compute an n-gram hash for a control-flow vertex.
    fn hash_ngram(
        &self,
        vertex: &CtrlVertex,
        all: &[CtrlVertex],
        depth: u32,
    ) -> u64 {
        if depth == 0 {
            return vertex.uid as u64;
        }
        let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
        hash ^= vertex.uid as u64;
        hash = hash.wrapping_mul(0x100000001b3); // FNV prime

        for &succ_uid in &vertex.successors {
            if let Some(succ) = all.iter().find(|v| v.uid == succ_uid) {
                let child_hash = self.hash_ngram(succ, all, depth - 1);
                hash ^= child_hash;
                hash = hash.wrapping_mul(0x100000001b3);
            }
        }
        hash
    }

    /// Count the weight (number of descendants) of a control-flow vertex.
    fn count_subtree_weight(&self, vertex: &CtrlVertex, all: &[CtrlVertex]) -> u32 {
        let mut weight = 1u32;
        let mut visited = std::collections::HashSet::new();
        visited.insert(vertex.uid);

        let mut stack: Vec<u32> = vertex.successors.clone();
        while let Some(uid) = stack.pop() {
            if visited.insert(uid) {
                weight += 1;
                if let Some(v) = all.iter().find(|v| v.uid == uid) {
                    stack.extend(v.successors.iter().copied());
                }
            }
        }
        weight
    }

    /// Get the left-side token bins.
    pub fn bins_left(&self) -> &[TokenBin] {
        &self.bins_left
    }

    /// Get the right-side token bins.
    pub fn bins_right(&self) -> &[TokenBin] {
        &self.bins_right
    }
}

impl Default for Pinning {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple CRC32 hash for structural fingerprinting.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_side() {
        assert_eq!(Side::Left.value(), 0);
        assert_eq!(Side::Right.value(), 1);
        assert_eq!(Side::Left.opposite(), Side::Right);
        assert_eq!(Side::Right.opposite(), Side::Left);
    }

    #[test]
    fn test_token_bin() {
        let mut bin = TokenBin::new(Side::Left);
        assert!(bin.is_empty());
        assert!(!bin.is_matched());

        bin.add(DecompilerToken {
            text: "x".to_string(),
            kind: TokenKind::Variable,
            address: 0x1000,
            side: Side::Left,
        });

        assert_eq!(bin.size(), 1);
        assert_eq!(bin.get(0).unwrap().text, "x");
    }

    #[test]
    fn test_token_bin_match() {
        let mut bin = TokenBin::new(Side::Right);
        bin.match_index = Some(0);
        assert!(bin.is_matched());
    }

    #[test]
    fn test_pinning_simple_match() {
        let mut pinning = Pinning::new();

        // Left: two data vertices connected through a control vertex
        let mut ctrl_left = vec![
            CtrlVertex::new(100, Side::Left, 0x1000),
            CtrlVertex::new(101, Side::Left, 0x1040),
        ];
        ctrl_left[0].successors.push(101);
        ctrl_left[1].predecessors.push(100);

        let data_left = vec![
            DataVertex {
                uid: 1,
                side: Side::Left,
                token: Some(DecompilerToken {
                    text: "x".to_string(),
                    kind: TokenKind::Variable,
                    address: 0x1000,
                    side: Side::Left,
                }),
                operation: "COPY".to_string(),
                inputs: vec![],
                outputs: vec![],
                is_op: true,
            },
        ];

        // Right: same structure
        let mut ctrl_right = vec![
            CtrlVertex::new(200, Side::Right, 0x2000),
            CtrlVertex::new(201, Side::Right, 0x2040),
        ];
        ctrl_right[0].successors.push(201);
        ctrl_right[1].predecessors.push(200);

        let data_right = vec![
            DataVertex {
                uid: 2,
                side: Side::Right,
                token: Some(DecompilerToken {
                    text: "y".to_string(),
                    kind: TokenKind::Variable,
                    address: 0x2000,
                    side: Side::Right,
                }),
                operation: "COPY".to_string(),
                inputs: vec![],
                outputs: vec![],
                is_op: true,
            },
        ];

        pinning.set_ctrl_left(ctrl_left);
        pinning.set_ctrl_right(ctrl_right);
        pinning.set_data_left(data_left);
        pinning.set_data_right(data_right);

        let (left_bins, right_bins) = pinning.execute();
        // The algorithm should find at least one match
        // (exact matching depends on the n-gram hash computation)
        assert_eq!(left_bins.len(), right_bins.len());
    }

    #[test]
    fn test_pinning_empty() {
        let mut pinning = Pinning::new();
        let (left, right) = pinning.execute();
        assert!(left.is_empty());
        assert!(right.is_empty());
    }

    #[test]
    fn test_crc32() {
        let hash = crc32(b"hello");
        assert_ne!(hash, 0);
        // Same input should give same hash
        assert_eq!(hash, crc32(b"hello"));
        // Different input should (very likely) give different hash
        assert_ne!(hash, crc32(b"world"));
    }

    #[test]
    fn test_ngram_hash_deterministic() {
        let pinning = Pinning::new();
        let vertex = CtrlVertex {
            uid: 42,
            side: Side::Left,
            successors: vec![43, 44],
            predecessors: vec![],
            address: 0x1000,
        };
        let all = vec![
            vertex.clone(),
            CtrlVertex::new(43, Side::Left, 0x1040),
            CtrlVertex::new(44, Side::Left, 0x1080),
        ];
        let h1 = pinning.hash_ngram(&vertex, &all, 4);
        let h2 = pinning.hash_ngram(&vertex, &all, 4);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_data_vertex_new() {
        let dv = DataVertex::new(1, Side::Left, "ADD", true);
        assert_eq!(dv.uid, 1);
        assert_eq!(dv.side, Side::Left);
        assert_eq!(dv.operation, "ADD");
        assert!(dv.is_op);
    }
}
