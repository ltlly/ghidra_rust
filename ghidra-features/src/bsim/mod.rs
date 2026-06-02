//! BSim — Behavioral Similarity module.
//!
//! Finds functionally similar code by comparing function "signatures" (feature
//! vectors).  Based on Ghidra's BSim (Behavioral Similarity) framework.
//!
//! # Architecture
//!
//! - [`FeatureVector`] — a sparse weighted set of feature hashes extracted from
//!   a function.  Similarity between two functions is the cosine similarity of
//!   their aggregated feature vectors.
//!
//! - [`BSimSignature`] — bundles a [`FeatureVector`] set with an identifying
//!   SHA-256 function hash and metadata (name, architecture, compiler, basic-
//!   block / instruction / call counts).
//!
//! - [`BSimIndex`] — in-memory index mapping function hashes to aggregated
//!   feature vectors for fast threshold queries.
//!
//! - [`BSimDatabase`] — persists signatures in SQLite (via the `ghidra-core`
//!   [`Database`]) and keeps a hot [`BSimIndex`] in memory.
//!
//! # Example
//!
//! ```ignore
//! use ghidra_features::bsim::{BSimDatabase, BSimQuery};
//!
//! let mut db = BSimDatabase::in_memory()?;
//! let sig = BSimDatabase::compute_signature(&some_function)?;
//! db.insert(sig.clone())?;
//!
//! let query = BSimQuery::new(sig, 0.7, 20);
//! let matches = db.query(&query)?;
//! for m in &matches {
//!     println!("  {} -> {:.2}", m.target.metadata.function_name, m.similarity);
//! }
//! ```

use anyhow::{anyhow, Context, Result};
use ghidra_core::addr::{Address, AddressRange};
use ghidra_core::database::Database;
use ghidra_core::program::listing::{Function, FunctionData};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// FunctionFunction trait
// ---------------------------------------------------------------------------

/// Trait abstracting the minimal function interface needed by BSim signature
/// computation.  Both [`Function`] and custom wrappers can implement this.
pub trait FunctionFunction {
    /// The function name.
    fn get_name(&self) -> &str;
    /// The entry-point address.
    fn get_entry_point(&self) -> Address;
    /// The body address range (start..=end).
    fn get_body(&self) -> AddressRange;
    /// A human-readable signature string (e.g., `"void foo(int x, int y)"`).
    fn signature_string(&self) -> String;
}

impl FunctionFunction for Function {
    fn get_name(&self) -> &str {
        &self.name
    }
    fn get_entry_point(&self) -> Address {
        self.entry_point
    }
    fn get_body(&self) -> AddressRange {
        self.body
    }
    fn signature_string(&self) -> String {
        self.signature_string()
    }
}
use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// FeatureVector
// ---------------------------------------------------------------------------

/// A sparse weighted feature vector.
///
/// Each entry is a 32-bit feature hash paired with a `f32` weight.  Two
/// vectors are compared via cosine similarity (see
/// [`FeatureVector::cosine_similarity`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeatureVector {
    /// Number of distinct feature hashes (redundant with `hashes.len()`).
    pub hash_count: u32,
    /// The feature hashes.
    pub hashes: Vec<u32>,
    /// Per-hash weight (same length as `hashes`).
    pub weights: Vec<f32>,
}

impl FeatureVector {
    /// Create an empty feature vector.
    pub fn new() -> Self {
        Self {
            hash_count: 0,
            hashes: Vec::new(),
            weights: Vec::new(),
        }
    }

    /// Create a feature vector from parallel `hashes` / `weights` slices.
    pub fn from_pairs(hashes: Vec<u32>, weights: Vec<f32>) -> Self {
        assert_eq!(
            hashes.len(),
            weights.len(),
            "hashes and weights must have the same length"
        );
        let hash_count = hashes.len() as u32;
        Self {
            hash_count,
            hashes,
            weights,
        }
    }

    /// L2 norm (magnitude) of the weight vector.
    pub fn magnitude(&self) -> f64 {
        let sum_sq: f64 = self
            .weights
            .iter()
            .map(|w| (*w as f64) * (*w as f64))
            .sum();
        sum_sq.sqrt()
    }

    /// Cosine similarity to `other`.
    ///
    /// Returns 0.0 when either vector is empty or has zero magnitude.
    /// Returns 1.0 for identical non-zero vectors.
    pub fn cosine_similarity(&self, other: &FeatureVector) -> f64 {
        if self.hashes.is_empty() || other.hashes.is_empty() {
            return 0.0;
        }

        // Build lookup: hash → weight for the other vector.
        let other_map: HashMap<u32, f32> = other
            .hashes
            .iter()
            .copied()
            .zip(other.weights.iter().copied())
            .collect();

        let mut dot_product: f64 = 0.0;
        for (h, w) in self.hashes.iter().zip(self.weights.iter()) {
            if let Some(ow) = other_map.get(h) {
                dot_product += (*w as f64) * (*ow as f64);
            }
        }

        let mag_a = self.magnitude();
        let mag_b = other.magnitude();
        if mag_a == 0.0 || mag_b == 0.0 {
            return 0.0;
        }
        dot_product / (mag_a * mag_b)
    }

    /// Jaccard similarity (presence-only — ignores weights).
    pub fn jaccard_similarity(&self, other: &FeatureVector) -> f64 {
        if self.hashes.is_empty() && other.hashes.is_empty() {
            return 1.0;
        }
        let a_set: HashSet<u32> = self.hashes.iter().copied().collect();
        let b_set: HashSet<u32> = other.hashes.iter().copied().collect();
        let intersection = a_set.intersection(&b_set).count();
        let union = a_set.union(&b_set).count();
        if union == 0 {
            return 0.0;
        }
        intersection as f64 / union as f64
    }
}

impl Default for FeatureVector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BSimMetadata
// ---------------------------------------------------------------------------

/// Metadata attached to a BSim signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BSimMetadata {
    /// The function's name.
    pub function_name: String,
    /// Target architecture string (e.g. `"x86:LE:64:default"`).
    pub architecture: String,
    /// Compiler identification, if known.
    pub compiler: Option<String>,
    /// Approximate number of machine instructions in the function body.
    pub num_instructions: u32,
    /// Approximate number of basic blocks.
    pub num_basic_blocks: u32,
    /// Number of call sites in the function.
    pub num_calls: u32,
}

impl BSimMetadata {
    /// Build metadata from a [`Function`] and an architecture hint.
    pub fn from_function(func: &Function, arch: &str) -> Self {
        // Rough instruction estimate: ~4 bytes per instruction on average.
        let body_size = func.get_body().len();
        let est_instructions = if body_size < 4 { 0 } else { body_size / 4 } as u32;
        // Rough basic-block estimate: one block per ~5 instructions.
        let est_blocks = (est_instructions.max(1) / 5).max(1);
        Self {
            function_name: func.get_name().to_string(),
            architecture: arch.to_string(),
            compiler: None,
            num_instructions: est_instructions,
            num_basic_blocks: est_blocks,
            num_calls: count_substrings(&func.signature_string(), "call"),
        }
    }
}

// ---------------------------------------------------------------------------
// BSimSignature
// ---------------------------------------------------------------------------

/// A complete BSim signature: identity hash, feature vectors, and metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BSimSignature {
    /// SHA-256 of the function's normalised representation (stable identity).
    pub function_hash: [u8; 32],
    /// Feature vectors extracted from the function (n-gram, token, structural).
    pub features: Vec<FeatureVector>,
    /// Human-readable metadata.
    pub metadata: BSimMetadata,
}

impl BSimSignature {
    /// Create a signature from its components.
    pub fn new(
        function_hash: [u8; 32],
        features: Vec<FeatureVector>,
        metadata: BSimMetadata,
    ) -> Self {
        Self {
            function_hash,
            features,
            metadata,
        }
    }

    /// Merge all feature vectors into a single aggregated vector.
    ///
    /// Weights for duplicate hashes are summed, which makes the aggregate
    /// suitable for cosine-similarity comparison.
    pub fn aggregate_features(&self) -> FeatureVector {
        let mut combined: HashMap<u32, f32> = HashMap::new();
        for fv in &self.features {
            for (h, w) in fv.hashes.iter().zip(fv.weights.iter()) {
                *combined.entry(*h).or_insert(0.0) += *w;
            }
        }
        let hash_count = combined.len() as u32;
        let (hashes, weights): (Vec<u32>, Vec<f32>) = combined.into_iter().unzip();
        FeatureVector {
            hash_count,
            hashes,
            weights,
        }
    }
}

// ---------------------------------------------------------------------------
// BSimIndex — in-memory index
// ---------------------------------------------------------------------------

/// In-memory index for fast similarity lookups.
///
/// Stores aggregated feature vectors in `vectors` and maps function hashes to
/// their index in that list.
#[derive(Debug, Clone, Default)]
pub struct BSimIndex {
    /// Aggregated feature vectors (one per indexed signature).
    pub vectors: Vec<FeatureVector>,
    /// Function-hash → index into `vectors` + the full signature.
    pub fnv_table: HashMap<[u8; 32], (usize, BSimSignature)>,
}

impl BSimIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self {
            vectors: Vec::new(),
            fnv_table: HashMap::new(),
        }
    }

    /// Insert a signature into the index.
    pub fn insert(&mut self, sig: BSimSignature) {
        let aggregated = sig.aggregate_features();
        let idx = self.vectors.len();
        self.vectors.push(aggregated);
        self.fnv_table.insert(sig.function_hash, (idx, sig));
    }

    /// Find signatures whose cosine similarity to `query_vec` is at least
    /// `threshold`.  Returns at most `max_results`, sorted descending.
    pub fn query(
        &self,
        query_vec: &FeatureVector,
        threshold: f64,
        max_results: usize,
    ) -> Vec<(f64, &BSimSignature)> {
        let mut scored: Vec<(f64, usize)> = Vec::new();

        for (i, vec) in self.vectors.iter().enumerate() {
            let sim = query_vec.cosine_similarity(vec);
            if sim >= threshold {
                scored.push((sim, i));
            }
        }

        // Sort descending by similarity.
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(max_results);

        // Map vector index → signature reference.
        scored
            .into_iter()
            .filter_map(|(sim, idx)| {
                self.fnv_table
                    .values()
                    .find(|(i, _)| *i == idx)
                    .map(|(_, sig)| (sim, sig))
            })
            .collect()
    }

    /// Number of indexed signatures.
    pub fn len(&self) -> usize {
        self.fnv_table.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.fnv_table.is_empty()
    }
}

// ---------------------------------------------------------------------------
// BSimQuery / BSimMatch
// ---------------------------------------------------------------------------

/// Parameters for a similarity search.
#[derive(Debug, Clone)]
pub struct BSimQuery {
    /// The probe signature.
    pub signature: BSimSignature,
    /// Minimum cosine similarity (0.0 – 1.0).
    pub threshold: f64,
    /// Maximum number of results to return.
    pub max_results: usize,
}

impl BSimQuery {
    /// Create a new query.
    pub fn new(signature: BSimSignature, threshold: f64, max_results: usize) -> Self {
        Self {
            signature,
            threshold,
            max_results,
        }
    }
}

/// A single match result from a BSim query.
#[derive(Debug, Clone)]
pub struct BSimMatch {
    /// The query function hash.
    pub query_signature_hash: [u8; 32],
    /// The matching target signature.
    pub target: BSimSignature,
    /// Cosine similarity score (0.0 – 1.0).
    pub similarity: f64,
    /// Confidence score blending cosine similarity and feature overlap ratio.
    pub confidence: f64,
}

// ---------------------------------------------------------------------------
// BSimDatabase
// ---------------------------------------------------------------------------

/// Persisted BSim database wrapping an SQLite store and an in-memory index.
pub struct BSimDatabase {
    /// The underlying SQLite database.
    pub db: Database,
    /// The in-memory index for fast similarity queries.
    pub signature_index: BSimIndex,
}

impl BSimDatabase {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Open (or create) a BSim database at `path`.
    ///
    /// Existing signatures are loaded into the in-memory index automatically.
    pub fn open(path: &str) -> Result<Self> {
        let db = Database::open(path).map_err(|e| anyhow!("BSim: open db: {}", e))?;
        Self::init_tables(&db)?;
        let signature_index = Self::load_index(&*db.conn())?;
        Ok(Self {
            db,
            signature_index,
        })
    }

    /// Create a new in-memory BSim database (no persistent storage).
    pub fn in_memory() -> Result<Self> {
        let db = Database::in_memory().map_err(|e| anyhow!("BSim: in-memory db: {}", e))?;
        Self::init_tables(&db)?;
        Ok(Self {
            db,
            signature_index: BSimIndex::new(),
        })
    }

    /// Ensure the required SQL tables exist.
    fn init_tables(db: &Database) -> Result<()> {
        db.conn()
            .execute(
                "CREATE TABLE IF NOT EXISTS bsim_signatures (
                    function_hash   BLOB PRIMARY KEY,
                    function_name   TEXT    NOT NULL,
                    architecture    TEXT    NOT NULL,
                    compiler        TEXT,
                    num_instructions INTEGER NOT NULL DEFAULT 0,
                    num_basic_blocks INTEGER NOT NULL DEFAULT 0,
                    num_calls       INTEGER NOT NULL DEFAULT 0,
                    features_blob   BLOB    NOT NULL
                )",
                [],
            )
            .map_err(|e| anyhow!("BSim: create bsim_signatures table: {}", e))?;

        db.conn()
            .execute(
                "CREATE INDEX IF NOT EXISTS idx_bsim_func_name
                 ON bsim_signatures(function_name)",
                [],
            )
            .map_err(|e| anyhow!("BSim: create index: {}", e))?;

        Ok(())
    }

    /// Load every persisted signature into an in-memory [`BSimIndex`].
    fn load_index(conn: &rusqlite::Connection) -> Result<BSimIndex> {
        let mut index = BSimIndex::new();

        let mut stmt = conn
            .prepare(
                "SELECT function_hash, function_name, architecture, compiler,
                        num_instructions, num_basic_blocks, num_calls, features_blob
                 FROM bsim_signatures",
            )
            .map_err(|e| anyhow!("BSim: prepare load: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                let hash_bytes: Vec<u8> = row.get(0)?;
                let function_hash: [u8; 32] =
                    hash_bytes.as_slice().try_into().unwrap_or([0u8; 32]);
                let function_name: String = row.get(1)?;
                let architecture: String = row.get(2)?;
                let compiler: Option<String> = row.get(3)?;
                let num_instructions: u32 = row.get(4)?;
                let num_basic_blocks: u32 = row.get(5)?;
                let num_calls: u32 = row.get(6)?;
                let features_blob: Vec<u8> = row.get(7)?;
                Ok((
                    function_hash,
                    function_name,
                    architecture,
                    compiler,
                    num_instructions,
                    num_basic_blocks,
                    num_calls,
                    features_blob,
                ))
            })
            .map_err(|e| anyhow!("BSim: query signatures: {}", e))?;

        for row in rows {
            let (
                function_hash,
                function_name,
                architecture,
                compiler,
                num_instructions,
                num_basic_blocks,
                num_calls,
                features_blob,
            ) = row.map_err(|e| anyhow!("BSim: read row: {}", e))?;

            let features: Vec<FeatureVector> =
                bincode::deserialize(&features_blob).context("BSim: deserialize features")?;

            let metadata = BSimMetadata {
                function_name,
                architecture,
                compiler,
                num_instructions,
                num_basic_blocks,
                num_calls,
            };
            let sig = BSimSignature::new(function_hash, features, metadata);
            index.insert(sig);
        }

        Ok(index)
    }

    // -----------------------------------------------------------------------
    // Insertion
    // -----------------------------------------------------------------------

    /// Insert a single signature into both the persistent store and the index.
    pub fn insert(&mut self, sig: BSimSignature) -> Result<()> {
        let features_blob =
            bincode::serialize(&sig.features).context("BSim: serialize features")?;

        self.db
            .conn()
            .execute(
                "INSERT OR REPLACE INTO bsim_signatures
                 (function_hash, function_name, architecture, compiler,
                  num_instructions, num_basic_blocks, num_calls, features_blob)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    &sig.function_hash[..],
                    sig.metadata.function_name,
                    sig.metadata.architecture,
                    sig.metadata.compiler,
                    sig.metadata.num_instructions,
                    sig.metadata.num_basic_blocks,
                    sig.metadata.num_calls,
                    features_blob,
                ],
            )
            .map_err(|e| anyhow!("BSim: insert signature: {}", e))?;

        self.signature_index.insert(sig);
        Ok(())
    }

    /// Batch-insert multiple signatures.
    ///
    /// Each insert is an individual SQL statement; for very large batches
    /// consider wrapping in an explicit transaction externally.
    pub fn insert_batch(&mut self, sigs: Vec<BSimSignature>) -> Result<()> {
        for sig in sigs {
            self.insert(sig)?;
        }
        Ok(())
    }

    /// Remove a signature by its function hash.
    pub fn remove(&mut self, hash: &[u8; 32]) -> Result<bool> {
        let existed = self.signature_index.fnv_table.remove(hash).is_some();
        if existed {
            self.db
                .conn()
                .execute(
                    "DELETE FROM bsim_signatures WHERE function_hash = ?1",
                    rusqlite::params![&hash[..]],
                )
                .map_err(|e| anyhow!("BSim: delete signature: {}", e))?;

            // Rebuild the vectors list to keep indices tight.
            self.rebuild_vectors();
        }
        Ok(existed)
    }

    /// Rebuild `self.signature_index.vectors` from the `fnv_table`.
    fn rebuild_vectors(&mut self) {
        // Collect entries sorted by their old index to preserve ordering.
        let mut entries: Vec<([u8; 32], (usize, BSimSignature))> =
            self.signature_index.fnv_table.drain().collect();
        entries.sort_by_key(|(_, (idx, _))| *idx);

        self.signature_index.vectors.clear();
        for (hash, (_old_idx, sig)) in entries {
            let aggregated = sig.aggregate_features();
            let new_idx = self.signature_index.vectors.len();
            self.signature_index.vectors.push(aggregated);
            self.signature_index
                .fnv_table
                .insert(hash, (new_idx, sig));
        }
    }

    // -----------------------------------------------------------------------
    // Query
    // -----------------------------------------------------------------------

    /// Search for signatures similar to `query.signature`.
    pub fn query(&self, query: &BSimQuery) -> Result<Vec<BSimMatch>> {
        let query_vec = query.signature.aggregate_features();
        let matches =
            self.signature_index
                .query(&query_vec, query.threshold, query.max_results);

        let results: Vec<BSimMatch> = matches
            .into_iter()
            .map(|(similarity, target)| {
                let confidence =
                    Self::compute_confidence(&query_vec, &target.aggregate_features(), similarity);
                BSimMatch {
                    query_signature_hash: query.signature.function_hash,
                    target: target.clone(),
                    similarity,
                    confidence,
                }
            })
            .collect();

        Ok(results)
    }

    /// Confidence score blending cosine similarity with feature-overlap ratio.
    fn compute_confidence(
        query_vec: &FeatureVector,
        target_vec: &FeatureVector,
        similarity: f64,
    ) -> f64 {
        if query_vec.hashes.is_empty() || target_vec.hashes.is_empty() {
            return 0.0;
        }
        let query_set: HashSet<u32> = query_vec.hashes.iter().copied().collect();
        let target_set: HashSet<u32> = target_vec.hashes.iter().copied().collect();
        let intersection = query_set.intersection(&target_set).count();
        let min_size = query_set.len().min(target_set.len());
        if min_size == 0 {
            return 0.0;
        }
        let overlap_ratio = intersection as f64 / min_size as f64;
        0.5 * similarity + 0.5 * overlap_ratio
    }

    // -----------------------------------------------------------------------
    // Signature computation
    // -----------------------------------------------------------------------

    /// Compute a BSim signature from a [`Function`].
    ///
    /// Extracts three families of feature vectors:
    ///
    /// 1. **N-gram features** — 4-gram sliding window over the function's
    ///    decompiled signature string.
    /// 2. **Token features** — unigrams + bigrams of tokens parsed from the
    ///    signature.
    /// 3. **Structural features** — body-size bucket, token-count bucket,
    ///    name-length bucket.
    pub fn compute_signature(func: &Function) -> Result<BSimSignature> {
        let mut hasher = Sha256::new();

        // Stable identity hash from function properties.
        hasher.update(func.get_name().as_bytes());
        hasher.update(&func.get_entry_point().offset.to_le_bytes());
        hasher.update(&func.get_body().start.offset.to_le_bytes());
        hasher.update(&func.get_body().end.offset.to_le_bytes());
        hasher.update(func.signature_string().as_bytes());

        let function_hash: [u8; 32] = hasher.finalize().into();

        let features = vec![
            Self::extract_ngram_features(func),
            Self::extract_token_features(func),
            Self::extract_structural_features(func),
        ];

        let metadata = BSimMetadata::from_function(func, "unknown");

        Ok(BSimSignature::new(function_hash, features, metadata))
    }

    // -----------------------------------------------------------------------
    // Cosine similarity convenience
    // -----------------------------------------------------------------------

    /// Compute the cosine similarity between two feature vectors.
    pub fn similarity(a: &FeatureVector, b: &FeatureVector) -> f64 {
        a.cosine_similarity(b)
    }

    // -----------------------------------------------------------------------
    // Feature extraction helpers
    // -----------------------------------------------------------------------

    /// Extract 4-gram features from the function's decompiled signature.
    fn extract_ngram_features(func: &Function) -> FeatureVector {
        let sig_bytes: Vec<u8> = func.signature_string().bytes().collect();
        if sig_bytes.len() < 4 {
            return FeatureVector::new();
        }

        let mut count_map: HashMap<u32, u32> = HashMap::new();
        let n = 4usize;
        let limit = sig_bytes.len().min(1024).saturating_sub(n);

        for i in 0..=limit {
            let gram: u32 = ((sig_bytes[i] as u32) << 24)
                | ((sig_bytes[i + 1] as u32) << 16)
                | ((sig_bytes[i + 2] as u32) << 8)
                | (sig_bytes[i + 3] as u32);
            *count_map.entry(gram).or_insert(0) += 1;
        }

        counts_to_feature_vector(&count_map)
    }

    /// Extract token unigram + bigram features from the signature string.
    fn extract_token_features(func: &Function) -> FeatureVector {
        let sig = func.signature_string();
        let tokens: Vec<&str> = sig
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ',' || c == ';')
            .filter(|s| !s.is_empty())
            .collect();

        if tokens.is_empty() {
            return FeatureVector::new();
        }

        let mut count_map: HashMap<u32, u32> = HashMap::new();

        // Unigrams
        for token in &tokens {
            *count_map.entry(hash_token(token)).or_insert(0) += 1;
        }

        // Bigrams
        for window in tokens.windows(2) {
            let bigram = format!("{}_{}", window[0], window[1]);
            *count_map.entry(hash_token(&bigram)).or_insert(0) += 1;
        }

        counts_to_feature_vector(&count_map)
    }

    /// Extract structural features (size buckets, complexity buckets).
    fn extract_structural_features(func: &Function) -> FeatureVector {
        let body_size = func.get_body().len();
        let mut hashes = Vec::with_capacity(3);
        let mut weights = Vec::with_capacity(3);

        // Body-size bucket (log2).
        let size_bucket = if body_size == 0 {
            0
        } else {
            ((body_size as f64).log2().ceil() as u32).min(63)
        };
        hashes.push(0x0100_0000 | size_bucket);
        weights.push(1.0);

        // Token-count bucket (log2).
        let sig = func.signature_string();
        let token_count = sig
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ',' || c == ';')
            .filter(|s| !s.is_empty())
            .count() as u32;
        let token_bucket = if token_count == 0 {
            0
        } else {
            ((token_count as f64).log2().ceil() as u32).min(63)
        };
        hashes.push(0x0200_0000 | token_bucket);
        weights.push(1.0);

        // Name-length bucket (log2).
        let name_len = func.get_name().len() as u32;
        let name_bucket = if name_len == 0 {
            0
        } else {
            ((name_len as f64).log2().ceil() as u32).min(63)
        };
        hashes.push(0x0300_0000 | name_bucket);
        weights.push(0.5);

        FeatureVector {
            hash_count: hashes.len() as u32,
            hashes,
            weights,
        }
    }

    // -----------------------------------------------------------------------
    // Lookup helpers
    // -----------------------------------------------------------------------

    /// Number of signatures in the database.
    pub fn len(&self) -> usize {
        self.signature_index.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.signature_index.is_empty()
    }

    /// Look up a signature by its function hash.
    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<&BSimSignature> {
        self.signature_index
            .fnv_table
            .get(hash)
            .map(|(_, sig)| sig)
    }

    /// Return all function hashes in the database.
    pub fn function_hashes(&self) -> Vec<[u8; 32]> {
        self.signature_index.fnv_table.keys().copied().collect()
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// 32-bit FNV-1a hash of a string token.
fn hash_token(token: &str) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for byte in token.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// Count (case-insensitive) occurrences of `needle` in `haystack`.
fn count_substrings(haystack: &str, needle: &str) -> u32 {
    let hay_lower = haystack.to_lowercase();
    let ndl_lower = needle.to_lowercase();
    hay_lower
        .match_indices(&ndl_lower)
        .count() as u32
}

/// Convert a count map into a TF-weighted [`FeatureVector`].
fn counts_to_feature_vector(counts: &HashMap<u32, u32>) -> FeatureVector {
    let total: u32 = counts.values().sum();
    if total == 0 {
        return FeatureVector::new();
    }

    let hash_count = counts.len() as u32;
    let mut hashes = Vec::with_capacity(counts.len());
    let mut weights = Vec::with_capacity(counts.len());

    for (h, c) in counts {
        hashes.push(*h);
        weights.push(*c as f32 / total as f32);
    }

    FeatureVector {
        hash_count,
        hashes,
        weights,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};

    // ---- test fixtures -----------------------------------------------------

    fn func_a() -> FunctionData {
        FunctionData::new("strcpy", Address::new(0x1000), addr_range(0x1000, 0x10FF))
            .with_signature("char * strcpy(char *dest, const char *src)")
    }

    fn func_b() -> FunctionData {
        FunctionData::new("strncpy", Address::new(0x2000), addr_range(0x2000, 0x2100))
            .with_signature("char * strncpy(char *dest, const char *src, size_t n)")
    }

    fn func_c() -> FunctionData {
        FunctionData::new("main", Address::new(0x3000), addr_range(0x3000, 0x3200))
            .with_signature("int main(int argc, char **argv)")
    }

    fn func_d() -> FunctionData {
        FunctionData::new("memset", Address::new(0x4000), addr_range(0x4000, 0x403F))
            .with_signature("void * memset(void *s, int c, size_t n)")
    }

    fn addr_range(start: u64, end: u64) -> AddressRange {
        AddressRange::new(Address::new(start), Address::new(end))
    }

    // ---- FeatureVector tests -----------------------------------------------

    #[test]
    fn fv_cosine_identical_returns_one() {
        let fv = FeatureVector::from_pairs(vec![0xAA, 0xBB], vec![0.5, 0.5]);
        let sim = fv.cosine_similarity(&fv);
        assert!(
            (sim - 1.0).abs() < 1e-6,
            "identical vectors: expected 1.0, got {}",
            sim
        );
    }

    #[test]
    fn fv_cosine_orthogonal_returns_zero() {
        let a = FeatureVector::from_pairs(vec![0xAA], vec![1.0]);
        let b = FeatureVector::from_pairs(vec![0xBB], vec![1.0]);
        let sim = a.cosine_similarity(&b);
        assert!(
            (sim - 0.0).abs() < 1e-6,
            "disjoint vectors: expected 0.0, got {}",
            sim
        );
    }

    #[test]
    fn fv_empty_returns_zero() {
        let a = FeatureVector::new();
        let b = FeatureVector::new();
        assert_eq!(a.cosine_similarity(&b), 0.0);
    }

    #[test]
    fn fv_magnitude_three_four_five() {
        let fv = FeatureVector::from_pairs(vec![1, 2], vec![3.0, 4.0]);
        assert!((fv.magnitude() - 5.0).abs() < 1e-6);
    }

    #[test]
    fn fv_jaccard_half_overlap() {
        let a = FeatureVector::from_pairs(vec![1, 2, 3], vec![1.0; 3]);
        let b = FeatureVector::from_pairs(vec![2, 3, 4], vec![1.0; 3]);
        assert!((a.jaccard_similarity(&b) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn fv_jaccard_both_empty() {
        assert_eq!(
            FeatureVector::new().jaccard_similarity(&FeatureVector::new()),
            1.0
        );
    }

    // ---- Signature computation ---------------------------------------------

    #[test]
    fn compute_signature_produces_features() {
        let sig = BSimDatabase::compute_signature(&func_a()).unwrap();
        assert_eq!(sig.metadata.function_name, "strcpy");
        assert_eq!(sig.features.len(), 3);
        assert!(sig.function_hash.iter().any(|b| *b != 0));
    }

    #[test]
    fn signature_aggregation_combines_vectors() {
        let a = FeatureVector::from_pairs(vec![1, 2], vec![0.5, 0.5]);
        let b = FeatureVector::from_pairs(vec![2, 3], vec![0.5, 0.5]);
        let sig = BSimSignature::new(
            [0u8; 32],
            vec![a, b],
            BSimMetadata::from_function(&func_a(), "x86"),
        );
        let agg = sig.aggregate_features();
        // hash 2 appears in both → weight should sum to 1.0
        let mut map: HashMap<u32, f32> = HashMap::new();
        for (h, w) in agg.hashes.iter().zip(agg.weights.iter()) {
            map.insert(*h, *w);
        }
        assert!((map.get(&2).copied().unwrap_or(0.0) - 1.0).abs() < 1e-6);
    }

    // ---- Database round-trip -----------------------------------------------

    #[test]
    fn in_memory_insert_and_query() {
        let mut db = BSimDatabase::in_memory().unwrap();

        let sig_a = BSimDatabase::compute_signature(&func_a()).unwrap();
        let sig_b = BSimDatabase::compute_signature(&func_b()).unwrap();
        let sig_c = BSimDatabase::compute_signature(&func_c()).unwrap();

        db.insert(sig_a.clone()).unwrap();
        db.insert(sig_b).unwrap();
        db.insert(sig_c).unwrap();

        assert_eq!(db.len(), 3);

        let results = db
            .query(&BSimQuery::new(sig_a, 0.1, 10))
            .unwrap();
        assert!(!results.is_empty(), "should find at least self-match");
    }

    #[test]
    fn self_match_has_similarity_one() {
        let mut db = BSimDatabase::in_memory().unwrap();
        let sig = BSimDatabase::compute_signature(&func_a()).unwrap();
        let sig_clone = sig.clone();
        db.insert(sig).unwrap();

        let results = db
            .query(&BSimQuery::new(sig_clone, 0.99, 1))
            .unwrap();
        assert_eq!(results.len(), 1);
        assert!(
            (results[0].similarity - 1.0).abs() < 1e-6,
            "self-match similarity = {}",
            results[0].similarity
        );
    }

    #[test]
    fn high_threshold_filters_non_matches() {
        let mut db = BSimDatabase::in_memory().unwrap();

        let sig_a = BSimDatabase::compute_signature(&func_a()).unwrap();
        let sig_d = BSimDatabase::compute_signature(&func_d()).unwrap();

        db.insert(sig_a.clone()).unwrap();
        db.insert(sig_d).unwrap();

        let results = db
            .query(&BSimQuery::new(sig_a, 0.99, 10))
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn empty_database_query_returns_empty() {
        let db = BSimDatabase::in_memory().unwrap();
        let sig = BSimDatabase::compute_signature(&func_a()).unwrap();
        assert!(db
            .query(&BSimQuery::new(sig, 0.0, 10))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn get_by_hash_round_trip() {
        let mut db = BSimDatabase::in_memory().unwrap();
        let sig = BSimDatabase::compute_signature(&func_a()).unwrap();
        let hash = sig.function_hash;
        db.insert(sig).unwrap();

        let found = db.get_by_hash(&hash).unwrap();
        assert_eq!(found.metadata.function_name, "strcpy");
    }

    #[test]
    fn function_hashes_returns_all() {
        let mut db = BSimDatabase::in_memory().unwrap();
        db.insert(BSimDatabase::compute_signature(&func_a()).unwrap())
            .unwrap();
        db.insert(BSimDatabase::compute_signature(&func_b()).unwrap())
            .unwrap();
        assert_eq!(db.function_hashes().len(), 2);
    }

    #[test]
    fn remove_signature() {
        let mut db = BSimDatabase::in_memory().unwrap();
        let sig = BSimDatabase::compute_signature(&func_a()).unwrap();
        let hash = sig.function_hash;
        db.insert(sig).unwrap();
        assert_eq!(db.len(), 1);

        assert!(db.remove(&hash).unwrap());
        assert_eq!(db.len(), 0);
        assert!(db.get_by_hash(&hash).is_none());
    }

    #[test]
    fn remove_nonexistent_returns_false() {
        let mut db = BSimDatabase::in_memory().unwrap();
        assert!(!db.remove(&[0u8; 32]).unwrap());
    }

    #[test]
    fn batch_insert() {
        let mut db = BSimDatabase::in_memory().unwrap();
        let sigs: Vec<BSimSignature> = [func_a(), func_b(), func_c(), func_d()]
            .iter()
            .map(|f| BSimDatabase::compute_signature(f).unwrap())
            .collect();

        db.insert_batch(sigs).unwrap();
        assert_eq!(db.len(), 4);
    }

    #[test]
    fn hash_token_deterministic() {
        assert_eq!(hash_token("mov"), hash_token("mov"));
        assert_ne!(hash_token("mov"), hash_token("add"));
    }

    #[test]
    fn metadata_counts_calls() {
        let func = FunctionData::new("caller", Address::new(0x1000), addr_range(0x1000, 0x10FF))
            .with_signature("void caller(void) { call foo; call bar; }");
        let meta = BSimMetadata::from_function(&func, "x86");
        assert_eq!(meta.num_calls, 2);
    }

    #[test]
    fn persisted_database_survives_reopen() {
        let tmp = std::env::temp_dir().join(format!("bsim_test_{}.db", std::process::id()));
        let path = tmp.to_str().unwrap();

        // Round 1: insert.
        {
            let mut db = BSimDatabase::open(path).unwrap();
            let sig = BSimDatabase::compute_signature(&func_a()).unwrap();
            db.insert(sig).unwrap();
            assert_eq!(db.len(), 1);
        }

        // Round 2: reopen — should load from disk.
        {
            let db = BSimDatabase::open(path).unwrap();
            assert_eq!(db.len(), 1);
            let found = db.get_by_hash(
                &BSimDatabase::compute_signature(&func_a()).unwrap().function_hash,
            );
            assert!(found.is_some());
        }

        // Cleanup
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn similarity_convenience_matches_cosine() {
        let a = FeatureVector::from_pairs(vec![1, 2], vec![1.0, 1.0]);
        let b = FeatureVector::from_pairs(vec![1, 2], vec![1.0, 1.0]);
        assert!((BSimDatabase::similarity(&a, &b) - 1.0).abs() < 1e-6);
    }

    #[test]
    fn confidence_bounded_zero_to_one() {
        let mut db = BSimDatabase::in_memory().unwrap();
        let sig_a = BSimDatabase::compute_signature(&func_a()).unwrap();
        db.insert(sig_a.clone()).unwrap();
        let sig_b = BSimDatabase::compute_signature(&func_b()).unwrap();
        db.insert(sig_b).unwrap();

        let results = db
            .query(&BSimQuery::new(sig_a, 0.0, 10))
            .unwrap();
        for m in &results {
            assert!(
                (0.0..=1.0).contains(&m.confidence),
                "confidence {} out of range",
                m.confidence
            );
            assert!(
                (0.0..=1.0).contains(&m.similarity),
                "similarity {} out of range",
                m.similarity
            );
        }
    }
}
