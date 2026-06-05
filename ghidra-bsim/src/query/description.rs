//! BSim function and executable description types.
//!
//! Ports `ghidra.features.bsim.query.description` from Ghidra's Java source.
//!
//! Contains the core data model for function signatures, executable metadata,
//! and similarity search results.

use serde::{Deserialize, Serialize};

/// Metadata about a binary executable registered with BSim.
///
/// Ports `ghidra.features.bsim.query.description.ExecutableRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimExecutableInfo {
    /// Unique identifier for this executable.
    pub executable_id: String,
    /// Human-readable name of the executable.
    pub executable_name: String,
    /// MD5 hash of the executable file.
    pub md5: String,
    /// Architecture (e.g., "x86", "ARM", "MIPS").
    pub architecture: String,
    /// Compiler used to build the executable (e.g., "gcc", "msvc").
    pub compiler: String,
    /// The path of the executable when it was analyzed.
    pub path: String,
    /// When this executable was ingested (Unix timestamp).
    pub ingest_date: Option<i64>,
    /// Whether this executable is marked as executable (vs. library).
    pub is_executable: bool,
    /// Number of functions in this executable.
    pub function_count: usize,
    /// Version string (if known).
    pub version: String,
    /// Whether this executable is trusted.
    pub trusted: bool,
    /// Optional parent executable ID for libraries.
    pub parent_id: Option<String>,
    /// Category tags.
    pub categories: Vec<String>,
}

impl BSimExecutableInfo {
    /// Create a new executable info with just an ID and name.
    pub fn new(executable_id: impl Into<String>, executable_name: impl Into<String>) -> Self {
        Self {
            executable_id: executable_id.into(),
            executable_name: executable_name.into(),
            md5: String::new(),
            architecture: String::new(),
            compiler: String::new(),
            path: String::new(),
            ingest_date: None,
            is_executable: true,
            function_count: 0,
            version: String::new(),
            trusted: false,
            parent_id: None,
            categories: Vec::new(),
        }
    }

    /// Set the MD5 hash.
    pub fn with_md5(mut self, md5: impl Into<String>) -> Self {
        self.md5 = md5.into();
        self
    }

    /// Set the architecture.
    pub fn with_architecture(mut self, arch: impl Into<String>) -> Self {
        self.architecture = arch.into();
        self
    }

    /// Set the compiler.
    pub fn with_compiler(mut self, compiler: impl Into<String>) -> Self {
        self.compiler = compiler.into();
        self
    }

    /// Set the path.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// Set the ingest date.
    pub fn with_ingest_date(mut self, timestamp: i64) -> Self {
        self.ingest_date = Some(timestamp);
        self
    }

    /// Add a category tag.
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.categories.push(category.into());
        self
    }
}

/// Description of a single function in BSim.
///
/// Ports `ghidra.features.bsim.query.description.FunctionDescription`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimFunctionDescription {
    /// ID of the executable this function belongs to.
    pub executable_id: String,
    /// Name of the function.
    pub function_name: String,
    /// Entry point address.
    pub entry_point: u64,
    /// Hash of the function body.
    pub function_hash: String,
    /// Size of the function in bytes.
    pub size: usize,
    /// Number of basic blocks.
    pub basic_block_count: usize,
    /// Number of call sites.
    pub call_count: usize,
    /// Instruction count.
    pub instruction_count: usize,
    /// The function's signature (sequence of mnemonics or P-code ops).
    pub signature: FunctionSignatureInfo,
    /// Whether this function is a library function.
    pub is_library: bool,
    /// Calling convention (e.g., "cdecl", "stdcall").
    pub calling_convention: String,
    /// Return type string.
    pub return_type: String,
    /// Parameter count.
    pub parameter_count: usize,
    /// Namespace or class name.
    pub namespace: String,
}

impl BSimFunctionDescription {
    /// Create a new function description.
    pub fn new(
        executable_id: impl Into<String>,
        function_name: impl Into<String>,
        entry_point: u64,
    ) -> Self {
        Self {
            executable_id: executable_id.into(),
            function_name: function_name.into(),
            entry_point,
            function_hash: String::new(),
            size: 0,
            basic_block_count: 0,
            call_count: 0,
            instruction_count: 0,
            signature: FunctionSignatureInfo::default(),
            is_library: false,
            calling_convention: String::new(),
            return_type: String::new(),
            parameter_count: 0,
            namespace: String::new(),
        }
    }

    /// Set the function hash.
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.function_hash = hash.into();
        self
    }

    /// Set the function size.
    pub fn with_size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    /// Set the basic block count.
    pub fn with_basic_block_count(mut self, count: usize) -> Self {
        self.basic_block_count = count;
        self
    }
}

/// Function signature information for similarity matching.
///
/// Contains the data used to compute similarity between functions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionSignatureInfo {
    /// The mnemonic sequence (instruction mnemonics).
    pub mnemonic_sequence: Vec<String>,
    /// The P-code flow signature.
    pub pcode_flow_signature: Vec<u8>,
    /// Number of constants referenced.
    pub constant_count: usize,
    /// Unique constants used in the function.
    pub constants: Vec<u64>,
    /// Call targets (addresses of called functions).
    pub call_targets: Vec<u64>,
    /// The byte histogram (256 bins for each byte value).
    pub byte_histogram: Vec<f64>,
    /// The CFG shape hash.
    pub cfg_hash: String,
    /// Data flow signature bytes.
    pub dataflow_signature: Vec<u8>,
    /// String references in the function.
    pub string_refs: Vec<String>,
    /// Register usage bitmask.
    pub register_usage: u64,
}

impl FunctionSignatureInfo {
    /// Create an empty signature.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the mnemonic sequence.
    pub fn with_mnemonics(mut self, mnemonics: Vec<String>) -> Self {
        self.mnemonic_sequence = mnemonics;
        self
    }

    /// Set the call targets.
    pub fn with_call_targets(mut self, targets: Vec<u64>) -> Self {
        self.call_targets = targets;
        self
    }

    /// Compute a simple hash of the signature.
    pub fn compute_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for m in &self.mnemonic_sequence {
            hasher.update(m.as_bytes());
        }
        for c in &self.constants {
            hasher.update(&c.to_le_bytes());
        }
        format!("{:x}", hasher.finalize())
    }
}

/// The similarity metric used for matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SimilarityMetric {
    /// Jaccard similarity on mnemonic sets.
    Jaccard,
    /// Cosine similarity on feature vectors.
    Cosine,
    /// Edit distance (normalized).
    EditDistance,
    /// LSH-based approximate matching.
    LshApproximate,
    /// Combined weighted metric.
    Combined,
}

impl SimilarityMetric {
    /// Get the display name of this metric.
    pub fn display_name(&self) -> &'static str {
        match self {
            SimilarityMetric::Jaccard => "Jaccard Similarity",
            SimilarityMetric::Cosine => "Cosine Similarity",
            SimilarityMetric::EditDistance => "Edit Distance",
            SimilarityMetric::LshApproximate => "LSH Approximate",
            SimilarityMetric::Combined => "Combined",
        }
    }
}

impl std::fmt::Display for SimilarityMetric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Result of a BSim similarity query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimResultSet {
    /// The matching function descriptions.
    pub results: Vec<BSimFunctionDescription>,
    /// Total number of matches found.
    pub total_matches: usize,
    /// Query execution time in milliseconds.
    pub query_time_ms: u64,
}

impl BSimResultSet {
    /// Create an empty result set.
    pub fn empty() -> Self {
        Self {
            results: Vec::new(),
            total_matches: 0,
            query_time_ms: 0,
        }
    }

    /// Whether the result set is empty.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Number of results.
    pub fn len(&self) -> usize {
        self.results.len()
    }
}

/// Result of comparing two function signatures.
///
/// Contains the similarity score and supporting information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildMatchRecord {
    /// Similarity score (0.0 to 1.0).
    pub similarity: f64,
    /// The matched function from the database.
    pub matched_function: BSimFunctionDescription,
    /// Which metric produced this match.
    pub metric: SimilarityMetric,
    /// Confidence level.
    pub confidence: f64,
}

impl ChildMatchRecord {
    /// Create a new match record.
    pub fn new(matched_function: BSimFunctionDescription, similarity: f64) -> Self {
        Self {
            similarity,
            matched_function,
            metric: SimilarityMetric::Combined,
            confidence: similarity,
        }
    }

    /// Whether this is a high-confidence match.
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executable_info_new() {
        let info = BSimExecutableInfo::new("id1", "test.exe");
        assert_eq!(info.executable_id, "id1");
        assert_eq!(info.executable_name, "test.exe");
        assert!(info.md5.is_empty());
        assert!(info.is_executable);
        assert!(!info.trusted);
    }

    #[test]
    fn test_executable_info_builder() {
        let info = BSimExecutableInfo::new("id1", "test.exe")
            .with_md5("abc123")
            .with_architecture("x86")
            .with_compiler("gcc")
            .with_path("/usr/bin/test")
            .with_category("malware");
        assert_eq!(info.md5, "abc123");
        assert_eq!(info.architecture, "x86");
        assert_eq!(info.categories.len(), 1);
    }

    #[test]
    fn test_function_description() {
        let func = BSimFunctionDescription::new("exe1", "main", 0x1000)
            .with_hash("deadbeef")
            .with_size(256);
        assert_eq!(func.function_name, "main");
        assert_eq!(func.entry_point, 0x1000);
        assert_eq!(func.function_hash, "deadbeef");
        assert_eq!(func.size, 256);
    }

    #[test]
    fn test_similarity_metric_display() {
        assert_eq!(SimilarityMetric::Jaccard.to_string(), "Jaccard Similarity");
        assert_eq!(SimilarityMetric::Cosine.to_string(), "Cosine Similarity");
    }

    #[test]
    fn test_bsim_result_set() {
        let rs = BSimResultSet::empty();
        assert!(rs.is_empty());
        assert_eq!(rs.len(), 0);

        let rs = BSimResultSet {
            results: vec![
                BSimFunctionDescription::new("e1", "f1", 0),
                BSimFunctionDescription::new("e1", "f2", 0x100),
            ],
            total_matches: 2,
            query_time_ms: 15,
        };
        assert!(!rs.is_empty());
        assert_eq!(rs.len(), 2);
    }

    #[test]
    fn test_child_match_record() {
        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        let record = ChildMatchRecord::new(func, 0.95);
        assert!(record.is_high_confidence());
        assert_eq!(record.similarity, 0.95);

        let func = BSimFunctionDescription::new("exe1", "other", 0x2000);
        let record = ChildMatchRecord::new(func, 0.5);
        assert!(!record.is_high_confidence());
    }

    #[test]
    fn test_signature_info_default() {
        let sig = FunctionSignatureInfo::new();
        assert!(sig.mnemonic_sequence.is_empty());
        assert!(sig.constants.is_empty());
        assert!(sig.byte_histogram.is_empty());
    }
}
