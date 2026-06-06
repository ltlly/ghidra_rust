//! BSim wire protocol types.
//!
//! Ports `ghidra.features.bsim.query.protocol` from Ghidra's Java source.
//!
//! This module contains:
//! - **Request/Response** types for BSim RPC communication
//! - **Filter types** (`FilterAtom`, `ChildAtom`, `BSimFilter`) for query filtering
//! - **Protocol types** (`ExeSpecifier`, `FunctionEntry`, `PairInput`, etc.)
//! - **Query/Response record** types (`QueryNearest`, `ResponseNearest`, etc.)
//! - **Staging** types for splitting large queries

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::description::{BSimExecutableInfo, BSimFunctionDescription, SimilarityMetric};

// ============================================================================
// Request / Response (high-level RPC messages)
// ============================================================================

/// A BSim request message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BSimRequest {
    /// Register a new executable.
    RegisterExecutable(BSimExecutableInfo),
    /// Ingest function descriptions.
    IngestFunctions(Vec<BSimFunctionDescription>),
    /// Query for similar functions.
    QuerySimilar {
        /// The function to find matches for.
        description: BSimFunctionDescription,
        /// Which metric to use.
        metric: SimilarityMetric,
        /// Maximum results to return.
        max_results: usize,
        /// Minimum similarity threshold.
        min_similarity: f64,
    },
    /// Query by function hash.
    QueryByHash(String),
    /// Get functions for an executable.
    GetFunctions(String),
    /// Get executable info.
    GetExecutableInfo(String),
    /// Get total function count.
    GetFunctionCount,
    /// Get total executable count.
    GetExecutableCount,
    /// Remove an executable.
    RemoveExecutable(String),
    /// Create a new database.
    CreateDatabase(String),
    /// Drop a database.
    DropDatabase(String),
    /// Insert function descriptions.
    InsertRequest(InsertRequestData),
    /// Update function descriptions.
    UpdateRequest {
        /// Functions to update.
        functions: Vec<BSimFunctionDescription>,
    },
    /// Query for function info.
    QueryInfo,
    /// Query by name.
    QueryName {
        /// Function name to search for.
        name: String,
    },
    /// Delete functions.
    QueryDelete {
        /// Executable name.
        exe_name: String,
    },
    /// Query for cluster information.
    QueryCluster {
        /// Functions to query.
        descriptions: Vec<BSimFunctionDescription>,
        /// Similarity threshold.
        threshold: f64,
    },
    /// Query for children of a function.
    QueryChildren {
        /// Parent function.
        description: BSimFunctionDescription,
    },
    /// Query for a pair of functions.
    QueryPair(PairInputData),
    /// Install category request.
    InstallCategory {
        /// Category name.
        category: String,
    },
    /// Install metadata request.
    InstallMetadata {
        /// Key-value pairs.
        metadata: HashMap<String, String>,
    },
    /// Install tag request.
    InstallTag {
        /// Tag name.
        tag: String,
    },
    /// Adjust vector index.
    AdjustVectorIndex {
        /// New index value.
        new_index: i64,
    },
    /// Change password.
    PasswordChange {
        /// Old password.
        old_password: String,
        /// New password.
        new_password: String,
    },
    /// Prewarm request.
    PrewarmRequest,
    /// Query nearest by vector.
    QueryNearestVector {
        /// Function descriptions to query.
        descriptions: Vec<BSimFunctionDescription>,
        /// Similarity threshold.
        threshold: f64,
        /// Max results per function.
        max_results: usize,
    },
    /// Health check / ping.
    Ping,
}

/// A BSim response message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BSimResponse {
    /// Success with no data.
    Success,
    /// Function descriptions returned.
    Functions(Vec<BSimFunctionDescription>),
    /// Executable info returned.
    ExecutableInfo(Option<BSimExecutableInfo>),
    /// A count value.
    Count(usize),
    /// An error response.
    Error(String),
    /// Pong response to ping.
    Pong,
    /// Nearest matches for a query.
    NearestResults(Vec<SimilarityNoteData>),
    /// Cluster results.
    ClusterResults(Vec<ClusterNoteData>),
    /// Children results.
    ChildrenResults(Vec<FunctionEntryData>),
    /// Pair comparison results.
    PairResult(PairNoteData),
    /// Executable info with name.
    ExeResult(ExeResultData),
    /// Vector match results.
    VectorResults(Vec<VectorResultData>),
    /// Vector ID results.
    VectorIdResults(Vec<i64>),
    /// Name results.
    NameResults(Vec<String>),
    /// Database info.
    DatabaseInfo(DatabaseInfoData),
    /// Query info results.
    InfoResult(QueryInfoData),
}

impl BSimResponse {
    /// Whether this response indicates success.
    pub fn is_success(&self) -> bool {
        !matches!(self, BSimResponse::Error(_))
    }

    /// Get the error message if this is an error response.
    pub fn error_message(&self) -> Option<&str> {
        match self {
            BSimResponse::Error(msg) => Some(msg),
            _ => None,
        }
    }
}

// ============================================================================
// ExeSpecifier -- Identifies an executable
// ============================================================================

/// Identifies an executable in the BSim database.
///
/// Ports `ghidra.features.bsim.query.protocol.ExeSpecifier`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExeSpecifier {
    /// Name of the executable.
    pub exe_name: String,
    /// Architecture (e.g., x86, ARM).
    pub arch: String,
    /// Compiler name.
    pub compiler_name: String,
    /// MD5 hash of the executable.
    pub md5: String,
}

impl ExeSpecifier {
    /// Create a new ExeSpecifier with just a name.
    pub fn new(exe_name: impl Into<String>) -> Self {
        Self {
            exe_name: exe_name.into(),
            ..Default::default()
        }
    }

    /// Create an ExeSpecifier from an MD5 hash.
    pub fn from_md5(md5: impl Into<String>) -> Self {
        Self {
            md5: md5.into(),
            ..Default::default()
        }
    }

    /// Get the executable name with MD5.
    pub fn exe_name_with_md5(&self) -> String {
        let mut buf = String::new();
        if !self.exe_name.is_empty() {
            buf.push_str(&self.exe_name);
        }
        if !self.md5.is_empty() {
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(&self.md5);
        }
        buf
    }

    /// Check if this specifier is empty (no identifying information).
    pub fn is_empty(&self) -> bool {
        self.exe_name.is_empty() && self.md5.is_empty()
    }
}

impl PartialEq for ExeSpecifier {
    fn eq(&self, other: &Self) -> bool {
        if !self.md5.is_empty() {
            return self.md5 == other.md5;
        }
        self.exe_name == other.exe_name && self.arch == other.arch && self.compiler_name == other.compiler_name
    }
}

impl Eq for ExeSpecifier {}

impl PartialOrd for ExeSpecifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExeSpecifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        if !self.md5.is_empty() {
            return self.md5.cmp(&other.md5);
        }
        self.exe_name
            .cmp(&other.exe_name)
            .then_with(|| self.arch.cmp(&other.arch))
            .then_with(|| self.compiler_name.cmp(&other.compiler_name))
    }
}

// ============================================================================
// FunctionEntry -- Identifies a function within an executable
// ============================================================================

/// Identifying information for a function within a single executable.
///
/// Ports `ghidra.features.bsim.query.protocol.FunctionEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntryData {
    /// Name of the function within the executable.
    pub func_name: String,
    /// Address of the function.
    pub address: u64,
}

impl FunctionEntryData {
    /// Create a new function entry.
    pub fn new(func_name: impl Into<String>, address: u64) -> Self {
        Self {
            func_name: func_name.into(),
            address,
        }
    }
}

// ============================================================================
// FilterAtom -- A single filter element
// ============================================================================

/// The type of filter operation.
///
/// Ports Ghidra's `BSimFilterType` names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterType {
    /// Blank/empty filter.
    Blank,
    /// Filter by executable name (positive match).
    ExeNameMatch,
    /// Filter by executable name (negative match).
    ExeNameNotMatch,
    /// Filter by architecture.
    ArchitectureMatch,
    /// Filter by compiler.
    CompilerMatch,
    /// Filter by MD5.
    Md5Match,
    /// Filter by date (earlier than).
    DateEarlier,
    /// Filter by date (later than).
    DateLater,
    /// Filter by executable category.
    ExeCategory,
    /// Filter by function tag.
    FunctionTag(String),
    /// Filter by path prefix.
    PathStarts,
    /// Filter by named child.
    HasNamedChild,
    /// Custom filter type by name.
    Custom(String),
}

impl FilterType {
    /// Whether this filter type is blank/empty.
    pub fn is_blank(&self) -> bool {
        matches!(self, FilterType::Blank)
    }

    /// Whether this is a child filter type.
    pub fn is_child_filter(&self) -> bool {
        matches!(self, FilterType::HasNamedChild)
    }

    /// Whether this filter should use OR semantics for multiple values.
    pub fn or_multiple_entries(&self) -> bool {
        matches!(
            self,
            FilterType::ExeNameNotMatch | FilterType::Md5Match
        )
    }

    /// Get the label for this filter type.
    pub fn label(&self) -> &str {
        match self {
            FilterType::Blank => "",
            FilterType::ExeNameMatch => "Executable name",
            FilterType::ExeNameNotMatch => "Executable name (not)",
            FilterType::ArchitectureMatch => "Architecture",
            FilterType::CompilerMatch => "Compiler",
            FilterType::Md5Match => "MD5",
            FilterType::DateEarlier => "Date (earlier)",
            FilterType::DateLater => "Date (later)",
            FilterType::ExeCategory => "Category",
            FilterType::FunctionTag(tag) => tag,
            FilterType::PathStarts => "Path",
            FilterType::HasNamedChild => "Has named child",
            FilterType::Custom(name) => name,
        }
    }

    /// Get the flag value for function tag filters.
    pub fn flag(&self) -> Option<u32> {
        match self {
            FilterType::FunctionTag(_tag) => {
                // In Ghidra, each FunctionTagBSimFilterType has a unique flag.
                // Here we compute a simple hash-based flag.
                Some(1)
            }
            _ => None,
        }
    }
}

/// A single element for filtering on specific properties of ExecutableRecords
/// or FunctionDescriptions.
///
/// Ports `ghidra.features.bsim.query.protocol.FilterAtom`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterAtom {
    /// The type of filter to perform.
    pub filter_type: FilterType,
    /// The value to match against.
    pub value: String,
}

impl FilterAtom {
    /// Create a new FilterAtom.
    pub fn new(filter_type: FilterType, value: impl Into<String>) -> Self {
        Self {
            filter_type,
            value: value.into(),
        }
    }

    /// Whether this atom has a non-null value.
    pub fn is_valid(&self) -> bool {
        !self.value.is_empty()
    }

    /// Get the info string for this atom.
    pub fn info_string(&self) -> Option<String> {
        if self.filter_type.is_blank() {
            return None;
        }
        Some(format!("{} {}", self.filter_type.label(), self.value))
    }

    /// Get the value string.
    pub fn value_string(&self) -> &str {
        &self.value
    }
}

/// A child atom filter -- extends FilterAtom with child function information.
///
/// Ports `ghidra.features.bsim.query.protocol.ChildAtom`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildAtom {
    /// Base filter atom.
    pub atom: FilterAtom,
    /// Name of the child function.
    pub child_name: String,
    /// Name of the executable containing the child.
    pub exe_name: Option<String>,
}

impl ChildAtom {
    /// Create a new ChildAtom.
    pub fn new(filter_type: FilterType, child_name: impl Into<String>) -> Self {
        let child_name = child_name.into();
        Self {
            atom: FilterAtom::new(filter_type, child_name.clone()),
            child_name,
            exe_name: None,
        }
    }

    /// Get the info string.
    pub fn info_string(&self) -> Option<String> {
        if self.child_name.is_empty() {
            return None;
        }
        let mut res = String::from("Has child ");
        if let Some(exe) = &self.exe_name {
            res.push('[');
            res.push_str(exe);
            res.push(']');
        }
        res.push_str(&self.child_name);
        Some(res)
    }

    /// Get the value string (including exe name prefix if present).
    pub fn value_string(&self) -> String {
        if let Some(exe) = &self.exe_name {
            format!("[{}]{}", exe, self.child_name)
        } else {
            self.child_name.clone()
        }
    }
}

// ============================================================================
// BSimFilter -- A collection of filter atoms
// ============================================================================

/// A collection of filter atoms for filtering BSim results.
///
/// Ports `ghidra.features.bsim.query.protocol.BSimFilter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimFilter {
    /// The filter atoms.
    atoms: Vec<FilterAtomEntry>,
    /// Mask for function description flags.
    filter_flags_mask: u32,
    /// Value for function description flags.
    filter_flags_value: u32,
}

/// An entry in the filter (either a regular or child atom).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FilterAtomEntry {
    /// A regular filter atom.
    Regular(FilterAtom),
    /// A child filter atom.
    Child(ChildAtom),
}

impl BSimFilter {
    /// Create a new empty BSimFilter.
    pub fn new() -> Self {
        Self {
            atoms: Vec::new(),
            filter_flags_mask: 0,
            filter_flags_value: 0,
        }
    }

    /// Get the number of atoms in this filter.
    pub fn num_atoms(&self) -> usize {
        self.atoms.len()
    }

    /// Get an atom by index.
    pub fn get_atom(&self, index: usize) -> Option<&FilterAtomEntry> {
        self.atoms.get(index)
    }

    /// Add a regular filter atom.
    pub fn add_atom(&mut self, filter_type: FilterType, value: impl Into<String>) {
        let atom = FilterAtom::new(filter_type.clone(), value);
        if atom.is_valid() {
            if let Some(flag) = filter_type.flag() {
                self.filter_flags_mask |= flag;
                if atom.value == "true" {
                    self.filter_flags_value |= flag;
                }
            }
            self.atoms.push(FilterAtomEntry::Regular(atom));
        }
    }

    /// Add a child filter atom.
    pub fn add_child_atom(
        &mut self,
        filter_type: FilterType,
        child_name: impl Into<String>,
        exe_name: Option<String>,
    ) {
        let mut child = ChildAtom::new(filter_type, child_name);
        child.exe_name = exe_name;
        self.atoms.push(FilterAtomEntry::Child(child));
    }

    /// Whether this filter is empty.
    pub fn is_empty(&self) -> bool {
        if self.filter_flags_mask != 0 {
            return false;
        }
        self.atoms.iter().all(|entry| match entry {
            FilterAtomEntry::Regular(atom) => atom.filter_type.is_blank(),
            FilterAtomEntry::Child(_) => false,
        })
    }

    /// Clear all atoms.
    pub fn clear(&mut self) {
        self.atoms.clear();
        self.filter_flags_mask = 0;
        self.filter_flags_value = 0;
    }

    /// Get the filter flags mask.
    pub fn flags_mask(&self) -> u32 {
        self.filter_flags_mask
    }

    /// Get the filter flags value.
    pub fn flags_value(&self) -> u32 {
        self.filter_flags_value
    }

    /// Replace the contents of this filter with another.
    pub fn replace_with(&mut self, other: &BSimFilter) {
        self.atoms = other.atoms.clone();
        self.filter_flags_mask = other.filter_flags_mask;
        self.filter_flags_value = other.filter_flags_value;
    }

    /// Check if function flags pass the filter.
    pub fn check_flags(&self, flags: u32) -> bool {
        (flags & self.filter_flags_mask) == self.filter_flags_value
    }

    /// Get all filter entries grouped by their label.
    pub fn get_filter_entries(&self) -> HashMap<String, Vec<String>> {
        let mut entries: HashMap<String, Vec<String>> = HashMap::new();
        for entry in &self.atoms {
            let (label, value) = match entry {
                FilterAtomEntry::Regular(atom) => {
                    (atom.filter_type.label().to_string(), atom.value.clone())
                }
                FilterAtomEntry::Child(child) => {
                    ("Has named child".to_string(), child.value_string())
                }
            };
            entries.entry(label).or_default().push(value);
        }
        entries
    }
}

impl Default for BSimFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// PairInput -- Identifiers for a pair of functions
// ============================================================================

/// Identifiers for a pair of functions for comparison.
///
/// Ports `ghidra.features.bsim.query.protocol.PairInput`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairInputData {
    /// First executable.
    pub exec_a: ExeSpecifier,
    /// First function.
    pub func_a: FunctionEntryData,
    /// Second executable.
    pub exec_b: ExeSpecifier,
    /// Second function.
    pub func_b: FunctionEntryData,
}

impl PairInputData {
    /// Create a new PairInput.
    pub fn new(
        exec_a: ExeSpecifier,
        func_a: FunctionEntryData,
        exec_b: ExeSpecifier,
        func_b: FunctionEntryData,
    ) -> Self {
        Self {
            exec_a,
            func_a,
            exec_b,
            func_b,
        }
    }
}

// ============================================================================
// PairNote -- Result of a pair comparison
// ============================================================================

/// Result of comparing a pair of functions.
///
/// Ports `ghidra.features.bsim.query.protocol.PairNote`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairNoteData {
    /// First executable specifier.
    pub exe_a: Option<ExeSpecifier>,
    /// First function entry.
    pub func_a: Option<FunctionEntryData>,
    /// Second executable specifier.
    pub exe_b: Option<ExeSpecifier>,
    /// Second function entry.
    pub func_b: Option<FunctionEntryData>,
    /// Similarity score.
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
    /// Unnormalized dot product of the two feature vectors.
    pub dot_product: f64,
    /// Number of hashes from function A.
    pub func1_hash_count: u32,
    /// Number of hashes from function B.
    pub func2_hash_count: u32,
    /// Number of hashes in the intersection.
    pub intersection_count: u32,
    /// Whether the pair was found.
    pub found: bool,
}

impl PairNoteData {
    /// Create a new PairNote with full comparison metrics.
    pub fn new(similarity: f64, significance: f64) -> Self {
        Self {
            exe_a: None,
            func_a: None,
            exe_b: None,
            func_b: None,
            similarity,
            significance,
            dot_product: 0.0,
            func1_hash_count: 0,
            func2_hash_count: 0,
            intersection_count: 0,
            found: true,
        }
    }

    /// Create a PairNote with full details (matching Java constructor).
    pub fn with_details(
        exe_a: ExeSpecifier,
        func_a: FunctionEntryData,
        exe_b: ExeSpecifier,
        func_b: FunctionEntryData,
        similarity: f64,
        significance: f64,
        dot_product: f64,
        func1_hash_count: u32,
        func2_hash_count: u32,
        intersection_count: u32,
    ) -> Self {
        Self {
            exe_a: Some(exe_a),
            func_a: Some(func_a),
            exe_b: Some(exe_b),
            func_b: Some(func_b),
            similarity,
            significance,
            dot_product,
            func1_hash_count,
            func2_hash_count,
            intersection_count,
            found: true,
        }
    }

    /// Create a not-found result.
    pub fn not_found() -> Self {
        Self {
            exe_a: None,
            func_a: None,
            exe_b: None,
            func_b: None,
            similarity: 0.0,
            significance: 0.0,
            dot_product: 0.0,
            func1_hash_count: 0,
            func2_hash_count: 0,
            intersection_count: 0,
            found: false,
        }
    }

    /// Get the dot product of the two feature vectors.
    pub fn dot_product(&self) -> f64 {
        self.dot_product
    }

    /// Get the number of hashes from function A.
    pub fn func1_hash_count(&self) -> u32 {
        self.func1_hash_count
    }

    /// Get the number of hashes from function B.
    pub fn func2_hash_count(&self) -> u32 {
        self.func2_hash_count
    }

    /// Get the number of hashes in the intersection.
    pub fn intersection_count(&self) -> u32 {
        self.intersection_count
    }
}

// ============================================================================
// SimilarityNote -- A single function match
// ============================================================================

/// A description of a single function similarity match.
///
/// Ports `ghidra.features.bsim.query.protocol.SimilarityNote`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimilarityNoteData {
    /// The executable name.
    pub exe_name: String,
    /// The function name.
    pub func_name: String,
    /// The function address.
    pub address: u64,
    /// Similarity score (0.0 to 1.0).
    pub similarity: f64,
    /// Significance of the match (higher = more significant).
    pub significance: f64,
}

impl SimilarityNoteData {
    /// Create a new similarity note.
    pub fn new(
        exe_name: impl Into<String>,
        func_name: impl Into<String>,
        address: u64,
        similarity: f64,
        significance: f64,
    ) -> Self {
        Self {
            exe_name: exe_name.into(),
            func_name: func_name.into(),
            address,
            similarity,
            significance,
        }
    }
}

impl PartialEq for SimilarityNoteData {
    fn eq(&self, other: &Self) -> bool {
        self.exe_name == other.exe_name
            && self.func_name == other.func_name
            && self.address == other.address
    }
}

impl Eq for SimilarityNoteData {}

impl PartialOrd for SimilarityNoteData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SimilarityNoteData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.exe_name
            .cmp(&other.exe_name)
            .then_with(|| self.func_name.cmp(&other.func_name))
            .then_with(|| self.address.cmp(&other.address))
    }
}

// ============================================================================
// ClusterNote -- A cluster match result
// ============================================================================

/// A description of a function cluster match.
///
/// Ports `ghidra.features.bsim.query.protocol.ClusterNote`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNoteData {
    /// The executable name.
    pub exe_name: String,
    /// The function name.
    pub func_name: String,
    /// The function address.
    pub address: u64,
    /// Number of hits in the cluster.
    pub set_size: usize,
    /// Highest similarity score.
    pub max_similarity: f64,
    /// Significance of the highest similarity.
    pub significance: f64,
}

impl ClusterNoteData {
    /// Create a new cluster note.
    pub fn new(
        exe_name: impl Into<String>,
        func_name: impl Into<String>,
        address: u64,
        set_size: usize,
        max_similarity: f64,
        significance: f64,
    ) -> Self {
        Self {
            exe_name: exe_name.into(),
            func_name: func_name.into(),
            address,
            set_size,
            max_similarity,
            significance,
        }
    }
}

// ============================================================================
// VectorResult -- A vector match result
// ============================================================================

/// A single vector match result.
///
/// Ports `ghidra.features.bsim.query.protocol.VectorResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorResultData {
    /// The vector ID.
    pub vector_id: i64,
    /// Number of functions matching this vector.
    pub hit_count: usize,
    /// The vector features (key-value pairs).
    pub features: Vec<(i32, i32)>,
}

impl VectorResultData {
    /// Create a new vector result.
    pub fn new(vector_id: i64, hit_count: usize) -> Self {
        Self {
            vector_id,
            hit_count,
            features: Vec::new(),
        }
    }
}

// ============================================================================
// ExeResult -- Executable query result
// ============================================================================

/// An executable result from the BSim database.
///
/// Ports `ghidra.features.bsim.query.protocol.ResponseExe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExeResultData {
    /// The executable name.
    pub exe_name: String,
    /// The MD5 hash.
    pub md5: String,
    /// The architecture.
    pub arch: String,
    /// The compiler.
    pub compiler: String,
    /// The function count.
    pub function_count: usize,
    /// Ingest date (Unix timestamp).
    pub ingest_date: Option<i64>,
}

impl ExeResultData {
    /// Create a new ExeResult.
    pub fn new(exe_name: impl Into<String>, md5: impl Into<String>) -> Self {
        Self {
            exe_name: exe_name.into(),
            md5: md5.into(),
            arch: String::new(),
            compiler: String::new(),
            function_count: 0,
            ingest_date: None,
        }
    }
}

// ============================================================================
// DatabaseInfo -- Database information result
// ============================================================================

/// Information about a BSim database.
///
/// Ports `ghidra.features.bsim.query.protocol.ResponseInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInfoData {
    /// Database name.
    pub name: String,
    /// Number of executables.
    pub exe_count: usize,
    /// Number of functions.
    pub function_count: usize,
    /// Whether the database exists.
    pub exists: bool,
}

impl DatabaseInfoData {
    /// Create a new DatabaseInfo.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            exe_count: 0,
            function_count: 0,
            exists: false,
        }
    }
}

// ============================================================================
// QueryInfoData -- Query info result
// ============================================================================

/// Information from a QueryInfo response.
///
/// Ports `ghidra.features.bsim.query.protocol.ResponseInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryInfoData {
    /// Database name.
    pub database_name: String,
    /// Number of executables.
    pub exe_count: usize,
    /// Number of functions.
    pub function_count: usize,
    /// Number of clusters.
    pub cluster_count: usize,
    /// Schema version.
    pub schema_version: String,
}

impl QueryInfoData {
    /// Create a new QueryInfoData.
    pub fn new(database_name: impl Into<String>) -> Self {
        Self {
            database_name: database_name.into(),
            exe_count: 0,
            function_count: 0,
            cluster_count: 0,
            schema_version: String::new(),
        }
    }
}

// ============================================================================
// InsertRequestData -- Insert request payload
// ============================================================================

/// Data for an insert request.
///
/// Ports `ghidra.features.bsim.query.protocol.InsertRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertRequestData {
    /// Executable to insert into.
    pub exe_specifier: ExeSpecifier,
    /// Functions to insert.
    pub functions: Vec<BSimFunctionDescription>,
    /// Whether to overwrite existing entries.
    pub overwrite: bool,
}

impl InsertRequestData {
    /// Create a new InsertRequest.
    pub fn new(exe_specifier: ExeSpecifier) -> Self {
        Self {
            exe_specifier,
            functions: Vec::new(),
            overwrite: false,
        }
    }

    /// Add a function to insert.
    pub fn add_function(&mut self, func: BSimFunctionDescription) {
        self.functions.push(func);
    }

    /// Set the overwrite flag.
    pub fn set_overwrite(&mut self, overwrite: bool) {
        self.overwrite = overwrite;
    }
}

// ============================================================================
// StagingManager -- Splitting large queries
// ============================================================================

/// Abstract manager for splitting large queries into smaller stages.
///
/// Ports `ghidra.features.bsim.query.protocol.StagingManager`.
#[derive(Debug)]
pub struct StagingManager {
    /// Total number of queries being staged.
    total_size: usize,
    /// Number of queries sent so far.
    queries_made: usize,
    /// The batch size per stage.
    batch_size: usize,
    /// Current offset into the data.
    current_offset: usize,
    /// Total items to process.
    total_items: usize,
}

impl StagingManager {
    /// Create a new StagingManager with the given batch size.
    pub fn new(batch_size: usize) -> Self {
        Self {
            total_size: 0,
            queries_made: 0,
            batch_size,
            current_offset: 0,
            total_items: 0,
        }
    }

    /// Get the total size (number of stages).
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Get the number of queries made so far.
    pub fn queries_made(&self) -> usize {
        self.queries_made
    }

    /// Get the batch size.
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Initialize staging with the total number of items.
    pub fn initialize(&mut self, total_items: usize) -> bool {
        self.total_items = total_items;
        self.total_size = if self.batch_size > 0 {
            (total_items + self.batch_size - 1) / self.batch_size
        } else {
            1
        };
        self.current_offset = 0;
        self.queries_made = 0;
        self.total_size > 0
    }

    /// Get the current stage range [start, end).
    pub fn current_range(&self) -> (usize, usize) {
        let end = std::cmp::min(self.current_offset + self.batch_size, self.total_items);
        (self.current_offset, end)
    }

    /// Advance to the next stage. Returns false if no more stages.
    pub fn next_stage(&mut self) -> bool {
        self.current_offset += self.batch_size;
        self.queries_made += 1;
        self.current_offset < self.total_items
    }

    /// Get the progress as a fraction (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        if self.total_items == 0 {
            return 0.0;
        }
        (self.current_offset as f64) / (self.total_items as f64)
    }

    /// Whether all stages are complete.
    pub fn is_complete(&self) -> bool {
        self.current_offset >= self.total_items
    }
}

// ============================================================================
// PreFilter -- Predicate-based filtering before query
// ============================================================================

/// A collection of predicates for pre-filtering functions before BSim queries.
///
/// Ports `ghidra.features.bsim.query.protocol.PreFilter`.
#[derive(Debug, Clone, Default)]
pub struct PreFilter {
    /// Minimum function size (in bytes).
    pub min_function_size: Option<u64>,
    /// Maximum function size (in bytes).
    pub max_function_size: Option<u64>,
    /// Whether to include library functions.
    pub include_library: bool,
    /// Whether to include thunk functions.
    pub include_thunks: bool,
    /// Whether to include external functions.
    pub include_externals: bool,
    /// Function name patterns to include (regex).
    pub include_patterns: Vec<String>,
    /// Function name patterns to exclude (regex).
    pub exclude_patterns: Vec<String>,
}

impl PreFilter {
    /// Create a new PreFilter with default settings.
    pub fn new() -> Self {
        Self {
            include_library: true,
            include_thunks: false,
            include_externals: false,
            ..Default::default()
        }
    }

    /// Set the minimum function size.
    pub fn with_min_size(mut self, size: u64) -> Self {
        self.min_function_size = Some(size);
        self
    }

    /// Set the maximum function size.
    pub fn with_max_size(mut self, size: u64) -> Self {
        self.max_function_size = Some(size);
        self
    }

    /// Set whether to include library functions.
    pub fn with_include_library(mut self, include: bool) -> Self {
        self.include_library = include;
        self
    }

    /// Set whether to include thunk functions.
    pub fn with_include_thunks(mut self, include: bool) -> Self {
        self.include_thunks = include;
        self
    }

    /// Add an include pattern.
    pub fn add_include_pattern(&mut self, pattern: impl Into<String>) {
        self.include_patterns.push(pattern.into());
    }

    /// Add an exclude pattern.
    pub fn add_exclude_pattern(&mut self, pattern: impl Into<String>) {
        self.exclude_patterns.push(pattern.into());
    }

    /// Check if a function passes this pre-filter.
    pub fn accepts(&self, func_name: &str, func_size: u64, is_library: bool, is_thunk: bool) -> bool {
        // Check size constraints
        if let Some(min) = self.min_function_size {
            if func_size < min {
                return false;
            }
        }
        if let Some(max) = self.max_function_size {
            if func_size > max {
                return false;
            }
        }
        // Check library/thunk flags
        if is_library && !self.include_library {
            return false;
        }
        if is_thunk && !self.include_thunks {
            return false;
        }
        // Check exclude patterns (if any match, reject)
        if !self.exclude_patterns.is_empty() {
            for pattern in &self.exclude_patterns {
                if func_name.contains(pattern.as_str()) {
                    return false;
                }
            }
        }
        // Check include patterns (if set, must match at least one)
        if !self.include_patterns.is_empty() {
            let mut matched = false;
            for pattern in &self.include_patterns {
                if func_name.contains(pattern.as_str()) {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return false;
            }
        }
        true
    }

    /// Clear all filters.
    pub fn clear(&mut self) {
        self.min_function_size = None;
        self.max_function_size = None;
        self.include_patterns.clear();
        self.exclude_patterns.clear();
    }
}

// ============================================================================
// NullStaging -- A no-op staging manager
// ============================================================================

/// A staging manager that does no staging (passes everything through).
///
/// Ports `ghidra.features.bsim.query.protocol.NullStaging`.
#[derive(Debug)]
pub struct NullStaging;

impl NullStaging {
    /// Create a new NullStaging.
    pub fn new() -> Self {
        Self
    }

    /// Always returns true (single stage).
    pub fn initialize(&mut self) -> bool {
        true
    }

    /// Always returns false (no more stages).
    pub fn next_stage(&self) -> bool {
        false
    }

    /// Total size is always 1.
    pub fn total_size(&self) -> usize {
        1
    }

    /// Queries made is always 1.
    pub fn queries_made(&self) -> usize {
        1
    }
}

impl Default for NullStaging {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Query/Response Record base types
// ============================================================================

/// A response record from a BSim query.
///
/// Ports `ghidra.features.bsim.query.protocol.QueryResponseRecord`.
#[derive(Debug, Clone)]
pub struct QueryResponseRecord {
    /// The query name.
    pub name: String,
    /// Whether an error occurred.
    pub has_error: bool,
    /// Error message if any.
    pub error_message: Option<String>,
}

impl QueryResponseRecord {
    /// Create a new QueryResponseRecord.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            has_error: false,
            error_message: None,
        }
    }

    /// Set an error on this response.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.has_error = true;
        self.error_message = Some(message.into());
    }

    /// Check if the response has an error.
    pub fn has_error(&self) -> bool {
        self.has_error
    }
}

// ============================================================================
// QueryNearest -- Nearest-match query
// ============================================================================

/// Query for nearest matches within the database to a set of functions.
///
/// Ports `ghidra.features.bsim.query.protocol.QueryNearest`.
#[derive(Debug, Clone)]
pub struct QueryNearest {
    /// Similarity threshold (0.0 to 1.0).
    pub threshold: f64,
    /// Significance threshold.
    pub significance_threshold: f64,
    /// Maximum results per function.
    pub max_results: usize,
    /// Maximum unique vectors to return.
    pub vector_max: usize,
    /// Whether to fill in categories for returned executables.
    pub fill_categories: bool,
    /// Optional filter.
    pub filter: Option<BSimFilter>,
}

impl QueryNearest {
    /// Default similarity threshold.
    pub const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.7;
    /// Default significance threshold.
    pub const DEFAULT_SIGNIFICANCE_THRESHOLD: f64 = 0.0;
    /// Default maximum matches.
    pub const DEFAULT_MAX_MATCHES: usize = 100;

    /// Create a new QueryNearest with default settings.
    pub fn new() -> Self {
        Self {
            threshold: Self::DEFAULT_SIMILARITY_THRESHOLD,
            significance_threshold: Self::DEFAULT_SIGNIFICANCE_THRESHOLD,
            max_results: Self::DEFAULT_MAX_MATCHES,
            vector_max: 0,
            fill_categories: true,
            filter: None,
        }
    }

    /// Create a partial copy suitable for staging.
    pub fn local_staging_copy(&self) -> Self {
        Self {
            threshold: self.threshold,
            significance_threshold: self.significance_threshold,
            max_results: self.max_results,
            vector_max: self.vector_max,
            fill_categories: self.fill_categories,
            filter: self.filter.clone(),
        }
    }
}

impl Default for QueryNearest {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ResponseNearest -- Nearest-match response
// ============================================================================

/// Response from a nearest-match query.
///
/// Ports `ghidra.features.bsim.query.protocol.ResponseNearest`.
#[derive(Debug, Clone, Default)]
pub struct ResponseNearest {
    /// Similarity notes grouped by queried function.
    pub results: Vec<SimilarityNoteData>,
    /// Total count of matches.
    pub total_count: usize,
}

impl ResponseNearest {
    /// Create a new empty response.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add results.
    pub fn add_results(&mut self, notes: Vec<SimilarityNoteData>) {
        self.total_count += notes.len();
        self.results.extend(notes);
    }

    /// Sort results by similarity (descending).
    pub fn sort_by_similarity(&mut self) {
        self.results.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
}

// ============================================================================
// QueryCluster -- Cluster query
// ============================================================================

/// Query for function clusters.
///
/// Ports `ghidra.features.bsim.query.protocol.QueryCluster`.
#[derive(Debug, Clone)]
pub struct QueryCluster {
    /// Similarity threshold.
    pub threshold: f64,
    /// Maximum cluster size.
    pub max_cluster_size: usize,
}

impl QueryCluster {
    /// Create a new QueryCluster.
    pub fn new(threshold: f64) -> Self {
        Self {
            threshold,
            max_cluster_size: 1000,
        }
    }
}

// ============================================================================
// QueryChildren -- Children query
// ============================================================================

/// Query for children of a function.
///
/// Ports `ghidra.features.bsim.query.protocol.QueryChildren`.
#[derive(Debug, Clone)]
pub struct QueryChildren {
    /// The parent function.
    pub parent_exe: String,
    /// The parent function name.
    pub parent_name: String,
    /// The parent function address.
    pub parent_address: u64,
}

impl QueryChildren {
    /// Create a new QueryChildren.
    pub fn new(
        parent_exe: impl Into<String>,
        parent_name: impl Into<String>,
        parent_address: u64,
    ) -> Self {
        Self {
            parent_exe: parent_exe.into(),
            parent_name: parent_name.into(),
            parent_address,
        }
    }
}

// ============================================================================
// QueryPair -- Pair comparison query
// ============================================================================

/// Query for comparing a pair of functions.
///
/// Ports `ghidra.features.bsim.query.protocol.QueryPair`.
#[derive(Debug, Clone)]
pub struct QueryPair {
    /// The pair input.
    pub pair: PairInputData,
}

impl QueryPair {
    /// Create a new QueryPair.
    pub fn new(pair: PairInputData) -> Self {
        Self { pair }
    }
}

// ============================================================================
// QueryInfo -- Database info query
// ============================================================================

/// Query for database information.
///
/// Ports `ghidra.features.bsim.query.protocol.QueryInfo`.
#[derive(Debug, Clone, Default)]
pub struct QueryInfo;

impl QueryInfo {
    /// Create a new QueryInfo.
    pub fn new() -> Self {
        Self
    }
}

// ============================================================================
// QueryName -- Name search query
// ============================================================================

/// Query for functions by name.
///
/// Ports `ghidra.features.bsim.query.protocol.QueryName`.
#[derive(Debug, Clone)]
pub struct QueryName {
    /// The function name to search for.
    pub name: String,
}

impl QueryName {
    /// Create a new QueryName.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

// ============================================================================
// QueryDelete -- Delete query
// ============================================================================

/// Query to delete an executable.
///
/// Ports `ghidra.features.bsim.query.protocol.QueryDelete`.
#[derive(Debug, Clone)]
pub struct QueryDelete {
    /// The executable specifier to delete.
    pub exe: ExeSpecifier,
}

impl QueryDelete {
    /// Create a new QueryDelete.
    pub fn new(exe: ExeSpecifier) -> Self {
        Self { exe }
    }
}

// ============================================================================
// CreateDatabase -- Create database request
// ============================================================================

/// Request to create a new BSim database.
///
/// Ports `ghidra.features.bsim.query.protocol.CreateDatabase`.
#[derive(Debug, Clone)]
pub struct CreateDatabaseRequest {
    /// Database name.
    pub database_name: String,
}

impl CreateDatabaseRequest {
    /// Create a new CreateDatabase request.
    pub fn new(database_name: impl Into<String>) -> Self {
        Self {
            database_name: database_name.into(),
        }
    }
}

// ============================================================================
// DropDatabase -- Drop database request
// ============================================================================

/// Request to drop a BSim database.
///
/// Ports `ghidra.features.bsim.query.protocol.DropDatabase`.
#[derive(Debug, Clone)]
pub struct DropDatabaseRequest {
    /// Database name.
    pub database_name: String,
}

impl DropDatabaseRequest {
    /// Create a new DropDatabase request.
    pub fn new(database_name: impl Into<String>) -> Self {
        Self {
            database_name: database_name.into(),
        }
    }
}

// ============================================================================
// PasswordChange -- Change password request
// ============================================================================

/// Request to change the database password.
///
/// Ports `ghidra.features.bsim.query.protocol.PasswordChange`.
#[derive(Debug, Clone)]
pub struct PasswordChangeRequest {
    /// Old password.
    pub old_password: String,
    /// New password.
    pub new_password: String,
}

impl PasswordChangeRequest {
    /// Create a new PasswordChange request.
    pub fn new(old_password: impl Into<String>, new_password: impl Into<String>) -> Self {
        Self {
            old_password: old_password.into(),
            new_password: new_password.into(),
        }
    }
}

// ============================================================================
// AdjustVectorIndex -- Adjust vector index request
// ============================================================================

/// Request to adjust the vector index.
///
/// Ports `ghidra.features.bsim.query.protocol.AdjustVectorIndex`.
#[derive(Debug, Clone)]
pub struct AdjustVectorIndexRequest {
    /// New index value.
    pub new_index: i64,
}

impl AdjustVectorIndexRequest {
    /// Create a new AdjustVectorIndex request.
    pub fn new(new_index: i64) -> Self {
        Self { new_index }
    }
}

// ============================================================================
// InsertOptionalValues -- Optional values for insertion
// ============================================================================

/// Optional values that can be inserted with function descriptions.
///
/// Ports `ghidra.features.bsim.query.protocol.InsertOptionalValues`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InsertOptionalValues {
    /// Function tags.
    pub tags: Vec<String>,
    /// Function signatures.
    pub signatures: Vec<String>,
    /// Additional metadata.
    pub metadata: HashMap<String, String>,
}

impl InsertOptionalValues {
    /// Create new empty optional values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a tag.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Add metadata.
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Check if there are any optional values.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty() && self.signatures.is_empty() && self.metadata.is_empty()
    }
}

// ============================================================================
// SimilarityResultRecord -- A collection of match notes for one queried function
// ============================================================================

/// A collection of match notes for a single queried function.
///
/// Ports `ghidra.features.bsim.query.protocol.SimilarityResult` (the list-of-notes
/// pattern, not the flat struct in `additional_protocol.rs`).
#[derive(Debug, Clone)]
pub struct SimilarityResultRecord {
    /// The base function that was queried.
    pub base_exe_name: String,
    /// The base function name.
    pub base_func_name: String,
    /// The base function address.
    pub base_address: u64,
    /// Functions to which the base is similar.
    pub notes: Vec<SimilarityNoteData>,
    /// Total number of functions in the database meeting similarity and significance.
    pub total_count: u32,
}

impl SimilarityResultRecord {
    /// Create a new empty result for a queried function.
    pub fn new(
        base_exe_name: impl Into<String>,
        base_func_name: impl Into<String>,
        base_address: u64,
    ) -> Self {
        Self {
            base_exe_name: base_exe_name.into(),
            base_func_name: base_func_name.into(),
            base_address,
            notes: Vec::new(),
            total_count: 0,
        }
    }

    /// Add a similarity note (match).
    pub fn add_note(&mut self, note: SimilarityNoteData) {
        self.notes.push(note);
    }

    /// Get the number of notes (matches).
    pub fn size(&self) -> usize {
        self.notes.len()
    }

    /// Set the total count of matching functions.
    pub fn set_total_count(&mut self, count: u32) {
        self.total_count = count;
    }

    /// Sort notes by their natural ordering (exe, function, address).
    pub fn sort_notes(&mut self) {
        self.notes.sort();
    }

    /// Iterate over the notes.
    pub fn iter(&self) -> impl Iterator<Item = &SimilarityNoteData> {
        self.notes.iter()
    }
}

// ============================================================================
// FunctionStaging -- Iterator-based staging for function queries
// ============================================================================

/// A function-based staging manager that splits large queries by function count.
///
/// Ports `ghidra.features.bsim.query.protocol.FunctionStaging` as a staging
/// manager (the Java class that extends `StagingManager`).
#[derive(Debug, Clone)]
pub struct FunctionStagingManager {
    /// Number of functions per stage.
    pub stage_size: usize,
    /// Total number of functions.
    pub total: usize,
    /// Queries made so far.
    pub made: usize,
    /// Start index of the current stage.
    pub current_start: usize,
    /// End index (exclusive) of the current stage.
    pub current_end: usize,
}

impl FunctionStagingManager {
    /// Create a new FunctionStagingManager with the given stage size.
    pub fn new(stage_size: usize) -> Self {
        Self {
            stage_size,
            total: 0,
            made: 0,
            current_start: 0,
            current_end: 0,
        }
    }

    /// Get the start index for the current stage.
    pub fn stage_start(&self) -> usize {
        self.current_start
    }

    /// Get the end index (exclusive) for the current stage.
    pub fn stage_end(&self) -> usize {
        self.current_end
    }

    /// Initialize staging with the total number of items.
    /// Returns true if there is data to stage.
    pub fn initialize(&mut self, total: usize) -> bool {
        self.total = total;
        self.made = 0;
        self.current_start = 0;

        if total == 0 {
            self.current_end = 0;
            return false;
        }

        let count = self.stage_size.min(total);
        self.current_end = count;
        self.made = count;
        true
    }

    /// Advance to the next stage. Returns false if no more stages.
    pub fn next_stage(&mut self) -> bool {
        if self.current_end >= self.total {
            return false;
        }

        self.current_start = self.current_end;
        let remaining = self.total - self.current_end;
        let count = self.stage_size.min(remaining);
        self.current_end += count;
        self.made += count;
        count > 0
    }

    /// Whether all stages are complete.
    pub fn is_complete(&self) -> bool {
        self.current_end >= self.total
    }

    /// Get the progress as a fraction (0.0 to 1.0).
    pub fn progress(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.made as f64) / (self.total as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_serialization() {
        let req = BSimRequest::Ping;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("Ping"));

        let req = BSimRequest::GetFunctionCount;
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("GetFunctionCount"));
    }

    #[test]
    fn test_response_success() {
        let resp = BSimResponse::Success;
        assert!(resp.is_success());
        assert!(resp.error_message().is_none());
    }

    #[test]
    fn test_response_error() {
        let resp = BSimResponse::Error("connection failed".into());
        assert!(!resp.is_success());
        assert_eq!(resp.error_message(), Some("connection failed"));
    }

    #[test]
    fn test_response_count() {
        let resp = BSimResponse::Count(42);
        assert!(resp.is_success());
        match resp {
            BSimResponse::Count(n) => assert_eq!(n, 42),
            _ => panic!("expected Count"),
        }
    }

    #[test]
    fn test_response_pong() {
        let resp = BSimResponse::Pong;
        assert!(resp.is_success());
    }

    #[test]
    fn test_request_query_serialization() {
        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        let req = BSimRequest::QuerySimilar {
            description: func,
            metric: SimilarityMetric::Jaccard,
            max_results: 100,
            min_similarity: 0.5,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: BSimRequest = serde_json::from_str(&json).unwrap();
        match deserialized {
            BSimRequest::QuerySimilar { max_results, min_similarity, .. } => {
                assert_eq!(max_results, 100);
                assert!((min_similarity - 0.5).abs() < f64::EPSILON);
            }
            _ => panic!("expected QuerySimilar"),
        }
    }

    // ---- ExeSpecifier tests ----

    #[test]
    fn exe_specifier_new() {
        let spec = ExeSpecifier::new("test.exe");
        assert_eq!(spec.exe_name, "test.exe");
        assert!(spec.md5.is_empty());
    }

    #[test]
    fn exe_specifier_from_md5() {
        let spec = ExeSpecifier::from_md5("abc123");
        assert_eq!(spec.md5, "abc123");
        assert!(spec.exe_name.is_empty());
    }

    #[test]
    fn exe_specifier_name_with_md5() {
        let mut spec = ExeSpecifier::new("test.exe");
        spec.md5 = "abc123".to_string();
        assert_eq!(spec.exe_name_with_md5(), "test.exe abc123");
    }

    #[test]
    fn exe_specifier_eq_by_md5() {
        let a = ExeSpecifier::from_md5("abc");
        let b = ExeSpecifier {
            exe_name: "other".to_string(),
            md5: "abc".to_string(),
            ..Default::default()
        };
        assert_eq!(a, b);
    }

    #[test]
    fn exe_specifier_ord() {
        let a = ExeSpecifier::new("aaa");
        let b = ExeSpecifier::new("bbb");
        assert!(a < b);
    }

    // ---- FunctionEntryData tests ----

    #[test]
    fn function_entry_data_new() {
        let entry = FunctionEntryData::new("main", 0x1000);
        assert_eq!(entry.func_name, "main");
        assert_eq!(entry.address, 0x1000);
    }

    // ---- FilterType tests ----

    #[test]
    fn filter_type_properties() {
        assert!(FilterType::Blank.is_blank());
        assert!(!FilterType::ExeNameMatch.is_blank());
        assert!(FilterType::HasNamedChild.is_child_filter());
        assert!(!FilterType::ExeNameMatch.is_child_filter());
        assert!(FilterType::ExeNameNotMatch.or_multiple_entries());
        assert!(!FilterType::ExeNameMatch.or_multiple_entries());
    }

    #[test]
    fn filter_type_labels() {
        assert_eq!(FilterType::ExeNameMatch.label(), "Executable name");
        assert_eq!(FilterType::Blank.label(), "");
        assert_eq!(FilterType::FunctionTag("tag1".into()).label(), "tag1");
    }

    // ---- FilterAtom tests ----

    #[test]
    fn filter_atom_validity() {
        let atom = FilterAtom::new(FilterType::ExeNameMatch, "test");
        assert!(atom.is_valid());
        let empty = FilterAtom::new(FilterType::Blank, "");
        assert!(!empty.is_valid());
    }

    #[test]
    fn filter_atom_info_string() {
        let atom = FilterAtom::new(FilterType::ExeNameMatch, "myexe");
        assert_eq!(atom.info_string(), Some("Executable name myexe".to_string()));
    }

    // ---- ChildAtom tests ----

    #[test]
    fn child_atom_value_string() {
        let child = ChildAtom::new(FilterType::HasNamedChild, "callee");
        assert_eq!(child.value_string(), "callee");
        let mut child_with_exe = ChildAtom::new(FilterType::HasNamedChild, "callee");
        child_with_exe.exe_name = Some("lib.so".to_string());
        assert_eq!(child_with_exe.value_string(), "[lib.so]callee");
    }

    #[test]
    fn child_atom_info_string() {
        let mut child = ChildAtom::new(FilterType::HasNamedChild, "callee");
        child.exe_name = Some("lib.so".to_string());
        assert_eq!(
            child.info_string(),
            Some("Has child [lib.so]callee".to_string())
        );
    }

    // ---- BSimFilter tests ----

    #[test]
    fn bsim_filter_empty() {
        let filter = BSimFilter::new();
        assert!(filter.is_empty());
        assert_eq!(filter.num_atoms(), 0);
    }

    #[test]
    fn bsim_filter_add_atom() {
        let mut filter = BSimFilter::new();
        filter.add_atom(FilterType::ExeNameMatch, "test.exe");
        assert_eq!(filter.num_atoms(), 1);
        assert!(!filter.is_empty());
    }

    #[test]
    fn bsim_filter_add_child() {
        let mut filter = BSimFilter::new();
        filter.add_child_atom(
            FilterType::HasNamedChild,
            "callee",
            Some("lib.so".to_string()),
        );
        assert_eq!(filter.num_atoms(), 1);
    }

    #[test]
    fn bsim_filter_check_flags() {
        let filter = BSimFilter::new();
        assert!(filter.check_flags(0xFFFF));
        assert!(filter.check_flags(0));
    }

    #[test]
    fn bsim_filter_get_entries() {
        let mut filter = BSimFilter::new();
        filter.add_atom(FilterType::ExeNameMatch, "a.exe");
        filter.add_atom(FilterType::ExeNameMatch, "b.exe");
        let entries = filter.get_filter_entries();
        let names = entries.get("Executable name").unwrap();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn bsim_filter_clear() {
        let mut filter = BSimFilter::new();
        filter.add_atom(FilterType::ExeNameMatch, "test");
        filter.clear();
        assert!(filter.is_empty());
    }

    #[test]
    fn bsim_filter_clone() {
        let mut filter = BSimFilter::new();
        filter.add_atom(FilterType::ExeNameMatch, "test");
        let cloned = filter.clone();
        assert_eq!(cloned.num_atoms(), 1);
    }

    // ---- PairInputData tests ----

    #[test]
    fn pair_input_data_new() {
        let pair = PairInputData::new(
            ExeSpecifier::new("a.exe"),
            FunctionEntryData::new("funcA", 0x100),
            ExeSpecifier::new("b.exe"),
            FunctionEntryData::new("funcB", 0x200),
        );
        assert_eq!(pair.exec_a.exe_name, "a.exe");
        assert_eq!(pair.func_b.func_name, "funcB");
    }

    // ---- PairNoteData tests ----

    #[test]
    fn pair_note_data_found() {
        let note = PairNoteData::new(0.95, 10.0);
        assert!(note.found);
        assert!((note.similarity - 0.95).abs() < f64::EPSILON);
    }

    #[test]
    fn pair_note_data_not_found() {
        let note = PairNoteData::not_found();
        assert!(!note.found);
    }

    // ---- SimilarityNoteData tests ----

    #[test]
    fn similarity_note_data_ordering() {
        let a = SimilarityNoteData::new("exe", "aaa", 0x100, 0.9, 5.0);
        let b = SimilarityNoteData::new("exe", "bbb", 0x200, 0.8, 4.0);
        assert!(a < b);
    }

    #[test]
    fn similarity_note_data_eq() {
        let a = SimilarityNoteData::new("exe", "func", 0x100, 0.9, 5.0);
        let b = SimilarityNoteData::new("exe", "func", 0x100, 0.5, 2.0);
        assert_eq!(a, b); // equality ignores similarity/significance
    }

    // ---- ClusterNoteData tests ----

    #[test]
    fn cluster_note_data_new() {
        let note = ClusterNoteData::new("exe", "func", 0x100, 5, 0.95, 10.0);
        assert_eq!(note.set_size, 5);
        assert!((note.max_similarity - 0.95).abs() < f64::EPSILON);
    }

    // ---- VectorResultData tests ----

    #[test]
    fn vector_result_data_new() {
        let result = VectorResultData::new(42, 100);
        assert_eq!(result.vector_id, 42);
        assert_eq!(result.hit_count, 100);
        assert!(result.features.is_empty());
    }

    // ---- StagingManager tests ----

    #[test]
    fn staging_manager_basic() {
        let mut sm = StagingManager::new(10);
        assert!(sm.initialize(25));
        assert_eq!(sm.total_size(), 3); // ceil(25/10) = 3
        assert_eq!(sm.current_range(), (0, 10));

        assert!(sm.next_stage());
        assert_eq!(sm.current_range(), (10, 20));

        assert!(sm.next_stage());
        assert_eq!(sm.current_range(), (20, 25));

        assert!(!sm.next_stage()); // no more stages
        assert!(sm.is_complete());
    }

    #[test]
    fn staging_manager_progress() {
        let mut sm = StagingManager::new(10);
        sm.initialize(20);
        assert!((sm.progress() - 0.0).abs() < f64::EPSILON);
        sm.next_stage();
        assert!((sm.progress() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn staging_manager_empty() {
        let mut sm = StagingManager::new(10);
        assert!(!sm.initialize(0));
        assert_eq!(sm.total_size(), 0);
    }

    // ---- PreFilter tests ----

    #[test]
    fn pre_filter_accepts_default() {
        let filter = PreFilter::new();
        assert!(filter.accepts("main", 100, false, false));
        assert!(filter.accepts("small", 1, false, false));
    }

    #[test]
    fn pre_filter_min_size() {
        let filter = PreFilter::new().with_min_size(50);
        assert!(!filter.accepts("small", 10, false, false));
        assert!(filter.accepts("large", 100, false, false));
    }

    #[test]
    fn pre_filter_max_size() {
        let filter = PreFilter::new().with_max_size(100);
        assert!(filter.accepts("small", 50, false, false));
        assert!(!filter.accepts("huge", 200, false, false));
    }

    #[test]
    fn pre_filter_include_exclude() {
        let mut filter = PreFilter::new();
        filter.add_exclude_pattern("debug_");
        assert!(filter.accepts("main", 100, false, false));
        assert!(!filter.accepts("debug_init", 100, false, false));
    }

    #[test]
    fn pre_filter_include_pattern() {
        let mut filter = PreFilter::new();
        filter.add_include_pattern("func");
        assert!(filter.accepts("my_func", 100, false, false));
        assert!(!filter.accepts("main", 100, false, false));
    }

    #[test]
    fn pre_filter_library() {
        let filter = PreFilter::new().with_include_library(false);
        assert!(filter.accepts("main", 100, false, false));
        assert!(!filter.accepts("lib_func", 100, true, false));
    }

    // ---- NullStaging tests ----

    #[test]
    fn null_staging() {
        let mut ns = NullStaging::new();
        assert!(ns.initialize());
        assert_eq!(ns.total_size(), 1);
        assert!(!ns.next_stage());
        assert_eq!(ns.queries_made(), 1);
    }

    // ---- QueryNearest tests ----

    #[test]
    fn query_nearest_defaults() {
        let q = QueryNearest::new();
        assert!((q.threshold - 0.7).abs() < f64::EPSILON);
        assert_eq!(q.max_results, 100);
        assert!(q.fill_categories);
        assert!(q.filter.is_none());
    }

    #[test]
    fn query_nearest_staging_copy() {
        let mut q = QueryNearest::new();
        q.threshold = 0.9;
        q.max_results = 50;
        let copy = q.local_staging_copy();
        assert!((copy.threshold - 0.9).abs() < f64::EPSILON);
        assert_eq!(copy.max_results, 50);
    }

    // ---- ResponseNearest tests ----

    #[test]
    fn response_nearest_add_and_sort() {
        let mut resp = ResponseNearest::new();
        resp.add_results(vec![
            SimilarityNoteData::new("exe", "a", 0x100, 0.5, 1.0),
            SimilarityNoteData::new("exe", "b", 0x200, 0.9, 5.0),
        ]);
        assert_eq!(resp.total_count, 2);
        resp.sort_by_similarity();
        assert!((resp.results[0].similarity - 0.9).abs() < f64::EPSILON);
    }

    // ---- InsertRequestData tests ----

    #[test]
    fn insert_request_data() {
        let mut req = InsertRequestData::new(ExeSpecifier::new("test.exe"));
        req.add_function(BSimFunctionDescription::new("test.exe", "main", 0x1000));
        req.set_overwrite(true);
        assert_eq!(req.functions.len(), 1);
        assert!(req.overwrite);
    }

    // ---- InsertOptionalValues tests ----

    #[test]
    fn insert_optional_values() {
        let mut vals = InsertOptionalValues::new();
        assert!(vals.is_empty());
        vals.add_tag("important");
        vals.add_metadata("key", "value");
        assert!(!vals.is_empty());
        assert_eq!(vals.tags.len(), 1);
        assert_eq!(vals.metadata.get("key").unwrap(), "value");
    }

    // ---- QueryNearest serialization tests ----

    #[test]
    fn bsim_request_create_database() {
        let req = BSimRequest::CreateDatabase("mydb".into());
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("CreateDatabase"));
    }

    #[test]
    fn bsim_request_insert() {
        let req = BSimRequest::InsertRequest(InsertRequestData::new(ExeSpecifier::new("exe")));
        let json = serde_json::to_string(&req).unwrap();
        let _: BSimRequest = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn bsim_response_nearest() {
        let resp = BSimResponse::NearestResults(vec![SimilarityNoteData::new(
            "exe", "func", 0x100, 0.9, 5.0,
        )]);
        let json = serde_json::to_string(&resp).unwrap();
        let _: BSimResponse = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn bsim_response_cluster() {
        let resp = BSimResponse::ClusterResults(vec![ClusterNoteData::new(
            "exe", "func", 0x100, 5, 0.95, 10.0,
        )]);
        let json = serde_json::to_string(&resp).unwrap();
        let _: BSimResponse = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn filter_type_flag() {
        assert!(FilterType::FunctionTag("tag".into()).flag().is_some());
        assert!(FilterType::ExeNameMatch.flag().is_none());
    }

    // ---- DatabaseInfoData tests ----

    #[test]
    fn database_info_data() {
        let mut info = DatabaseInfoData::new("mydb");
        info.exe_count = 10;
        info.function_count = 1000;
        info.exists = true;
        assert_eq!(info.name, "mydb");
        assert!(info.exists);
    }

    // ---- QueryInfoData tests ----

    #[test]
    fn query_info_data() {
        let mut info = QueryInfoData::new("mydb");
        info.exe_count = 5;
        info.function_count = 500;
        info.schema_version = "1.0".to_string();
        assert_eq!(info.database_name, "mydb");
    }

    // ---- PairNoteData enhanced tests ----

    #[test]
    fn pair_note_data_with_details() {
        let note = PairNoteData::with_details(
            ExeSpecifier::new("a.exe"),
            FunctionEntryData::new("funcA", 0x100),
            ExeSpecifier::new("b.exe"),
            FunctionEntryData::new("funcB", 0x200),
            0.85,
            12.0,
            42.5,
            100,
            120,
            80,
        );
        assert!(note.found);
        assert!((note.similarity - 0.85).abs() < f64::EPSILON);
        assert!((note.dot_product() - 42.5).abs() < f64::EPSILON);
        assert_eq!(note.func1_hash_count(), 100);
        assert_eq!(note.func2_hash_count(), 120);
        assert_eq!(note.intersection_count(), 80);
        assert!(note.exe_a.is_some());
        assert_eq!(note.func_a.as_ref().unwrap().func_name, "funcA");
    }

    #[test]
    fn pair_note_data_new_defaults() {
        let note = PairNoteData::new(0.5, 2.0);
        assert!(note.found);
        assert!(note.exe_a.is_none());
        assert_eq!(note.func1_hash_count(), 0);
        assert!((note.dot_product() - 0.0).abs() < f64::EPSILON);
    }

    // ---- SimilarityResultRecord tests ----

    #[test]
    fn similarity_result_record_new() {
        let mut result = SimilarityResultRecord::new("exe1", "main", 0x1000);
        assert_eq!(result.base_func_name, "main");
        assert_eq!(result.size(), 0);
        assert_eq!(result.total_count, 0);
    }

    #[test]
    fn similarity_result_record_add_note() {
        let mut result = SimilarityResultRecord::new("exe1", "main", 0x1000);
        result.add_note(SimilarityNoteData::new("exe2", "match1", 0x2000, 0.9, 5.0));
        result.add_note(SimilarityNoteData::new("exe2", "match2", 0x3000, 0.8, 3.0));
        assert_eq!(result.size(), 2);
    }

    #[test]
    fn similarity_result_record_sort() {
        let mut result = SimilarityResultRecord::new("exe1", "main", 0x1000);
        result.add_note(SimilarityNoteData::new("exe3", "zzz", 0x4000, 0.9, 5.0));
        result.add_note(SimilarityNoteData::new("exe2", "aaa", 0x2000, 0.8, 3.0));
        result.sort_notes();
        // Should sort by exe_name then func_name
        assert_eq!(result.notes[0].exe_name, "exe2");
        assert_eq!(result.notes[1].exe_name, "exe3");
    }

    #[test]
    fn similarity_result_record_total_count() {
        let mut result = SimilarityResultRecord::new("exe1", "main", 0x1000);
        result.set_total_count(500);
        assert_eq!(result.total_count, 500);
    }

    #[test]
    fn similarity_result_record_iter() {
        let mut result = SimilarityResultRecord::new("exe1", "main", 0x1000);
        result.add_note(SimilarityNoteData::new("exe2", "f1", 0x2000, 0.9, 5.0));
        result.add_note(SimilarityNoteData::new("exe2", "f2", 0x3000, 0.8, 3.0));
        let names: Vec<&str> = result.iter().map(|n| n.func_name.as_str()).collect();
        assert_eq!(names, vec!["f1", "f2"]);
    }

    // ---- FunctionStaging tests ----

    #[test]
    fn function_staging_basic() {
        let mut fs = FunctionStagingManager::new(10);
        assert!(fs.initialize(25));
        assert_eq!(fs.total, 25);
        assert_eq!(fs.made, 10);
        assert_eq!(fs.stage_end(), 10);

        assert!(fs.next_stage());
        assert_eq!(fs.stage_end(), 20);
        assert_eq!(fs.made, 20);

        assert!(fs.next_stage());
        assert_eq!(fs.stage_end(), 25);
        assert_eq!(fs.made, 25);

        assert!(!fs.next_stage());
        assert!(fs.is_complete());
    }

    #[test]
    fn function_staging_exact_batch() {
        let mut fs = FunctionStagingManager::new(10);
        assert!(fs.initialize(20));
        assert_eq!(fs.stage_end(), 10);
        assert!(fs.next_stage());
        assert_eq!(fs.stage_end(), 20);
        assert!(!fs.next_stage());
    }

    #[test]
    fn function_staging_empty() {
        let mut fs = FunctionStagingManager::new(10);
        assert!(!fs.initialize(0));
        assert_eq!(fs.total, 0);
    }

    #[test]
    fn function_staging_progress() {
        let mut fs = FunctionStagingManager::new(10);
        fs.initialize(20);
        assert!((fs.progress() - 0.5).abs() < f64::EPSILON);
        fs.next_stage();
        assert!((fs.progress() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn function_staging_stage_ranges() {
        let mut fs = FunctionStagingManager::new(5);
        fs.initialize(12);
        assert_eq!(fs.stage_start(), 0);
        assert_eq!(fs.stage_end(), 5);

        fs.next_stage();
        assert_eq!(fs.stage_start(), 5);
        assert_eq!(fs.stage_end(), 10);

        fs.next_stage();
        assert_eq!(fs.stage_start(), 10);
        assert_eq!(fs.stage_end(), 12);
    }
}
