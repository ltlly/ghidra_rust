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
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

// ============================================================================
// Additional description types ported from Java
// ============================================================================

/// Database row key used to identify records in BSim databases.
///
/// Ports `ghidra.features.bsim.query.description.RowKey`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RowKey {
    /// The 64-bit row identifier.
    pub id: i64,
}

impl RowKey {
    /// Create a new row key.
    pub fn new(id: i64) -> Self {
        Self { id }
    }

    /// Get the key as a 64-bit value.
    pub fn as_long(&self) -> i64 {
        self.id
    }
}

impl PartialOrd for RowKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RowKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl std::fmt::Display for RowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// A user-defined category associated with an executable.
///
/// Ports `ghidra.features.bsim.query.description.CategoryRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryRecord {
    /// The type of category (e.g., "source", "classification").
    pub category_type: String,
    /// The specific category within the type.
    pub category: String,
}

impl CategoryRecord {
    /// Create a new category record.
    pub fn new(category_type: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            category_type: category_type.into(),
            category: category.into(),
        }
    }

    /// Validate that the type string contains only allowed characters.
    pub fn enforce_type_characters(val: &str) -> bool {
        if val.is_empty() {
            return false;
        }
        val.chars().all(|c| {
            c.is_alphanumeric() || c == ' ' || c == '.' || c == '_' || c == ':' || c == '/' || c == '(' || c == ')'
        })
    }
}

impl PartialEq for CategoryRecord {
    fn eq(&self, other: &Self) -> bool {
        self.category_type == other.category_type && self.category == other.category
    }
}

impl Eq for CategoryRecord {}

impl PartialOrd for CategoryRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CategoryRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.category_type
            .cmp(&other.category_type)
            .then_with(|| self.category.cmp(&other.category))
    }
}

impl std::fmt::Display for CategoryRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.category_type, self.category)
    }
}

/// Metadata about the BSim database itself.
///
/// Ports `ghidra.features.bsim.query.description.DatabaseInformation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseInformation {
    /// Formal name of this database.
    pub database_name: String,
    /// Owner of this database.
    pub owner: String,
    /// Description of the database.
    pub description: String,
    /// Signature strategy major version.
    pub major: i16,
    /// Signature strategy minor version.
    pub minor: i16,
    /// Settings for signature generation.
    pub settings: i32,
    /// Executable categories for this database.
    pub exe_categories: Vec<String>,
    /// Named boolean properties on functions.
    pub function_tags: Vec<String>,
    /// Override of the date column name.
    pub date_column_name: Option<String>,
    /// Version of the database layout.
    pub layout_version: i32,
    /// Whether database is read-only.
    pub readonly: bool,
    /// Whether database tracks callgraph information.
    pub track_callgraph: bool,
}

impl DatabaseInformation {
    /// Create a new database information with default values.
    pub fn new() -> Self {
        Self {
            database_name: "Example Database".to_string(),
            owner: "Example Owner".to_string(),
            description: "A collection of functions for testing purposes".to_string(),
            major: 0,
            minor: 0,
            settings: 0,
            exe_categories: Vec::new(),
            function_tags: Vec::new(),
            date_column_name: None,
            layout_version: 0,
            readonly: false,
            track_callgraph: true,
        }
    }

    /// Whether signatures have been inserted (major version > 0).
    pub fn has_signatures(&self) -> bool {
        self.major > 0
    }

    /// Set the database name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.database_name = name.into();
        self
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Add an executable category.
    pub fn add_exe_category(&mut self, category: impl Into<String>) {
        self.exe_categories.push(category.into());
    }

    /// Add a function tag.
    pub fn add_function_tag(&mut self, tag: impl Into<String>) {
        self.function_tags.push(tag.into());
    }
}

impl Default for DatabaseInformation {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DatabaseInformation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (v{}.{})", self.database_name, self.major, self.minor)
    }
}

/// An entry in the callgraph: a call from one function to another.
///
/// Ports `ghidra.features.bsim.query.description.CallgraphEntry`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallgraphEntry {
    /// The function being called (destination).
    pub dest_function: String,
    /// Entry point of the destination function.
    pub dest_entry_point: u64,
    /// Location hash of the call site.
    pub location_hash: u32,
    /// ID of the executable containing the destination function.
    pub dest_executable_id: String,
}

impl CallgraphEntry {
    /// Create a new callgraph entry.
    pub fn new(
        dest_function: impl Into<String>,
        dest_entry_point: u64,
        location_hash: u32,
    ) -> Self {
        Self {
            dest_function: dest_function.into(),
            dest_entry_point,
            location_hash,
            dest_executable_id: String::new(),
        }
    }

    /// Set the destination executable ID.
    pub fn with_exe_id(mut self, id: impl Into<String>) -> Self {
        self.dest_executable_id = id.into();
        self
    }
}

impl PartialEq for CallgraphEntry {
    fn eq(&self, other: &Self) -> bool {
        self.dest_entry_point == other.dest_entry_point
            && self.dest_executable_id == other.dest_executable_id
    }
}

impl Eq for CallgraphEntry {}

impl PartialOrd for CallgraphEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CallgraphEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.dest_executable_id
            .cmp(&other.dest_executable_id)
            .then_with(|| self.dest_entry_point.cmp(&other.dest_entry_point))
    }
}

/// A signature record associated with a function.
///
/// Ports `ghidra.features.bsim.query.description.SignatureRecord`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRecord {
    /// The LSH signature vector.
    pub vector: Vec<f64>,
    /// Database ID of this signature vector.
    pub vector_id: i64,
    /// Number of duplicates of this signature in the database.
    pub count: usize,
    /// The function this signature is attached to.
    pub function_entry_point: u64,
}

impl SignatureRecord {
    /// Create a new signature record.
    pub fn new(vector: Vec<f64>) -> Self {
        Self {
            vector,
            vector_id: 0,
            count: 0,
            function_entry_point: 0,
        }
    }

    /// Set the vector ID.
    pub fn with_vector_id(mut self, id: i64) -> Self {
        self.vector_id = id;
        self
    }

    /// Set the count.
    pub fn with_count(mut self, count: usize) -> Self {
        self.count = count;
        self
    }

    /// Set the function entry point.
    pub fn with_function(mut self, entry_point: u64) -> Self {
        self.function_entry_point = entry_point;
        self
    }

    /// Compute the L2 (Euclidean) norm of the vector.
    pub fn l2_norm(&self) -> f64 {
        self.vector.iter().map(|x| x * x).sum::<f64>().sqrt()
    }

    /// Normalize the vector in-place to unit length.
    pub fn normalize(&mut self) {
        let norm = self.l2_norm();
        if norm > 0.0 {
            for v in &mut self.vector {
                *v /= norm;
            }
        }
    }
}

/// Result of a vector similarity query.
///
/// Ports `ghidra.features.bsim.query.description.VectorResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorResult {
    /// The matched signature.
    pub signature: SignatureRecord,
    /// The associated function description.
    pub function: BSimFunctionDescription,
    /// The similarity score.
    pub score: f64,
    /// Rank in the result set.
    pub rank: usize,
}

impl VectorResult {
    /// Create a new vector result.
    pub fn new(signature: SignatureRecord, function: BSimFunctionDescription, score: f64) -> Self {
        Self {
            signature,
            function,
            score,
            rank: 0,
        }
    }

    /// Set the rank.
    pub fn with_rank(mut self, rank: usize) -> Self {
        self.rank = rank;
        self
    }
}

/// Maps between function descriptions and their database representations.
///
/// Ports `ghidra.features.bsim.query.description.FunctionDescriptionMapper`.
#[derive(Debug, Clone)]
pub struct FunctionDescriptionMapper {
    /// Map from entry point to function description.
    by_entry_point: std::collections::BTreeMap<u64, BSimFunctionDescription>,
    /// Map from function name to entry points.
    by_name: std::collections::HashMap<String, Vec<u64>>,
}

impl FunctionDescriptionMapper {
    /// Create a new empty mapper.
    pub fn new() -> Self {
        Self {
            by_entry_point: std::collections::BTreeMap::new(),
            by_name: std::collections::HashMap::new(),
        }
    }

    /// Add a function description to the mapper.
    pub fn insert(&mut self, func: BSimFunctionDescription) {
        let ep = func.entry_point;
        let name = func.function_name.clone();
        self.by_name.entry(name).or_default().push(ep);
        self.by_entry_point.insert(ep, func);
    }

    /// Look up a function by entry point.
    pub fn get_by_entry_point(&self, ep: u64) -> Option<&BSimFunctionDescription> {
        self.by_entry_point.get(&ep)
    }

    /// Look up functions by name.
    pub fn get_by_name(&self, name: &str) -> Vec<&BSimFunctionDescription> {
        self.by_name
            .get(name)
            .map(|eps| {
                eps.iter()
                    .filter_map(|ep| self.by_entry_point.get(ep))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the number of mapped functions.
    pub fn len(&self) -> usize {
        self.by_entry_point.len()
    }

    /// Whether the mapper is empty.
    pub fn is_empty(&self) -> bool {
        self.by_entry_point.is_empty()
    }

    /// Get all functions in entry-point order.
    pub fn all_functions(&self) -> Vec<&BSimFunctionDescription> {
        self.by_entry_point.values().collect()
    }
}

impl Default for FunctionDescriptionMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Container for metadata about executables, functions, and their associated signatures.
///
/// Ports `ghidra.features.bsim.query.description.DescriptionManager`.
#[derive(Debug, Clone)]
pub struct DescriptionManager {
    /// Functions in this container.
    functions: std::collections::BTreeMap<u64, BSimFunctionDescription>,
    /// Executables in this container.
    executables: std::collections::HashMap<String, BSimExecutableInfo>,
    /// Callgraph entries.
    callgraph: Vec<CallgraphEntry>,
    /// Signature records indexed by function entry point.
    signatures: std::collections::HashMap<u64, SignatureRecord>,
    /// Categories per executable.
    exe_categories: std::collections::HashMap<String, Vec<CategoryRecord>>,
    /// Decompiler major version.
    major: i16,
    /// Decompiler minor version.
    minor: i16,
    /// Signature strategy settings.
    settings: i32,
}

impl DescriptionManager {
    /// Create a new empty description manager.
    pub fn new() -> Self {
        Self {
            functions: std::collections::BTreeMap::new(),
            executables: std::collections::HashMap::new(),
            callgraph: Vec::new(),
            signatures: std::collections::HashMap::new(),
            exe_categories: std::collections::HashMap::new(),
            major: 0,
            minor: 0,
            settings: 0,
        }
    }

    /// Set the decompiler version.
    pub fn set_version(&mut self, major: i16, minor: i16) {
        self.major = major;
        self.minor = minor;
    }

    /// Set the signature settings.
    pub fn set_settings(&mut self, settings: i32) {
        self.settings = settings;
    }

    /// Get the major version.
    pub fn major_version(&self) -> i16 {
        self.major
    }

    /// Get the minor version.
    pub fn minor_version(&self) -> i16 {
        self.minor
    }

    /// Get the settings.
    pub fn settings(&self) -> i32 {
        self.settings
    }

    /// Add an executable record.
    pub fn add_executable(&mut self, exe: BSimExecutableInfo) {
        self.executables.insert(exe.executable_id.clone(), exe);
    }

    /// Get an executable by ID.
    pub fn get_executable(&self, id: &str) -> Option<&BSimExecutableInfo> {
        self.executables.get(id)
    }

    /// Get a mutable reference to an executable by ID.
    pub fn get_executable_mut(&mut self, id: &str) -> Option<&mut BSimExecutableInfo> {
        self.executables.get_mut(id)
    }

    /// Set categories for an executable.
    pub fn set_exe_categories(&mut self, exe_id: &str, categories: Vec<CategoryRecord>) {
        self.exe_categories.insert(exe_id.to_string(), categories);
    }

    /// Get categories for an executable.
    pub fn get_exe_categories(&self, exe_id: &str) -> Option<&Vec<CategoryRecord>> {
        self.exe_categories.get(exe_id)
    }

    /// Add a function description.
    pub fn add_function(&mut self, func: BSimFunctionDescription) {
        self.functions.insert(func.entry_point, func);
    }

    /// Get a function by entry point.
    pub fn get_function(&self, entry_point: u64) -> Option<&BSimFunctionDescription> {
        self.functions.get(&entry_point)
    }

    /// Get a mutable reference to a function by entry point.
    pub fn get_function_mut(&mut self, entry_point: u64) -> Option<&mut BSimFunctionDescription> {
        self.functions.get_mut(&entry_point)
    }

    /// Attach a signature to a function.
    pub fn attach_signature(&mut self, entry_point: u64, sig: SignatureRecord) {
        self.signatures.insert(entry_point, sig);
    }

    /// Get the signature for a function.
    pub fn get_signature(&self, entry_point: u64) -> Option<&SignatureRecord> {
        self.signatures.get(&entry_point)
    }

    /// Add a callgraph entry.
    pub fn add_callgraph_entry(&mut self, entry: CallgraphEntry) {
        self.callgraph.push(entry);
    }

    /// Get all callgraph entries.
    pub fn callgraph_entries(&self) -> &[CallgraphEntry] {
        &self.callgraph
    }

    /// Get the number of functions.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Get the number of executables.
    pub fn executable_count(&self) -> usize {
        self.executables.len()
    }

    /// Get the number of signatures.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Get all functions in entry-point order.
    pub fn all_functions(&self) -> impl Iterator<Item = &BSimFunctionDescription> {
        self.functions.values()
    }

    /// Get all executables.
    pub fn all_executables(&self) -> impl Iterator<Item = &BSimExecutableInfo> {
        self.executables.values()
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.functions.clear();
        self.executables.clear();
        self.callgraph.clear();
        self.signatures.clear();
        self.exe_categories.clear();
    }

    /// Whether the container is empty.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty() && self.executables.is_empty()
    }
}

impl Default for DescriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DescriptionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DescriptionManager: {} exes, {} funcs, {} sigs, {} calls",
            self.executable_count(),
            self.function_count(),
            self.signature_count(),
            self.callgraph.len()
        )
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

    #[test]
    fn test_row_key() {
        let key = RowKey::new(42);
        assert_eq!(key.as_long(), 42);
        let key2 = RowKey::new(100);
        assert!(key < key2);
    }

    #[test]
    fn test_row_key_display() {
        let key = RowKey::new(123);
        assert_eq!(key.to_string(), "123");
    }

    #[test]
    fn test_category_record() {
        let cat = CategoryRecord::new("source", "gcc");
        assert_eq!(cat.category_type, "source");
        assert_eq!(cat.category, "gcc");
    }

    #[test]
    fn test_category_record_ordering() {
        let c1 = CategoryRecord::new("a", "1");
        let c2 = CategoryRecord::new("b", "1");
        let c3 = CategoryRecord::new("a", "2");
        assert!(c1 < c2);
        assert!(c1 < c3);
    }

    #[test]
    fn test_category_record_enforce_type() {
        assert!(CategoryRecord::enforce_type_characters("valid_type"));
        assert!(CategoryRecord::enforce_type_characters("with:colon/and(paren)"));
        assert!(!CategoryRecord::enforce_type_characters(""));
        assert!(!CategoryRecord::enforce_type_characters("has@special"));
    }

    #[test]
    fn test_database_information() {
        let info = DatabaseInformation::new();
        assert_eq!(info.database_name, "Example Database");
        assert!(!info.has_signatures());
        assert!(info.track_callgraph);
        assert!(!info.readonly);
    }

    #[test]
    fn test_database_information_builder() {
        let info = DatabaseInformation::new()
            .with_name("MyDB")
            .with_description("Test database");
        assert_eq!(info.database_name, "MyDB");
        assert_eq!(info.description, "Test database");
    }

    #[test]
    fn test_database_information_categories() {
        let mut info = DatabaseInformation::new();
        info.add_exe_category("malware");
        info.add_exe_category("benign");
        assert_eq!(info.exe_categories.len(), 2);
    }

    #[test]
    fn test_database_information_display() {
        let mut info = DatabaseInformation::new();
        info.database_name = "TestDB".to_string();
        info.major = 5;
        info.minor = 2;
        assert_eq!(info.to_string(), "TestDB (v5.2)");
    }

    #[test]
    fn test_callgraph_entry() {
        let entry = CallgraphEntry::new("printf", 0x4000, 0x1234);
        assert_eq!(entry.dest_function, "printf");
        assert_eq!(entry.dest_entry_point, 0x4000);
        assert_eq!(entry.location_hash, 0x1234);
    }

    #[test]
    fn test_callgraph_entry_ordering() {
        let e1 = CallgraphEntry::new("a", 0x1000, 0).with_exe_id("exe1");
        let e2 = CallgraphEntry::new("b", 0x2000, 0).with_exe_id("exe1");
        let e3 = CallgraphEntry::new("c", 0x1000, 0).with_exe_id("exe2");
        assert!(e1 < e2);
        assert!(e1 < e3);
    }

    #[test]
    fn test_signature_record() {
        let mut sig = SignatureRecord::new(vec![1.0, 2.0, 3.0])
            .with_vector_id(42)
            .with_count(5)
            .with_function(0x1000);
        assert_eq!(sig.vector_id, 42);
        assert_eq!(sig.count, 5);
        assert_eq!(sig.function_entry_point, 0x1000);

        let norm = sig.l2_norm();
        assert!((norm - (14.0_f64).sqrt()).abs() < 1e-10);

        sig.normalize();
        let norm = sig.l2_norm();
        assert!((norm - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_vector_result() {
        let sig = SignatureRecord::new(vec![0.1, 0.2, 0.3]);
        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        let result = VectorResult::new(sig, func, 0.95).with_rank(1);
        assert_eq!(result.score, 0.95);
        assert_eq!(result.rank, 1);
    }

    #[test]
    fn test_function_description_mapper() {
        let mut mapper = FunctionDescriptionMapper::new();
        assert!(mapper.is_empty());

        let f1 = BSimFunctionDescription::new("exe1", "main", 0x1000);
        let f2 = BSimFunctionDescription::new("exe1", "printf", 0x4000);
        let f3 = BSimFunctionDescription::new("exe2", "main", 0x8000);

        mapper.insert(f1);
        mapper.insert(f2);
        mapper.insert(f3);

        assert_eq!(mapper.len(), 3);
        assert!(mapper.get_by_entry_point(0x1000).is_some());
        assert!(mapper.get_by_entry_point(0x9999).is_none());

        let mains = mapper.get_by_name("main");
        assert_eq!(mains.len(), 2);
    }

    #[test]
    fn test_description_manager() {
        let mut mgr = DescriptionManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.function_count(), 0);
        assert_eq!(mgr.executable_count(), 0);

        mgr.set_version(5, 2);
        assert_eq!(mgr.major_version(), 5);
        assert_eq!(mgr.minor_version(), 2);

        let exe = BSimExecutableInfo::new("exe1", "test.exe")
            .with_md5("abc123")
            .with_architecture("x86");
        mgr.add_executable(exe);
        assert_eq!(mgr.executable_count(), 1);
        assert!(mgr.get_executable("exe1").is_some());
        assert!(mgr.get_executable("exe2").is_none());

        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        mgr.add_function(func);
        assert_eq!(mgr.function_count(), 1);
        assert!(mgr.get_function(0x1000).is_some());
    }

    #[test]
    fn test_description_manager_signatures() {
        let mut mgr = DescriptionManager::new();
        let func = BSimFunctionDescription::new("exe1", "main", 0x1000);
        mgr.add_function(func);

        let sig = SignatureRecord::new(vec![1.0, 0.5, 0.3]).with_count(3);
        mgr.attach_signature(0x1000, sig);

        assert_eq!(mgr.signature_count(), 1);
        let retrieved = mgr.get_signature(0x1000);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().count, 3);
    }

    #[test]
    fn test_description_manager_callgraph() {
        let mut mgr = DescriptionManager::new();
        let entry = CallgraphEntry::new("printf", 0x4000, 0x1234);
        mgr.add_callgraph_entry(entry);
        assert_eq!(mgr.callgraph_entries().len(), 1);
    }

    #[test]
    fn test_description_manager_categories() {
        let mut mgr = DescriptionManager::new();
        let exe = BSimExecutableInfo::new("exe1", "test.exe");
        mgr.add_executable(exe);

        let cats = vec![
            CategoryRecord::new("source", "gcc"),
            CategoryRecord::new("classification", "library"),
        ];
        mgr.set_exe_categories("exe1", cats);

        let retrieved = mgr.get_exe_categories("exe1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().len(), 2);
    }

    #[test]
    fn test_description_manager_clear() {
        let mut mgr = DescriptionManager::new();
        mgr.add_function(BSimFunctionDescription::new("e", "f", 0));
        mgr.add_executable(BSimExecutableInfo::new("e", "test"));
        assert!(!mgr.is_empty());

        mgr.clear();
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_description_manager_display() {
        let mut mgr = DescriptionManager::new();
        mgr.add_executable(BSimExecutableInfo::new("e", "test"));
        mgr.add_function(BSimFunctionDescription::new("e", "f", 0));
        let display = format!("{}", mgr);
        assert!(display.contains("1 exes"));
        assert!(display.contains("1 funcs"));
    }
}
