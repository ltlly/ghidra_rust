//! BSim description types -- Rust port of Ghidra's `ghidra.features.bsim.query.description` package.
//!
//! These types model the core data structures for BSim signature management:
//! - [`RowKey`] -- abstract row identifier
//! - [`CategoryRecord`] -- user-defined category on an executable
//! - [`ExecutableRecord`] -- metadata about an executable (md5, name, arch, compiler)
//! - [`SignatureRecord`] -- wraps a feature-vector with a database vector-id
//! - [`VectorResult`] -- a similarity search hit (similarity + significance scores)
//! - [`CallgraphEntry`] -- a call-graph edge (destination function + location hash)
//! - [`FunctionDescription`] -- complete function metadata (name, address, signature, calls)
//! - [`DatabaseInformation`] -- global BSim database metadata
//! - [`DescriptionManager`] -- container that owns executables and functions

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::FeatureVector;

// ---------------------------------------------------------------------------
// RowKey
// ---------------------------------------------------------------------------

/// A row identifier in the BSim database.
///
/// Mirrors the Java abstract class `RowKey` which provides a 64-bit long key.
/// In Rust we use a plain `u64` for concrete row keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RowKey(pub u64);

impl RowKey {
    /// The 64-bit key value.
    pub fn value(&self) -> u64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// CategoryRecord
// ---------------------------------------------------------------------------

/// A user-defined category associated with an executable.
///
/// Specified by a `type` (must not be empty) and a `category` within that type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryRecord {
    /// The type of category (must not be empty).
    pub category_type: String,
    /// The type-specific category value.
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

    /// Validate that the type string contains only allowed characters:
    /// letters, digits, space, dot, underscore, colon.
    pub fn enforce_type_characters(val: &str) -> bool {
        if val.is_empty() {
            return false;
        }
        val.chars().all(|c| {
            c.is_alphanumeric() || c == ' ' || c == '.' || c == '_' || c == ':'
        })
    }
}

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

// ---------------------------------------------------------------------------
// ExecutableRecord
// ---------------------------------------------------------------------------

/// Metadata about a specific executable in a BSim database.
///
/// There are two basic varieties:
/// - **Normal executables**: container of functions where each function has a
///   body and address (and a corresponding feature vector).
/// - **Library executables**: functions that can only be identified by name
///   (no body or feature vector).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableRecord {
    /// The MD5 hash of the executable (32 hex characters).
    pub md5: String,
    /// The name of the executable.
    pub executable_name: String,
    /// Architecture string (e.g. `"x86:LE:64:default"`).
    pub architecture: String,
    /// Name of the compiler used to build the executable.
    pub compiler_name: String,
    /// Ingest date (ISO-8601 string or empty).
    pub date: String,
    /// Repository URL, if any.
    pub repository: Option<String>,
    /// Path within the repository, if any.
    pub path: Option<String>,
    /// Boolean flags: `ALREADY_STORED`, `LIBRARY`, `CATEGORIES_SET`.
    pub flags: u32,
    /// User-defined categories this executable belongs to.
    pub categories: Vec<CategoryRecord>,
    /// Index for cross-referencing.
    pub xref_index: i32,
}

/// The executable has already been stored in the database.
pub const EXE_FLAG_ALREADY_STORED: u32 = 1;
/// The executable is a library (functions identified by name only).
pub const EXE_FLAG_LIBRARY: u32 = 2;
/// Categories have been set on this executable.
pub const EXE_FLAG_CATEGORIES_SET: u32 = 4;

impl ExecutableRecord {
    /// Create a new normal executable record.
    pub fn new(
        md5: impl Into<String>,
        executable_name: impl Into<String>,
        architecture: impl Into<String>,
        compiler_name: impl Into<String>,
    ) -> Self {
        Self {
            md5: md5.into(),
            executable_name: executable_name.into(),
            architecture: architecture.into(),
            compiler_name: compiler_name.into(),
            date: String::new(),
            repository: None,
            path: None,
            flags: 0,
            categories: Vec::new(),
            xref_index: -1,
        }
    }

    /// Create a library executable record (no body / feature vector).
    pub fn new_library(
        executable_name: impl Into<String>,
        architecture: impl Into<String>,
    ) -> Self {
        Self {
            md5: String::new(),
            executable_name: executable_name.into(),
            architecture: architecture.into(),
            compiler_name: String::new(),
            date: String::new(),
            repository: None,
            path: None,
            flags: EXE_FLAG_LIBRARY,
            categories: Vec::new(),
            xref_index: -1,
        }
    }

    /// Whether this is a library executable.
    pub fn is_library(&self) -> bool {
        self.flags & EXE_FLAG_LIBRARY != 0
    }

    /// Whether this record has already been stored in the database.
    pub fn is_already_stored(&self) -> bool {
        self.flags & EXE_FLAG_ALREADY_STORED != 0
    }

    /// Whether categories have been set.
    pub fn categories_set(&self) -> bool {
        self.flags & EXE_FLAG_CATEGORIES_SET != 0
    }

    /// Mark as already stored.
    pub fn set_already_stored(&mut self) {
        self.flags |= EXE_FLAG_ALREADY_STORED;
    }

    /// Add a category and mark `CATEGORIES_SET`.
    pub fn add_category(&mut self, cat: CategoryRecord) {
        self.categories.push(cat);
        self.flags |= EXE_FLAG_CATEGORIES_SET;
    }
}

impl PartialOrd for ExecutableRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExecutableRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.md5
            .cmp(&other.md5)
            .then_with(|| self.executable_name.cmp(&other.executable_name))
            .then_with(|| self.architecture.cmp(&other.architecture))
    }
}

// ---------------------------------------------------------------------------
// SignatureRecord
// ---------------------------------------------------------------------------

/// A signature attached to a function in the database.
///
/// Wraps a [`FeatureVector`] with a database vector-id and a duplicate count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureRecord {
    /// The feature vector (LSH signature).
    pub vector: FeatureVector,
    /// Database vector-id (0 if not yet stored).
    pub vector_id: u64,
    /// Number of duplicates of this signature within the database.
    pub count: u32,
}

impl SignatureRecord {
    /// Create a new signature record from a feature vector.
    pub fn new(vector: FeatureVector) -> Self {
        Self {
            vector,
            vector_id: 0,
            count: 0,
        }
    }

    /// Set the database vector-id (typically done by the database layer).
    pub fn set_vector_id(&mut self, id: u64) {
        self.vector_id = id;
    }

    /// Set the duplicate count.
    pub fn set_count(&mut self, c: u32) {
        self.count = c;
    }
}

// ---------------------------------------------------------------------------
// VectorResult
// ---------------------------------------------------------------------------

/// A single hit from a similarity search against the database.
///
/// Contains the vector-id, similarity score, significance score, hit count,
/// and optionally the full feature vector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VectorResult {
    /// Database vector-id of the matching signature.
    pub vector_id: u64,
    /// Cosine similarity score (0.0 - 1.0).
    pub similarity: f64,
    /// Significance score (higher means more significant).
    pub significance: f64,
    /// Number of duplicate results.
    pub hit_count: u32,
    /// Optional feature vector of the match.
    pub vector: Option<FeatureVector>,
}

impl VectorResult {
    /// Create a new vector result.
    pub fn new(
        vector_id: u64,
        hit_count: u32,
        similarity: f64,
        significance: f64,
        vector: Option<FeatureVector>,
    ) -> Self {
        Self {
            vector_id,
            similarity,
            significance,
            hit_count,
            vector,
        }
    }
}

impl Default for VectorResult {
    fn default() -> Self {
        Self {
            vector_id: 0,
            similarity: 0.0,
            significance: 0.0,
            hit_count: 0,
            vector: None,
        }
    }
}

// ---------------------------------------------------------------------------
// CallgraphEntry
// ---------------------------------------------------------------------------

/// A call-graph edge: a function calls another function at a specific
/// callsite identified by a location hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallgraphEntry {
    /// Index into the `DescriptionManager` function list for the destination.
    pub dest_index: usize,
    /// Location hash of the call-site (position-sensitive).
    pub location_hash: u32,
}

impl CallgraphEntry {
    /// Create a new callgraph entry.
    pub fn new(dest_index: usize, location_hash: u32) -> Self {
        Self {
            dest_index,
            location_hash,
        }
    }
}

impl PartialOrd for CallgraphEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CallgraphEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.dest_index
            .cmp(&other.dest_index)
            .then_with(|| self.location_hash.cmp(&other.location_hash))
    }
}

// ---------------------------------------------------------------------------
// FunctionDescription
// ---------------------------------------------------------------------------

/// Complete metadata for a function in the BSim database.
///
/// This is the primary entity managed by [`DescriptionManager`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDescription {
    /// Index into the DescriptionManager's executable list.
    pub exe_index: usize,
    /// Name of the function (unique within its executable).
    pub function_name: String,
    /// Address offset of this function within its executable,
    /// or `None` for a library function.
    pub address: Option<u64>,
    /// The signature record (feature vector + metadata).
    pub signature: Option<SignatureRecord>,
    /// Callgraph edges originating from this function.
    pub callgraph: Vec<CallgraphEntry>,
    /// Database row key (`None` if not yet stored).
    pub row_id: Option<RowKey>,
    /// Database vector-id of the attached signature.
    pub vector_id: u64,
    /// 1-bit flags (currently unused, mirrors Java `flags` field).
    pub flags: u32,
}

impl FunctionDescription {
    /// Create a new function description.
    pub fn new(
        exe_index: usize,
        function_name: impl Into<String>,
        address: Option<u64>,
    ) -> Self {
        Self {
            exe_index,
            function_name: function_name.into(),
            address,
            signature: None,
            callgraph: Vec::new(),
            row_id: None,
            vector_id: 0,
            flags: 0,
        }
    }

    /// Attach a signature record.
    pub fn set_signature(&mut self, sig: SignatureRecord) {
        self.signature = Some(sig);
    }

    /// Add a call-graph edge.
    pub fn add_call(&mut self, dest_index: usize, location_hash: u32) {
        self.callgraph
            .push(CallgraphEntry::new(dest_index, location_hash));
    }
}

impl PartialEq for FunctionDescription {
    fn eq(&self, other: &Self) -> bool {
        self.exe_index == other.exe_index
            && self.function_name == other.function_name
            && self.address == other.address
    }
}

impl Eq for FunctionDescription {}

impl PartialOrd for FunctionDescription {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FunctionDescription {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.exe_index
            .cmp(&other.exe_index)
            .then_with(|| self.function_name.cmp(&other.function_name))
            .then_with(|| self.address.cmp(&other.address))
    }
}

// ---------------------------------------------------------------------------
// DatabaseInformation
// ---------------------------------------------------------------------------

/// Global metadata for a BSim database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DatabaseInformation {
    /// Formal name of this database.
    pub database_name: String,
    /// Owner of the database.
    pub owner: String,
    /// Description of the database.
    pub description: String,
    /// Signature strategy major version.
    pub major: i16,
    /// Signature strategy minor version.
    pub minor: i16,
    /// Settings for signature generation.
    pub settings: u32,
    /// Executable categories for this database.
    pub executable_categories: Vec<String>,
    /// Named boolean properties on functions.
    pub function_tags: Vec<String>,
    /// Override of the default date column name ("Ingest Date").
    pub date_column_name: Option<String>,
    /// Version of the database layout.
    pub layout_version: u32,
    /// Whether the database is read-only.
    pub readonly: bool,
    /// Whether the database tracks call-graph information.
    pub track_callgraph: bool,
}

impl Default for DatabaseInformation {
    fn default() -> Self {
        Self {
            database_name: "Example Database".into(),
            owner: "Example Owner".into(),
            description: "A collection of functions for testing purposes".into(),
            major: 0,
            minor: 0,
            settings: 0,
            executable_categories: Vec::new(),
            function_tags: Vec::new(),
            date_column_name: None,
            layout_version: 0,
            readonly: false,
            track_callgraph: true,
        }
    }
}

impl DatabaseInformation {
    /// Check whether a given signature settings triple is compatible with this
    /// database.
    ///
    /// Returns:
    /// - `0` -- complete match
    /// - `1` -- minor difference in version/settings
    /// - `2` -- settings mismatch
    /// - `3` -- input has no setting information
    /// - `4` -- database has no setting information
    pub fn check_signature_settings(&self, maj: i16, min: i16, set: u32) -> u32 {
        if maj == 0 || set == 0 {
            return 3;
        }
        if self.major == 0 || self.settings == 0 {
            return 4;
        }
        if self.major != maj || self.settings != set {
            return 2;
        }
        if self.minor == min {
            return 0;
        }
        let diff = if self.minor > min {
            self.minor - min
        } else {
            min - self.minor
        } as u32;
        if diff > 1 {
            2
        } else {
            1
        }
    }
}

// ---------------------------------------------------------------------------
// DescriptionManager
// ---------------------------------------------------------------------------

/// Container for executables, functions, and their associated signatures.
///
/// This mirrors the Java `DescriptionManager` class.  It holds:
/// - A list of [`ExecutableRecord`]s indexed by position.
/// - A [`BTreeMap`] of [`FunctionDescription`]s sorted by
///   (exe_index, function_name, address) for consistent iteration.
#[derive(Debug, Clone, Default)]
pub struct DescriptionManager {
    /// Major version of the decompiler used to generate signatures.
    pub major_version: i16,
    /// The list of executables.  Indices into this list are used as
    /// `exe_index` in `FunctionDescription`.
    executables: Vec<ExecutableRecord>,
    /// Functions keyed by (exe_index, name, address) for sorted iteration.
    functions: BTreeMap<(usize, String, Option<u64>), FunctionDescription>,
    /// MD5-to-executable-index lookup.
    md5_index: BTreeMap<String, usize>,
}

impl DescriptionManager {
    /// Create a new empty description manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// The major decompiler version.
    pub fn get_major_version(&self) -> i16 {
        self.major_version
    }

    // -- Executable management -----------------------------------------------

    /// Add (or find an existing) normal executable record.
    ///
    /// Returns the index into the executables list.
    pub fn new_executable_record(
        &mut self,
        md5: impl Into<String>,
        name: impl Into<String>,
        compiler: impl Into<String>,
        architecture: impl Into<String>,
    ) -> usize {
        let md5_s = md5.into();
        if let Some(&idx) = self.md5_index.get(&md5_s) {
            return idx;
        }
        let idx = self.executables.len();
        let mut exe = ExecutableRecord::new(&md5_s, name, architecture, compiler);
        exe.set_already_stored();
        self.executables.push(exe);
        self.md5_index.insert(md5_s, idx);
        idx
    }

    /// Add a library executable (functions identified by name only).
    ///
    /// Returns the index into the executables list.
    pub fn new_executable_library(
        &mut self,
        name: impl Into<String>,
        architecture: impl Into<String>,
    ) -> usize {
        let idx = self.executables.len();
        self.executables
            .push(ExecutableRecord::new_library(name, architecture));
        idx
    }

    /// Get a reference to an executable by index.
    pub fn get_executable(&self, index: usize) -> Option<&ExecutableRecord> {
        self.executables.get(index)
    }

    /// Get a mutable reference to an executable by index.
    pub fn get_executable_mut(&mut self, index: usize) -> Option<&mut ExecutableRecord> {
        self.executables.get_mut(index)
    }

    /// Number of executables.
    pub fn executable_count(&self) -> usize {
        self.executables.len()
    }

    /// Iterate over all executables.
    pub fn executables(&self) -> &[ExecutableRecord] {
        &self.executables
    }

    // -- Function management -------------------------------------------------

    /// Add (or find an existing) function description.
    ///
    /// Returns a mutable reference so the caller can attach signatures and
    /// callgraph edges.
    pub fn new_function_description(
        &mut self,
        name: impl Into<String>,
        address: Option<u64>,
        exe_index: usize,
    ) -> &mut FunctionDescription {
        let name_s = name.into();
        let key = (exe_index, name_s.clone(), address);
        self.functions
            .entry(key)
            .or_insert_with(|| FunctionDescription::new(exe_index, name_s, address))
    }

    /// Attach a signature to an existing function.
    pub fn attach_signature(
        &mut self,
        exe_index: usize,
        function_name: &str,
        address: Option<u64>,
        sig: SignatureRecord,
    ) {
        let key = (exe_index, function_name.to_string(), address);
        if let Some(func) = self.functions.get_mut(&key) {
            func.set_signature(sig);
        }
    }

    /// Create a callgraph link between two functions.
    pub fn make_callgraph_link(
        &mut self,
        src_exe: usize,
        src_name: &str,
        src_addr: Option<u64>,
        dest_exe: usize,
        dest_name: &str,
        dest_addr: Option<u64>,
        location_hash: u32,
    ) {
        let dest_key = (dest_exe, dest_name.to_string(), dest_addr);
        // Ensure destination exists.
        self.functions
            .entry(dest_key.clone())
            .or_insert_with(|| {
                FunctionDescription::new(dest_exe, dest_name.to_string(), dest_addr)
            });
        let dest_idx = self.functions.keys().position(|k| k == &dest_key).unwrap_or(0);
        let src_key = (src_exe, src_name.to_string(), src_addr);
        if let Some(func) = self.functions.get_mut(&src_key) {
            func.add_call(dest_idx, location_hash);
        }
    }

    /// Get a reference to a function by key.
    pub fn get_function(
        &self,
        exe_index: usize,
        name: &str,
        address: Option<u64>,
    ) -> Option<&FunctionDescription> {
        let key = (exe_index, name.to_string(), address);
        self.functions.get(&key)
    }

    /// Iterate over all functions in sorted order.
    pub fn list_all_functions(&self) -> impl Iterator<Item = &FunctionDescription> {
        self.functions.values()
    }

    /// Number of functions.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Clear all functions (keep executables).
    pub fn clear_functions(&mut self) {
        self.functions.clear();
    }
}

// ---------------------------------------------------------------------------
// CompareSignatures
// ---------------------------------------------------------------------------

/// Pairwise signature comparison engine.
///
/// Reads functions from a [`DescriptionManager`] and compares all pairs,
/// reporting those that exceed the similarity and significance thresholds.
#[derive(Debug)]
pub struct CompareSignatures {
    manager: DescriptionManager,
    /// Minimum cosine similarity for a match (default 0.7).
    pub similarity_threshold: f64,
    /// Minimum significance score for a match (default 4.0).
    pub significance_threshold: f64,
}

/// A single comparison result from [`CompareSignatures`].
#[derive(Debug, Clone, PartialEq)]
pub struct ComparisonResult {
    /// Index of the first function.
    pub func1_index: usize,
    /// Index of the second function.
    pub func2_index: usize,
    /// Similarity score.
    pub similarity: f64,
    /// Significance score.
    pub significance: f64,
}

impl CompareSignatures {
    /// Create a new comparison engine from a description manager.
    pub fn new(manager: DescriptionManager) -> Self {
        Self {
            manager,
            similarity_threshold: 0.7,
            significance_threshold: 4.0,
        }
    }

    /// Access the underlying description manager.
    pub fn manager(&self) -> &DescriptionManager {
        &self.manager
    }

    /// Access the underlying description manager mutably.
    pub fn manager_mut(&mut self) -> &mut DescriptionManager {
        &mut self.manager
    }

    /// Run all-pairs comparison and return matching results.
    ///
    /// Two functions are compared via their aggregated feature vectors.
    /// A match is returned when `similarity >= self.similarity_threshold`
    /// and `significance >= self.significance_threshold`.
    pub fn compare_all(&self) -> Vec<ComparisonResult> {
        let funcs: Vec<&FunctionDescription> = self.manager.list_all_functions().collect();
        let mut results = Vec::new();

        for (i, func1) in funcs.iter().enumerate() {
            let vec1 = match &func1.signature {
                Some(sig) => &sig.vector,
                None => continue,
            };
            for (j, func2) in funcs.iter().enumerate().skip(i + 1) {
                let vec2 = match &func2.signature {
                    Some(sig) => &sig.vector,
                    None => continue,
                };
                let sim = vec1.cosine_similarity(vec2);
                if sim >= self.similarity_threshold {
                    // Significance: approximate as the product of the two
                    // vectors' non-zero entry counts (proxy for function size).
                    let signif =
                        (vec1.hash_count as f64 * vec2.hash_count as f64).sqrt();
                    if signif >= self.significance_threshold {
                        results.push(ComparisonResult {
                            func1_index: i,
                            func2_index: j,
                            similarity: sim,
                            significance: signif,
                        });
                    }
                }
            }
        }

        results.sort_by(|a, b| {
            b.similarity
                .partial_cmp(&a.similarity)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        results
    }
}

// ---------------------------------------------------------------------------
// FunctionDescriptionMapper
// ---------------------------------------------------------------------------

/// Abstract mapper for processing function descriptions from a BSim
/// description stream.
///
/// Ports Ghidra's `ghidra.features.bsim.query.description.FunctionDescriptionMapper`.
///
/// This type scans a BSim description (e.g. from an XML export) and,
/// for each `<exe>` and `<fdesc>` element, invokes callbacks to allow
/// the caller to process the records one at a time without accumulating
/// the entire description in memory.
#[derive(Debug, Clone, Default)]
pub struct FunctionDescriptionMapper {
    /// Index of the current FunctionDescription being processed.
    recnum: usize,
    /// Collected executables.
    executables: Vec<ExecutableRecord>,
    /// Collected function descriptions.
    functions: Vec<FunctionDescription>,
}

impl FunctionDescriptionMapper {
    /// Create a new mapper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Called for each executable record encountered in the stream.
    ///
    /// The default implementation stores the record for later retrieval.
    pub fn handle_executable(&mut self, exe: &ExecutableRecord) {
        self.executables.push(exe.clone());
    }

    /// Called for each function description encountered in the stream.
    ///
    /// The `record_number` is the 0-based index of this function within the
    /// current executable.
    ///
    /// The default implementation stores the record for later retrieval.
    pub fn handle_function(&mut self, func: &FunctionDescription, record_number: usize) {
        self.recnum = record_number + 1;
        self.functions.push(func.clone());
    }

    /// Process a list of executables and their functions from a
    /// [`DescriptionManager`].
    ///
    /// This is the Rust equivalent of the Java `processFile` method that
    /// reads from XML.  Here we operate on an already-populated
    /// `DescriptionManager` instead.
    pub fn process_manager(&mut self, manager: &DescriptionManager) {
        for (i, exe) in manager.executables().iter().enumerate() {
            self.handle_executable(exe);
            for (j, func) in manager.list_all_functions().enumerate() {
                if func.exe_index == i {
                    self.handle_function(func, j);
                }
            }
        }
    }

    /// The current record number (number of functions processed so far).
    pub fn current_record_number(&self) -> usize {
        self.recnum
    }

    /// Get the collected executables.
    pub fn executables(&self) -> &[ExecutableRecord] {
        &self.executables
    }

    /// Get the collected functions.
    pub fn functions(&self) -> &[FunctionDescription] {
        &self.functions
    }

    /// Clear the collected functions (keep executables).
    pub fn clear_functions(&mut self) {
        self.functions.clear();
    }

    /// Clear all collected data.
    pub fn clear(&mut self) {
        self.executables.clear();
        self.functions.clear();
        self.recnum = 0;
    }
}

// ---------------------------------------------------------------------------
// BSimClientConfig
// ---------------------------------------------------------------------------

/// Configuration for a BSim database client connection.
///
/// Encapsulates connection parameters for different backend types
/// (file-based, PostgreSQL, Elasticsearch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BSimClientConfig {
    /// The connection URL (file path, JDBC URL, or HTTP endpoint).
    pub url: String,
    /// The database name.
    pub database_name: String,
    /// Connection timeout in seconds.
    pub timeout_secs: u32,
    /// Whether to use SSL/TLS.
    pub use_tls: bool,
    /// Username for authenticated connections.
    pub username: Option<String>,
    /// Whether to create the database if it does not exist.
    pub create_if_missing: bool,
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
}

impl Default for BSimClientConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            database_name: String::new(),
            timeout_secs: 30,
            use_tls: false,
            username: None,
            create_if_missing: false,
            max_connections: 4,
        }
    }
}

impl BSimClientConfig {
    /// Create a configuration for a file-based (SQLite/H2) database.
    pub fn file(path: impl Into<String>) -> Self {
        Self {
            url: path.into(),
            ..Default::default()
        }
    }

    /// Create a configuration for a PostgreSQL database.
    pub fn postgres(host: impl Into<String>, port: u16, database: impl Into<String>) -> Self {
        Self {
            url: format!("jdbc:postgresql://{}:{}/{}", host.into(), port, database.into()),
            database_name: String::new(),
            timeout_secs: 30,
            use_tls: false,
            username: None,
            create_if_missing: false,
            max_connections: 4,
        }
    }

    /// Create a configuration for an Elasticsearch database.
    pub fn elastic(host: impl Into<String>, port: u16) -> Self {
        Self {
            url: format!("http://{}:{}", host.into(), port),
            database_name: String::new(),
            timeout_secs: 60,
            use_tls: false,
            username: None,
            create_if_missing: false,
            max_connections: 8,
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.url.is_empty() {
            return Err("URL is required".into());
        }
        if self.timeout_secs == 0 {
            return Err("Timeout must be greater than 0".into());
        }
        if self.max_connections == 0 {
            return Err("Max connections must be greater than 0".into());
        }
        Ok(())
    }

    /// Whether this configuration points to a file-based database.
    pub fn is_file_based(&self) -> bool {
        !self.url.starts_with("http")
            && !self.url.starts_with("jdbc:")
            && !self.url.contains("://")
    }

    /// Whether this configuration points to a PostgreSQL database.
    pub fn is_postgres(&self) -> bool {
        self.url.contains("postgresql") || self.url.starts_with("jdbc:postgresql")
    }

    /// Whether this configuration points to an Elasticsearch database.
    pub fn is_elastic(&self) -> bool {
        self.url.starts_with("http") && !self.url.contains("jdbc:")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_key_value() {
        let key = RowKey(42);
        assert_eq!(key.value(), 42);
    }

    #[test]
    fn category_record_ordering() {
        let c1 = CategoryRecord::new("malware", "trojan");
        let c2 = CategoryRecord::new("malware", "virus");
        let c3 = CategoryRecord::new("tool", "compiler");
        assert!(c1 < c2);
        assert!(c2 < c3);
    }

    #[test]
    fn category_record_enforce_type_chars() {
        assert!(CategoryRecord::enforce_type_characters("malware"));
        assert!(CategoryRecord::enforce_type_characters("my_type:sub"));
        assert!(!CategoryRecord::enforce_type_characters(""));
        assert!(!CategoryRecord::enforce_type_characters("bad!chars"));
    }

    #[test]
    fn executable_record_library() {
        let exe = ExecutableRecord::new_library("libc.so", "x86:LE:64:default");
        assert!(exe.is_library());
        assert!(!exe.is_already_stored());
        assert!(exe.md5.is_empty());
    }

    #[test]
    fn executable_record_normal() {
        let mut exe =
            ExecutableRecord::new("abc123", "a.out", "x86:LE:64:default", "gcc");
        assert!(!exe.is_library());
        exe.set_already_stored();
        assert!(exe.is_already_stored());
        exe.add_category(CategoryRecord::new("test", "sample"));
        assert!(exe.categories_set());
        assert_eq!(exe.categories.len(), 1);
    }

    #[test]
    fn executable_record_ordering() {
        let a = ExecutableRecord::new("aaa", "a", "x86", "gcc");
        let b = ExecutableRecord::new("bbb", "b", "x86", "gcc");
        assert!(a < b);
    }

    #[test]
    fn signature_record_defaults() {
        let sig = SignatureRecord::new(FeatureVector::from_pairs(
            vec![1, 2],
            vec![1.0, 1.0],
        ));
        assert_eq!(sig.vector_id, 0);
        assert_eq!(sig.count, 0);
    }

    #[test]
    fn vector_result_default() {
        let vr = VectorResult::default();
        assert_eq!(vr.similarity, 0.0);
        assert_eq!(vr.significance, 0.0);
    }

    #[test]
    fn vector_result_new() {
        let vr = VectorResult::new(100, 3, 0.85, 5.0, None);
        assert_eq!(vr.vector_id, 100);
        assert_eq!(vr.hit_count, 3);
        assert!((vr.similarity - 0.85).abs() < 1e-9);
    }

    #[test]
    fn callgraph_entry_ordering() {
        let a = CallgraphEntry::new(0, 100);
        let b = CallgraphEntry::new(0, 200);
        let c = CallgraphEntry::new(1, 50);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn function_description_create_and_attach() {
        let mut func = FunctionDescription::new(0, "main", Some(0x1000));
        assert_eq!(func.function_name, "main");
        assert_eq!(func.address, Some(0x1000));
        assert!(func.signature.is_none());
        func.set_signature(SignatureRecord::new(FeatureVector::from_pairs(
            vec![10, 20],
            vec![1.0, 0.5],
        )));
        assert!(func.signature.is_some());
    }

    #[test]
    fn function_description_callgraph() {
        let mut func = FunctionDescription::new(0, "caller", Some(0x1000));
        func.add_call(1, 0xABCD);
        func.add_call(2, 0x1234);
        assert_eq!(func.callgraph.len(), 2);
        assert_eq!(func.callgraph[0].dest_index, 1);
        assert_eq!(func.callgraph[0].location_hash, 0xABCD);
    }

    #[test]
    fn function_description_ordering() {
        let a = FunctionDescription::new(0, "alpha", Some(0x1000));
        let b = FunctionDescription::new(0, "beta", Some(0x2000));
        let c = FunctionDescription::new(1, "alpha", Some(0x1000));
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn database_information_defaults() {
        let info = DatabaseInformation::default();
        assert_eq!(info.database_name, "Example Database");
        assert_eq!(info.owner, "Example Owner");
        assert!(!info.readonly);
        assert!(info.track_callgraph);
        assert_eq!(info.major, 0);
    }

    #[test]
    fn database_information_signature_settings() {
        let info = DatabaseInformation::default();
        // No input info.
        assert_eq!(info.check_signature_settings(0, 0, 0), 3);
        // Database has no info.
        assert_eq!(info.check_signature_settings(1, 0, 1), 4);
    }

    #[test]
    fn database_information_signature_settings_match() {
        let mut info = DatabaseInformation::default();
        info.major = 1;
        info.minor = 0;
        info.settings = 0xABCD;
        // Exact match.
        assert_eq!(info.check_signature_settings(1, 0, 0xABCD), 0);
        // Minor difference.
        assert_eq!(info.check_signature_settings(1, 1, 0xABCD), 1);
        // Mismatch.
        assert_eq!(info.check_signature_settings(1, 0, 0x1234), 2);
    }

    #[test]
    fn description_manager_add_executable() {
        let mut dm = DescriptionManager::new();
        let idx0 = dm.new_executable_record("aaa", "prog1", "gcc", "x86");
        let idx1 = dm.new_executable_record("bbb", "prog2", "gcc", "x86");
        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(dm.executable_count(), 2);
    }

    #[test]
    fn description_manager_duplicate_md5() {
        let mut dm = DescriptionManager::new();
        let idx0 = dm.new_executable_record("aaa", "prog1", "gcc", "x86");
        let idx1 = dm.new_executable_record("aaa", "prog1_updated", "gcc", "x86");
        assert_eq!(idx0, idx1, "same MD5 should return same index");
    }

    #[test]
    fn description_manager_library_executable() {
        let mut dm = DescriptionManager::new();
        let idx = dm.new_executable_library("libc.so", "x86");
        assert!(dm.get_executable(idx).unwrap().is_library());
    }

    #[test]
    fn description_manager_functions() {
        let mut dm = DescriptionManager::new();
        dm.new_executable_record("aaa", "prog", "gcc", "x86");
        dm.new_function_description("main", Some(0x1000), 0);
        dm.new_function_description("helper", Some(0x2000), 0);
        assert_eq!(dm.function_count(), 2);

        let main_fn = dm.get_function(0, "main", Some(0x1000));
        assert!(main_fn.is_some());
        assert_eq!(main_fn.unwrap().function_name, "main");
    }

    #[test]
    fn description_manager_attach_signature() {
        let mut dm = DescriptionManager::new();
        dm.new_executable_record("aaa", "prog", "gcc", "x86");
        dm.new_function_description("main", Some(0x1000), 0);

        let sig = SignatureRecord::new(FeatureVector::from_pairs(
            vec![1, 2, 3],
            vec![1.0, 1.0, 1.0],
        ));
        dm.attach_signature(0, "main", Some(0x1000), sig);

        let func = dm.get_function(0, "main", Some(0x1000)).unwrap();
        assert!(func.signature.is_some());
    }

    #[test]
    fn description_manager_callgraph_link() {
        let mut dm = DescriptionManager::new();
        dm.new_executable_record("aaa", "prog", "gcc", "x86");
        dm.new_function_description("caller", Some(0x1000), 0);
        dm.new_function_description("callee", Some(0x2000), 0);

        dm.make_callgraph_link(0, "caller", Some(0x1000), 0, "callee", Some(0x2000), 0xBEEF);

        let caller = dm.get_function(0, "caller", Some(0x1000)).unwrap();
        assert_eq!(caller.callgraph.len(), 1);
        assert_eq!(caller.callgraph[0].location_hash, 0xBEEF);
    }

    #[test]
    fn description_manager_clear_functions() {
        let mut dm = DescriptionManager::new();
        dm.new_executable_record("aaa", "prog", "gcc", "x86");
        dm.new_function_description("main", Some(0x1000), 0);
        assert_eq!(dm.function_count(), 1);
        dm.clear_functions();
        assert_eq!(dm.function_count(), 0);
        assert_eq!(dm.executable_count(), 1);
    }

    #[test]
    fn compare_signatures_basic() {
        let mut dm = DescriptionManager::new();
        dm.new_executable_record("aaa", "prog", "gcc", "x86");

        // Two functions with identical feature vectors.
        let fv = FeatureVector::from_pairs(vec![1, 2, 3], vec![1.0, 1.0, 1.0]);
        dm.new_function_description("func_a", Some(0x1000), 0);
        dm.attach_signature(
            0,
            "func_a",
            Some(0x1000),
            SignatureRecord::new(fv.clone()),
        );

        dm.new_function_description("func_b", Some(0x2000), 0);
        dm.attach_signature(
            0,
            "func_b",
            Some(0x2000),
            SignatureRecord::new(fv),
        );

        let mut comp = CompareSignatures::new(dm);
        comp.similarity_threshold = 0.9;
        comp.significance_threshold = 0.0;

        let results = comp.compare_all();
        assert_eq!(results.len(), 1);
        assert!((results[0].similarity - 1.0).abs() < 1e-6);
    }

    #[test]
    fn compare_signatures_no_match_below_threshold() {
        let mut dm = DescriptionManager::new();
        dm.new_executable_record("aaa", "prog", "gcc", "x86");

        // Disjoint vectors.
        let fv1 = FeatureVector::from_pairs(vec![1], vec![1.0]);
        let fv2 = FeatureVector::from_pairs(vec![2], vec![1.0]);

        dm.new_function_description("a", Some(0x1000), 0);
        dm.attach_signature(0, "a", Some(0x1000), SignatureRecord::new(fv1));
        dm.new_function_description("b", Some(0x2000), 0);
        dm.attach_signature(0, "b", Some(0x2000), SignatureRecord::new(fv2));

        let comp = CompareSignatures::new(dm);
        let results = comp.compare_all();
        assert!(results.is_empty());
    }

    #[test]
    fn compare_signatures_skip_unsigned_functions() {
        let mut dm = DescriptionManager::new();
        dm.new_executable_record("aaa", "prog", "gcc", "x86");
        // Function with no signature.
        dm.new_function_description("unsigned_fn", Some(0x1000), 0);
        // Function with signature.
        dm.new_function_description("signed_fn", Some(0x2000), 0);
        dm.attach_signature(
            0,
            "signed_fn",
            Some(0x2000),
            SignatureRecord::new(FeatureVector::from_pairs(vec![1], vec![1.0])),
        );

        let comp = CompareSignatures::new(dm);
        let results = comp.compare_all();
        assert!(results.is_empty());
    }

    #[test]
    fn function_description_mapper_basic() {
        let mut mapper = FunctionDescriptionMapper::new();
        let exe = ExecutableRecord::new("aaa", "prog", "x86", "gcc");
        let mut func = FunctionDescription::new(0, "main", Some(0x1000));
        func.set_signature(SignatureRecord::new(FeatureVector::from_pairs(
            vec![1, 2, 3],
            vec![1.0, 1.0, 1.0],
        )));
        let func2 = FunctionDescription::new(0, "helper", Some(0x2000));

        mapper.handle_executable(&exe);
        mapper.handle_function(&func, 0);
        mapper.handle_function(&func2, 1);

        assert_eq!(mapper.executables().len(), 1);
        assert_eq!(mapper.functions().len(), 2);
        assert_eq!(mapper.current_record_number(), 2);
    }

    #[test]
    fn function_description_mapper_clear_and_reuse() {
        let mut mapper = FunctionDescriptionMapper::new();
        let exe = ExecutableRecord::new("aaa", "prog", "x86", "gcc");
        mapper.handle_executable(&exe);
        mapper.handle_function(&FunctionDescription::new(0, "f1", Some(0x100)), 0);
        assert_eq!(mapper.functions().len(), 1);

        mapper.clear_functions();
        assert_eq!(mapper.functions().len(), 0);
        assert_eq!(mapper.executables().len(), 1, "executables should be preserved");
    }

    #[test]
    fn bsim_client_config_file() {
        let cfg = BSimClientConfig::file("/tmp/test.db");
        assert!(cfg.is_file_based());
        assert!(!cfg.is_postgres());
        assert!(!cfg.is_elastic());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn bsim_client_config_postgres() {
        let cfg = BSimClientConfig::postgres("localhost", 5432, "bsim");
        assert!(!cfg.is_file_based());
        assert!(cfg.is_postgres());
        assert!(!cfg.is_elastic());
    }

    #[test]
    fn bsim_client_config_elastic() {
        let cfg = BSimClientConfig::elastic("localhost", 9200);
        assert!(!cfg.is_file_based());
        assert!(!cfg.is_postgres());
        assert!(cfg.is_elastic());
    }

    #[test]
    fn bsim_client_config_validate_empty_url() {
        let cfg = BSimClientConfig::default();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn bsim_client_config_validate_zero_timeout() {
        let mut cfg = BSimClientConfig::file("/tmp/test.db");
        cfg.timeout_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn function_description_mapper_process_manager() {
        let mut dm = DescriptionManager::new();
        dm.new_executable_record("aaa", "prog", "gcc", "x86");
        dm.new_function_description("main", Some(0x1000), 0);
        dm.new_function_description("helper", Some(0x2000), 0);

        let mut mapper = FunctionDescriptionMapper::new();
        mapper.process_manager(&dm);
        assert_eq!(mapper.executables().len(), 1);
        assert!(!mapper.functions().is_empty());
    }
}
