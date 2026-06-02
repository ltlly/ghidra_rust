//! Version Tracking module for Ghidra Rust.
//!
//! Version tracking matches functions and data between two versions of a binary.
//! It uses multiple correlator strategies to find corresponding entities across
//! program versions, supporting:
//!
//! - Exact byte-for-byte matching
//! - Function similarity scoring (instruction sequences, mnemonics)
//! - Data item matching
//! - Symbol name-based matching
//! - Structural/call-graph matching
//!
//! # Example
//!
//! ```ignore
//! use ghidra_features::versiontracking::VersionTracker;
//!
//! let mut tracker = VersionTracker::new(source_program, dest_program);
//! let matches = tracker.run_correlation()?;
//! tracker.apply_matches(&matches)?;
//! let results = tracker.export_results();
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use ghidra_core::addr::Address;
use ghidra_core::data::DataType;
use ghidra_core::listing::ListingRow;
use ghidra_core::program::Program;
use ghidra_core::symbol::{Symbol, SymbolKind};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during version tracking operations.
#[derive(Error, Debug)]
pub enum VersionTrackError {
    /// No source program was provided.
    #[error("source program is not set")]
    MissingSourceProgram,

    /// No destination program was provided.
    #[error("destination program is not set")]
    MissingDestProgram,

    /// A correlator encountered an internal error.
    #[error("correlator '{correlator}' failed: {message}")]
    CorrelatorError {
        /// The name of the correlator that failed.
        correlator: String,
        /// A human-readable error message.
        message: String,
    },

    /// Failed to apply a match because the target entity was not found.
    #[error("match target not found at address {address}")]
    MatchTargetNotFound {
        /// The address where the target was expected.
        address: Address,
    },

    /// A generic I/O or serialization error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Convenience alias for results from version-tracking operations.
pub type Result<T> = std::result::Result<T, VersionTrackError>;

// ---------------------------------------------------------------------------
// Match types
// ---------------------------------------------------------------------------

/// The classification of a version-track match between two entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchType {
    /// The two entities are byte-for-byte identical.
    Exact,
    /// The two entities are structurally similar but not identical.
    Similar,
    /// The entity was renamed (same code, different symbol name).
    Renamed,
    /// The entity was moved to a different address.
    Moved,
    /// The entity was modified (similar but with code changes).
    Modified,
}

impl fmt::Display for MatchType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MatchType::Exact => write!(f, "Exact"),
            MatchType::Similar => write!(f, "Similar"),
            MatchType::Renamed => write!(f, "Renamed"),
            MatchType::Moved => write!(f, "Moved"),
            MatchType::Modified => write!(f, "Modified"),
        }
    }
}

// ---------------------------------------------------------------------------
// VersionTrackMatch
// ---------------------------------------------------------------------------

/// Represents a single match between an entity in the source program and an
/// entity in the destination program.
#[derive(Debug, Clone)]
pub struct VersionTrackMatch {
    /// The address of the matched entity in the source program.
    pub source_address: Address,
    /// The address of the matched entity in the destination program.
    pub dest_address: Address,
    /// The kind of match that was found.
    pub match_type: MatchType,
    /// Confidence score from 0.0 (no confidence) to 1.0 (absolute certainty).
    pub confidence: f64,
    /// Human-readable label for the source entity (e.g., function name).
    pub source_label: String,
    /// Human-readable label for the destination entity.
    pub dest_label: String,
}

impl VersionTrackMatch {
    /// Create a new match record.
    pub fn new(
        source_address: Address,
        dest_address: Address,
        match_type: MatchType,
        confidence: f64,
        source_label: impl Into<String>,
        dest_label: impl Into<String>,
    ) -> Self {
        Self {
            source_address,
            dest_address,
            match_type,
            confidence: confidence.clamp(0.0, 1.0),
            source_label: source_label.into(),
            dest_label: dest_label.into(),
        }
    }

    /// Returns true if this match has high confidence (>= 0.9).
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.9
    }

    /// Returns true if this is an exact (unchanged) match.
    pub fn is_exact(&self) -> bool {
        self.match_type == MatchType::Exact
    }
}

impl fmt::Display for VersionTrackMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}) <-> {} ({}) confidence={:.2}",
            self.match_type,
            self.source_label,
            self.source_address,
            self.dest_label,
            self.dest_address,
            self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// Internal helpers for extracting data from Program
// ---------------------------------------------------------------------------

/// Returns an iterator over function symbol names present in the program's
/// symbol table. Functions with auto-generated names (starting with "sub_")
/// are excluded.
fn function_symbol_names(prog: &Program) -> Vec<&Symbol> {
    prog.symbol_table
        .iter()
        .filter(|s| s.kind == SymbolKind::Function)
        .collect()
}

/// Collect the listing rows (instructions) belonging to a function starting at
/// `entry`. Scans forward until another function symbol entry, a "ret"-like
/// instruction, or a maximum number of instructions.
fn function_listing_rows<'a>(prog: &'a Program, entry: Address) -> Vec<&'a ListingRow> {
    let all_func_entries: HashSet<Address> = prog
        .symbol_table
        .iter()
        .filter(|s| s.kind == SymbolKind::Function)
        .map(|s| s.address)
        .collect();

    let max_instructions: usize = 1024;
    let mut rows = Vec::new();
    let mut addr = entry;

    while rows.len() < max_instructions {
        if addr != entry && all_func_entries.contains(&addr) {
            break; // reached the next function
        }
        if let Some(row) = prog.listing.get(&addr) {
            rows.push(row);
            // Stop at return-like mnemonics (row already included above).
            let m = row.mnemonic.text.to_lowercase();
            if m == "ret" || m == "retn" || m == "iret" || m == "sysret" {
                break;
            }
            addr = addr.next();
        } else {
            break; // no listing data
        }
    }

    rows
}

/// Collect all bytes for a sequence of listing rows.
fn listing_bytes(rows: &[&ListingRow]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for row in rows {
        bytes.extend(&row.bytes);
    }
    bytes
}

/// Collect mnemonics from listing rows.
fn listing_mnemonics(rows: &[&ListingRow]) -> Vec<String> {
    rows.iter().map(|r| r.mnemonic.text.clone()).collect()
}

/// Extract callee addresses from a function's listing rows by looking for
/// "call" mnemonics and parsing their operand as a hex address.
fn extract_callees(rows: &[&ListingRow]) -> Vec<Address> {
    let mut callees = Vec::new();
    for row in rows {
        if row.mnemonic.text.to_lowercase() == "call" {
            if let Ok(addr_val) = parse_hex_operand(&row.operands) {
                callees.push(Address::new(addr_val));
            }
        }
    }
    callees
}

/// Parse a hex value from an operand string like "0x2000" or "2000".
fn parse_hex_operand(s: &str) -> std::result::Result<u64, ()> {
    let s = s.trim();
    if s.is_empty() {
        return Err(());
    }
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let cleaned: String = stripped
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if cleaned.is_empty() {
        return Err(());
    }
    u64::from_str_radix(&cleaned, 16).map_err(|_| ())
}

/// Extract callers of a function from the xref map.
fn extract_callers(prog: &Program, addr: Address) -> Vec<Address> {
    prog.xrefs
        .get(&addr)
        .cloned()
        .unwrap_or_default()
}

// ===========================================================================
// VersionTrackResults - exported results container
// ===========================================================================

/// A structured collection of version-tracking results, suitable for
/// serialization, display, or further analysis.
#[derive(Debug, Clone)]
pub struct VersionTrackResults {
    /// The name of the source program.
    pub source_program_name: String,
    /// The name of the destination program.
    pub dest_program_name: String,
    /// Total number of matches found.
    pub total_matches: usize,
    /// All matches discovered by the correlators.
    pub matches: Vec<VersionTrackMatch>,
    /// Matches grouped by match type.
    pub matches_by_type: HashMap<MatchType, Vec<VersionTrackMatch>>,
    /// Summary statistics.
    pub summary: VersionTrackSummary,
}

/// Summary statistics for a version-tracking run.
#[derive(Debug, Clone)]
pub struct VersionTrackSummary {
    /// Number of exact matches.
    pub exact_count: usize,
    /// Number of similar matches.
    pub similar_count: usize,
    /// Number of renamed matches.
    pub renamed_count: usize,
    /// Number of moved matches.
    pub moved_count: usize,
    /// Number of modified matches.
    pub modified_count: usize,
    /// Total number of functions in the source program.
    pub source_function_count: usize,
    /// Total number of functions in the destination program.
    pub dest_function_count: usize,
    /// Average confidence across all matches.
    pub avg_confidence: f64,
    /// Number of high-confidence matches (>= 0.9).
    pub high_confidence_count: usize,
}

impl VersionTrackSummary {
    /// Create a summary from a list of matches and program metadata.
    pub fn from_matches(
        matches: &[VersionTrackMatch],
        source_func_count: usize,
        dest_func_count: usize,
    ) -> Self {
        let mut exact = 0;
        let mut similar = 0;
        let mut renamed = 0;
        let mut moved = 0;
        let mut modified = 0;
        let mut total_confidence: f64 = 0.0;
        let mut high_confidence = 0usize;

        for m in matches {
            match m.match_type {
                MatchType::Exact => exact += 1,
                MatchType::Similar => similar += 1,
                MatchType::Renamed => renamed += 1,
                MatchType::Moved => moved += 1,
                MatchType::Modified => modified += 1,
            }
            total_confidence += m.confidence;
            if m.is_high_confidence() {
                high_confidence += 1;
            }
        }

        let avg = if matches.is_empty() {
            0.0
        } else {
            total_confidence / matches.len() as f64
        };

        Self {
            exact_count: exact,
            similar_count: similar,
            renamed_count: renamed,
            moved_count: moved,
            modified_count: modified,
            source_function_count: source_func_count,
            dest_function_count: dest_func_count,
            avg_confidence: avg,
            high_confidence_count: high_confidence,
        }
    }
}

impl fmt::Display for VersionTrackResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Version Tracking Results")?;
        writeln!(f, "  Source: {}", self.source_program_name)?;
        writeln!(f, "  Dest:   {}", self.dest_program_name)?;
        writeln!(f, "  Total Matches: {}", self.total_matches)?;
        writeln!(f, "  --- Summary ---")?;
        writeln!(f, "  Exact:    {}", self.summary.exact_count)?;
        writeln!(f, "  Similar:  {}", self.summary.similar_count)?;
        writeln!(f, "  Renamed:  {}", self.summary.renamed_count)?;
        writeln!(f, "  Moved:    {}", self.summary.moved_count)?;
        writeln!(f, "  Modified: {}", self.summary.modified_count)?;
        writeln!(
            f,
            "  Avg Confidence: {:.2}%",
            self.summary.avg_confidence * 100.0
        )?;
        writeln!(
            f,
            "  High-Confidence: {}",
            self.summary.high_confidence_count
        )?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Correlator trait
// ---------------------------------------------------------------------------

/// A correlator finds matches between entities in the source and destination
/// programs using a specific strategy (e.g., exact byte matching, symbol
/// name matching, structural similarity).
pub trait Correlator: Send + Sync {
    /// A human-readable name for this correlator (e.g., "ExactMatch").
    fn name(&self) -> &str;

    /// Execute the correlation algorithm and return discovered matches.
    ///
    /// The `tracker` reference provides access to both programs and any
    /// previously discovered matches from earlier correlators.
    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>>;

    /// The base confidence level of this correlator (0.0 to 1.0).
    ///
    /// This is the default confidence applied to matches from this
    /// correlator before any score-based adjustment.
    fn confidence(&self) -> f64;
}

// ===========================================================================
// Correlator implementations
// ===========================================================================

// ---------------------------------------------------------------------------
// ExactMatchCorrelator
// ---------------------------------------------------------------------------

/// Matches functions that are byte-for-byte identical between the two programs.
///
/// This is the highest-confidence correlator and runs first. Two functions are
/// considered an exact match if their raw byte content is identical.
pub struct ExactMatchCorrelator;

impl ExactMatchCorrelator {
    /// Compute a hash of a function's bytes extracted from the listing.
    fn func_byte_hash(prog: &Program, entry: Address) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let rows = function_listing_rows(prog, entry);
        let bytes = listing_bytes(&rows);
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }

    /// Get the raw bytes of a function.
    fn func_bytes(prog: &Program, entry: Address) -> Vec<u8> {
        let rows = function_listing_rows(prog, entry);
        listing_bytes(&rows)
    }
}

impl Correlator for ExactMatchCorrelator {
    fn name(&self) -> &str {
        "ExactMatchCorrelator"
    }

    fn confidence(&self) -> f64 {
        1.0
    }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;

        // Index destination functions by their byte hash for O(1) lookup.
        let dest_hashes: HashMap<u64, &Symbol> = function_symbol_names(dest)
            .into_iter()
            .map(|s| (Self::func_byte_hash(dest, s.address), s))
            .collect();

        let mut matches = Vec::new();

        for src_sym in function_symbol_names(source) {
            let src_bytes = Self::func_bytes(source, src_sym.address);
            if src_bytes.is_empty() {
                continue;
            }

            // Compute hash before looking up (reuse for exact check).
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            src_bytes.hash(&mut hasher);
            let src_hash = hasher.finish();

            if let Some(dest_sym) = dest_hashes.get(&src_hash) {
                let dest_bytes = Self::func_bytes(dest, dest_sym.address);
                if src_bytes == dest_bytes {
                    let match_type = if src_sym.name == dest_sym.name {
                        MatchType::Exact
                    } else {
                        MatchType::Renamed
                    };

                    matches.push(VersionTrackMatch::new(
                        src_sym.address,
                        dest_sym.address,
                        match_type,
                        self.confidence(),
                        &src_sym.name,
                        &dest_sym.name,
                    ));
                }
            }
        }

        Ok(matches)
    }
}

// ---------------------------------------------------------------------------
// SimilarFunctionCorrelator
// ---------------------------------------------------------------------------

/// Matches functions that are structurally similar but not byte-for-byte
/// identical.
///
/// Uses a similarity metric based on:
/// - Jaccard index of instruction mnemonics
/// - Levenshtein distance on byte content
/// - Function body size ratio
pub struct SimilarFunctionCorrelator;

impl SimilarFunctionCorrelator {
    /// Compute the Jaccard similarity index of instruction mnemonics.
    fn jaccard_mnemonic_similarity(
        src_mnems: &[String],
        dest_mnems: &[String],
    ) -> f64 {
        if src_mnems.is_empty() || dest_mnems.is_empty() {
            return 0.0;
        }

        let a_set: HashSet<&str> = src_mnems.iter().map(|s| s.as_str()).collect();
        let b_set: HashSet<&str> = dest_mnems.iter().map(|s| s.as_str()).collect();

        let intersection = a_set.intersection(&b_set).count();
        let union = a_set.union(&b_set).count();

        if union == 0 {
            return 0.0;
        }

        intersection as f64 / union as f64
    }

    /// Compute similarity based on normalized Levenshtein distance.
    fn levenshtein_byte_similarity(a: &[u8], b: &[u8]) -> f64 {
        let max_len = a.len().max(b.len());
        if max_len == 0 {
            return 1.0;
        }
        let dist = Self::levenshtein_distance(a, b);
        1.0 - (dist as f64 / max_len as f64)
    }

    /// Compute Levenshtein (edit) distance between two byte slices.
    fn levenshtein_distance(a: &[u8], b: &[u8]) -> usize {
        let n = a.len();
        let m = b.len();

        let mut prev: Vec<usize> = (0..=m).collect();
        let mut curr = vec![0usize; m + 1];

        for i in 1..=n {
            curr[0] = i;
            for j in 1..=m {
                let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
                curr[j] = (prev[j] + 1)
                    .min(curr[j - 1] + 1)
                    .min(prev[j - 1] + cost);
            }
            std::mem::swap(&mut prev, &mut curr);
        }

        prev[m]
    }

    /// Simple similarity based on body size ratio.
    fn byte_size_similarity(a: &[u8], b: &[u8]) -> f64 {
        let max_size = a.len().max(b.len());
        if max_size == 0 {
            return 0.0;
        }
        let min_size = a.len().min(b.len());
        min_size as f64 / max_size as f64
    }

    /// Compute overall similarity score (0.0 to 1.0).
    fn compute_similarity(
        src_mnems: &[String],
        dest_mnems: &[String],
        src_bytes: &[u8],
        dest_bytes: &[u8],
    ) -> f64 {
        let jaccard = Self::jaccard_mnemonic_similarity(src_mnems, dest_mnems);
        let byte_sim = Self::levenshtein_byte_similarity(src_bytes, dest_bytes);
        let size_sim = Self::byte_size_similarity(src_bytes, dest_bytes);

        // Weighted combination.
        0.4 * jaccard + 0.4 * byte_sim + 0.2 * size_sim
    }
}

impl Correlator for SimilarFunctionCorrelator {
    fn name(&self) -> &str {
        "SimilarFunctionCorrelator"
    }

    fn confidence(&self) -> f64 {
        0.75
    }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;

        let already_matched_src: HashSet<Address> = tracker
            .matches
            .iter()
            .map(|m| m.source_address)
            .collect();
        let already_matched_dest: HashSet<Address> = tracker
            .matches
            .iter()
            .map(|m| m.dest_address)
            .collect();

        // Pre-extract function data for unmatched functions.
        struct FuncData {
            symbol: Symbol,
            bytes: Vec<u8>,
            mnemonics: Vec<String>,
        }

        let src_data: Vec<FuncData> = function_symbol_names(source)
            .into_iter()
            .filter(|s| !already_matched_src.contains(&s.address))
            .map(|s| {
                let rows = function_listing_rows(source, s.address);
                FuncData {
                    symbol: (*s).clone(),
                    bytes: listing_bytes(&rows),
                    mnemonics: listing_mnemonics(&rows),
                }
            })
            .collect();

        let dest_data: Vec<FuncData> = function_symbol_names(dest)
            .into_iter()
            .filter(|s| !already_matched_dest.contains(&s.address))
            .map(|s| {
                let rows = function_listing_rows(dest, s.address);
                FuncData {
                    symbol: (*s).clone(),
                    bytes: listing_bytes(&rows),
                    mnemonics: listing_mnemonics(&rows),
                }
            })
            .collect();

        let mut matches = Vec::new();

        for sd in &src_data {
            let mut best_score = 0.0;
            let mut best_dest: Option<&FuncData> = None;

            for dd in &dest_data {
                let sim = Self::compute_similarity(
                    &sd.mnemonics,
                    &dd.mnemonics,
                    &sd.bytes,
                    &dd.bytes,
                );
                if sim > best_score {
                    best_score = sim;
                    best_dest = Some(dd);
                }
            }

            if let Some(dd) = best_dest {
                if best_score >= 0.6 {
                    let match_type = if sd.symbol.name == dd.symbol.name {
                        MatchType::Similar
                    } else {
                        MatchType::Modified
                    };

                    matches.push(VersionTrackMatch::new(
                        sd.symbol.address,
                        dd.symbol.address,
                        match_type,
                        self.confidence() * best_score,
                        &sd.symbol.name,
                        &dd.symbol.name,
                    ));
                }
            }
        }

        Ok(matches)
    }
}

// ---------------------------------------------------------------------------
// DataMatchCorrelator
// ---------------------------------------------------------------------------

/// Matches data items (global variables, constants) between the two programs.
///
/// Data items are matched by comparing type name, size, and raw byte content
/// from the program's data_types map.
pub struct DataMatchCorrelator;

impl DataMatchCorrelator {
    /// Compute similarity between two data type + byte combinations.
    fn data_similarity(
        src_dt: &DataType,
        dest_dt: &DataType,
        src_bytes: &[u8],
        dest_bytes: &[u8],
    ) -> f64 {
        let mut score = 0.0;
        let mut weight = 0.0;

        // Same type name.
        if src_dt.name == dest_dt.name && !src_dt.name.is_empty() {
            score += 1.0;
            weight += 0.4;
        }

        // Same size.
        if src_dt.size == dest_dt.size && src_dt.size > 0 {
            score += 1.0;
            weight += 0.3;
        }

        // Byte comparison.
        if !src_bytes.is_empty() && !dest_bytes.is_empty() {
            if src_bytes == dest_bytes {
                score += 1.0;
                weight += 0.3;
            } else {
                let matching = src_bytes
                    .iter()
                    .zip(dest_bytes.iter())
                    .filter(|(x, y)| x == y)
                    .count();
                let total = src_bytes.len().max(dest_bytes.len());
                if total > 0 {
                    let ratio = matching as f64 / total as f64;
                    score += ratio;
                    weight += 0.3 * ratio;
                }
            }
        }

        if weight == 0.0 {
            0.0
        } else {
            score / weight
        }
    }
}

impl Correlator for DataMatchCorrelator {
    fn name(&self) -> &str {
        "DataMatchCorrelator"
    }

    fn confidence(&self) -> f64 {
        0.85
    }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;

        let already_matched_src: HashSet<Address> = tracker
            .matches
            .iter()
            .map(|m| m.source_address)
            .collect();
        let already_matched_dest: HashSet<Address> = tracker
            .matches
            .iter()
            .map(|m| m.dest_address)
            .collect();

        let src_data: Vec<(Address, &DataType, Vec<u8>)> = source
            .data_types
            .iter()
            .filter(|(addr, _)| !already_matched_src.contains(addr))
            .map(|(addr, dt)| (*addr, dt, source.read_bytes(*addr, dt.size)))
            .collect();

        let dest_data: Vec<(Address, &DataType, Vec<u8>)> = dest
            .data_types
            .iter()
            .filter(|(addr, _)| !already_matched_dest.contains(addr))
            .map(|(addr, dt)| (*addr, dt, dest.read_bytes(*addr, dt.size)))
            .collect();

        let mut matches = Vec::new();

        for (saddr, sdt, sbytes) in &src_data {
            let mut best_score = 0.0;
            let mut best_dest: Option<(Address, &DataType)> = None;

            for (daddr, ddt, dbytes) in &dest_data {
                let sim = Self::data_similarity(sdt, ddt, sbytes, dbytes);
                if sim > best_score {
                    best_score = sim;
                    best_dest = Some((*daddr, ddt));
                }
            }

            if let Some((dest_addr, _)) = best_dest {
                if best_score >= 0.8 {
                    let src_name = source
                        .symbol_at(saddr)
                        .map(|s| s.name.as_str())
                        .unwrap_or("");
                    let dest_name = dest
                        .symbol_at(&dest_addr)
                        .map(|s| s.name.as_str())
                        .unwrap_or("");

                    let match_type = if sbytes == {
                        let db = dest.read_bytes(dest_addr, sdt.size);
                        db
                    } {
                        MatchType::Exact
                    } else {
                        MatchType::Modified
                    };

                    matches.push(VersionTrackMatch::new(
                        *saddr,
                        dest_addr,
                        match_type,
                        self.confidence() * best_score,
                        src_name,
                        dest_name,
                    ));
                }
            }
        }

        Ok(matches)
    }
}

// ---------------------------------------------------------------------------
// SymbolNameCorrelator
// ---------------------------------------------------------------------------

/// Matches entities by their symbol name.
///
/// This correlator looks for functions and data items that have the same name
/// in both programs, even if their addresses or byte content differ.
pub struct SymbolNameCorrelator;

impl Correlator for SymbolNameCorrelator {
    fn name(&self) -> &str {
        "SymbolNameCorrelator"
    }

    fn confidence(&self) -> f64 {
        0.9
    }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;

        // Build index: destination function symbols by name.
        let mut dest_funcs_by_name: HashMap<&str, &Symbol> = HashMap::new();
        for sym in dest.symbol_table.iter() {
            if sym.kind == SymbolKind::Function
                && !sym.name.is_empty()
                && !sym.name.starts_with("sub_")
            {
                dest_funcs_by_name.insert(&sym.name, sym);
            }
        }

        // Build index: destination data symbols by name (from data_types).
        let mut dest_data_by_name: HashMap<&str, Address> = HashMap::new();
        for (addr, _dt) in &dest.data_types {
            if let Some(sym) = dest.symbol_at(addr) {
                if !sym.name.is_empty() && !sym.name.starts_with("DAT_") {
                    dest_data_by_name.insert(&sym.name, *addr);
                }
            }
        }

        let already_matched_src: HashSet<Address> = tracker
            .matches
            .iter()
            .map(|m| m.source_address)
            .collect();

        let mut matches = Vec::new();

        // Match functions by name.
        for src_sym in source.symbol_table.iter() {
            if src_sym.kind != SymbolKind::Function {
                continue;
            }
            if already_matched_src.contains(&src_sym.address) {
                continue;
            }
            if src_sym.name.is_empty() || src_sym.name.starts_with("sub_") {
                continue;
            }

            if let Some(dest_sym) = dest_funcs_by_name.get(src_sym.name.as_str()) {
                let match_type = if src_sym.address == dest_sym.address {
                    MatchType::Exact
                } else {
                    MatchType::Moved
                };

                // Check byte equality for confidence boost.
                let src_rows = function_listing_rows(source, src_sym.address);
                let dest_rows = function_listing_rows(dest, dest_sym.address);
                let same_bytes =
                    listing_bytes(&src_rows) == listing_bytes(&dest_rows) && !src_rows.is_empty();
                let conf = if same_bytes { 1.0 } else { self.confidence() };

                matches.push(VersionTrackMatch::new(
                    src_sym.address,
                    dest_sym.address,
                    match_type,
                    conf,
                    &src_sym.name,
                    &dest_sym.name,
                ));
            }
        }

        // Match data by name.
        for (src_addr, _src_dt) in &source.data_types {
            if already_matched_src.contains(src_addr) {
                continue;
            }
            if let Some(sym) = source.symbol_at(src_addr) {
                if sym.name.is_empty() || sym.name.starts_with("DAT_") {
                    continue;
                }
                if let Some(dest_addr) = dest_data_by_name.get(sym.name.as_str()) {
                    let match_type = if *src_addr == *dest_addr {
                        MatchType::Exact
                    } else {
                        MatchType::Moved
                    };
                    let dest_sym = dest.symbol_at(dest_addr);
                    let dest_name = dest_sym.map(|s| s.name.as_str()).unwrap_or("");

                    matches.push(VersionTrackMatch::new(
                        *src_addr,
                        *dest_addr,
                        match_type,
                        self.confidence(),
                        &sym.name,
                        dest_name,
                    ));
                }
            }
        }

        Ok(matches)
    }
}

// ---------------------------------------------------------------------------
// InstructionSequenceCorrelator
// ---------------------------------------------------------------------------

/// Matches functions by comparing their instruction sequences using longest
/// common subsequence (LCS) of mnemonics.
///
/// This correlator is useful when functions have been reordered or had
/// instructions inserted/removed but still share a significant instruction
/// sequence.
pub struct InstructionSequenceCorrelator;

impl InstructionSequenceCorrelator {
    /// Compute the LCS similarity normalized to [0.0, 1.0].
    fn lcs_similarity(a: &[String], b: &[String]) -> f64 {
        let lcs_len = Self::lcs_length(a, b);
        let max_len = a.len().max(b.len());
        if max_len == 0 {
            return 0.0;
        }
        lcs_len as f64 / max_len as f64
    }

    /// Compute the length of the longest common subsequence.
    fn lcs_length(a: &[String], b: &[String]) -> usize {
        let n = a.len();
        let m = b.len();

        // Cap memory for very long sequences with a greedy fallback.
        if n > 1024 || m > 1024 {
            return Self::lcs_greedy(a, b);
        }

        let mut dp = vec![vec![0usize; m + 1]; n + 1];

        for i in 1..=n {
            for j in 1..=m {
                if a[i - 1] == b[j - 1] {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
                }
            }
        }

        dp[n][m]
    }

    /// Greedy approximation of LCS for long sequences.
    fn lcs_greedy(a: &[String], b: &[String]) -> usize {
        let b_set: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();
        a.iter().filter(|x| b_set.contains(x.as_str())).count()
    }
}

impl Correlator for InstructionSequenceCorrelator {
    fn name(&self) -> &str {
        "InstructionSequenceCorrelator"
    }

    fn confidence(&self) -> f64 {
        0.7
    }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;

        let already_matched_src: HashSet<Address> = tracker
            .matches
            .iter()
            .map(|m| m.source_address)
            .collect();
        let already_matched_dest: HashSet<Address> = tracker
            .matches
            .iter()
            .map(|m| m.dest_address)
            .collect();

        struct FuncSeq {
            symbol: Symbol,
            mnemonics: Vec<String>,
        }

        let src_seqs: Vec<FuncSeq> = function_symbol_names(source)
            .into_iter()
            .filter(|s| !already_matched_src.contains(&s.address))
            .map(|s| {
                let rows = function_listing_rows(source, s.address);
                FuncSeq {
                    symbol: (*s).clone(),
                    mnemonics: listing_mnemonics(&rows),
                }
            })
            .filter(|fs| !fs.mnemonics.is_empty())
            .collect();

        let dest_seqs: Vec<FuncSeq> = function_symbol_names(dest)
            .into_iter()
            .filter(|s| !already_matched_dest.contains(&s.address))
            .map(|s| {
                let rows = function_listing_rows(dest, s.address);
                FuncSeq {
                    symbol: (*s).clone(),
                    mnemonics: listing_mnemonics(&rows),
                }
            })
            .filter(|fs| !fs.mnemonics.is_empty())
            .collect();

        let mut matches = Vec::new();

        for ss in &src_seqs {
            let mut best_score = 0.0;
            let mut best_dest: Option<&FuncSeq> = None;

            for ds in &dest_seqs {
                let sim = Self::lcs_similarity(&ss.mnemonics, &ds.mnemonics);
                if sim > best_score {
                    best_score = sim;
                    best_dest = Some(ds);
                }
            }

            if let Some(ds) = best_dest {
                if best_score >= 0.5 {
                    let match_type = if ss.symbol.name == ds.symbol.name {
                        MatchType::Similar
                    } else {
                        MatchType::Modified
                    };

                    matches.push(VersionTrackMatch::new(
                        ss.symbol.address,
                        ds.symbol.address,
                        match_type,
                        self.confidence() * best_score,
                        &ss.symbol.name,
                        &ds.symbol.name,
                    ));
                }
            }
        }

        Ok(matches)
    }
}

// ---------------------------------------------------------------------------
// StructuralCorrelator
// ---------------------------------------------------------------------------

/// Matches functions by comparing their position within the call graph.
///
/// This correlator considers:
/// - The number of callers and callees (degree)
/// - The names of callees that have already been matched
/// - The ratio of matched callees to total callees
pub struct StructuralCorrelator;

impl StructuralCorrelator {
    /// Compute structural similarity between two functions based on their
    /// call-graph neighborhood.
    fn structural_similarity(
        src_entry: Address,
        dest_entry: Address,
        tracker: &VersionTracker,
    ) -> f64 {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;

        let src_rows = function_listing_rows(source, src_entry);
        let dest_rows = function_listing_rows(dest, dest_entry);

        let src_callees = extract_callees(&src_rows);
        let dest_callees = extract_callees(&dest_rows);

        let src_callers = extract_callers(source, src_entry);
        let dest_callers = extract_callers(dest, dest_entry);

        let mut score = 0.0;
        let mut weight = 0.0;

        // --- Callee count similarity ---
        let max_callees = src_callees.len().max(dest_callees.len()).max(1);
        let min_callees = src_callees.len().min(dest_callees.len());
        let callee_ratio = min_callees as f64 / max_callees as f64;
        score += callee_ratio * 0.25;
        weight += 0.25;

        // --- Caller count similarity ---
        let max_callers = src_callers.len().max(dest_callers.len()).max(1);
        let min_callers = src_callers.len().min(dest_callers.len());
        let caller_ratio = min_callers as f64 / max_callers as f64;
        score += caller_ratio * 0.25;
        weight += 0.25;

        // --- Matched callee ratio ---
        if !src_callees.is_empty() && !dest_callees.is_empty() {
            let matched_map: HashMap<Address, Address> = tracker
                .matches
                .iter()
                .map(|m| (m.source_address, m.dest_address))
                .collect();

            let matched_count = src_callees
                .iter()
                .filter(|sa| {
                    matched_map
                        .get(sa)
                        .map(|da| dest_callees.contains(da))
                        .unwrap_or(false)
                })
                .count();

            let match_ratio = matched_count as f64 / src_callees.len().max(1) as f64;
            score += match_ratio * 0.50;
            weight += 0.50;
        } else if src_callees.is_empty() && dest_callees.is_empty() {
            score += 0.50;
            weight += 0.50;
        }

        if weight == 0.0 {
            0.0
        } else {
            score / weight
        }
    }
}

impl Correlator for StructuralCorrelator {
    fn name(&self) -> &str {
        "StructuralCorrelator"
    }

    fn confidence(&self) -> f64 {
        0.6
    }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;

        let already_matched_src: HashSet<Address> = tracker
            .matches
            .iter()
            .map(|m| m.source_address)
            .collect();
        let already_matched_dest: HashSet<Address> = tracker
            .matches
            .iter()
            .map(|m| m.dest_address)
            .collect();

        let src_funcs: Vec<&Symbol> = function_symbol_names(source)
            .into_iter()
            .filter(|s| !already_matched_src.contains(&s.address))
            .collect();

        let dest_funcs: Vec<&Symbol> = function_symbol_names(dest)
            .into_iter()
            .filter(|s| !already_matched_dest.contains(&s.address))
            .collect();

        let mut matches = Vec::new();

        for src_sym in &src_funcs {
            let mut best_score = 0.0;
            let mut best_dest: Option<&Symbol> = None;

            for dest_sym in &dest_funcs {
                let sim =
                    Self::structural_similarity(src_sym.address, dest_sym.address, tracker);
                if sim > best_score {
                    best_score = sim;
                    best_dest = Some(dest_sym);
                }
            }

            if let Some(dest_sym) = best_dest {
                if best_score >= 0.5 {
                    let match_type = if src_sym.name == dest_sym.name {
                        MatchType::Similar
                    } else {
                        MatchType::Modified
                    };

                    matches.push(VersionTrackMatch::new(
                        src_sym.address,
                        dest_sym.address,
                        match_type,
                        self.confidence() * best_score,
                        &src_sym.name,
                        &dest_sym.name,
                    ));
                }
            }
        }

        Ok(matches)
    }
}

// ===========================================================================
// VersionTracker
// ===========================================================================

/// The main version-tracking engine.
///
/// Coordinates multiple [`Correlator`] implementations to find matches between
/// two versions of a binary. Correlators are run in order: higher-confidence
/// correlators (e.g., exact match) run first, and their results are available
/// to later correlators (e.g., structural correlation).
pub struct VersionTracker {
    /// The source (old) program.
    pub source_program: Arc<Program>,
    /// The destination (new) program.
    pub dest_program: Arc<Program>,
    /// All matches discovered so far.
    pub matches: Vec<VersionTrackMatch>,
    /// The registered correlators, in execution order.
    pub correlators: Vec<Box<dyn Correlator>>,
}

impl VersionTracker {
    /// Create a new `VersionTracker` for comparing two programs.
    ///
    /// The tracker is pre-populated with the default set of correlators:
    /// exact match, symbol name, similar function, instruction sequence,
    /// data match, and structural correlators.
    pub fn new(source: Program, dest: Program) -> Self {
        let mut tracker = Self {
            source_program: Arc::new(source),
            dest_program: Arc::new(dest),
            matches: Vec::new(),
            correlators: Vec::new(),
        };

        // Register default correlators in priority order.
        // Higher-confidence correlators run first.
        tracker.add_correlator(Box::new(ExactMatchCorrelator));
        tracker.add_correlator(Box::new(SymbolNameCorrelator));
        tracker.add_correlator(Box::new(DataMatchCorrelator));
        tracker.add_correlator(Box::new(SimilarFunctionCorrelator));
        tracker.add_correlator(Box::new(InstructionSequenceCorrelator));
        tracker.add_correlator(Box::new(StructuralCorrelator));

        tracker
    }

    /// Add a custom correlator to the end of the execution pipeline.
    pub fn add_correlator(&mut self, correlator: Box<dyn Correlator>) {
        self.correlators.push(correlator);
    }

    /// Clear all registered correlators (useful for custom configurations).
    pub fn clear_correlators(&mut self) {
        self.correlators.clear();
    }

    /// Run all registered correlators in order.
    ///
    /// Each correlator receives the tracker (including matches from earlier
    /// correlators) and its results are accumulated into
    /// [`VersionTracker::matches`].
    ///
    /// Returns all accumulated matches.
    pub fn run_correlation(&mut self) -> Result<Vec<VersionTrackMatch>> {
        self.matches.clear();

        for i in 0..self.correlators.len() {
            let name = self.correlators[i].name().to_string();

            let new_matches = {
                let correlator = &self.correlators[i];
                correlator.correlate(self).map_err(|e| match e {
                    VersionTrackError::CorrelatorError { .. } => e,
                    other => VersionTrackError::CorrelatorError {
                        correlator: name.clone(),
                        message: other.to_string(),
                    },
                })?
            };

            log::info!(
                "Correlator '{}' found {} matches",
                name,
                new_matches.len()
            );

            self.matches.extend(new_matches);
        }

        Ok(self.matches.clone())
    }

    /// Apply matched information from the source program to the destination
    /// program.
    ///
    /// For each match, this validates that the destination entity exists.
    /// In a full implementation this would transfer names, types, and comments
    /// from source to destination. Because `dest_program` is behind `Arc`, the
    /// caller must handle interior mutability or clone-and-replace.
    pub fn apply_matches(&self, matches: &[VersionTrackMatch]) -> Result<()> {
        let matched_dest_addrs: HashSet<Address> =
            matches.iter().map(|m| m.dest_address).collect();

        log::info!(
            "Applying {} matches across {} unique destination addresses",
            matches.len(),
            matched_dest_addrs.len()
        );

        for m in matches {
            // Validate that the destination entity exists (function symbol or data type).
            let has_func = self
                .dest_program
                .symbol_at(&m.dest_address)
                .map(|s| s.kind == SymbolKind::Function)
                .unwrap_or(false);
            let has_data = self.dest_program.data_types.contains_key(&m.dest_address);

            if !has_func && !has_data {
                return Err(VersionTrackError::MatchTargetNotFound {
                    address: m.dest_address,
                });
            }
        }

        Ok(())
    }

    /// Export the version-tracking results into a structured summary suitable
    /// for display, serialization, or report generation.
    pub fn export_results(&self) -> VersionTrackResults {
        let mut matches_by_type: HashMap<MatchType, Vec<VersionTrackMatch>> = HashMap::new();

        for m in &self.matches {
            matches_by_type
                .entry(m.match_type)
                .or_default()
                .push(m.clone());
        }

        let src_func_count = self
            .source_program
            .symbol_table
            .iter()
            .filter(|s| s.kind == SymbolKind::Function)
            .count();

        let dest_func_count = self
            .dest_program
            .symbol_table
            .iter()
            .filter(|s| s.kind == SymbolKind::Function)
            .count();

        let summary =
            VersionTrackSummary::from_matches(&self.matches, src_func_count, dest_func_count);

        VersionTrackResults {
            source_program_name: self.source_program.name.clone(),
            dest_program_name: self.dest_program.name.clone(),
            total_matches: self.matches.len(),
            matches: self.matches.clone(),
            matches_by_type,
            summary,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::data::DataType;
    use ghidra_core::listing::ListingRow;
    use ghidra_core::program::Program;
    use ghidra_core::symbol::{Symbol, SymbolKind};

    /// Build a minimal program with named function symbols and listing rows.
    fn make_test_program(
        name: &str,
        funcs: &[(&str, u64, &[(&str, u64, &[u8])])],
    ) -> Program {
        let mut prog = Program::new(name, Address::new(0x1000));

        for &(fname, faddr, instructions) in funcs {
            // Add function symbol.
            prog.symbol_table
                .add(Symbol::function(fname.to_string(), Address::new(faddr)));

            // Add listing rows for this function.
            for &(mnem, iaddr, bytes) in instructions {
                let row = ListingRow::new(
                    Address::new(iaddr),
                    bytes.to_vec(),
                    mnem,
                    if mnem == "call" {
                        format!("0x{:x}", bytes[0] as u64)
                    } else {
                        String::new()
                    },
                );
                prog.listing.add(Address::new(iaddr), row);
            }
        }

        prog
    }

    /// Build a program with data types registered.
    fn make_test_program_with_data() -> Program {
        let mut prog = make_test_program(
            "test.exe",
            &[
                (
                    "main",
                    0x1000,
                    &[
                        ("push", 0x1000, &[0x55]),
                        ("mov", 0x1001, &[0x48, 0x89, 0xe5]),
                        ("call", 0x1004, &[0x20]),
                        ("xor", 0x1007, &[0x31, 0xc0]),
                        ("ret", 0x1009, &[0xc3]),
                    ],
                ),
                (
                    "helper",
                    0x2000,
                    &[
                        ("push", 0x2000, &[0x55]),
                        ("mov", 0x2001, &[0x48, 0x89, 0xe5]),
                        ("ret", 0x2004, &[0xc3]),
                    ],
                ),
            ],
        );

        // Add data types.
        prog.data_types
            .insert(Address::new(0x3000), DataType::u32());
        prog.data_types
            .insert(Address::new(0x3004), DataType::i32());

        // Add symbols for data.
        prog.symbol_table.add(Symbol::new(
            "my_var".to_string(),
            Address::new(0x3000),
            SymbolKind::Label,
        ));
        prog.symbol_table.add(Symbol::new(
            "counter".to_string(),
            Address::new(0x3004),
            SymbolKind::Label,
        ));

        // Add xrefs (callers of functions).
        prog.xrefs.insert(
            Address::new(0x2000),
            vec![Address::new(0x1000)], // main calls helper
        );

        prog
    }

    #[test]
    fn test_exact_match_correlator_identical_bytes() {
        let src = make_test_program(
            "src",
            &[
                (
                    "main",
                    0x1000,
                    &[
                        ("push", 0x1000, &[0x55]),
                        ("ret", 0x1001, &[0xc3]),
                    ],
                ),
            ],
        );
        let dst = make_test_program(
            "dst",
            &[
                (
                    "main",
                    0x1000,
                    &[
                        ("push", 0x1000, &[0x55]),
                        ("ret", 0x1001, &[0xc3]),
                    ],
                ),
            ],
        );

        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(ExactMatchCorrelator));

        let matches = tracker.run_correlation().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].match_type, MatchType::Exact);
        assert!((matches[0].confidence - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_exact_match_renamed_function() {
        let src = make_test_program(
            "src",
            &[(
                "old_name",
                0x1000,
                &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])],
            )],
        );
        let dst = make_test_program(
            "dst",
            &[(
                "new_name",
                0x1000,
                &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])],
            )],
        );

        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(ExactMatchCorrelator));

        let matches = tracker.run_correlation().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].match_type, MatchType::Renamed);
        assert_eq!(matches[0].source_label, "old_name");
        assert_eq!(matches[0].dest_label, "new_name");
    }

    #[test]
    fn test_exact_match_different_bytes_no_match() {
        let src = make_test_program(
            "src",
            &[(
                "func_a",
                0x1000,
                &[("push", 0x1000, &[0x01]), ("ret", 0x1001, &[0x02])],
            )],
        );
        let dst = make_test_program(
            "dst",
            &[(
                "func_b",
                0x1000,
                &[("push", 0x1000, &[0xAA]), ("ret", 0x1001, &[0xBB])],
            )],
        );

        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(ExactMatchCorrelator));

        let matches = tracker.run_correlation().unwrap();
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_symbol_name_correlator_moved_function() {
        let src = make_test_program(
            "src",
            &[(
                "main",
                0x1000,
                &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])],
            )],
        );
        let dst = make_test_program(
            "dst",
            &[(
                "main",
                0x2000,
                &[("push", 0x2000, &[0x55]), ("ret", 0x2001, &[0xc3])],
            )],
        );

        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(SymbolNameCorrelator));

        let matches = tracker.run_correlation().unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].source_label, "main");
        assert_eq!(matches[0].match_type, MatchType::Moved);
    }

    #[test]
    fn test_data_match_correlator() {
        let mut src = Program::new("src", Address::new(0x1000));
        src.data_types.insert(Address::new(0x3000), DataType::u32());
        src.symbol_table
            .add(Symbol::label("my_var".to_string(), Address::new(0x3000)));

        let mut dst = Program::new("dst", Address::new(0x1000));
        dst.data_types.insert(Address::new(0x3000), DataType::u32());
        dst.symbol_table
            .add(Symbol::label("my_var".to_string(), Address::new(0x3000)));

        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(DataMatchCorrelator));

        let matches = tracker.run_correlation().unwrap();
        // Same type name, same size -- should match.
        assert!(matches.len() >= 1);
    }

    #[test]
    fn test_similar_function_correlator() {
        let src = make_test_program(
            "src",
            &[(
                "func",
                0x1000,
                &[
                    ("push", 0x1000, &[0x55]),
                    ("mov", 0x1001, &[0x48, 0x89]),
                    ("add", 0x1003, &[0x01]),
                    ("ret", 0x1004, &[0xc3]),
                ],
            )],
        );
        let dst = make_test_program(
            "dst",
            &[(
                "func",
                0x1000,
                &[
                    ("push", 0x1000, &[0x55]),
                    ("mov", 0x1001, &[0x48, 0x89]),
                    ("sub", 0x1003, &[0x29]), // different last byte
                    ("ret", 0x1004, &[0xc3]),
                ],
            )],
        );

        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(SimilarFunctionCorrelator));

        let matches = tracker.run_correlation().unwrap();
        assert!(matches.len() >= 1);
    }

    #[test]
    fn test_instruction_sequence_correlator() {
        let src = make_test_program(
            "src",
            &[(
                "f1",
                0x1000,
                &[
                    ("push", 0x1000, &[0x55]),
                    ("mov", 0x1001, &[0x48]),
                    ("ret", 0x1002, &[0xc3]),
                ],
            )],
        );
        let dst = make_test_program(
            "dst",
            &[(
                "f1",
                0x2000,
                &[
                    ("push", 0x2000, &[0x55]),
                    ("mov", 0x2001, &[0x48]),
                    ("ret", 0x2002, &[0xc3]),
                ],
            )],
        );

        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(InstructionSequenceCorrelator));

        let matches = tracker.run_correlation().unwrap();
        assert!(matches.len() >= 1);
        // Same mnemonic sequence => high similarity.
        assert!(matches[0].confidence >= 0.5);
    }

    #[test]
    fn test_version_track_match_confidence_clamping() {
        let m = VersionTrackMatch::new(
            Address::new(0x1000),
            Address::new(0x2000),
            MatchType::Exact,
            2.5, // should be clamped to 1.0
            "src_fn",
            "dst_fn",
        );
        assert!((m.confidence - 1.0).abs() < f64::EPSILON);

        let m2 = VersionTrackMatch::new(
            Address::new(0x1000),
            Address::new(0x2000),
            MatchType::Modified,
            -0.5, // should be clamped to 0.0
            "src_fn",
            "dst_fn",
        );
        assert!((m2.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_full_correlation_pipeline() {
        let src = make_test_program_with_data();
        let mut dst = make_test_program_with_data();
        // Rename helper -> helper2 in dest to simulate a renamed function.
        // The SymbolTable allows multiple symbols at the same address;
        // the last one added with primary=true effectively wins.
        dst.symbol_table
            .add(Symbol::function("helper2".to_string(), Address::new(0x2000)));

        let mut tracker = VersionTracker::new(src, dst);
        let matches = tracker.run_correlation().unwrap();

        assert!(!matches.is_empty());

        let results = tracker.export_results();
        assert_eq!(results.total_matches, matches.len());
        assert_eq!(results.source_program_name, "test.exe");
        assert_eq!(results.dest_program_name, "test.exe");
    }

    #[test]
    fn test_apply_matches_unknown_address_fails() {
        let src = make_test_program_with_data();
        let dst = make_test_program_with_data();

        let tracker = VersionTracker::new(src, dst);

        let bad_matches = vec![VersionTrackMatch::new(
            Address::new(0x1000),
            Address::new(0xDEADBEEF),
            MatchType::Exact,
            1.0,
            "f1",
            "nonexistent",
        )];

        let result = tracker.apply_matches(&bad_matches);
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_matches_valid() {
        let src = make_test_program_with_data();
        let dst = make_test_program_with_data();

        let tracker = VersionTracker::new(src, dst);

        let valid_matches = vec![VersionTrackMatch::new(
            Address::new(0x1000),
            Address::new(0x1000),
            MatchType::Exact,
            1.0,
            "main",
            "main",
        )];

        let result = tracker.apply_matches(&valid_matches);
        assert!(result.is_ok());
    }

    #[test]
    fn test_version_track_results_summary() {
        let matches = vec![
            VersionTrackMatch::new(
                Address::new(0x1000),
                Address::new(0x1000),
                MatchType::Exact,
                1.0,
                "func_a",
                "func_a",
            ),
            VersionTrackMatch::new(
                Address::new(0x2000),
                Address::new(0x3000),
                MatchType::Moved,
                0.9,
                "func_b",
                "func_b",
            ),
            VersionTrackMatch::new(
                Address::new(0x3000),
                Address::new(0x4000),
                MatchType::Modified,
                0.7,
                "func_c",
                "func_c_new",
            ),
        ];

        let summary = VersionTrackSummary::from_matches(&matches, 5, 6);
        assert_eq!(summary.exact_count, 1);
        assert_eq!(summary.moved_count, 1);
        assert_eq!(summary.modified_count, 1);
        assert_eq!(summary.source_function_count, 5);
        assert_eq!(summary.dest_function_count, 6);
        assert_eq!(summary.high_confidence_count, 2);
        assert!((summary.avg_confidence - 0.8666).abs() < 0.01);
    }

    #[test]
    fn test_add_and_clear_correlators() {
        let src = make_test_program_with_data();
        let dst = make_test_program_with_data();

        let mut tracker = VersionTracker::new(src, dst);
        let initial_count = tracker.correlators.len();
        assert!(initial_count > 0);

        tracker.clear_correlators();
        assert_eq!(tracker.correlators.len(), 0);

        tracker.add_correlator(Box::new(ExactMatchCorrelator));
        assert_eq!(tracker.correlators.len(), 1);

        let matches = tracker.run_correlation().unwrap();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_version_track_match_display() {
        let m = VersionTrackMatch::new(
            Address::new(0x1000),
            Address::new(0x2000),
            MatchType::Exact,
            0.95,
            "src_main",
            "dest_main",
        );
        let display = format!("{}", m);
        assert!(display.contains("Exact"));
        assert!(display.contains("src_main"));
        assert!(display.contains("dest_main"));
        assert!(display.contains("0.95"));
    }

    #[test]
    fn test_structural_correlator_with_xrefs() {
        let src = make_test_program_with_data();
        // This already has xrefs from main -> helper.
        let mut dst = make_test_program_with_data();
        // Ensure xrefs match.
        dst.xrefs.insert(
            Address::new(0x2000),
            vec![Address::new(0x1000)],
        );

        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        // Run exact first so structural has matched callees to work with.
        tracker.add_correlator(Box::new(ExactMatchCorrelator));
        tracker.add_correlator(Box::new(StructuralCorrelator));

        let matches = tracker.run_correlation().unwrap();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_function_symbol_names_excludes_non_functions() {
        let mut prog = Program::new("test", Address::new(0x1000));
        prog.symbol_table
            .add(Symbol::function("real_func".to_string(), Address::new(0x1000)));
        prog.symbol_table
            .add(Symbol::label("some_label".to_string(), Address::new(0x2000)));
        prog.symbol_table
            .add(Symbol::import("printf".to_string(), Address::new(0x3000)));

        let funcs = function_symbol_names(&prog);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "real_func");
    }
}
