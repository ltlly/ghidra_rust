//! Version Tracking module for Ghidra Rust.
//!
//! A comprehensive port of Ghidra's Version Tracking feature.
//!
//! # Submodules
//!
//! - [`types`] - Core enums and types
//! - [`error`] - Error types
//! - [`options`] - Correlator options
//! - [`association`] - Associations and manager
//! - [`match_set`] - Match and match set
//! - [`markup`] - Markup items and types
//! - [`session`] - Session container
//! - [`db`] - Database persistence layer (rusqlite)
//! - [`impl_module`] - Implementation details (events, change management)
//! - [`correlator`] - Address and program correlators
//! - [`stringable`] - Value serialization
//! - [`markuptype`] - Markup type definitions
//! - [`helpers`] - Utility functions
//! - [`abstract_vt_correlator`] - Abstract base for VT program correlators
//! - [`vt_correlator`] - VTProgramCorrelator trait and factory
//! - [`vt_match`] - VTMatch trait and implementation
//! - [`vt_match_set`] - VTMatchSet trait and implementation
//! - [`vt_session`] - VTSession trait and implementation
//! - [`vt_match_db`] - Database-backed VTMatch
//! - [`vt_session_db`] - Database-backed VTSession

pub mod abstract_vt_correlator;
pub mod association;
pub mod correlator;
pub mod db;
pub mod error;
pub mod helpers;
pub mod impl_module;
pub mod markup;
pub mod match_set;
pub mod markuptype;
pub mod options;
pub mod session;
pub mod stringable;
pub mod types;
pub mod vt_correlator;
pub mod vt_match;
pub mod vt_match_db;
pub mod vt_match_set;
pub mod vt_session;
pub mod vt_session_db;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use ghidra_core::addr::Address;
use ghidra_core::program::program::SimpleDataType;
use ghidra_core::program::Program;
use ghidra_core::symbol::{Symbol, SymbolType};
use thiserror::Error;

use helpers::{
    extract_callers, extract_callees, function_listing_rows, function_symbol_names,
    listing_bytes, listing_mnemonics,
};

pub use error::VtError;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Error, Debug)]
pub enum VersionTrackError {
    #[error("source program is not set")]
    MissingSourceProgram,
    #[error("destination program is not set")]
    MissingDestProgram,
    #[error("correlator '{correlator}' failed: {message}")]
    CorrelatorError { correlator: String, message: String },
    #[error("match target not found at address {address}")]
    MatchTargetNotFound { address: Address },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VersionTrackError>;

// ---------------------------------------------------------------------------
// Match types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchType {
    Exact,
    Similar,
    Renamed,
    Moved,
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

#[derive(Debug, Clone)]
pub struct VersionTrackMatch {
    pub source_address: Address,
    pub dest_address: Address,
    pub match_type: MatchType,
    pub confidence: f64,
    pub source_label: String,
    pub dest_label: String,
}

impl VersionTrackMatch {
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

    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.9
    }

    pub fn is_exact(&self) -> bool {
        self.match_type == MatchType::Exact
    }
}

impl fmt::Display for VersionTrackMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} ({}) <-> {} ({}) confidence={:.2}",
            self.match_type, self.source_label, self.source_address,
            self.dest_label, self.dest_address, self.confidence
        )
    }
}

// ---------------------------------------------------------------------------
// VersionTrackResults
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct VersionTrackResults {
    pub source_program_name: String,
    pub dest_program_name: String,
    pub total_matches: usize,
    pub matches: Vec<VersionTrackMatch>,
    pub matches_by_type: HashMap<MatchType, Vec<VersionTrackMatch>>,
    pub summary: VersionTrackSummary,
}

#[derive(Debug, Clone)]
pub struct VersionTrackSummary {
    pub exact_count: usize,
    pub similar_count: usize,
    pub renamed_count: usize,
    pub moved_count: usize,
    pub modified_count: usize,
    pub source_function_count: usize,
    pub dest_function_count: usize,
    pub avg_confidence: f64,
    pub high_confidence_count: usize,
}

impl VersionTrackSummary {
    pub fn from_matches(matches: &[VersionTrackMatch], source_func_count: usize, dest_func_count: usize) -> Self {
        let mut exact = 0; let mut similar = 0; let mut renamed = 0;
        let mut moved = 0; let mut modified = 0;
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
            if m.is_high_confidence() { high_confidence += 1; }
        }

        let avg = if matches.is_empty() { 0.0 } else { total_confidence / matches.len() as f64 };

        Self {
            exact_count: exact, similar_count: similar, renamed_count: renamed,
            moved_count: moved, modified_count: modified,
            source_function_count: source_func_count, dest_function_count: dest_func_count,
            avg_confidence: avg, high_confidence_count: high_confidence,
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
        writeln!(f, "  Avg Confidence: {:.2}%", self.summary.avg_confidence * 100.0)?;
        writeln!(f, "  High-Confidence: {}", self.summary.high_confidence_count)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Correlator trait
// ---------------------------------------------------------------------------

pub trait Correlator: Send + Sync {
    fn name(&self) -> &str;
    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>>;
    fn confidence(&self) -> f64;
}

// ===========================================================================
// Correlator implementations
// ===========================================================================

pub struct ExactMatchCorrelator;

impl ExactMatchCorrelator {
    fn func_byte_hash(prog: &Program, entry: Address) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let rows = function_listing_rows(prog, entry);
        let bytes = listing_bytes(&rows);
        let mut hasher = DefaultHasher::new();
        bytes.hash(&mut hasher);
        hasher.finish()
    }

    fn func_bytes(prog: &Program, entry: Address) -> Vec<u8> {
        let rows = function_listing_rows(prog, entry);
        listing_bytes(&rows)
    }
}

impl Correlator for ExactMatchCorrelator {
    fn name(&self) -> &str { "ExactMatchCorrelator" }
    fn confidence(&self) -> f64 { 1.0 }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;

        let dest_hashes: HashMap<u64, &Symbol> = function_symbol_names(dest)
            .into_iter()
            .map(|s| (Self::func_byte_hash(dest, *s.address()), s))
            .collect();

        let mut matches = Vec::new();

        for src_sym in function_symbol_names(source) {
            let src_bytes = Self::func_bytes(source, *src_sym.address());
            if src_bytes.is_empty() { continue; }

            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut hasher = DefaultHasher::new();
            src_bytes.hash(&mut hasher);
            let src_hash = hasher.finish();

            if let Some(dest_sym) = dest_hashes.get(&src_hash) {
                let dest_bytes = Self::func_bytes(dest, *dest_sym.address());
                if src_bytes == dest_bytes {
                    let match_type = if src_sym.name() == dest_sym.name() {
                        MatchType::Exact
                    } else {
                        MatchType::Renamed
                    };
                    matches.push(VersionTrackMatch::new(
                        *src_sym.address(), *dest_sym.address(),
                        match_type, self.confidence(),
                        src_sym.name(), dest_sym.name(),
                    ));
                }
            }
        }
        Ok(matches)
    }
}

pub struct SimilarFunctionCorrelator;

impl SimilarFunctionCorrelator {
    fn jaccard_mnemonic_similarity(src_mnems: &[String], dest_mnems: &[String]) -> f64 {
        helpers::jaccard_mnemonic_similarity(src_mnems, dest_mnems)
    }

    fn levenshtein_byte_similarity(a: &[u8], b: &[u8]) -> f64 {
        let max_len = a.len().max(b.len());
        if max_len == 0 { return 1.0; }
        let dist = helpers::levenshtein_distance(a, b);
        1.0 - (dist as f64 / max_len as f64)
    }

    fn byte_size_similarity(a: &[u8], b: &[u8]) -> f64 {
        let max_size = a.len().max(b.len());
        if max_size == 0 { return 0.0; }
        a.len().min(b.len()) as f64 / max_size as f64
    }

    fn compute_similarity(src_mnems: &[String], dest_mnems: &[String], src_bytes: &[u8], dest_bytes: &[u8]) -> f64 {
        0.4 * Self::jaccard_mnemonic_similarity(src_mnems, dest_mnems)
            + 0.4 * Self::levenshtein_byte_similarity(src_bytes, dest_bytes)
            + 0.2 * Self::byte_size_similarity(src_bytes, dest_bytes)
    }
}

impl Correlator for SimilarFunctionCorrelator {
    fn name(&self) -> &str { "SimilarFunctionCorrelator" }
    fn confidence(&self) -> f64 { 0.75 }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;

        let already_matched_src: HashSet<Address> = tracker.matches.iter().map(|m| m.source_address).collect();
        let already_matched_dest: HashSet<Address> = tracker.matches.iter().map(|m| m.dest_address).collect();

        struct FuncData { symbol: Symbol, bytes: Vec<u8>, mnemonics: Vec<String> }

        let src_data: Vec<FuncData> = function_symbol_names(source)
            .into_iter()
            .filter(|s| !already_matched_src.contains(s.address()))
            .map(|s| {
                let rows = function_listing_rows(source, *s.address());
                FuncData { symbol: s.clone(), bytes: listing_bytes(&rows), mnemonics: listing_mnemonics(&rows) }
            })
            .collect();

        let dest_data: Vec<FuncData> = function_symbol_names(dest)
            .into_iter()
            .filter(|s| !already_matched_dest.contains(s.address()))
            .map(|s| {
                let rows = function_listing_rows(dest, *s.address());
                FuncData { symbol: s.clone(), bytes: listing_bytes(&rows), mnemonics: listing_mnemonics(&rows) }
            })
            .collect();

        let mut matches = Vec::new();

        for sd in &src_data {
            let mut best_score = 0.0;
            let mut best_dest: Option<&FuncData> = None;
            for dd in &dest_data {
                let sim = Self::compute_similarity(&sd.mnemonics, &dd.mnemonics, &sd.bytes, &dd.bytes);
                if sim > best_score { best_score = sim; best_dest = Some(dd); }
            }
            if let Some(dd) = best_dest {
                if best_score >= 0.6 {
                    let match_type = if sd.symbol.name() == dd.symbol.name() { MatchType::Similar } else { MatchType::Modified };
                    matches.push(VersionTrackMatch::new(
                        *sd.symbol.address(), *dd.symbol.address(),
                        match_type, self.confidence() * best_score,
                        sd.symbol.name(), dd.symbol.name(),
                    ));
                }
            }
        }
        Ok(matches)
    }
}

pub struct DataMatchCorrelator;

impl DataMatchCorrelator {
    fn data_similarity(src_dt: &SimpleDataType, dest_dt: &SimpleDataType, src_bytes: &[u8], dest_bytes: &[u8]) -> f64 {
        let mut score = 0.0; let mut weight = 0.0;
        if src_dt.name == dest_dt.name && !src_dt.name.is_empty() { score += 1.0; weight += 0.4; }
        if src_dt.size == dest_dt.size && src_dt.size > 0 { score += 1.0; weight += 0.3; }
        if !src_bytes.is_empty() && !dest_bytes.is_empty() {
            if src_bytes == dest_bytes { score += 1.0; weight += 0.3; }
            else {
                let matching = src_bytes.iter().zip(dest_bytes.iter()).filter(|(x, y)| x == y).count();
                let total = src_bytes.len().max(dest_bytes.len());
                if total > 0 { let ratio = matching as f64 / total as f64; score += ratio; weight += 0.3 * ratio; }
            }
        }
        if weight == 0.0 { 0.0 } else { score / weight }
    }
}

impl Correlator for DataMatchCorrelator {
    fn name(&self) -> &str { "DataMatchCorrelator" }
    fn confidence(&self) -> f64 { 0.85 }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;
        let already_matched_src: HashSet<Address> = tracker.matches.iter().map(|m| m.source_address).collect();
        let already_matched_dest: HashSet<Address> = tracker.matches.iter().map(|m| m.dest_address).collect();

        let src_data: Vec<(Address, &SimpleDataType, Vec<u8>)> = source.data_types.iter()
            .filter(|(addr, _)| !already_matched_src.contains(addr))
            .map(|(addr, dt)| (*addr, dt, source.read_bytes(*addr, dt.size)))
            .collect();

        let dest_data: Vec<(Address, &SimpleDataType, Vec<u8>)> = dest.data_types.iter()
            .filter(|(addr, _)| !already_matched_dest.contains(addr))
            .map(|(addr, dt)| (*addr, dt, dest.read_bytes(*addr, dt.size)))
            .collect();

        let mut matches = Vec::new();
        for (saddr, sdt, sbytes) in &src_data {
            let mut best_score = 0.0;
            let mut best_dest: Option<(Address, &SimpleDataType)> = None;
            for (daddr, ddt, dbytes) in &dest_data {
                let sim = Self::data_similarity(sdt, ddt, sbytes, dbytes);
                if sim > best_score { best_score = sim; best_dest = Some((*daddr, ddt)); }
            }
            if let Some((dest_addr, _)) = best_dest {
                if best_score >= 0.8 {
                    let src_name = source.symbol_at(saddr).map(|s| s.name()).unwrap_or_default();
                    let dest_name = dest.symbol_at(&dest_addr).map(|s| s.name()).unwrap_or_default();
                    let match_type = if *sbytes == dest.read_bytes(dest_addr, sdt.size) { MatchType::Exact } else { MatchType::Modified };
                    matches.push(VersionTrackMatch::new(
                        *saddr, dest_addr, match_type, self.confidence() * best_score,
                        src_name, dest_name,
                    ));
                }
            }
        }
        Ok(matches)
    }
}

pub struct SymbolNameCorrelator;

impl Correlator for SymbolNameCorrelator {
    fn name(&self) -> &str { "SymbolNameCorrelator" }
    fn confidence(&self) -> f64 { 0.9 }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;

        let mut dest_funcs_by_name: HashMap<String, &Symbol> = HashMap::new();
        for sym in dest.symbol_table.iter() {
            if sym.kind() == SymbolType::Function && !sym.name().is_empty() && !sym.name().starts_with("sub_") {
                dest_funcs_by_name.insert(sym.name(), sym);
            }
        }

        let mut dest_data_by_name: HashMap<String, Address> = HashMap::new();
        for (addr, _dt) in &dest.data_types {
            if let Some(sym) = dest.symbol_at(addr) {
                if !sym.name().is_empty() && !sym.name().starts_with("DAT_") {
                    dest_data_by_name.insert(sym.name(), *addr);
                }
            }
        }

        let already_matched_src: HashSet<Address> = tracker.matches.iter().map(|m| m.source_address).collect();
        let mut matches = Vec::new();

        for src_sym in source.symbol_table.iter() {
            if src_sym.kind() != SymbolType::Function { continue; }
            if already_matched_src.contains(src_sym.address()) { continue; }
            if src_sym.name().is_empty() || src_sym.name().starts_with("sub_") { continue; }

            if let Some(dest_sym) = dest_funcs_by_name.get(&src_sym.name()) {
                let match_type = if src_sym.address() == dest_sym.address() { MatchType::Exact } else { MatchType::Moved };
                let src_rows = function_listing_rows(source, *src_sym.address());
                let dest_rows = function_listing_rows(dest, *dest_sym.address());
                let same_bytes = listing_bytes(&src_rows) == listing_bytes(&dest_rows) && !src_rows.is_empty();
                let conf = if same_bytes { 1.0 } else { self.confidence() };
                matches.push(VersionTrackMatch::new(
                    *src_sym.address(), *dest_sym.address(), match_type, conf,
                    src_sym.name(), dest_sym.name(),
                ));
            }
        }

        for (src_addr, _src_dt) in &source.data_types {
            if already_matched_src.contains(src_addr) { continue; }
            if let Some(sym) = source.symbol_at(src_addr) {
                if sym.name().is_empty() || sym.name().starts_with("DAT_") { continue; }
                if let Some(dest_addr) = dest_data_by_name.get(&sym.name()) {
                    let match_type = if *src_addr == *dest_addr { MatchType::Exact } else { MatchType::Moved };
                    let dest_name = dest.symbol_at(dest_addr).map(|s| s.name()).unwrap_or_default();
                    matches.push(VersionTrackMatch::new(*src_addr, *dest_addr, match_type, self.confidence(), sym.name(), dest_name));
                }
            }
        }
        Ok(matches)
    }
}

pub struct InstructionSequenceCorrelator;

impl InstructionSequenceCorrelator {
    fn lcs_similarity(a: &[String], b: &[String]) -> f64 {
        let lcs_len = helpers::lcs_length(a, b);
        let max_len = a.len().max(b.len());
        if max_len == 0 { return 0.0; }
        lcs_len as f64 / max_len as f64
    }
}

impl Correlator for InstructionSequenceCorrelator {
    fn name(&self) -> &str { "InstructionSequenceCorrelator" }
    fn confidence(&self) -> f64 { 0.7 }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;
        let already_matched_src: HashSet<Address> = tracker.matches.iter().map(|m| m.source_address).collect();
        let already_matched_dest: HashSet<Address> = tracker.matches.iter().map(|m| m.dest_address).collect();

        struct FuncSeq { symbol: Symbol, mnemonics: Vec<String> }

        let src_seqs: Vec<FuncSeq> = function_symbol_names(source).into_iter()
            .filter(|s| !already_matched_src.contains(s.address()))
            .map(|s| { let rows = function_listing_rows(source, *s.address()); FuncSeq { symbol: (*s).clone(), mnemonics: listing_mnemonics(&rows) } })
            .filter(|fs| !fs.mnemonics.is_empty()).collect();

        let dest_seqs: Vec<FuncSeq> = function_symbol_names(dest).into_iter()
            .filter(|s| !already_matched_dest.contains(s.address()))
            .map(|s| { let rows = function_listing_rows(dest, *s.address()); FuncSeq { symbol: (*s).clone(), mnemonics: listing_mnemonics(&rows) } })
            .filter(|fs| !fs.mnemonics.is_empty()).collect();

        let mut matches = Vec::new();
        for ss in &src_seqs {
            let mut best_score = 0.0; let mut best_dest: Option<&FuncSeq> = None;
            for ds in &dest_seqs {
                let sim = Self::lcs_similarity(&ss.mnemonics, &ds.mnemonics);
                if sim > best_score { best_score = sim; best_dest = Some(ds); }
            }
            if let Some(ds) = best_dest {
                if best_score >= 0.5 {
                    let match_type = if ss.symbol.name() == ds.symbol.name() { MatchType::Similar } else { MatchType::Modified };
                    matches.push(VersionTrackMatch::new(
                        *ss.symbol.address(), *ds.symbol.address(),
                        match_type, self.confidence() * best_score,
                        ss.symbol.name(), ds.symbol.name(),
                    ));
                }
            }
        }
        Ok(matches)
    }
}

pub struct StructuralCorrelator;

impl StructuralCorrelator {
    fn structural_similarity(src_entry: Address, dest_entry: Address, tracker: &VersionTracker) -> f64 {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;
        let src_rows = function_listing_rows(source, src_entry);
        let dest_rows = function_listing_rows(dest, dest_entry);
        let src_callees = extract_callees(&src_rows);
        let dest_callees = extract_callees(&dest_rows);
        let src_callers = extract_callers(source, src_entry);
        let dest_callers = extract_callers(dest, dest_entry);
        let mut score = 0.0; let mut weight = 0.0;

        let max_callees = src_callees.len().max(dest_callees.len()).max(1);
        score += src_callees.len().min(dest_callees.len()) as f64 / max_callees as f64 * 0.25;
        weight += 0.25;

        let max_callers = src_callers.len().max(dest_callers.len()).max(1);
        score += src_callers.len().min(dest_callers.len()) as f64 / max_callers as f64 * 0.25;
        weight += 0.25;

        if !src_callees.is_empty() && !dest_callees.is_empty() {
            let matched_map: HashMap<Address, Address> = tracker.matches.iter().map(|m| (m.source_address, m.dest_address)).collect();
            let matched_count = src_callees.iter().filter(|sa| matched_map.get(sa).map(|da| dest_callees.contains(da)).unwrap_or(false)).count();
            score += matched_count as f64 / src_callees.len().max(1) as f64 * 0.50;
            weight += 0.50;
        } else if src_callees.is_empty() && dest_callees.is_empty() {
            score += 0.50; weight += 0.50;
        }

        if weight == 0.0 { 0.0 } else { score / weight }
    }
}

impl Correlator for StructuralCorrelator {
    fn name(&self) -> &str { "StructuralCorrelator" }
    fn confidence(&self) -> f64 { 0.6 }

    fn correlate(&self, tracker: &VersionTracker) -> Result<Vec<VersionTrackMatch>> {
        let source = &tracker.source_program;
        let dest = &tracker.dest_program;
        let already_matched_src: HashSet<Address> = tracker.matches.iter().map(|m| m.source_address).collect();
        let already_matched_dest: HashSet<Address> = tracker.matches.iter().map(|m| m.dest_address).collect();

        let src_funcs: Vec<&Symbol> = function_symbol_names(source).into_iter().filter(|s| !already_matched_src.contains(s.address())).collect();
        let dest_funcs: Vec<&Symbol> = function_symbol_names(dest).into_iter().filter(|s| !already_matched_dest.contains(s.address())).collect();

        let mut matches = Vec::new();
        for src_sym in &src_funcs {
            let mut best_score = 0.0; let mut best_dest: Option<&Symbol> = None;
            for dest_sym in &dest_funcs {
                let sim = Self::structural_similarity(*src_sym.address(), *dest_sym.address(), tracker);
                if sim > best_score { best_score = sim; best_dest = Some(dest_sym); }
            }
            if let Some(dest_sym) = best_dest {
                if best_score >= 0.5 {
                    let match_type = if src_sym.name() == dest_sym.name() { MatchType::Similar } else { MatchType::Modified };
                    matches.push(VersionTrackMatch::new(
                        *src_sym.address(), *dest_sym.address(),
                        match_type, self.confidence() * best_score,
                        src_sym.name(), dest_sym.name(),
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

pub struct VersionTracker {
    pub source_program: Arc<Program>,
    pub dest_program: Arc<Program>,
    pub matches: Vec<VersionTrackMatch>,
    pub correlators: Vec<Box<dyn Correlator>>,
}

impl VersionTracker {
    pub fn new(source: Program, dest: Program) -> Self {
        let mut tracker = Self {
            source_program: Arc::new(source),
            dest_program: Arc::new(dest),
            matches: Vec::new(),
            correlators: Vec::new(),
        };
        tracker.add_correlator(Box::new(ExactMatchCorrelator));
        tracker.add_correlator(Box::new(SymbolNameCorrelator));
        tracker.add_correlator(Box::new(DataMatchCorrelator));
        tracker.add_correlator(Box::new(SimilarFunctionCorrelator));
        tracker.add_correlator(Box::new(InstructionSequenceCorrelator));
        tracker.add_correlator(Box::new(StructuralCorrelator));
        tracker
    }

    pub fn add_correlator(&mut self, correlator: Box<dyn Correlator>) {
        self.correlators.push(correlator);
    }

    pub fn clear_correlators(&mut self) {
        self.correlators.clear();
    }

    pub fn run_correlation(&mut self) -> Result<Vec<VersionTrackMatch>> {
        self.matches.clear();
        for i in 0..self.correlators.len() {
            let name = self.correlators[i].name().to_string();
            let new_matches = {
                let correlator = &self.correlators[i];
                correlator.correlate(self).map_err(|e| match e {
                    VersionTrackError::CorrelatorError { .. } => e,
                    other => VersionTrackError::CorrelatorError { correlator: name.clone(), message: other.to_string() },
                })?
            };
            log::info!("Correlator '{}' found {} matches", name, new_matches.len());
            self.matches.extend(new_matches);
        }
        Ok(self.matches.clone())
    }

    pub fn apply_matches(&self, matches: &[VersionTrackMatch]) -> Result<()> {
        let matched_dest_addrs: HashSet<Address> = matches.iter().map(|m| m.dest_address).collect();
        log::info!("Applying {} matches across {} unique destination addresses", matches.len(), matched_dest_addrs.len());
        for m in matches {
            let has_func = self.dest_program.symbol_at(&m.dest_address)
                .map(|s| s.kind() == SymbolType::Function).unwrap_or(false);
            let has_data = self.dest_program.data_types.contains_key(&m.dest_address);
            if !has_func && !has_data {
                return Err(VersionTrackError::MatchTargetNotFound { address: m.dest_address });
            }
        }
        Ok(())
    }

    pub fn export_results(&self) -> VersionTrackResults {
        let mut matches_by_type: HashMap<MatchType, Vec<VersionTrackMatch>> = HashMap::new();
        for m in &self.matches { matches_by_type.entry(m.match_type).or_default().push(m.clone()); }
        let src_func_count = self.source_program.symbol_table.iter().filter(|s| s.kind() == SymbolType::Function).count();
        let dest_func_count = self.dest_program.symbol_table.iter().filter(|s| s.kind() == SymbolType::Function).count();
        let summary = VersionTrackSummary::from_matches(&self.matches, src_func_count, dest_func_count);
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
    use ghidra_core::listing::ListingRow;
    use ghidra_core::program::program::SimpleDataType;
    use ghidra_core::program::Program;
    use ghidra_core::symbol::{Symbol, SymbolType};

    fn make_test_program(name: &str, funcs: &[(&str, u64, &[(&str, u64, &[u8])])]) -> Program {
        let mut prog = Program::new(name, Address::new(0x1000));
        for &(fname, faddr, instructions) in funcs {
            prog.symbol_table.add(Symbol::function(fname.to_string(), Address::new(faddr)));
            for &(mnem, iaddr, bytes) in instructions {
                let row = ListingRow::new(Address::new(iaddr), bytes.to_vec(), mnem,
                    if mnem == "call" { format!("0x{:x}", bytes[0] as u64) } else { String::new() });
                prog.listing.add(Address::new(iaddr), row);
            }
        }
        prog
    }

    fn make_test_program_with_data() -> Program {
        let mut prog = make_test_program("test.exe", &[
            ("main", 0x1000, &[("push", 0x1000, &[0x55]), ("mov", 0x1001, &[0x48, 0x89, 0xe5]),
                ("call", 0x1004, &[0x20]), ("xor", 0x1007, &[0x31, 0xc0]), ("ret", 0x1009, &[0xc3])]),
            ("helper", 0x2000, &[("push", 0x2000, &[0x55]), ("mov", 0x2001, &[0x48, 0x89, 0xe5]),
                ("ret", 0x2004, &[0xc3])]),
        ]);
        prog.data_types.insert(Address::new(0x3000), SimpleDataType::u32());
        prog.data_types.insert(Address::new(0x3004), SimpleDataType::i32());
        prog.symbol_table.add(Symbol::new("my_var".to_string(), Address::new(0x3000), SymbolType::Label));
        prog.symbol_table.add(Symbol::new("counter".to_string(), Address::new(0x3004), SymbolType::Label));
        prog.xrefs.insert(Address::new(0x2000), vec![Address::new(0x1000)]);
        prog
    }

    #[test]
    fn test_exact_match_correlator_identical_bytes() {
        let src = make_test_program("src", &[("main", 0x1000, &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])])]);
        let dst = make_test_program("dst", &[("main", 0x1000, &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])])]);
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
        let src = make_test_program("src", &[("old_name", 0x1000, &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])])]);
        let dst = make_test_program("dst", &[("new_name", 0x1000, &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])])]);
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
        let src = make_test_program("src", &[("func_a", 0x1000, &[("push", 0x1000, &[0x01]), ("ret", 0x1001, &[0x02])])]);
        let dst = make_test_program("dst", &[("func_b", 0x1000, &[("push", 0x1000, &[0xAA]), ("ret", 0x1001, &[0xBB])])]);
        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(ExactMatchCorrelator));
        let matches = tracker.run_correlation().unwrap();
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_symbol_name_correlator_moved_function() {
        let src = make_test_program("src", &[("main", 0x1000, &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])])]);
        let dst = make_test_program("dst", &[("main", 0x2000, &[("push", 0x2000, &[0x55]), ("ret", 0x2001, &[0xc3])])]);
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
        src.data_types.insert(Address::new(0x3000), SimpleDataType::u32());
        src.symbol_table.add(Symbol::label("my_var".to_string(), Address::new(0x3000)));
        let mut dst = Program::new("dst", Address::new(0x1000));
        dst.data_types.insert(Address::new(0x3000), SimpleDataType::u32());
        dst.symbol_table.add(Symbol::label("my_var".to_string(), Address::new(0x3000)));
        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(DataMatchCorrelator));
        let matches = tracker.run_correlation().unwrap();
        assert!(matches.len() >= 1);
    }

    #[test]
    fn test_similar_function_correlator() {
        let src = make_test_program("src", &[("func", 0x1000, &[("push", 0x1000, &[0x55]), ("mov", 0x1001, &[0x48, 0x89]), ("add", 0x1003, &[0x01]), ("ret", 0x1004, &[0xc3])])]);
        let dst = make_test_program("dst", &[("func", 0x1000, &[("push", 0x1000, &[0x55]), ("mov", 0x1001, &[0x48, 0x89]), ("sub", 0x1003, &[0x29]), ("ret", 0x1004, &[0xc3])])]);
        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(SimilarFunctionCorrelator));
        let matches = tracker.run_correlation().unwrap();
        assert!(matches.len() >= 1);
    }

    #[test]
    fn test_instruction_sequence_correlator() {
        let src = make_test_program("src", &[("f1", 0x1000, &[("push", 0x1000, &[0x55]), ("mov", 0x1001, &[0x48]), ("ret", 0x1002, &[0xc3])])]);
        let dst = make_test_program("dst", &[("f1", 0x2000, &[("push", 0x2000, &[0x55]), ("mov", 0x2001, &[0x48]), ("ret", 0x2002, &[0xc3])])]);
        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(InstructionSequenceCorrelator));
        let matches = tracker.run_correlation().unwrap();
        assert!(matches.len() >= 1);
        assert!(matches[0].confidence >= 0.5);
    }

    #[test]
    fn test_version_track_match_confidence_clamping() {
        let m = VersionTrackMatch::new(Address::new(0x1000), Address::new(0x2000), MatchType::Exact, 2.5, "src_fn", "dst_fn");
        assert!((m.confidence - 1.0).abs() < f64::EPSILON);
        let m2 = VersionTrackMatch::new(Address::new(0x1000), Address::new(0x2000), MatchType::Modified, -0.5, "src_fn", "dst_fn");
        assert!((m2.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_full_correlation_pipeline() {
        let src = make_test_program_with_data();
        let mut dst = make_test_program_with_data();
        dst.symbol_table.add(Symbol::function("helper2".to_string(), Address::new(0x2000)));
        let mut tracker = VersionTracker::new(src, dst);
        let matches = tracker.run_correlation().unwrap();
        assert!(!matches.is_empty());
        let results = tracker.export_results();
        assert_eq!(results.total_matches, matches.len());
        assert_eq!(results.source_program_name, "test.exe");
    }

    #[test]
    fn test_apply_matches_unknown_address_fails() {
        let src = make_test_program_with_data();
        let dst = make_test_program_with_data();
        let tracker = VersionTracker::new(src, dst);
        let bad_matches = vec![VersionTrackMatch::new(Address::new(0x1000), Address::new(0xDEADBEEF), MatchType::Exact, 1.0, "f1", "nonexistent")];
        assert!(tracker.apply_matches(&bad_matches).is_err());
    }

    #[test]
    fn test_apply_matches_valid() {
        let src = make_test_program_with_data();
        let dst = make_test_program_with_data();
        let tracker = VersionTracker::new(src, dst);
        let valid_matches = vec![VersionTrackMatch::new(Address::new(0x1000), Address::new(0x1000), MatchType::Exact, 1.0, "main", "main")];
        assert!(tracker.apply_matches(&valid_matches).is_ok());
    }

    #[test]
    fn test_version_track_results_summary() {
        let matches = vec![
            VersionTrackMatch::new(Address::new(0x1000), Address::new(0x1000), MatchType::Exact, 1.0, "func_a", "func_a"),
            VersionTrackMatch::new(Address::new(0x2000), Address::new(0x3000), MatchType::Moved, 0.9, "func_b", "func_b"),
            VersionTrackMatch::new(Address::new(0x3000), Address::new(0x4000), MatchType::Modified, 0.7, "func_c", "func_c_new"),
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
        let m = VersionTrackMatch::new(Address::new(0x1000), Address::new(0x2000), MatchType::Exact, 0.95, "src_main", "dest_main");
        let display = format!("{}", m);
        assert!(display.contains("Exact"));
        assert!(display.contains("src_main"));
        assert!(display.contains("0.95"));
    }

    #[test]
    fn test_structural_correlator_with_xrefs() {
        let src = make_test_program_with_data();
        let mut dst = make_test_program_with_data();
        dst.xrefs.insert(Address::new(0x2000), vec![Address::new(0x1000)]);
        let mut tracker = VersionTracker::new(src, dst);
        tracker.clear_correlators();
        tracker.add_correlator(Box::new(ExactMatchCorrelator));
        tracker.add_correlator(Box::new(StructuralCorrelator));
        let matches = tracker.run_correlation().unwrap();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_function_symbol_names_excludes_non_functions() {
        let mut prog = Program::new("test", Address::new(0x1000));
        prog.symbol_table.add(Symbol::function("real_func".to_string(), Address::new(0x1000)));
        prog.symbol_table.add(Symbol::label("some_label".to_string(), Address::new(0x2000)));
        prog.symbol_table.add(Symbol::import("printf".to_string(), Address::new(0x3000)));
        let funcs = function_symbol_names(&prog);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name(), "real_func");
    }

    #[test]
    fn test_submodules_accessible() {
        let _ = types::VtAssociationType::Function;
        let _ = error::VtError::MissingSourceProgram;
        let _ = options::VtOptions::new("test");
        let _ = markup::MarkupType::FunctionName;
        let _ = markup::VtMarkupItem::new(1, markup::MarkupType::Label, Address::new(0x1000));
        let _ = match_set::VtMatchSet::new(1, "test");
        let _ = types::VtMatchTag::new("test");
        let _ = types::VtScore::new(0.95);
    }

    #[test]
    fn test_session_via_submodule() {
        let src = Program::new("src", Address::new(0x1000));
        let dst = Program::new("dst", Address::new(0x2000));
        let mut session = session::VtSession::new("test.vt", src, dst);
        assert_eq!(session.name(), "test.vt");
        let _ = session.create_match_set("ExactMatch");
        assert_eq!(session.match_sets().len(), 1);
    }

    #[test]
    fn test_association_via_submodule() {
        let mut assoc = association::VtAssociation::new(1, types::VtAssociationType::Function, Address::new(0x1000), Address::new(0x2000));
        assert_eq!(assoc.status(), types::VtAssociationStatus::Available);
        assoc.set_accepted().unwrap();
        assert_eq!(assoc.status(), types::VtAssociationStatus::Accepted);
    }

    #[test]
    fn test_correlator_factories() {
        let factories = correlator::program::all_correlator_factories();
        assert_eq!(factories.len(), 15);
        assert_eq!(factories[0].name(), "Symbol Name Match");
    }

    #[test]
    fn test_address_correlators() {
        use correlator::address::*;
        let exact = ExactMatchAddressCorrelator::new();
        assert_eq!(exact.name(), "ExactMatchAddressCorrelator");
        let linear = LinearAddressCorrelator::new();
        assert_eq!(linear.name(), "LinearAddressCorrelator");
    }

    #[test]
    fn test_stringable_roundtrip() {
        let s = markup::Stringable::FunctionName("main".to_string());
        let storage = s.to_storage_string();
        let restored = markup::Stringable::from_storage_string(&storage).unwrap();
        assert_eq!(s, restored);
    }

    #[test]
    fn test_markup_type_factory() {
        let mt = markup::VtMarkupTypeFactory::get_markup_type(13);
        assert_eq!(mt, Some(markup::MarkupType::FunctionName));
    }

    #[test]
    fn test_helpers() {
        use helpers::*;
        let dist = levenshtein_distance(b"kitten", b"sitting");
        assert_eq!(dist, 3);
        let a = vec!["push".to_string(), "mov".to_string()];
        let b = vec!["push".to_string(), "add".to_string()];
        let sim = jaccard_mnemonic_similarity(&a, &b);
        assert!((sim - 1.0/3.0).abs() < 0.01);
    }
}
