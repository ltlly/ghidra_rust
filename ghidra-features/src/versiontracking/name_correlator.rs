//! Name-based function and data correlator.
//!
//! Corresponds to Ghidra's `SymbolNameCorrelatorFactory` and
//! `SimilarSymbolNameCorrelatorFactory` Java classes.
//!
//! This correlator matches functions and data items between two programs
//! based on their symbol names.  Two strategies are supported:
//!
//! - **Exact name match**: functions/data with the same non-default symbol
//!   name in both programs are paired.
//! - **Similar name match**: functions/data whose names share a high degree
//!   of string similarity (Levenshtein-based) are paired.

use std::collections::{HashMap, HashSet};

use ghidra_core::addr::Address;
use ghidra_core::program::Program;
use ghidra_core::symbol::{Symbol, SymbolType};

use crate::versiontracking::error::VtResult;
use crate::versiontracking::helpers::{
    function_listing_rows, function_symbol_names, levenshtein_distance, listing_bytes,
};
use crate::versiontracking::match_set::VtMatchSet;
use crate::versiontracking::options::VtOptions;
use crate::versiontracking::session::VtSession;
use crate::versiontracking::types::{VtAssociationType, VtMatchTag, VtScore};
use crate::versiontracking::vt_correlator::VtProgramCorrelator;

/// Minimum name similarity ratio (0.0-1.0) for similar-name matching.
pub const OPTION_MIN_NAME_SIMILARITY: &str = "Minimum Name Similarity";
/// Default minimum name similarity.
pub const OPTION_MIN_NAME_SIMILARITY_DEFAULT: f64 = 0.8;

/// Whether to include data symbols in correlation.
pub const OPTION_INCLUDE_DATA: &str = "Include Data";
/// Default for including data.
pub const OPTION_INCLUDE_DATA_DEFAULT: bool = true;

/// Whether to skip auto-generated names (sub_*, DAT_*, etc.).
pub const OPTION_SKIP_GENERATED_NAMES: &str = "Skip Generated Names";
/// Default for skipping generated names.
pub const OPTION_SKIP_GENERATED_NAMES_DEFAULT: bool = true;

/// Strategy for name-based correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameStrategy {
    /// Match only when names are exactly equal.
    Exact,
    /// Match when names are similar above a threshold.
    Similar,
}

/// A correlator that matches functions and data items by symbol name.
pub struct NameCorrelator {
    source_program: Program,
    source_address_set: Vec<Address>,
    destination_program: Program,
    destination_address_set: Vec<Address>,
    options: VtOptions,
    strategy: NameStrategy,
}

impl NameCorrelator {
    /// Create a new name correlator with exact matching strategy.
    pub fn new_exact(
        source_program: Program,
        source_address_set: Vec<Address>,
        destination_program: Program,
        destination_address_set: Vec<Address>,
        options: VtOptions,
    ) -> Self {
        Self {
            source_program,
            source_address_set,
            destination_program,
            destination_address_set,
            options,
            strategy: NameStrategy::Exact,
        }
    }

    /// Create a new name correlator with similar matching strategy.
    pub fn new_similar(
        source_program: Program,
        source_address_set: Vec<Address>,
        destination_program: Program,
        destination_address_set: Vec<Address>,
        options: VtOptions,
    ) -> Self {
        Self {
            source_program,
            source_address_set,
            destination_program,
            destination_address_set,
            options,
            strategy: NameStrategy::Similar,
        }
    }

    /// Get the name strategy.
    pub fn strategy(&self) -> NameStrategy {
        self.strategy
    }

    /// Whether a name looks auto-generated.
    fn is_generated_name(name: impl AsRef<str>) -> bool {
        let name = name.as_ref();
        name.starts_with("sub_")
            || name.starts_with("DAT_")
            || name.starts_with("LAB_")
            || name.starts_with("FUN_")
            || name.is_empty()
    }

    /// Compute string similarity using normalized Levenshtein distance.
    fn name_similarity(a: impl AsRef<str>, b: impl AsRef<str>) -> f64 {
        let a = a.as_ref();
        let b = b.as_ref();
        if a == b {
            return 1.0;
        }
        let max_len = a.len().max(b.len());
        if max_len == 0 {
            return 1.0;
        }
        let dist = levenshtein_distance(a.as_bytes(), b.as_bytes());
        1.0 - (dist as f64 / max_len as f64)
    }

    /// Get source symbols filtered by address set.
    fn source_function_symbols(&self) -> Vec<&Symbol> {
        if self.source_address_set.is_empty() {
            function_symbol_names(&self.source_program)
        } else {
            self.source_address_set
                .iter()
                .filter_map(|addr| {
                    self.source_program
                        .symbol_table
                        .iter()
                        .find(|s| s.address() == addr && s.kind() == SymbolType::Function)
                })
                .collect()
        }
    }

    /// Get destination function symbols.
    fn dest_function_symbols(&self) -> Vec<&Symbol> {
        if self.destination_address_set.is_empty() {
            function_symbol_names(&self.destination_program)
        } else {
            self.destination_address_set
                .iter()
                .filter_map(|addr| {
                    self.destination_program
                        .symbol_table
                        .iter()
                        .find(|s| s.address() == addr && s.kind() == SymbolType::Function)
                })
                .collect()
        }
    }

    /// Build a name-to-symbol lookup for destination functions.
    fn dest_function_name_map(&self) -> HashMap<String, &Symbol> {
        let skip_generated = self
            .options
            .get_bool(OPTION_SKIP_GENERATED_NAMES, OPTION_SKIP_GENERATED_NAMES_DEFAULT);
        let mut map = HashMap::new();
        for sym in self.dest_function_symbols() {
            let name = sym.name();
            if skip_generated && Self::is_generated_name(&name) {
                continue;
            }
            map.insert(name, sym);
        }
        map
    }

    /// Build a name-to-address lookup for destination data symbols.
    fn dest_data_name_map(&self) -> HashMap<String, Address> {
        let skip_generated = self
            .options
            .get_bool(OPTION_SKIP_GENERATED_NAMES, OPTION_SKIP_GENERATED_NAMES_DEFAULT);
        let mut map = HashMap::new();
        for (addr, _) in &self.destination_program.data_types {
            if let Some(sym) = self.destination_program.symbol_at(addr) {
                let name = sym.name();
                if skip_generated && Self::is_generated_name(&name) {
                    continue;
                }
                map.insert(name, *addr);
            }
        }
        map
    }

    /// Perform exact function matching.
    fn match_functions_exact(&self) -> Vec<(Address, Address, f64)> {
        let skip_generated = self
            .options
            .get_bool(OPTION_SKIP_GENERATED_NAMES, OPTION_SKIP_GENERATED_NAMES_DEFAULT);
        let dest_map = self.dest_function_name_map();
        let mut results = Vec::new();

        for src_sym in self.source_function_symbols() {
            let src_name = src_sym.name();
            if skip_generated && Self::is_generated_name(&src_name) {
                continue;
            }

            if let Some(dest_sym) = dest_map.get(&src_name) {
                let src_rows = function_listing_rows(&self.source_program, *src_sym.address());
                let dest_rows = function_listing_rows(&self.destination_program, *dest_sym.address());
                let src_bytes = listing_bytes(&src_rows);
                let dest_bytes = listing_bytes(&dest_rows);

                let confidence = if src_bytes == dest_bytes && !src_bytes.is_empty() {
                    1.0
                } else {
                    0.9
                };

                results.push((*src_sym.address(), *dest_sym.address(), confidence));
            }
        }

        results
    }

    /// Perform similar function matching.
    fn match_functions_similar(&self) -> Vec<(Address, Address, f64)> {
        let skip_generated = self
            .options
            .get_bool(OPTION_SKIP_GENERATED_NAMES, OPTION_SKIP_GENERATED_NAMES_DEFAULT);
        let min_similarity = self
            .options
            .get_double(OPTION_MIN_NAME_SIMILARITY, OPTION_MIN_NAME_SIMILARITY_DEFAULT);
        let dest_syms = self.dest_function_symbols();
        let mut results = Vec::new();
        let mut matched_dest: HashSet<Address> = HashSet::new();

        for src_sym in self.source_function_symbols() {
            let src_name = src_sym.name();
            if skip_generated && Self::is_generated_name(&src_name) {
                continue;
            }

            let mut best_sim = 0.0f64;
            let mut best_dest: Option<&Symbol> = None;

            for dest_sym in &dest_syms {
                if matched_dest.contains(dest_sym.address()) {
                    continue;
                }
                let dest_name = dest_sym.name();
                if skip_generated && Self::is_generated_name(&dest_name) {
                    continue;
                }

                let sim = Self::name_similarity(&src_name, &dest_name);
                if sim > best_sim {
                    best_sim = sim;
                    best_dest = Some(dest_sym);
                }
            }

            if let Some(dest_sym) = best_dest {
                if best_sim >= min_similarity {
                    matched_dest.insert(*dest_sym.address());
                    results.push((
                        *src_sym.address(),
                        *dest_sym.address(),
                        best_sim,
                    ));
                }
            }
        }

        results
    }

    /// Perform exact data matching.
    fn match_data_exact(&self) -> Vec<(Address, Address, f64)> {
        let skip_generated = self
            .options
            .get_bool(OPTION_SKIP_GENERATED_NAMES, OPTION_SKIP_GENERATED_NAMES_DEFAULT);
        let include_data = self
            .options
            .get_bool(OPTION_INCLUDE_DATA, OPTION_INCLUDE_DATA_DEFAULT);
        if !include_data {
            return Vec::new();
        }

        let dest_map = self.dest_data_name_map();
        let mut results = Vec::new();

        for (src_addr, _) in &self.source_program.data_types {
            if let Some(sym) = self.source_program.symbol_at(src_addr) {
                let name = sym.name();
                if skip_generated && Self::is_generated_name(&name) {
                    continue;
                }
                if let Some(dest_addr) = dest_map.get(&name) {
                    results.push((*src_addr, *dest_addr, 0.85));
                }
            }
        }

        results
    }
}

impl VtProgramCorrelator for NameCorrelator {
    fn correlate(&self, session: &mut VtSession) -> VtResult<VtMatchSet> {
        let name = match self.strategy {
            NameStrategy::Exact => "Symbol Name Match",
            NameStrategy::Similar => "Similar Symbol Name Match",
        };

        let match_set_id = session.create_match_set(name);
        let mut match_set = VtMatchSet::new(match_set_id, name);

        let func_matches = match self.strategy {
            NameStrategy::Exact => self.match_functions_exact(),
            NameStrategy::Similar => self.match_functions_similar(),
        };

        let data_matches = self.match_data_exact();

        let all_matches: Vec<(Address, Address, f64)> =
            func_matches.into_iter().chain(data_matches).collect();

        let mut match_id = 1u64;
        for (src_addr, dst_addr, confidence) in all_matches {
            let _src_name = self
                .source_program
                .symbol_table
                .iter()
                .find(|s| s.address() == &src_addr)
                .map(|s| s.name())
                .unwrap_or_default();
            let _dst_name = self
                .destination_program
                .symbol_table
                .iter()
                .find(|s| s.address() == &dst_addr)
                .map(|s| s.name())
                .unwrap_or_default();

            let assoc_type = if self
                .source_program
                .data_types
                .contains_key(&src_addr)
            {
                VtAssociationType::Data
            } else {
                VtAssociationType::Function
            };

            let src_len = function_listing_rows(&self.source_program, src_addr).len() as u64;
            let dst_len = function_listing_rows(&self.destination_program, dst_addr).len() as u64;

            let entry = crate::versiontracking::match_set::VtMatch {
                association_id: match_id,
                match_set_id,
                source_address: src_addr,
                destination_address: dst_addr,
                association_type: assoc_type,
                similarity_score: VtScore::new(confidence),
                confidence_score: VtScore::new(confidence),
                source_length: src_len,
                destination_length: dst_len,
                length_type: "instructions".to_string(),
                tag: VtMatchTag::untagged(),
            };
            match_set.add_match(entry);
            match_id += 1;
        }

        log::info!(
            "NameCorrelator ({:?}) found {} matches",
            self.strategy,
            match_set.match_count()
        );

        Ok(match_set)
    }

    fn name(&self) -> &str {
        match self.strategy {
            NameStrategy::Exact => "SymbolNameCorrelator",
            NameStrategy::Similar => "SimilarSymbolNameCorrelator",
        }
    }

    fn options(&self) -> &VtOptions {
        &self.options
    }

    fn source_address_set(&self) -> Vec<Address> {
        self.source_address_set.clone()
    }

    fn destination_address_set(&self) -> Vec<Address> {
        self.destination_address_set.clone()
    }

    fn source_program(&self) -> &Program {
        &self.source_program
    }

    fn destination_program(&self) -> &Program {
        &self.destination_program
    }

    fn description(&self) -> &str {
        match self.strategy {
            NameStrategy::Exact => "Matches functions and data items that have the same symbol name in both programs.",
            NameStrategy::Similar => "Matches functions and data items that have similar symbol names.",
        }
    }
}

impl std::fmt::Debug for NameCorrelator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NameCorrelator")
            .field("strategy", &self.strategy)
            .field("source_program", &self.source_program.name)
            .field("dest_program", &self.destination_program.name)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::listing::ListingRow;
    use ghidra_core::program::program::SimpleDataType;
    use ghidra_core::symbol::Symbol;

    fn addr(v: u64) -> Address {
        Address::new(v)
    }

    fn make_program(
        name: &str,
        funcs: &[(&str, u64, &[(&str, u64, &[u8])])],
    ) -> Program {
        let mut prog = Program::new(name, addr(0x1000));
        for &(fname, faddr, instructions) in funcs {
            prog.symbol_table
                .add(Symbol::function(fname.to_string(), addr(faddr)));
            for &(mnem, iaddr, bytes) in instructions {
                let row = ListingRow::new(
                    addr(iaddr),
                    bytes.to_vec(),
                    mnem,
                    String::new(),
                );
                prog.listing.add(addr(iaddr), row);
            }
        }
        prog
    }

    #[test]
    fn test_exact_name_match_function() {
        let src = make_program(
            "src",
            &[("main", 0x1000, &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])])],
        );
        let dst = make_program(
            "dst",
            &[("main", 0x2000, &[("push", 0x2000, &[0x55]), ("ret", 0x2001, &[0xc3])])],
        );
        let corr = NameCorrelator::new_exact(src, vec![], dst, vec![], VtOptions::new("test"));
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 1);
    }

    #[test]
    fn test_exact_name_match_moved_function() {
        let src = make_program(
            "src",
            &[("main", 0x1000, &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])])],
        );
        let dst = make_program(
            "dst",
            &[("main", 0x3000, &[("push", 0x3000, &[0x55]), ("ret", 0x3001, &[0xc3])])],
        );
        let corr = NameCorrelator::new_exact(src, vec![], dst, vec![], VtOptions::new("test"));
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 1);
        // Same bytes -> 1.0 confidence
        let m = ms.get_matches()[0];
        assert!((m.confidence_score.score() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_exact_name_no_match_different_names() {
        let src = make_program(
            "src",
            &[("foo", 0x1000, &[("ret", 0x1000, &[0xc3])])],
        );
        let dst = make_program(
            "dst",
            &[("bar", 0x2000, &[("ret", 0x2000, &[0xc3])])],
        );
        let corr = NameCorrelator::new_exact(src, vec![], dst, vec![], VtOptions::new("test"));
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 0);
    }

    #[test]
    fn test_exact_name_skips_generated() {
        let src = make_program(
            "src",
            &[("sub_1000", 0x1000, &[("ret", 0x1000, &[0xc3])])],
        );
        let dst = make_program(
            "dst",
            &[("sub_2000", 0x2000, &[("ret", 0x2000, &[0xc3])])],
        );
        let corr = NameCorrelator::new_exact(src, vec![], dst, vec![], VtOptions::new("test"));
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        // sub_* names are skipped by default
        assert_eq!(ms.match_count(), 0);
    }

    #[test]
    fn test_exact_name_include_generated() {
        let src = make_program(
            "src",
            &[("sub_1000", 0x1000, &[("ret", 0x1000, &[0xc3])])],
        );
        let dst = make_program(
            "dst",
            &[("sub_1000", 0x2000, &[("ret", 0x2000, &[0xc3])])],
        );
        let mut opts = VtOptions::new("test");
        opts.set_bool(OPTION_SKIP_GENERATED_NAMES, false);
        let corr = NameCorrelator::new_exact(src, vec![], dst, vec![], opts);
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 1);
    }

    #[test]
    fn test_similar_name_match() {
        let src = make_program(
            "src",
            &[("processData", 0x1000, &[("ret", 0x1000, &[0xc3])])],
        );
        let dst = make_program(
            "dst",
            &[("process_data", 0x2000, &[("ret", 0x2000, &[0xc3])])],
        );
        let corr = NameCorrelator::new_similar(src, vec![], dst, vec![], VtOptions::new("test"));
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 1);
    }

    #[test]
    fn test_similar_name_no_match_too_different() {
        let src = make_program(
            "src",
            &[("aaaa", 0x1000, &[("ret", 0x1000, &[0xc3])])],
        );
        let dst = make_program(
            "dst",
            &[("zzzz", 0x2000, &[("ret", 0x2000, &[0xc3])])],
        );
        let corr = NameCorrelator::new_similar(src, vec![], dst, vec![], VtOptions::new("test"));
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 0);
    }

    #[test]
    fn test_data_match() {
        let mut src = Program::new("src", addr(0x1000));
        src.data_types.insert(addr(0x3000), SimpleDataType::u32());
        src.symbol_table
            .add(Symbol::new("my_var".to_string(), addr(0x3000), SymbolType::Label));
        let mut dst = Program::new("dst", addr(0x1000));
        dst.data_types.insert(addr(0x4000), SimpleDataType::u32());
        dst.symbol_table
            .add(Symbol::new("my_var".to_string(), addr(0x4000), SymbolType::Label));

        let corr = NameCorrelator::new_exact(src, vec![], dst, vec![], VtOptions::new("test"));
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 1);
    }

    #[test]
    fn test_data_match_disabled() {
        let mut src = Program::new("src", addr(0x1000));
        src.data_types.insert(addr(0x3000), SimpleDataType::u32());
        src.symbol_table
            .add(Symbol::new("my_var".to_string(), addr(0x3000), SymbolType::Label));
        let mut dst = Program::new("dst", addr(0x1000));
        dst.data_types.insert(addr(0x4000), SimpleDataType::u32());
        dst.symbol_table
            .add(Symbol::new("my_var".to_string(), addr(0x4000), SymbolType::Label));

        let mut opts = VtOptions::new("test");
        opts.set_bool(OPTION_INCLUDE_DATA, false);
        let corr = NameCorrelator::new_exact(src, vec![], dst, vec![], opts);
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 0);
    }

    #[test]
    fn test_strategy_names() {
        let c1 = NameCorrelator::new_exact(Program::new("s", addr(0)), vec![], Program::new("d", addr(0)), vec![], VtOptions::new("t"));
        assert_eq!(c1.name(), "SymbolNameCorrelator");
        let c2 = NameCorrelator::new_similar(Program::new("s", addr(0)), vec![], Program::new("d", addr(0)), vec![], VtOptions::new("t"));
        assert_eq!(c2.name(), "SimilarSymbolNameCorrelator");
    }

    #[test]
    fn test_strategy_accessor() {
        let src = Program::new("s", addr(0));
        let dst = Program::new("d", addr(0));
        let c = NameCorrelator::new_similar(src, vec![], dst, vec![], VtOptions::new("t"));
        assert_eq!(c.strategy(), NameStrategy::Similar);
    }

    #[test]
    fn test_description() {
        let src = Program::new("s", addr(0));
        let dst = Program::new("d", addr(0));
        let c = NameCorrelator::new_exact(src, vec![], dst, vec![], VtOptions::new("t"));
        assert!(!c.description().is_empty());
    }

    #[test]
    fn test_debug_format() {
        let src = Program::new("s", addr(0));
        let dst = Program::new("d", addr(0));
        let c = NameCorrelator::new_exact(src, vec![], dst, vec![], VtOptions::new("t"));
        let debug = format!("{:?}", c);
        assert!(debug.contains("NameCorrelator"));
    }

    #[test]
    fn test_name_similarity_identical() {
        assert!((NameCorrelator::name_similarity("foo", "foo") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_name_similarity_empty() {
        assert!((NameCorrelator::name_similarity("", "") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_name_similarity_similar() {
        let sim = NameCorrelator::name_similarity("processData", "process_data");
        assert!(sim > 0.8);
    }

    #[test]
    fn test_is_generated_name() {
        assert!(NameCorrelator::is_generated_name("sub_1000"));
        assert!(NameCorrelator::is_generated_name("DAT_2000"));
        assert!(NameCorrelator::is_generated_name("LAB_3000"));
        assert!(NameCorrelator::is_generated_name("FUN_4000"));
        assert!(NameCorrelator::is_generated_name(""));
        assert!(!NameCorrelator::is_generated_name("main"));
        assert!(!NameCorrelator::is_generated_name("process_data"));
    }

    #[test]
    fn test_address_set_filtering() {
        let src = make_program(
            "src",
            &[
                ("main", 0x1000, &[("ret", 0x1000, &[0xc3])]),
                ("helper", 0x2000, &[("ret", 0x2000, &[0xc3])]),
            ],
        );
        let dst = make_program(
            "dst",
            &[
                ("main", 0x3000, &[("ret", 0x3000, &[0xc3])]),
                ("helper", 0x4000, &[("ret", 0x4000, &[0xc3])]),
            ],
        );
        // Only correlate "main" from source
        let corr = NameCorrelator::new_exact(
            src,
            vec![addr(0x1000)],
            dst,
            vec![],
            VtOptions::new("test"),
        );
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 1);
    }

    #[test]
    fn test_multiple_functions() {
        let src = make_program(
            "src",
            &[
                ("alpha", 0x1000, &[("ret", 0x1000, &[0xc3])]),
                ("beta", 0x2000, &[("ret", 0x2000, &[0xc3])]),
                ("gamma", 0x3000, &[("ret", 0x3000, &[0xc3])]),
            ],
        );
        let dst = make_program(
            "dst",
            &[
                ("alpha", 0x4000, &[("ret", 0x4000, &[0xc3])]),
                ("beta", 0x5000, &[("ret", 0x5000, &[0xc3])]),
                ("gamma", 0x6000, &[("ret", 0x6000, &[0xc3])]),
            ],
        );
        let corr = NameCorrelator::new_exact(src, vec![], dst, vec![], VtOptions::new("test"));
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 3);
    }
}
