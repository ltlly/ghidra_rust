//! Hash-based function correlator.
//!
//! Corresponds to Ghidra's `ExactMatchBytesCorrelatorFactory` and related
//! hash-match program correlators.
//!
//! This correlator hashes the byte content (and optionally instruction
//! mnemonics) of each function in both programs, then matches functions
//! whose hashes collide.  When the bytes are verified to be identical, the
//! match confidence is 1.0.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use ghidra_core::addr::Address;
use ghidra_core::program::Program;
use ghidra_core::symbol::{Symbol, SymbolType};

use crate::versiontracking::error::{VtError, VtResult};
use crate::versiontracking::helpers::{
    function_listing_rows, function_symbol_names, listing_bytes, listing_mnemonics,
};
use crate::versiontracking::match_set::VtMatchSet;
use crate::versiontracking::options::VtOptions;
use crate::versiontracking::session::VtSession;
use crate::versiontracking::types::{VtAssociationType, VtScore};
use crate::versiontracking::vt_correlator::VtProgramCorrelator;

/// Minimum function size (in bytes) for hash correlation.
pub const OPTION_FUNCTION_MINIMUM_SIZE: &str = "Function Minimum Size";
/// Default minimum function size.
pub const OPTION_FUNCTION_MINIMUM_SIZE_DEFAULT: i64 = 10;

/// Strategy for hashing functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashStrategy {
    /// Hash raw bytes.
    Bytes,
    /// Hash instruction mnemonics only.
    Mnemonics,
    /// Hash bytes then fall back to mnemonics for unmatched functions.
    BytesThenMnemonics,
}

/// A correlator that matches functions by hashing their contents.
pub struct HashCorrelator {
    source_program: Program,
    source_address_set: Vec<Address>,
    destination_program: Program,
    destination_address_set: Vec<Address>,
    options: VtOptions,
    strategy: HashStrategy,
}

impl HashCorrelator {
    /// Create a new hash correlator with the Bytes strategy.
    pub fn new_bytes(
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
            strategy: HashStrategy::Bytes,
        }
    }

    /// Create a new hash correlator with the Mnemonics strategy.
    pub fn new_mnemonics(
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
            strategy: HashStrategy::Mnemonics,
        }
    }

    /// Create a new hash correlator with the BytesThenMnemonics strategy.
    pub fn new_bytes_then_mnemonics(
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
            strategy: HashStrategy::BytesThenMnemonics,
        }
    }

    /// Get the hash strategy.
    pub fn strategy(&self) -> HashStrategy {
        self.strategy
    }

    /// Compute a hash of a byte slice using the default hasher.
    fn hash_bytes(data: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish()
    }

    /// Compute a hash of mnemonic strings.
    fn hash_mnemonics(mnemonics: &[String]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        let mut hasher = DefaultHasher::new();
        for m in mnemonics {
            m.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Get the minimum function size from options.
    fn min_function_size(&self) -> usize {
        self.options
            .get_int(OPTION_FUNCTION_MINIMUM_SIZE, OPTION_FUNCTION_MINIMUM_SIZE_DEFAULT)
            as usize
    }

    /// Build a hash map from function content hash to symbol for a program.
    fn build_hash_map<'a>(
        prog: &'a Program,
        address_set: &[Address],
        strategy: HashStrategy,
        min_size: usize,
    ) -> HashMap<u64, (&'a Symbol, Vec<u8>, Vec<String>)> {
        let mut map = HashMap::new();
        let syms: Vec<&Symbol> = if address_set.is_empty() {
            function_symbol_names(prog)
        } else {
            address_set
                .iter()
                .filter_map(|addr| prog.symbol_table.iter().find(|s| s.address() == addr && s.kind() == SymbolType::Function))
                .collect()
        };

        for sym in syms {
            let rows = function_listing_rows(prog, *sym.address());
            let bytes = listing_bytes(&rows);
            let mnemonics = listing_mnemonics(&rows);

            let effective_size = match strategy {
                HashStrategy::Bytes | HashStrategy::BytesThenMnemonics => bytes.len(),
                HashStrategy::Mnemonics => mnemonics.len(),
            };

            if effective_size < min_size {
                continue;
            }

            let hash = match strategy {
                HashStrategy::Bytes | HashStrategy::BytesThenMnemonics => {
                    Self::hash_bytes(&bytes)
                }
                HashStrategy::Mnemonics => Self::hash_mnemonics(&mnemonics),
            };
            map.insert(hash, (sym, bytes, mnemonics));
        }
        map
    }

    /// Perform the core matching between source and destination using the
    /// given strategy, returning (source_addr, dest_addr, association_type, confidence).
    fn do_match(
        &self,
        strategy: HashStrategy,
    ) -> Vec<(Address, Address, VtAssociationType, f64)> {
        let min_size = self.min_function_size();
        let dest_map = Self::build_hash_map(
            &self.destination_program,
            &self.destination_address_set,
            strategy,
            min_size,
        );

        let src_syms: Vec<&Symbol> = if self.source_address_set.is_empty() {
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
        };

        let mut results = Vec::new();

        for src_sym in src_syms {
            let src_rows = function_listing_rows(&self.source_program, *src_sym.address());
            let src_bytes = listing_bytes(&src_rows);
            let src_mnemonics = listing_mnemonics(&src_rows);

            let effective_size = match strategy {
                HashStrategy::Bytes | HashStrategy::BytesThenMnemonics => src_bytes.len(),
                HashStrategy::Mnemonics => src_mnemonics.len(),
            };
            if effective_size < min_size {
                continue;
            }

            let hash = match strategy {
                HashStrategy::Bytes | HashStrategy::BytesThenMnemonics => {
                    Self::hash_bytes(&src_bytes)
                }
                HashStrategy::Mnemonics => Self::hash_mnemonics(&src_mnemonics),
            };

            if let Some(&(dest_sym, ref dest_bytes, _)) = dest_map.get(&hash) {
                // Verify: for bytes strategy, confirm actual byte equality.
                let confirmed = match strategy {
                    HashStrategy::Bytes | HashStrategy::BytesThenMnemonics => {
                        src_bytes == *dest_bytes
                    }
                    HashStrategy::Mnemonics => true, // mnemonic hash collision is the match
                };

                if confirmed {
                    let assoc_type = VtAssociationType::Function;
                    let confidence = if src_sym.name() == dest_sym.name() {
                        1.0
                    } else {
                        0.95
                    };
                    results.push((
                        *src_sym.address(),
                        *dest_sym.address(),
                        assoc_type,
                        confidence,
                    ));
                }
            }
        }

        results
    }
}

impl VtProgramCorrelator for HashCorrelator {
    fn correlate(&self, session: &mut VtSession) -> VtResult<VtMatchSet> {
        let name = match self.strategy {
            HashStrategy::Bytes => "Exact Function Bytes Match",
            HashStrategy::Mnemonics => "Exact Function Mnemonics Match",
            HashStrategy::BytesThenMnemonics => "Exact Function Bytes+Mnemonics Match",
        };

        let match_set_id = session.create_match_set(name);
        let mut match_set = VtMatchSet::new(match_set_id, name);

        // First pass: try the primary strategy.
        let mut results = self.do_match(self.strategy);

        // For BytesThenMnemonics, collect unmatched sources and do a second pass.
        if self.strategy == HashStrategy::BytesThenMnemonics {
            let matched_src: std::collections::HashSet<Address> =
                results.iter().map(|(s, _, _, _)| *s).collect();
            let matched_dst: std::collections::HashSet<Address> =
                results.iter().map(|(_, d, _, _)| *d).collect();

            // Re-run with mnemonics for unmatched functions.
            let min_size = self.min_function_size();
            let dest_map = Self::build_hash_map(
                &self.destination_program,
                &self.destination_address_set,
                HashStrategy::Mnemonics,
                min_size,
            );

            let src_syms: Vec<&Symbol> = if self.source_address_set.is_empty() {
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
            };

            for src_sym in src_syms {
                if matched_src.contains(src_sym.address()) {
                    continue;
                }
                let src_rows =
                    function_listing_rows(&self.source_program, *src_sym.address());
                let src_mnemonics = listing_mnemonics(&src_rows);
                if src_mnemonics.len() < min_size {
                    continue;
                }
                let hash = Self::hash_mnemonics(&src_mnemonics);
                if let Some(&(dest_sym, _, _)) = dest_map.get(&hash) {
                    if !matched_dst.contains(dest_sym.address()) {
                        results.push((
                            *src_sym.address(),
                            *dest_sym.address(),
                            VtAssociationType::Function,
                            0.85, // lower confidence for mnemonic-only match
                        ));
                    }
                }
            }
        }

        // Populate the match set.
        let mut match_id_counter = 1u64;
        for (src_addr, dst_addr, assoc_type, confidence) in results {
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

            let src_rows = function_listing_rows(&self.source_program, src_addr);
            let dst_rows = function_listing_rows(&self.destination_program, dst_addr);

            let match_entry = crate::versiontracking::match_set::VtMatch {
                association_id: match_id_counter,
                match_set_id,
                source_address: src_addr,
                destination_address: dst_addr,
                association_type: assoc_type,
                similarity_score: VtScore::new(confidence),
                confidence_score: VtScore::new(confidence),
                source_length: src_rows.len() as u64,
                destination_length: dst_rows.len() as u64,
                length_type: crate::versiontracking::vt_match::length_type::INSTRUCTIONS.to_string(),
                tag: crate::versiontracking::types::VtMatchTag::untagged(),
            };
            match_set.add_match(match_entry);
            match_id_counter += 1;
        }

        log::info!(
            "HashCorrelator ({:?}) found {} matches",
            self.strategy,
            match_set.match_count()
        );

        Ok(match_set)
    }

    fn name(&self) -> &str {
        match self.strategy {
            HashStrategy::Bytes => "ExactMatchBytesCorrelator",
            HashStrategy::Mnemonics => "ExactMatchMnemonicsCorrelator",
            HashStrategy::BytesThenMnemonics => "ExactMatchBytesThenMnemonicsCorrelator",
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
            HashStrategy::Bytes => "Compares code by hashing bytes, looking for identical functions.",
            HashStrategy::Mnemonics => "Compares code by hashing instruction mnemonics.",
            HashStrategy::BytesThenMnemonics => {
                "Compares code by hashing bytes first, then falls back to mnemonic matching."
            }
        }
    }
}

impl std::fmt::Debug for HashCorrelator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashCorrelator")
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

    fn min_size_1_opts() -> VtOptions {
        let mut opts = VtOptions::new("test");
        opts.set_int(OPTION_FUNCTION_MINIMUM_SIZE, 1);
        opts
    }

    #[test]
    fn test_hash_bytes_identical() {
        let src = make_program(
            "src",
            &[("main", 0x1000, &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])])],
        );
        let dst = make_program(
            "dst",
            &[("main", 0x2000, &[("push", 0x2000, &[0x55]), ("ret", 0x2001, &[0xc3])])],
        );
        let corr = HashCorrelator::new_bytes(
            src, vec![], dst, vec![], min_size_1_opts(),
        );
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let result = corr.correlate(&mut session);
        assert!(result.is_ok());
        let ms = result.unwrap();
        assert_eq!(ms.match_count(), 1);
    }

    #[test]
    fn test_hash_bytes_different() {
        let src = make_program(
            "src",
            &[("f1", 0x1000, &[("push", 0x1000, &[0x01]), ("ret", 0x1001, &[0x02])])],
        );
        let dst = make_program(
            "dst",
            &[("f2", 0x2000, &[("push", 0x2000, &[0xAA]), ("ret", 0x2001, &[0xBB])])],
        );
        let corr = HashCorrelator::new_bytes(
            src, vec![], dst, vec![], min_size_1_opts(),
        );
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 0);
    }

    #[test]
    fn test_hash_mnemonics_match() {
        let src = make_program(
            "src",
            &[("f1", 0x1000, &[("push", 0x1000, &[0x55]), ("mov", 0x1001, &[0x48]), ("ret", 0x1002, &[0xc3])])],
        );
        let dst = make_program(
            "dst",
            &[("f1", 0x2000, &[("push", 0x2000, &[0x90]), ("mov", 0x2001, &[0x90]), ("ret", 0x2002, &[0x90])])],
        );
        let corr = HashCorrelator::new_mnemonics(
            src, vec![], dst, vec![], min_size_1_opts(),
        );
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 1);
    }

    #[test]
    fn test_hash_strategy_names() {
        let opts = VtOptions::new("test");

        let c1 = HashCorrelator::new_bytes(Program::new("s", addr(0)), vec![], Program::new("d", addr(0)), vec![], opts.clone());
        assert_eq!(c1.name(), "ExactMatchBytesCorrelator");

        let c2 = HashCorrelator::new_mnemonics(Program::new("s", addr(0)), vec![], Program::new("d", addr(0)), vec![], opts.clone());
        assert_eq!(c2.name(), "ExactMatchMnemonicsCorrelator");

        let c3 = HashCorrelator::new_bytes_then_mnemonics(Program::new("s", addr(0)), vec![], Program::new("d", addr(0)), vec![], opts);
        assert_eq!(c3.name(), "ExactMatchBytesThenMnemonicsCorrelator");
    }

    #[test]
    fn test_hash_strategy_accessors() {
        let src = Program::new("s", addr(0));
        let dst = Program::new("d", addr(0));
        let opts = VtOptions::new("test");
        let c = HashCorrelator::new_mnemonics(src, vec![], dst, vec![], opts);
        assert_eq!(c.strategy(), HashStrategy::Mnemonics);
    }

    #[test]
    fn test_minimum_size_filter() {
        let src = make_program(
            "src",
            &[("tiny", 0x1000, &[("nop", 0x1000, &[0x90])])],
        );
        let dst = make_program(
            "dst",
            &[("tiny", 0x2000, &[("nop", 0x2000, &[0x90])])],
        );
        let mut opts = VtOptions::new("test");
        opts.set_int(OPTION_FUNCTION_MINIMUM_SIZE, 5);
        let corr = HashCorrelator::new_bytes(src, vec![], dst, vec![], opts);
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        // Function is only 1 byte, below minimum of 5
        assert_eq!(ms.match_count(), 0);
    }

    #[test]
    fn test_renamed_function_confidence() {
        let src = make_program(
            "src",
            &[("old_name", 0x1000, &[("push", 0x1000, &[0x55]), ("ret", 0x1001, &[0xc3])])],
        );
        let dst = make_program(
            "dst",
            &[("new_name", 0x2000, &[("push", 0x2000, &[0x55]), ("ret", 0x2001, &[0xc3])])],
        );
        let corr = HashCorrelator::new_bytes(
            src, vec![], dst, vec![], min_size_1_opts(),
        );
        let mut session = VtSession::new("test", Program::new("s", addr(0)), Program::new("d", addr(0)));
        let ms = corr.correlate(&mut session).unwrap();
        assert_eq!(ms.match_count(), 1);
        let m = ms.get_matches()[0];
        // Renamed functions get 0.95 confidence
        assert!((m.confidence_score.score() - 0.95).abs() < 0.01);
    }

    #[test]
    fn test_debug_format() {
        let src = Program::new("s", addr(0));
        let dst = Program::new("d", addr(0));
        let corr = HashCorrelator::new_bytes(src, vec![], dst, vec![], VtOptions::new("test"));
        let debug = format!("{:?}", corr);
        assert!(debug.contains("HashCorrelator"));
        assert!(debug.contains("Bytes"));
    }

    #[test]
    fn test_description() {
        let src = Program::new("s", addr(0));
        let dst = Program::new("d", addr(0));
        let corr = HashCorrelator::new_bytes(src, vec![], dst, vec![], VtOptions::new("test"));
        assert!(!corr.description().is_empty());
    }
}
