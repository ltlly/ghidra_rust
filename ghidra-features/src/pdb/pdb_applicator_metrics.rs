//! PDB Applicator Metrics -- metrics tracking for PDB application.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.pdbapplicator.PdbApplicatorMetrics`.

use std::collections::HashSet;
use std::fmt;

/// Metrics captured during the application of a PDB.
///
/// This helps quantify and qualify the ability to apply PDB data to a program.
/// It tracks which types and symbols could not be applied, unexpected symbol
/// placements, and other diagnostic information.
#[derive(Debug, Default)]
pub struct PdbApplicatorMetrics {
    /// Type names that could not be applied.
    cannot_apply_types: HashSet<String>,
    /// Symbol names that could not be applied.
    cannot_apply_symbols: HashSet<String>,
    /// Symbol names that could not be nested.
    non_nestable_symbols: HashSet<String>,
    /// Unexpected global symbol names.
    unexpected_global_symbols: HashSet<String>,
    /// Unexpected public symbol names.
    unexpected_public_symbols: HashSet<String>,
    /// Unusual this pointer type names.
    unusual_this_pointer_types: HashSet<String>,
    /// Unusual this pointer underlying type names.
    unusual_this_pointer_underlying_types: HashSet<String>,
    /// Unusual member function container type names.
    unusual_container_types: HashSet<String>,
    /// Whether enumerate narrowing was witnessed.
    witness_enumerate_narrowing: bool,
    /// Whether C11 lines were witnessed.
    witness_c11_lines: bool,
    /// Whether C13 inlinee lines were witnessed.
    witness_c13_inlinee_lines: bool,
    /// Total types processed.
    types_processed: u64,
    /// Total symbols processed.
    symbols_processed: u64,
    /// Total types applied successfully.
    types_applied: u64,
    /// Total symbols applied successfully.
    symbols_applied: u64,
}

impl PdbApplicatorMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a type that could not be applied.
    pub fn witness_cannot_apply_type(&mut self, type_name: &str) {
        self.cannot_apply_types.insert(type_name.to_string());
    }

    /// Record a symbol that could not be applied.
    pub fn witness_cannot_apply_symbol(&mut self, symbol_name: &str) {
        self.cannot_apply_symbols.insert(symbol_name.to_string());
    }

    /// Record a symbol that could not be nested.
    pub fn witness_non_nestable_symbol(&mut self, symbol_name: &str) {
        self.non_nestable_symbols.insert(symbol_name.to_string());
    }

    /// Record an unexpected global symbol.
    pub fn witness_unexpected_global_symbol(&mut self, symbol_name: &str) {
        self.unexpected_global_symbols
            .insert(symbol_name.to_string());
    }

    /// Record an unexpected public symbol.
    pub fn witness_unexpected_public_symbol(&mut self, symbol_name: &str) {
        self.unexpected_public_symbols
            .insert(symbol_name.to_string());
    }

    /// Record an unusual this pointer type.
    pub fn witness_unusual_this_pointer(&mut self, type_name: &str) {
        self.unusual_this_pointer_types
            .insert(type_name.to_string());
    }

    /// Record an unusual this pointer underlying type.
    pub fn witness_unusual_this_pointer_underlying(&mut self, type_name: &str) {
        self.unusual_this_pointer_underlying_types
            .insert(type_name.to_string());
    }

    /// Record an unusual member function container type.
    pub fn witness_unusual_container(&mut self, type_name: &str) {
        self.unusual_container_types
            .insert(type_name.to_string());
    }

    /// Record witnessing of enumerate narrowing.
    pub fn witness_enumerate_narrowing(&mut self) {
        self.witness_enumerate_narrowing = true;
    }

    /// Record witnessing of C11 lines.
    pub fn witness_c11_lines(&mut self) {
        self.witness_c11_lines = true;
    }

    /// Record witnessing of C13 inlinee lines.
    pub fn witness_c13_inlinee_lines(&mut self) {
        self.witness_c13_inlinee_lines = true;
    }

    /// Increment the count of types processed.
    pub fn inc_types_processed(&mut self) {
        self.types_processed += 1;
    }

    /// Increment the count of symbols processed.
    pub fn inc_symbols_processed(&mut self) {
        self.symbols_processed += 1;
    }

    /// Increment the count of types applied successfully.
    pub fn inc_types_applied(&mut self) {
        self.types_applied += 1;
    }

    /// Increment the count of symbols applied successfully.
    pub fn inc_symbols_applied(&mut self) {
        self.symbols_applied += 1;
    }

    /// Get the number of types that could not be applied.
    pub fn cannot_apply_type_count(&self) -> usize {
        self.cannot_apply_types.len()
    }

    /// Get the number of symbols that could not be applied.
    pub fn cannot_apply_symbol_count(&self) -> usize {
        self.cannot_apply_symbols.len()
    }

    /// Get the total number of types processed.
    pub fn types_processed(&self) -> u64 {
        self.types_processed
    }

    /// Get the total number of symbols processed.
    pub fn symbols_processed(&self) -> u64 {
        self.symbols_processed
    }

    /// Get the total number of types applied successfully.
    pub fn types_applied(&self) -> u64 {
        self.types_applied
    }

    /// Get the total number of symbols applied successfully.
    pub fn symbols_applied(&self) -> u64 {
        self.symbols_applied
    }

    /// Check if there were any issues during application.
    pub fn has_issues(&self) -> bool {
        !self.cannot_apply_types.is_empty()
            || !self.cannot_apply_symbols.is_empty()
            || !self.non_nestable_symbols.is_empty()
            || !self.unexpected_global_symbols.is_empty()
            || !self.unexpected_public_symbols.is_empty()
            || self.witness_enumerate_narrowing
            || self.witness_c11_lines
            || self.witness_c13_inlinee_lines
    }

    /// Generate a summary report.
    pub fn report(&self) -> String {
        let mut report = String::new();

        if !self.cannot_apply_types.is_empty() {
            report.push_str("=== Types that could not be applied ===\n");
            for name in &self.cannot_apply_types {
                report.push_str(&format!("  - {}\n", name));
            }
        }

        if !self.cannot_apply_symbols.is_empty() {
            report.push_str("=== Symbols that could not be applied ===\n");
            for name in &self.cannot_apply_symbols {
                report.push_str(&format!("  - {}\n", name));
            }
        }

        if !self.non_nestable_symbols.is_empty() {
            report.push_str("=== Symbols that could not be nested ===\n");
            for name in &self.non_nestable_symbols {
                report.push_str(&format!("  - {}\n", name));
            }
        }

        if !self.unexpected_global_symbols.is_empty() {
            report.push_str("=== Unexpected global symbols ===\n");
            for name in &self.unexpected_global_symbols {
                report.push_str(&format!("  - {}\n", name));
            }
        }

        if !self.unexpected_public_symbols.is_empty() {
            report.push_str("=== Unexpected public symbols ===\n");
            for name in &self.unexpected_public_symbols {
                report.push_str(&format!("  - {}\n", name));
            }
        }

        if self.witness_enumerate_narrowing {
            report.push_str("Enumerate narrowing was witnessed\n");
        }
        if self.witness_c11_lines {
            report.push_str("Could not process C11Lines\n");
        }
        if self.witness_c13_inlinee_lines {
            report.push_str("Could not process C13InlineeLines\n");
        }

        report.push_str(&format!(
            "\n=== Summary ===\nTypes: {}/{} applied\nSymbols: {}/{} applied\n",
            self.types_applied, self.types_processed,
            self.symbols_applied, self.symbols_processed,
        ));

        if report.is_empty() {
            "No issues reported".to_string()
        } else {
            report
        }
    }
}

impl fmt::Display for PdbApplicatorMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdbApplicatorMetrics [types={}/{}, symbols={}/{}, issues={}]",
            self.types_applied,
            self.types_processed,
            self.symbols_applied,
            self.symbols_processed,
            self.has_issues()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_metrics() {
        let m = PdbApplicatorMetrics::new();
        assert!(!m.has_issues());
        assert_eq!(m.types_processed(), 0);
        assert_eq!(m.symbols_processed(), 0);
    }

    #[test]
    fn test_witness_cannot_apply_type() {
        let mut m = PdbApplicatorMetrics::new();
        m.witness_cannot_apply_type("SomeType");
        assert!(m.has_issues());
        assert_eq!(m.cannot_apply_type_count(), 1);
    }

    #[test]
    fn test_witness_cannot_apply_symbol() {
        let mut m = PdbApplicatorMetrics::new();
        m.witness_cannot_apply_symbol("SomeSymbol");
        assert!(m.has_issues());
        assert_eq!(m.cannot_apply_symbol_count(), 1);
    }

    #[test]
    fn test_witness_enumerate_narrowing() {
        let mut m = PdbApplicatorMetrics::new();
        m.witness_enumerate_narrowing();
        assert!(m.has_issues());
    }

    #[test]
    fn test_witness_c11_lines() {
        let mut m = PdbApplicatorMetrics::new();
        m.witness_c11_lines();
        assert!(m.has_issues());
    }

    #[test]
    fn test_witness_c13_inlinee_lines() {
        let mut m = PdbApplicatorMetrics::new();
        m.witness_c13_inlinee_lines();
        assert!(m.has_issues());
    }

    #[test]
    fn test_counters() {
        let mut m = PdbApplicatorMetrics::new();
        m.inc_types_processed();
        m.inc_types_processed();
        m.inc_types_applied();
        m.inc_symbols_processed();
        m.inc_symbols_applied();
        assert_eq!(m.types_processed(), 2);
        assert_eq!(m.types_applied(), 1);
        assert_eq!(m.symbols_processed(), 1);
        assert_eq!(m.symbols_applied(), 1);
    }

    #[test]
    fn test_report_empty() {
        let m = PdbApplicatorMetrics::new();
        let report = m.report();
        assert!(report.contains("Summary"));
        assert!(report.contains("0/0 applied"));
    }

    #[test]
    fn test_report_with_issues() {
        let mut m = PdbApplicatorMetrics::new();
        m.witness_cannot_apply_type("BadType");
        m.witness_cannot_apply_symbol("BadSymbol");
        m.inc_types_processed();
        m.inc_symbols_processed();
        let report = m.report();
        assert!(report.contains("BadType"));
        assert!(report.contains("BadSymbol"));
    }

    #[test]
    fn test_display() {
        let mut m = PdbApplicatorMetrics::new();
        m.inc_types_processed();
        m.inc_types_applied();
        let s = format!("{}", m);
        assert!(s.contains("types=1/1"));
    }

    #[test]
    fn test_unique_witnesses() {
        let mut m = PdbApplicatorMetrics::new();
        m.witness_cannot_apply_type("SameType");
        m.witness_cannot_apply_type("SameType");
        assert_eq!(m.cannot_apply_type_count(), 1);
    }
}
