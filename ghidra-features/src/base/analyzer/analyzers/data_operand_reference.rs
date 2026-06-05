//! Data operand reference analyzer.
//!
//! Ported from Ghidra's `DataOperandReferenceAnalyzer.java`.
//!
//! Extends the operand reference analyzer to check references to memory
//! locations looking for data. Unlike the instruction operand reference
//! analyzer, this analyzer never creates functions from data pointers --
//! it only establishes cross-references between data units.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// DataRefKind
// ---------------------------------------------------------------------------

/// The kind of data reference discovered by the analyzer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataRefKind {
    /// A pointer stored in a data unit that points to another address.
    Pointer,
    /// A computed offset stored in a data unit.
    Offset,
    /// A string reference (pointer to a null-terminated string).
    StringRef,
    /// An embedded structure/object reference.
    Embedded,
}

// ---------------------------------------------------------------------------
// DataRefResult
// ---------------------------------------------------------------------------

/// A single discovered data-to-data reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRefResult {
    /// Address of the data unit containing the reference.
    pub from_addr: u64,
    /// Address being referenced.
    pub to_addr: u64,
    /// The kind of data reference.
    pub kind: DataRefKind,
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Analyzes data referenced by data operands.
///
/// Checks operand references to memory locations looking for data.
/// Unlike instruction-based reference analysis, this never creates
/// functions from data pointers.
///
/// Ported from `ghidra.app.plugin.core.analysis.DataOperandReferenceAnalyzer`.
#[derive(Debug, Clone)]
pub struct DataOperandReferenceAnalyzer {
    base: AbstractAnalyzer,
    /// Maximum number of data references to collect per run.
    pub max_references: usize,
}

impl DataOperandReferenceAnalyzer {
    pub fn new() -> Self {
        let mut b = AbstractAnalyzer::new(
            "Data Reference",
            "Analyzes data referenced by data.",
            AnalyzerType::Data,
        );
        b.set_priority(AnalysisPriority::REFERENCE_ANALYSIS.after().after());
        Self {
            base: b,
            max_references: 10_000,
        }
    }

    /// Analyze a slice of 64-bit words and return pointer-like references.
    ///
    /// A word is considered a candidate pointer if its value falls within
    /// the supplied address range `[lo, hi)`.
    pub fn scan_pointer_words(
        &self,
        words: &[u64],
        base_addr: u64,
        lo: u64,
        hi: u64,
    ) -> Vec<DataRefResult> {
        let mut results = Vec::new();
        for (i, &w) in words.iter().enumerate() {
            if results.len() >= self.max_references {
                break;
            }
            if w >= lo && w < hi {
                let addr = base_addr + (i as u64) * 8;
                results.push(DataRefResult {
                    from_addr: addr,
                    to_addr: w,
                    kind: DataRefKind::Pointer,
                });
            }
        }
        results
    }

    /// Scan for 32-bit pointer references.
    pub fn scan_pointer_dwords(
        &self,
        dwords: &[u32],
        base_addr: u64,
        lo: u32,
        hi: u32,
    ) -> Vec<DataRefResult> {
        let mut results = Vec::new();
        for (i, &d) in dwords.iter().enumerate() {
            if results.len() >= self.max_references {
                break;
            }
            if d >= lo && d < hi {
                let addr = base_addr + (i as u64) * 4;
                results.push(DataRefResult {
                    from_addr: addr,
                    to_addr: d as u64,
                    kind: DataRefKind::Pointer,
                });
            }
        }
        results
    }
}

impl Analyzer for DataOperandReferenceAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::REFERENCE_ANALYSIS.after().after()
    }
    fn can_analyze(&self, _: &Program) -> bool {
        true
    }
    fn default_enablement(&self, _: &Program) -> bool {
        true
    }
    fn added(
        &self,
        _p: &mut Program,
        s: &AddressSet,
        m: &dyn TaskMonitor,
        l: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        m.check_cancelled()?;
        m.set_message("Analyzing data references...");
        m.initialize(s.num_addresses());
        l.append_msg(format!(
            "DataOperandReferenceAnalyzer: processing {} addresses",
            s.num_addresses()
        ));
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let a = DataOperandReferenceAnalyzer::new();
        assert_eq!(a.name(), "Data Reference");
        assert_eq!(a.analysis_type(), AnalyzerType::Data);
        assert_eq!(a.max_references, 10_000);
    }

    #[test]
    fn test_scan_pointer_words_found() {
        let a = DataOperandReferenceAnalyzer::new();
        let words: Vec<u64> = vec![0, 0x401000, 0xDEAD, 0x402000];
        let results = a.scan_pointer_words(&words, 0x5000, 0x400000, 0x500000);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].from_addr, 0x5008); // index 1 * 8 + 0x5000
        assert_eq!(results[0].to_addr, 0x401000);
        assert_eq!(results[0].kind, DataRefKind::Pointer);
        assert_eq!(results[1].from_addr, 0x5018);
        assert_eq!(results[1].to_addr, 0x402000);
    }

    #[test]
    fn test_scan_pointer_words_none_found() {
        let a = DataOperandReferenceAnalyzer::new();
        let words: Vec<u64> = vec![0, 1, 2, 0x100000000];
        let results = a.scan_pointer_words(&words, 0, 0x400000, 0x500000);
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_pointer_dwords() {
        let a = DataOperandReferenceAnalyzer::new();
        let dwords: Vec<u32> = vec![0, 0x401000, 0xDEAD, 0x402000];
        let results = a.scan_pointer_dwords(&dwords, 0x1000, 0x400000, 0x500000);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].from_addr, 0x1004);
        assert_eq!(results[0].to_addr, 0x401000);
    }

    #[test]
    fn test_max_references_limit() {
        let mut a = DataOperandReferenceAnalyzer::new();
        a.max_references = 1;
        let words: Vec<u64> = vec![0x401000, 0x402000, 0x403000];
        let results = a.scan_pointer_words(&words, 0, 0x400000, 0x500000);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_scan_empty() {
        let a = DataOperandReferenceAnalyzer::new();
        assert!(a.scan_pointer_words(&[], 0, 0, u64::MAX).is_empty());
        assert!(a.scan_pointer_dwords(&[], 0, 0, u32::MAX).is_empty());
    }

    #[test]
    fn test_priority() {
        let a = DataOperandReferenceAnalyzer::new();
        assert_eq!(
            a.priority(),
            AnalysisPriority::REFERENCE_ANALYSIS.after().after()
        );
    }
}
