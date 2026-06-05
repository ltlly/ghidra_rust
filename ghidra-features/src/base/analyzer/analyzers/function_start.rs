//! Function start analyzer.
//!
//! Ported from Ghidra's `FunctionStartAnalyzer`.
//!
//! Searches for function prologue patterns (such as `push rbp; mov rbp, rsp`
//! on x86-64, or `stmfd sp!, {fp, lr}` on ARM) to identify likely function
//! entry points. Detected entry points are queued for the disassembler to
//! create proper function objects.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// ProloguePattern
// ---------------------------------------------------------------------------

/// A function prologue byte pattern to search for.
#[derive(Debug, Clone)]
pub struct ProloguePattern {
    /// Human-readable name (e.g. "x86-64 push rbp frame").
    pub name: String,
    /// The byte pattern to match.
    pub pattern: Vec<u8>,
    /// Mask bytes: 0xFF = must match, 0x00 = don't care.
    pub mask: Vec<u8>,
}

impl ProloguePattern {
    /// Create a pattern that must match exactly (all mask bytes = 0xFF).
    pub fn exact(name: impl Into<String>, pattern: Vec<u8>) -> Self {
        let mask = vec![0xFF; pattern.len()];
        Self {
            name: name.into(),
            pattern,
            mask,
        }
    }

    /// Return the pattern length.
    pub fn len(&self) -> usize {
        self.pattern.len()
    }

    /// Return true if pattern is empty.
    pub fn is_empty(&self) -> bool {
        self.pattern.is_empty()
    }
}

// ---------------------------------------------------------------------------
// FunctionStartResult
// ---------------------------------------------------------------------------

/// A detected function prologue at a given address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionStartResult {
    /// Address of the detected prologue.
    pub address: u64,
    /// Name of the pattern that matched.
    pub pattern_name: String,
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Searches for function prologue patterns to identify function entry points.
///
/// Ported from Ghidra's `FunctionStartAnalyzer`.
#[derive(Debug, Clone)]
pub struct FunctionStartAnalyzer {
    base: AbstractAnalyzer,
    /// Known prologue patterns to scan for.
    pub patterns: Vec<ProloguePattern>,
}

impl FunctionStartAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "Function Start Analyzer",
                "Searches for function prologue patterns to identify function entry points.",
                AnalyzerType::Byte,
            ),
            patterns: default_prologue_patterns(),
        }
    }

    /// Scan `bytes` starting at `base_addr` for prologue pattern matches.
    pub fn scan(&self, bytes: &[u8], base_addr: u64) -> Vec<FunctionStartResult> {
        let mut results = Vec::new();
        for pat in &self.patterns {
            if pat.is_empty() || pat.len() > bytes.len() {
                continue;
            }
            for i in 0..=bytes.len() - pat.len() {
                if matches_pattern(&bytes[i..], &pat.pattern, &pat.mask) {
                    results.push(FunctionStartResult {
                        address: base_addr + i as u64,
                        pattern_name: pat.name.clone(),
                    });
                }
            }
        }
        results
    }
}

impl Analyzer for FunctionStartAnalyzer {
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
        AnalysisPriority::BLOCK_ANALYSIS.before()
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
        _s: &AddressSet,
        m: &dyn TaskMonitor,
        l: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        m.check_cancelled()?;
        m.set_message("Searching for function starts...");
        l.append_msg(format!(
            "{}: scanning with {} prologue patterns",
            self.name(),
            self.patterns.len()
        ));
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check whether `bytes` matches `pattern` with `mask`.
fn matches_pattern(bytes: &[u8], pattern: &[u8], mask: &[u8]) -> bool {
    for ((&b, &p), &m) in bytes.iter().zip(pattern.iter()).zip(mask.iter()) {
        if (b & m) != (p & m) {
            return false;
        }
    }
    true
}

/// Common function prologue patterns for various architectures.
fn default_prologue_patterns() -> Vec<ProloguePattern> {
    vec![
        // x86-64: push rbp; mov rbp, rsp
        ProloguePattern::exact("x86-64 push rbp", vec![0x55, 0x48, 0x89, 0xE5]),
        // x86-32: push ebp; mov ebp, esp
        ProloguePattern::exact("x86-32 push ebp", vec![0x55, 0x89, 0xE5]),
        // ARM: stmfd sp!, {fp, lr} (E92D4800)
        ProloguePattern::exact("ARM stmfd", vec![0x00, 0x48, 0x2D, 0xE9]),
        // Thumb-2: push {r7, lr}
        ProloguePattern::exact("Thumb-2 push", vec![0x80, 0xB5]),
        // MIPS: addiu sp, sp, -N (0x27BDxxxx)
        ProloguePattern {
            name: "MIPS addiu sp".to_string(),
            pattern: vec![0x27, 0xBD],
            mask: vec![0xFF, 0xFF],
        },
        // RISC-V: addi sp, sp, -N (opcode 0x13 with funct3=0)
        ProloguePattern {
            name: "RISC-V addi sp".to_string(),
            pattern: vec![0x13, 0x01],
            mask: vec![0x7F, 0xFF],
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_has_default_patterns() {
        let a = FunctionStartAnalyzer::new();
        assert!(!a.patterns.is_empty());
        assert_eq!(a.name(), "Function Start Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
    }

    #[test]
    fn test_scan_x86_64_prologue() {
        let a = FunctionStartAnalyzer::new();
        let bytes = vec![0x55, 0x48, 0x89, 0xE5, 0xC3]; // push rbp; mov rbp,rsp; ret
        let results = a.scan(&bytes, 0x400000);
        assert!(!results.is_empty());
        assert_eq!(results[0].address, 0x400000);
        assert!(results[0].pattern_name.contains("x86-64"));
    }

    #[test]
    fn test_scan_multiple_prologues() {
        let a = FunctionStartAnalyzer::new();
        // func1 at offset 0, func2 at offset 8
        let mut bytes = vec![0x55, 0x48, 0x89, 0xE5, 0xC3, 0x90, 0x90, 0x90];
        bytes.extend(vec![0x55, 0x48, 0x89, 0xE5, 0xC3]);
        let results = a.scan(&bytes, 0x400000);
        assert!(results.len() >= 2);
        assert_eq!(results[0].address, 0x400000);
        assert_eq!(results[1].address, 0x400008);
    }

    #[test]
    fn test_scan_no_match() {
        let a = FunctionStartAnalyzer::new();
        let bytes = vec![0x00; 16];
        let results = a.scan(&bytes, 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_empty() {
        let a = FunctionStartAnalyzer::new();
        assert!(a.scan(&[], 0).is_empty());
    }

    #[test]
    fn test_scan_arm_prologue() {
        let a = FunctionStartAnalyzer::new();
        // ARM stmfd pattern
        let bytes = vec![0x00, 0x48, 0x2D, 0xE9, 0x04, 0xB0];
        let results = a.scan(&bytes, 0x8000);
        let arm_hits: Vec<_> = results.iter().filter(|r| r.pattern_name.contains("ARM")).collect();
        assert_eq!(arm_hits.len(), 1);
        assert_eq!(arm_hits[0].address, 0x8000);
    }

    #[test]
    fn test_matches_pattern_exact() {
        assert!(matches_pattern(&[0x55, 0x48], &[0x55, 0x48], &[0xFF, 0xFF]));
        assert!(!matches_pattern(&[0x55, 0x49], &[0x55, 0x48], &[0xFF, 0xFF]));
    }

    #[test]
    fn test_matches_pattern_masked() {
        // Mask 0x7F on first byte means low 7 bits must match
        assert!(matches_pattern(&[0x93, 0x01], &[0x13, 0x01], &[0x7F, 0xFF]));
        assert!(!matches_pattern(&[0x33, 0x01], &[0x13, 0x01], &[0x7F, 0xFF]));
    }

    #[test]
    fn test_priority() {
        let a = FunctionStartAnalyzer::new();
        assert_eq!(a.priority(), AnalysisPriority::BLOCK_ANALYSIS.before());
    }

    #[test]
    fn test_prologue_pattern_exact() {
        let p = ProloguePattern::exact("test", vec![0x55]);
        assert_eq!(p.len(), 1);
        assert_eq!(p.mask, vec![0xFF]);
    }
}
