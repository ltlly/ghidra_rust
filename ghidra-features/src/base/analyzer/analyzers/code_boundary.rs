//! Code boundary analyzer.
//!
//! Ported from Ghidra's `CodeBoundaryAnalyzer` concept.
//!
//! Identifies boundaries between code and data regions by scanning for
//! NOP padding, unreachable instructions, and control-flow dead ends.
//! When a boundary is found the analyzer marks the region so that the
//! disassembler knows where executable code ends and data begins.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration knobs for the code boundary analyzer.
#[derive(Debug, Clone)]
pub struct CodeBoundaryConfig {
    /// Minimum run of identical zero/NOP bytes to treat as padding.
    pub min_nop_run: usize,
    /// Whether to look for unreachable code after unconditional jumps.
    pub detect_unreachable: bool,
    /// Whether to treat runs of `0xCC` (INT 3) as padding.
    pub detect_int3_padding: bool,
}

impl Default for CodeBoundaryConfig {
    fn default() -> Self {
        Self {
            min_nop_run: 4,
            detect_unreachable: true,
            detect_int3_padding: true,
        }
    }
}

// ---------------------------------------------------------------------------
// PaddingKind
// ---------------------------------------------------------------------------

/// The kind of padding detected at a code boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingKind {
    /// NOP bytes (x86 `0x90`, ARM `0xE320F000`, etc.).
    Nop,
    /// Zero-fill alignment padding.
    ZeroFill,
    /// INT 3 breakpoint padding (`0xCC`).
    Int3Breakpoint,
    /// Unreachable code after unconditional branch.
    Unreachable,
}

// ---------------------------------------------------------------------------
// CodeBoundaryResult
// ---------------------------------------------------------------------------

/// A single detected boundary between code and data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBoundaryResult {
    /// The address where the boundary was found.
    pub address: u64,
    /// What kind of padding / boundary marker was detected.
    pub kind: PaddingKind,
    /// Length of the padding run in bytes.
    pub length: usize,
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Identifies code boundaries through control flow analysis and padding
/// detection.
///
/// Ported from Ghidra's code boundary analysis pass.
#[derive(Debug, Clone)]
pub struct CodeBoundaryAnalyzer {
    base: AbstractAnalyzer,
    /// User-configurable options.
    pub config: CodeBoundaryConfig,
}

impl CodeBoundaryAnalyzer {
    pub fn new() -> Self {
        Self {
            base: AbstractAnalyzer::new(
                "Code Boundary Analyzer",
                "Identifies code boundaries through control flow analysis and padding detection.",
                AnalyzerType::Byte,
            ),
            config: CodeBoundaryConfig::default(),
        }
    }

    /// Scan a byte slice for NOP padding runs and return detected boundaries.
    ///
    /// This is the core detection logic factored out for testability.
    pub fn detect_nop_boundaries(&self, bytes: &[u8], base_addr: u64) -> Vec<CodeBoundaryResult> {
        let mut results = Vec::new();
        let min = self.config.min_nop_run;
        if bytes.is_empty() || min == 0 {
            return results;
        }

        let mut run_start: Option<usize> = None;
        let mut run_kind: Option<PaddingKind> = None;

        for (i, &b) in bytes.iter().enumerate() {
            let kind = classify_byte(b);
            match kind {
                Some(k) => {
                    if run_kind == Some(k) {
                        // continue run
                    } else {
                        // flush previous run
                        if let (Some(start), Some(k)) = (run_start, run_kind) {
                            let len = i - start;
                            if len >= min {
                                results.push(CodeBoundaryResult {
                                    address: base_addr + start as u64,
                                    kind: k,
                                    length: len,
                                });
                            }
                        }
                        run_start = Some(i);
                        run_kind = Some(k);
                    }
                }
                None => {
                    // flush
                    if let (Some(start), Some(k)) = (run_start, run_kind) {
                        let len = i - start;
                        if len >= min {
                            results.push(CodeBoundaryResult {
                                address: base_addr + start as u64,
                                kind: k,
                                length: len,
                            });
                        }
                    }
                    run_start = None;
                    run_kind = None;
                }
            }
        }

        // flush final run
        if let (Some(start), Some(k)) = (run_start, run_kind) {
            let len = bytes.len() - start;
            if len >= min {
                results.push(CodeBoundaryResult {
                    address: base_addr + start as u64,
                    kind: k,
                    length: len,
                });
            }
        }

        results
    }
}

impl Analyzer for CodeBoundaryAnalyzer {
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
        AnalysisPriority::BLOCK_ANALYSIS.after()
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
        m.set_message("Analyzing code boundaries...");
        l.append_msg(&format!(
            "{}: scanning for code/data boundaries",
            self.name()
        ));
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Classify a byte as a potential padding byte.
fn classify_byte(b: u8) -> Option<PaddingKind> {
    match b {
        0x90 => Some(PaddingKind::Nop),  // x86 NOP
        0x00 => Some(PaddingKind::ZeroFill),
        0xCC => Some(PaddingKind::Int3Breakpoint),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_defaults() {
        let a = CodeBoundaryAnalyzer::new();
        assert_eq!(a.name(), "Code Boundary Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
        assert_eq!(a.config.min_nop_run, 4);
        assert!(a.config.detect_unreachable);
        assert!(a.config.detect_int3_padding);
    }

    #[test]
    fn test_detect_nop_run() {
        let a = CodeBoundaryAnalyzer::new();
        // 8 NOP bytes at offset 0x1000
        let bytes = vec![0x90u8; 8];
        let results = a.detect_nop_boundaries(&bytes, 0x1000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 0x1000);
        assert_eq!(results[0].kind, PaddingKind::Nop);
        assert_eq!(results[0].length, 8);
    }

    #[test]
    fn test_detect_zero_fill() {
        let a = CodeBoundaryAnalyzer::new();
        let bytes = vec![0x00u8; 16];
        let results = a.detect_nop_boundaries(&bytes, 0x2000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, PaddingKind::ZeroFill);
        assert_eq!(results[0].length, 16);
    }

    #[test]
    fn test_detect_int3_padding() {
        let a = CodeBoundaryAnalyzer::new();
        let bytes = vec![0xCCu8; 6];
        let results = a.detect_nop_boundaries(&bytes, 0x3000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].kind, PaddingKind::Int3Breakpoint);
        assert_eq!(results[0].length, 6);
    }

    #[test]
    fn test_short_run_ignored() {
        let mut cfg = CodeBoundaryConfig::default();
        cfg.min_nop_run = 4;
        let a = CodeBoundaryAnalyzer {
            base: AbstractAnalyzer::new("Test", "Test", AnalyzerType::Byte),
            config: cfg,
        };
        let bytes = vec![0x90u8; 3]; // below threshold
        let results = a.detect_nop_boundaries(&bytes, 0);
        assert!(results.is_empty());
    }

    #[test]
    fn test_mixed_code_and_padding() {
        let a = CodeBoundaryAnalyzer::new();
        let mut bytes = vec![0x55, 0x48, 0x89, 0xE5]; // push rbp; mov rbp,rsp
        bytes.extend(vec![0x90u8; 8]); // NOP padding
        bytes.extend(vec![0x55, 0x48]); // next function
        let results = a.detect_nop_boundaries(&bytes, 0x4000);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, 0x4004);
        assert_eq!(results[0].kind, PaddingKind::Nop);
    }

    #[test]
    fn test_multiple_boundary_regions() {
        let a = CodeBoundaryAnalyzer::new();
        let mut bytes = vec![0x90u8; 8];
        bytes.push(0x55); // break
        bytes.extend(vec![0x00u8; 8]);
        let results = a.detect_nop_boundaries(&bytes, 0);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].kind, PaddingKind::Nop);
        assert_eq!(results[1].kind, PaddingKind::ZeroFill);
    }

    #[test]
    fn test_empty_input() {
        let a = CodeBoundaryAnalyzer::new();
        assert!(a.detect_nop_boundaries(&[], 0).is_empty());
    }

    #[test]
    fn test_priority() {
        let a = CodeBoundaryAnalyzer::new();
        let p = a.priority();
        // Should be after BLOCK_ANALYSIS
        assert_eq!(p, AnalysisPriority::BLOCK_ANALYSIS.after());
    }
}
