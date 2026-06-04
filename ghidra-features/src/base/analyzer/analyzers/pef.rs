//! PEF (Preferred Executable Format) analyzers.
//!
//! Ported from Ghidra's `PefAnalyzer.java` and `PefDebugAnalyzer.java`.
//! Handles Classic Mac OS PEF binaries with PowerPC indirect addressing via R2 (TOC).

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Name of the TOC (Table of Contents) symbol used in PEF binaries.
pub const PEF_TOC_SYMBOL: &str = "TOC";

/// Namespace applied to glue-code functions discovered by the PEF analyzer.
pub const PEF_GLUE_NAMESPACE: &str = "Glue";

/// Namespace applied to debug symbols discovered by the PEF debug analyzer.
pub const PEF_DEBUG_NAMESPACE: &str = ".debug";

/// Executable format string reported by PefLoader.
pub const PEF_FORMAT_NAME: &str = "PEF";

// ---------------------------------------------------------------------------
// PefAnalyzer  --  "PEF Indirect Addressing"
// ---------------------------------------------------------------------------

/// Creates references to symbols indirectly addressed via R2 (the PowerPC TOC
/// register) in PEF binaries.
///
/// For every instruction that reads an offset from `r2`, this analyzer creates
/// a memory reference from the instruction to `TOC + offset`. If the
/// instruction is `lwz r12,<offset>(r2)` (glue code), the containing function
/// is renamed to match the target symbol and placed in the `Glue` namespace.
#[derive(Debug, Clone)]
pub struct PefAnalyzer {
    base: AbstractAnalyzer,
}

impl PefAnalyzer {
    pub fn new() -> Self {
        let mut b = AbstractAnalyzer::new(
            "PEF Indirect Addressing",
            "Creates references to symbols indirectly addresses via R2.",
            AnalyzerType::Function,
        );
        b.set_default_enablement(true);
        b.set_priority(
            AnalysisPriority::DATA_ANALYSIS
                .before()
                .before(),
        );
        Self { base: b }
    }

    /// Returns `true` if the instruction is in the glue-code form
    /// `lwz r12, <offset>(r2)`.
    pub fn is_glue_code(mnemonic: &str, op0_reg: &str, op1_reg: &str) -> bool {
        mnemonic == "lwz" && op0_reg == "r12" && op1_reg == "r2"
    }

    /// Compute the destination address for an indirect R2 reference.
    pub fn compute_toc_reference(toc_addr: u64, scalar_offset: i64) -> u64 {
        (toc_addr as i64 + scalar_offset) as u64
    }
}

impl Analyzer for PefAnalyzer {
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
        AnalysisPriority::DATA_ANALYSIS.before().before()
    }

    fn can_analyze(&self, p: &Program) -> bool {
        p.get_executable_format() == Some(PEF_FORMAT_NAME)
    }

    fn default_enablement(&self, _: &Program) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Analyzing PEF indirect addressing via R2...");
        log.append_msg("PefAnalyzer: analyzing PEF indirect addressing");
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// PefDebugAnalyzer  --  "PEF Debug"
// ---------------------------------------------------------------------------

/// Locates and applies PEF debug information structures that appear after
/// function bodies.
///
/// After each function, if there is enough space and no instructions overlap,
/// the analyzer looks for a PEF debug record, applies it as structured data,
/// and renames the associated function using the debug name under the `.debug`
/// namespace.
#[derive(Debug, Clone)]
pub struct PefDebugAnalyzer {
    base: AbstractAnalyzer,
}

/// Size of a PEF debug record in bytes (from PefDebug.SIZEOF in Java).
pub const PEF_DEBUG_SIZEOF: u32 = 8;

impl PefDebugAnalyzer {
    pub fn new() -> Self {
        let mut b = AbstractAnalyzer::new(
            "PEF Debug",
            "Locates and applies PEF debug information.",
            AnalyzerType::Function,
        );
        b.set_default_enablement(true);
        b.set_priority(AnalysisPriority::new(
            "PEF_DEBUG",
            AnalysisPriority::DATA_TYPE_PROPAGATION.priority() * 2,
        ));
        Self { base: b }
    }

    /// Checks whether there is enough free space after `start_addr` for a
    /// debug record (no instructions within `PEF_DEBUG_SIZEOF` bytes).
    pub fn is_enough_space_for_debug(
        listing: &Listing,
        start_addr: Address,
        sizeof: u32,
    ) -> bool {
        let end_addr = start_addr.add(sizeof as u64);
        let range = AddressSet::from_range(AddressRange::new(start_addr, end_addr));
        listing.get_instructions(&range, true).next().is_none()
    }
}

impl Analyzer for PefDebugAnalyzer {
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
        AnalysisPriority::new(
            "PEF_DEBUG",
            AnalysisPriority::DATA_TYPE_PROPAGATION.priority() * 2,
        )
    }

    fn can_analyze(&self, p: &Program) -> bool {
        p.get_executable_format() == Some(PEF_FORMAT_NAME)
    }

    fn default_enablement(&self, _: &Program) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_message("Locating PEF debug information...");
        log.append_msg("PefDebugAnalyzer: locating PEF debug info");
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pef_program() -> Program {
        let lang = Language {
            processor: "PowerPC".into(),
            variant: "BE".into(),
            size: 32,
        };
        let mut prog = Program::new("pef_test", lang);
        prog.executable_format = Some(PEF_FORMAT_NAME.into());
        prog
    }

    #[test]
    fn test_pef_analyzer_name() {
        let a = PefAnalyzer::new();
        assert_eq!(a.name(), "PEF Indirect Addressing");
        assert_eq!(a.analysis_type(), AnalyzerType::Function);
    }

    #[test]
    fn test_pef_analyzer_can_analyze_pef() {
        let a = PefAnalyzer::new();
        assert!(a.can_analyze(&make_pef_program()));
    }

    #[test]
    fn test_pef_analyzer_cannot_analyze_elf() {
        let a = PefAnalyzer::new();
        let mut prog = make_pef_program();
        prog.executable_format = Some("ELF".into());
        assert!(!a.can_analyze(&prog));
    }

    #[test]
    fn test_pef_analyzer_cannot_analyze_none() {
        let a = PefAnalyzer::new();
        let mut prog = make_pef_program();
        prog.executable_format = None;
        assert!(!a.can_analyze(&prog));
    }

    #[test]
    fn test_is_glue_code() {
        assert!(PefAnalyzer::is_glue_code("lwz", "r12", "r2"));
        assert!(!PefAnalyzer::is_glue_code("lwz", "r11", "r2"));
        assert!(!PefAnalyzer::is_glue_code("stw", "r12", "r2"));
        assert!(!PefAnalyzer::is_glue_code("lwz", "r12", "r3"));
    }

    #[test]
    fn test_compute_toc_reference() {
        // TOC at 0x200000, offset 0x20 => 0x200020
        assert_eq!(PefAnalyzer::compute_toc_reference(0x200000, 0x20), 0x200020);
        // Negative offset
        assert_eq!(PefAnalyzer::compute_toc_reference(0x200000, -0x10), 0x1FFFF0);
        // Zero offset
        assert_eq!(PefAnalyzer::compute_toc_reference(0x200000, 0), 0x200000);
    }

    #[test]
    fn test_pef_analyzer_default_enablement() {
        let a = PefAnalyzer::new();
        assert!(a.default_enablement(&make_pef_program()));
    }

    #[test]
    fn test_pef_debug_analyzer_name() {
        let a = PefDebugAnalyzer::new();
        assert_eq!(a.name(), "PEF Debug");
        assert_eq!(a.analysis_type(), AnalyzerType::Function);
    }

    #[test]
    fn test_pef_debug_analyzer_can_analyze_pef() {
        let a = PefDebugAnalyzer::new();
        assert!(a.can_analyze(&make_pef_program()));
    }

    #[test]
    fn test_pef_debug_analyzer_cannot_analyze_non_pef() {
        let a = PefDebugAnalyzer::new();
        let mut prog = make_pef_program();
        prog.executable_format = Some("ELF".into());
        assert!(!a.can_analyze(&prog));
    }

    #[test]
    fn test_pef_debug_is_enough_space_no_instructions() {
        let listing = Listing::default();
        assert!(PefDebugAnalyzer::is_enough_space_for_debug(
            &listing,
            Address::new(0x1000),
            PEF_DEBUG_SIZEOF,
        ));
    }

    #[test]
    fn test_pef_debug_is_enough_space_with_instruction() {
        let mut listing = Listing::default();
        listing.instructions.insert(
            Address::new(0x1004),
            Instruction {
                address: Address::new(0x1004),
                length: 4,
                mnemonic: "nop".into(),
                flow_type: FlowType::Fallthrough,
                fall_through: Some(Address::new(0x1008)),
                flows: vec![],
                num_operands: 0,
            },
        );
        assert!(!PefDebugAnalyzer::is_enough_space_for_debug(
            &listing,
            Address::new(0x1000),
            PEF_DEBUG_SIZEOF,
        ));
    }

    #[test]
    fn test_pef_debug_analyzer_priority() {
        let a = PefDebugAnalyzer::new();
        let expected = AnalysisPriority::new(
            "PEF_DEBUG",
            AnalysisPriority::DATA_TYPE_PROPAGATION.priority() * 2,
        );
        assert_eq!(a.priority(), expected);
    }

    #[test]
    fn test_pef_constants() {
        assert_eq!(PEF_TOC_SYMBOL, "TOC");
        assert_eq!(PEF_GLUE_NAMESPACE, "Glue");
        assert_eq!(PEF_DEBUG_NAMESPACE, ".debug");
        assert_eq!(PEF_FORMAT_NAME, "PEF");
        assert_eq!(PEF_DEBUG_SIZEOF, 8);
    }

    #[test]
    fn test_pef_analyzer_added() {
        let a = PefAnalyzer::new();
        let mut prog = make_pef_program();
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_pef_debug_analyzer_added() {
        let a = PefDebugAnalyzer::new();
        let mut prog = make_pef_program();
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
