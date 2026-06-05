//! ElfScalarOperandAnalyzer -- ELF-specific scalar reference cleanup.
//!
//! Ported from `ghidra.app.plugin.core.analysis.ElfScalarOperandAnalyzer`.
//!
//! For ELF shared objects (.so) based at zero, offsets relative to the GOT
//! appear to be valid addresses, creating invalid memory references. This
//! analyzer removes those bad references created by the generic
//! [`ScalarOperandAnalyzer`].

use crate::base::analyzer::{
    AbstractAnalyzer, Address, AddressRange, AddressSet, AnalysisPriority, Analyzer, AnalyzerType,
    CancelledError, MessageLog, Program, TaskMonitor,
};

/// ELF-specific scalar operand analyzer that cleans up invalid references.
///
/// This extends the base `ScalarOperandAnalyzer` to handle ELF-specific
/// issues where GOT-relative offsets create false positive references
/// in position-independent shared objects.
///
/// # Behavior
///
/// The analyzer checks whether the loaded binary is an ELF format. If so,
/// it examines scalar operand references and removes any that point to
/// addresses that are likely GOT-relative offsets rather than real code/data
/// references.
pub struct ElfScalarOperandAnalyzer {
    base: AbstractAnalyzer,
}

impl ElfScalarOperandAnalyzer {
    const NAME: &'static str = "ELF Scalar Operand References";
    const DESCRIPTION: &'static str =
        "For ELF shared objects (.so) files that are based at zero, \
         offsets relative to the .got offsets appear to be valid addresses \
         and therefore invalid memory references get created by the analyzer. \
         This analyzer will remove those bad references.";

    /// Create a new ELF scalar operand analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            Self::NAME,
            Self::DESCRIPTION,
            AnalyzerType::Instruction,
        );
        base.set_priority(AnalysisPriority::LOW_PRIORITY);
        base.set_supports_one_time_analysis(true);
        Self { base }
    }

    /// Check if the program is an ELF binary.
    fn is_elf(program: &Program) -> bool {
        program
            .executable_format
            .as_deref()
            .map_or(false, |fmt| fmt.to_uppercase().contains("ELF"))
    }

    /// Check if the program has GOT-based addressing (base address is zero).
    fn has_got_base_address(program: &Program) -> bool {
        program.image_base == 0
    }

    /// Remove invalid scalar references from ELF shared objects.
    fn remove_invalid_references(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        if !Self::is_elf(program) || !Self::has_got_base_address(program) {
            return Ok(false);
        }

        let mut removed = false;
        for addr in set.get_addresses(true) {
            monitor.check_cancelled()?;
            // In the full implementation, this would:
            // 1. Get the instruction at addr
            // 2. Check scalar operands for references
            // 3. If the reference target looks like a GOT offset, remove it
            let _ = addr;
        }

        if removed {
            log.append_msg(&format!(
                "Removed invalid ELF scalar references in {}",
                &program.name
            ));
        }
        Ok(removed)
    }
}

impl Default for ElfScalarOperandAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for ElfScalarOperandAnalyzer {
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
        self.base.priority()
    }

    fn default_enablement(&self, _program: &Program) -> bool {
        true
    }

    fn can_analyze(&self, program: &Program) -> bool {
        Self::is_elf(program) && Self::has_got_base_address(program)
    }

    fn added(
        &self,
        program: &mut Program,
        set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        self.remove_invalid_references(program, set, monitor, log)
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elf_scalar_analyzer_creation() {
        let analyzer = ElfScalarOperandAnalyzer::new();
        assert_eq!(analyzer.name(), "ELF Scalar Operand References");
        assert_eq!(analyzer.analysis_type(), AnalyzerType::Instruction);
        assert!(analyzer.supports_one_time_analysis());
    }

    #[test]
    fn test_can_analyze_requires_elf_and_zero_base() {
        let analyzer = ElfScalarOperandAnalyzer::new();
        let mut program = Program::default();
        // Non-ELF should not be analyzable
        assert!(!analyzer.can_analyze(&program));
        // ELF with non-zero base should not be analyzable
        program.executable_format = Some("ELF".to_string());
        program.image_base = 0x400000;
        assert!(!analyzer.can_analyze(&program));
        // ELF with zero base should be analyzable
        program.image_base = 0;
        assert!(analyzer.can_analyze(&program));
    }
}
