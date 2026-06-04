//! DWARF analyzer.
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct DWARFAnalyzer { base: AbstractAnalyzer, dwarf_loaded: bool }
impl DWARFAnalyzer { pub fn new() -> Self { let mut b = AbstractAnalyzer::new("DWARF", "Automatically extracts DWARF info from ELF/MachO/PE files.", AnalyzerType::Byte); b.set_default_enablement(true); b.set_priority(AnalysisPriority::FORMAT_ANALYSIS.after()); b.set_supports_one_time_analysis(true); Self { base: b, dwarf_loaded: false } } pub fn is_already_imported(_p: &Program) -> bool { false } }
impl Analyzer for DWARFAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::FORMAT_ANALYSIS.after() }
    fn can_analyze(&self, p: &Program) -> bool { !p.get_executable_format().unwrap_or("").is_empty() } fn default_enablement(&self, p: &Program) -> bool { !p.language.is_segmented() } fn supports_one_time_analysis(&self) -> bool { true }
    fn added(&self, _p: &mut Program, _s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; if self.dwarf_loaded { return Ok(true); } m.set_message("Extracting DWARF debug info..."); l.append_msg("DWARFAnalyzer: extracting DWARF info"); Ok(true) }
}
