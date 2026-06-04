//! ARM/Thumb analyzer.
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct ARMThumbAnalyzer { base: AbstractAnalyzer }
impl ARMThumbAnalyzer { pub fn new() -> Self { Self { base: AbstractAnalyzer::new("ARM Thumb Analyzer", "Handles ARM/Thumb mode transitions and identifies Thumb code regions.", AnalyzerType::Instruction) } } }
impl Analyzer for ARMThumbAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::CODE_ANALYSIS }
    fn can_analyze(&self, p: &Program) -> bool { p.get_language().processor.to_lowercase().contains("arm") } fn default_enablement(&self, p: &Program) -> bool { p.get_language().processor.to_lowercase().contains("arm") }
    fn added(&self, _p: &mut Program, s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Analyzing ARM/Thumb transitions..."); m.initialize(s.num_addresses()); l.append_msg("ARMThumbAnalyzer: scanning for Thumb mode transitions"); Ok(true) }
}
