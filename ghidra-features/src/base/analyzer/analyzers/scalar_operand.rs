//! Scalar operand analyzer.
use std::collections::HashMap;
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct ScalarOperandAnalyzer { base: AbstractAnalyzer, pub relocation_guide_enabled: bool }
impl ScalarOperandAnalyzer { pub fn new() -> Self { let mut b = AbstractAnalyzer::new("Scalar Operand References", "Analyzes scalar operands for references to valid addresses.", AnalyzerType::Instruction); b.set_priority(AnalysisPriority::REFERENCE_ANALYSIS.before().before()); Self { base: b, relocation_guide_enabled: true } } }
impl Analyzer for ScalarOperandAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::REFERENCE_ANALYSIS.before().before() }
    fn can_analyze(&self, p: &Program) -> bool { p.get_executable_format() != Some("ELF") && p.language.size >= 32 } fn default_enablement(&self, p: &Program) -> bool { p.get_executable_format() != Some("ELF") && p.language.size >= 32 }
    fn added(&self, _p: &mut Program, s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Analyzing scalar operands..."); m.initialize(s.num_addresses()); l.append_msg(format!("ScalarOperandAnalyzer: scanning {} addresses", s.num_addresses())); Ok(true) }
    fn analysis_ended(&self, _p: &Program) {} fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) { if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Relocation Table Guide") { self.relocation_guide_enabled = *v; } }
}
