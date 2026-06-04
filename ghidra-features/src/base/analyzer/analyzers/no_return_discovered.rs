//! Discovered non-returning function analyzer.
use std::collections::HashMap;
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;

#[derive(Debug, Clone)]
pub struct NoReturnLocation { pub suspect_addr: Address, pub why_addr: Option<Address>, pub explanation: String }

#[derive(Debug, Clone)]
pub struct NoReturnDiscoveredAnalyzer { base: AbstractAnalyzer, pub evidence_threshold: u32, pub repair_damage: bool, pub create_bookmarks: bool }
impl NoReturnDiscoveredAnalyzer {
    pub fn new() -> Self { let mut b = AbstractAnalyzer::new("Non-Returning Functions - Discovered", "Discovers indications that functions do not return.", AnalyzerType::Instruction); b.set_priority(AnalysisPriority::DISASSEMBLY.after().after()); b.set_supports_one_time_analysis(true); Self { base: b, evidence_threshold: 3, repair_damage: true, create_bookmarks: true } }
}
impl Analyzer for NoReturnDiscoveredAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::DISASSEMBLY.after().after() }
    fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, p: &Program) -> bool { !p.language.is_segmented() } fn supports_one_time_analysis(&self) -> bool { true }
    fn added(&self, _p: &mut Program, _s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("NoReturn - Finding non-returning functions"); l.append_msg("NoReturnDiscovered: starting analysis"); Ok(true) }
    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) { if let Some(AnalysisOptionValue::Integer(v)) = opts.get("Function Non-return Threshold") { self.evidence_threshold = *v as u32; } if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Repair Flow Damage") { self.repair_damage = *v; } }
}
