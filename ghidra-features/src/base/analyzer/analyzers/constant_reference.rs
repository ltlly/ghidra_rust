//! Constant propagation analyzer.
use std::collections::HashMap;
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;

#[derive(Debug, Clone)]
pub struct ConstantPropagationContextEvaluator { pub trust_memory_write: bool, pub min_store_load_offset: u64, pub min_speculative_offset: u64, pub max_speculative_offset: u64 }
impl ConstantPropagationContextEvaluator {
    pub fn new(trust: bool) -> Self { Self { trust_memory_write: trust, min_store_load_offset: 4, min_speculative_offset: 1024, max_speculative_offset: 256 } }
    pub fn with_offsets(mut self, sl: u64, ms: u64, mx: u64) -> Self { self.min_store_load_offset = sl; self.min_speculative_offset = ms; self.max_speculative_offset = mx; self }
    pub fn evaluate_constant(&self, value: u64, program: &Program) -> bool { if value == 0 || value == 0xFFFFFFFF || value == 0xFFFF || value == 0xFF00 { return false; } if value < self.min_store_load_offset { return false; } let addr = Address::new(value); program.memory.contains(&addr) || value >= self.min_speculative_offset }
}

#[derive(Debug, Clone)]
pub struct ConstantReferenceAnalyzer { base: AbstractAnalyzer, processor_name: String, pub check_param_refs: bool, pub check_stored_refs: bool, pub trust_write_mem: bool, pub min_known_ref_address: u64, pub min_speculative_ref_address: u64, pub max_speculative_ref_address: u64 }
impl ConstantReferenceAnalyzer {
    pub fn new() -> Self { Self::with_processor("Basic") }
    pub fn with_processor(p: &str) -> Self { let mut b = AbstractAnalyzer::new(&format!("{} Constant Reference Analyzer", p), &format!("{} Constant Propagation Analyzer.", p), AnalyzerType::Instruction); b.set_priority(AnalysisPriority::REFERENCE_ANALYSIS.before().before().before().before()); Self { base: b, processor_name: p.to_string(), check_param_refs: true, check_stored_refs: true, trust_write_mem: true, min_known_ref_address: 4, min_speculative_ref_address: 1024, max_speculative_ref_address: 256 } }
    pub fn processor_name(&self) -> &str { &self.processor_name }
}
impl Analyzer for ConstantReferenceAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::REFERENCE_ANALYSIS.before().before().before().before() }
    fn can_analyze(&self, p: &Program) -> bool { if self.processor_name == "Basic" { p.language.processor != "Specific" } else { p.language.processor == self.processor_name } }
    fn default_enablement(&self, _: &Program) -> bool { true }
    fn added(&self, _p: &mut Program, s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Propagating constants for reference analysis..."); m.initialize(s.num_addresses()); l.append_msg(format!("ConstantReferenceAnalyzer: analyzing {} for {}", s.num_addresses(), self.processor_name)); Ok(true) }
    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) { if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Function parameter/return Pointer analysis") { self.check_param_refs = *v; } if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Stored Value Pointer analysis") { self.check_stored_refs = *v; } }
}
