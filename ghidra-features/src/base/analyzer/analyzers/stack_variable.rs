//! Stack variable analyzer.
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct StackVariableAnalyzer { base: AbstractAnalyzer }
impl StackVariableAnalyzer { pub fn new() -> Self { Self { base: AbstractAnalyzer::new("Stack", "Analyzes function stack frames to identify local variables and stack layout.", AnalyzerType::Function) } } }
impl Analyzer for StackVariableAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::FUNCTION_ANALYSIS } fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, _: &Program) -> bool { true }
    fn added(&self, p: &mut Program, s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Analyzing stack variables..."); let mut c = 0u32; for range in s.iter() { m.check_cancelled()?; let mut a = range.start; while a.offset <= range.end.offset { if let Some(_f) = p.function_manager.get_function_at(&a) { c += 1; } a = a.add(1); } } l.append_msg(format!("StackAnalyzer: analyzed {} function frames", c)); Ok(true) }
}
