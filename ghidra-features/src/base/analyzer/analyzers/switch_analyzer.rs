//! Switch table analyzer.
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct SwitchAnalyzer { base: AbstractAnalyzer, pub min_table_entries: u32 }
impl SwitchAnalyzer { pub fn new() -> Self { Self { base: AbstractAnalyzer::new("Switch Table Analyzer", "Identifies switch/jump tables from indirect jump patterns.", AnalyzerType::Instruction), min_table_entries: 3 } } }
impl Analyzer for SwitchAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::REFERENCE_ANALYSIS.after().after() } fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, _: &Program) -> bool { true }
    fn added(&self, _p: &mut Program, _s: &AddressSet, m: &dyn TaskMonitor, _l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Analyzing switch tables..."); Ok(true) }
}
