//! Function start analyzer.
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct FunctionStartAnalyzer { base: AbstractAnalyzer }
impl FunctionStartAnalyzer { pub fn new() -> Self { Self { base: AbstractAnalyzer::new("Function Start Analyzer", "Searches for function prologue patterns to identify function entry points.", AnalyzerType::Byte) } } }
impl Analyzer for FunctionStartAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::BLOCK_ANALYSIS.before() } fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, _: &Program) -> bool { true }
    fn added(&self, _p: &mut Program, _s: &AddressSet, m: &dyn TaskMonitor, _l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Searching for function starts..."); Ok(true) }
}
