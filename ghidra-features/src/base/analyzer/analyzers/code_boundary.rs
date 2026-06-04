//! Code boundary analyzer.
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct CodeBoundaryAnalyzer { base: AbstractAnalyzer }
impl CodeBoundaryAnalyzer { pub fn new() -> Self { Self { base: AbstractAnalyzer::new("Code Boundary Analyzer", "Identifies code boundaries through control flow analysis and padding detection.", AnalyzerType::Byte) } } }
impl Analyzer for CodeBoundaryAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::BLOCK_ANALYSIS.after() } fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, _: &Program) -> bool { true }
    fn added(&self, _p: &mut Program, _s: &AddressSet, m: &dyn TaskMonitor, _l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Analyzing code boundaries..."); Ok(true) }
}
