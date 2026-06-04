//! Data operand reference analyzer.
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct DataOperandReferenceAnalyzer { base: AbstractAnalyzer }
impl DataOperandReferenceAnalyzer { pub fn new() -> Self { let mut b = AbstractAnalyzer::new("Data Reference", "Analyzes data referenced by data.", AnalyzerType::Data); b.set_priority(AnalysisPriority::REFERENCE_ANALYSIS.after().after()); Self { base: b } } }
impl Analyzer for DataOperandReferenceAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::REFERENCE_ANALYSIS.after().after() } fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, _: &Program) -> bool { true }
    fn added(&self, _p: &mut Program, s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Analyzing data references..."); m.initialize(s.num_addresses()); l.append_msg(format!("DataOperandReferenceAnalyzer: processing {} addresses", s.num_addresses())); Ok(true) }
}
