//! Source language analyzer.
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct SourceLanguageAnalyzer { base: AbstractAnalyzer, pub add_spec_extensions: bool }
impl SourceLanguageAnalyzer { pub fn new() -> Self { let mut b = AbstractAnalyzer::new("Source Language Support", "Adds/updates source language-specific support.", AnalyzerType::Byte); b.set_default_enablement(true); b.set_supports_one_time_analysis(true); b.set_priority(AnalysisPriority::FORMAT_ANALYSIS.before().before().before().before().before()); Self { base: b, add_spec_extensions: true } } }
impl Analyzer for SourceLanguageAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::FORMAT_ANALYSIS.before().before().before().before().before() } fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, _: &Program) -> bool { true } fn supports_one_time_analysis(&self) -> bool { true }
    fn added(&self, _p: &mut Program, _s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Detecting source language..."); l.append_msg("SourceLanguageAnalyzer: detecting languages"); Ok(true) }
}
