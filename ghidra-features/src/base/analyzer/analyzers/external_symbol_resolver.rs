//! External symbol resolver analyzer.
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct ExternalSymbolResolverAnalyzer { base: AbstractAnalyzer }
impl ExternalSymbolResolverAnalyzer { pub fn new() -> Self { let mut b = AbstractAnalyzer::new("External Symbol Resolver", "Links unresolved external symbols to library symbols.", AnalyzerType::Byte); b.set_default_enablement(true); b.set_supports_one_time_analysis(true); b.set_priority(AnalysisPriority::DATA_TYPE_PROPAGATION.before().before().before().before()); Self { base: b } } }
impl Analyzer for ExternalSymbolResolverAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::DATA_TYPE_PROPAGATION.before().before().before().before() }
    fn can_analyze(&self, p: &Program) -> bool { let f = p.get_executable_format().unwrap_or(""); f == "ELF" || f == "Mach-O" } fn default_enablement(&self, _: &Program) -> bool { true } fn supports_one_time_analysis(&self) -> bool { true }
    fn added(&self, _p: &mut Program, _s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Resolving external symbols..."); l.append_msg("ExternalSymbolResolver: resolving..."); Ok(true) }
}
