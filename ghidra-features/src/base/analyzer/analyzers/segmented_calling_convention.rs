//! Segmented x86 calling convention analyzer.
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentedCallingConvention { Near, Far, Interrupt, Unknown }
impl SegmentedCallingConvention { pub fn name(&self) -> &'static str { match self { SegmentedCallingConvention::Near => "near", SegmentedCallingConvention::Far => "far", SegmentedCallingConvention::Interrupt => "interrupt", SegmentedCallingConvention::Unknown => "unknown" } } }

#[derive(Debug, Clone)]
pub struct SegmentedCallingConventionAnalyzer { base: AbstractAnalyzer }
impl SegmentedCallingConventionAnalyzer {
    pub fn new() -> Self { let mut b = AbstractAnalyzer::new("Segmented X86 Calling Conventions", "Analyzes X86 segmented address spaces to identify calling conventions.", AnalyzerType::Function); b.set_default_enablement(true); b.set_supports_one_time_analysis(true); Self { base: b } }
    pub fn classify_return_opcode(opcode: u8) -> SegmentedCallingConvention { match opcode { 0xC3 | 0xC2 => SegmentedCallingConvention::Near, 0xCB | 0xCA => SegmentedCallingConvention::Far, 0xCF => SegmentedCallingConvention::Interrupt, _ => SegmentedCallingConvention::Unknown } }
}
impl Analyzer for SegmentedCallingConventionAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::FUNCTION_ANALYSIS }
    fn can_analyze(&self, p: &Program) -> bool { p.language.is_segmented() && p.language.processor.to_lowercase().contains("x86") } fn default_enablement(&self, _: &Program) -> bool { true } fn supports_one_time_analysis(&self) -> bool { true }
    fn added(&self, _p: &mut Program, _s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Analyzing segmented x86 calling conventions..."); l.append_msg("SegmentedCallingConventionAnalyzer: analyzing"); Ok(true) }
}
