//! Data reference analyzer.
use std::collections::HashMap;
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone)]
pub struct DataReferenceAnalyzer { base: AbstractAnalyzer, pub create_ascii_strings: bool, pub create_unicode_strings: bool, pub create_pointers: bool, pub create_address_tables: bool, pub min_string_length: u32 }
impl DataReferenceAnalyzer {
    pub fn new() -> Self { Self { base: AbstractAnalyzer::new("Reference", "Analyzes data referenced by instructions.", AnalyzerType::Instruction), create_ascii_strings: true, create_unicode_strings: true, create_pointers: true, create_address_tables: true, min_string_length: 5 } }
    pub fn with_string_creation(mut self, e: bool) -> Self { self.create_ascii_strings = e; self.create_unicode_strings = e; self }
    pub fn with_pointer_creation(mut self, e: bool) -> Self { self.create_pointers = e; self }
}
impl Analyzer for DataReferenceAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::REFERENCE_ANALYSIS } fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, _: &Program) -> bool { true } fn supports_one_time_analysis(&self) -> bool { true }
    fn added(&self, _p: &mut Program, s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Analyzing operand references for data..."); m.initialize(s.num_addresses()); l.append_msg(format!("DataReferenceAnalyzer: scanning {} addresses", s.num_addresses())); Ok(true) }
    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) { if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Ascii String References") { self.create_ascii_strings = *v; } if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Unicode String References") { self.create_unicode_strings = *v; } }
}
