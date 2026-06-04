//! Apply data archive analyzer.
use std::collections::HashMap;
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;
#[derive(Debug, Clone, PartialEq)]
pub enum ArchiveChooserMode { AutoDetect, UserFileArchive(String), UserProjectArchive(String) }
#[derive(Debug, Clone)]
pub struct ApplyDataArchiveAnalyzer { base: AbstractAnalyzer, pub create_bookmarks: bool, pub archive_chooser: ArchiveChooserMode }
impl ApplyDataArchiveAnalyzer { pub fn new() -> Self { let mut b = AbstractAnalyzer::new("Apply Data Archives", "Apply known data type archives based on program information.", AnalyzerType::Byte); b.set_default_enablement(true); b.set_priority(AnalysisPriority::DATA_TYPE_PROPAGATION.after().after().after()); Self { base: b, create_bookmarks: true, archive_chooser: ArchiveChooserMode::AutoDetect } } }
impl Analyzer for ApplyDataArchiveAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::DATA_TYPE_PROPAGATION.after().after().after() } fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, _: &Program) -> bool { true }
    fn added(&self, _p: &mut Program, _s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Applying data archives..."); l.append_msg("ApplyDataArchiveAnalyzer: applying archives"); Ok(true) }
    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) { if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Create Analysis Bookmarks") { self.create_bookmarks = *v; } }
}
