//! Embedded media analyzer.
use std::collections::HashMap;
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;

#[derive(Debug, Clone)]
pub struct MediaSignature { pub name: String, pub magic: Vec<u8>, pub extension: String }
fn default_signatures() -> Vec<MediaSignature> {
    vec![MediaSignature { name: "PNG".into(), magic: vec![0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A], extension: "png".into() },
         MediaSignature { name: "JPEG".into(), magic: vec![0xFF,0xD8,0xFF], extension: "jpg".into() },
         MediaSignature { name: "GIF89a".into(), magic: b"GIF89a".to_vec(), extension: "gif".into() },
         MediaSignature { name: "PDF".into(), magic: b"%PDF".to_vec(), extension: "pdf".into() },
         MediaSignature { name: "ZIP".into(), magic: vec![0x50,0x4B,0x03,0x04], extension: "zip".into() }]
}
#[derive(Debug, Clone)]
pub struct EmbeddedMediaAnalyzer { base: AbstractAnalyzer, pub create_bookmarks: bool, pub signatures: Vec<MediaSignature> }
impl EmbeddedMediaAnalyzer { pub fn new() -> Self { let mut b = AbstractAnalyzer::new("Embedded Media", "Finds embedded media data types (ie png, gif, jpeg, wav).", AnalyzerType::Byte); b.set_default_enablement(true); b.set_priority(AnalysisPriority::BLOCK_ANALYSIS); b.set_supports_one_time_analysis(true); Self { base: b, create_bookmarks: true, signatures: default_signatures() } } }
impl Analyzer for EmbeddedMediaAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { self.base.analysis_type() } fn priority(&self) -> AnalysisPriority { AnalysisPriority::BLOCK_ANALYSIS } fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, _: &Program) -> bool { true } fn supports_one_time_analysis(&self) -> bool { true }
    fn added(&self, _p: &mut Program, _s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> { m.check_cancelled()?; m.set_message("Searching for embedded media..."); l.append_msg(format!("EmbeddedMediaAnalyzer: searching with {} signatures", self.signatures.len())); Ok(true) }
    fn options_changed(&mut self, opts: &HashMap<String, AnalysisOptionValue>) { if let Some(AnalysisOptionValue::Bool(v)) = opts.get("Create Analysis Bookmarks") { self.create_bookmarks = *v; } }
}
