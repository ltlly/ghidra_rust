//! Known non-returning function analyzer.
use std::collections::HashSet;
use crate::base::analyzer::core::*; use crate::base::analyzer::priority::*; use crate::base::analyzer::r#trait::*;

const KNOWN_NORETURN: &[&str] = &["exit","_exit","abort","_Exit","quick_exit","ExitProcess","ExitThread","TerminateProcess","TerminateThread","pthread_exit","longjmp","_longjmp","siglongjmp","__cxa_throw","__cxa_rethrow","panic","__assert_fail","__stack_chk_fail"];

#[derive(Debug, Clone)]
pub struct NoReturnKnownAnalyzer { base: AbstractAnalyzer, pub create_bookmarks: bool, function_names: HashSet<String> }
impl NoReturnKnownAnalyzer {
    pub fn new() -> Self { let mut b = AbstractAnalyzer::new("Non-Returning Functions - Known", "Locates known functions by name that generally do not return.", AnalyzerType::Byte); b.set_default_enablement(true); b.set_priority(AnalysisPriority::FORMAT_ANALYSIS.before().before().before()); Self { base: b, create_bookmarks: true, function_names: KNOWN_NORETURN.iter().map(|s| s.to_string()).collect() } }
    fn is_noreturn(&self, name: &str) -> bool { let s = name.trim_start_matches('_'); self.function_names.contains(s) }
}
impl Analyzer for NoReturnKnownAnalyzer {
    fn name(&self) -> &str { self.base.name() } fn description(&self) -> &str { self.base.description() } fn analysis_type(&self) -> AnalyzerType { AnalyzerType::Byte } fn priority(&self) -> AnalysisPriority { AnalysisPriority::FORMAT_ANALYSIS.before().before().before() }
    fn can_analyze(&self, _: &Program) -> bool { true } fn default_enablement(&self, _: &Program) -> bool { true }
    fn added(&self, p: &mut Program, s: &AddressSet, m: &dyn TaskMonitor, l: &mut MessageLog) -> Result<bool, CancelledError> {
        m.check_cancelled()?; m.set_message("Identifying known non-returning functions..."); let mut found = 0u32;
        let addrs: Vec<Address> = p.symbols.keys().filter(|a| s.contains(a)).copied().collect();
        for addr in addrs { m.check_cancelled()?; if let Some(name) = p.symbols.get(&addr).cloned() { if self.is_noreturn(&name) { if let Some(f) = p.function_manager.functions.get_mut(&addr) { f.has_noreturn = true; found += 1; l.append_msg(format!("NoReturnKnown: set noreturn on '{}' at {}", name, addr)); if self.create_bookmarks { p.set_bookmark(addr, BookmarkType::Analysis, "Non-Returning Function", "Identified"); } } } } }
        l.append_msg(format!("NoReturnKnown: identified {} functions", found)); Ok(found > 0)
    }
}
