//! The Analyzer trait and AbstractAnalyzer convenience base.

use std::collections::HashMap;
use super::core::*;
use super::priority::*;

pub trait Analyzer: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn analysis_type(&self) -> AnalyzerType;
    fn priority(&self) -> AnalysisPriority;
    fn default_enablement(&self, _program: &Program) -> bool { true }
    fn can_analyze(&self, program: &Program) -> bool;
    fn added(&self, program: &mut Program, set: &AddressSet, monitor: &dyn TaskMonitor, log: &mut MessageLog) -> Result<bool, CancelledError>;
    fn removed(&self, _program: &mut Program, _set: &AddressSet, _monitor: &dyn TaskMonitor, _log: &mut MessageLog) -> Result<bool, CancelledError> { Ok(false) }
    fn register_options(&self, _program: &Program) -> Vec<AnalysisOption> { Vec::new() }
    fn options_changed(&mut self, _options: &HashMap<String, AnalysisOptionValue>) {}
    fn analysis_ended(&self, _program: &Program) {}
    fn supports_one_time_analysis(&self) -> bool { false }
    fn is_prototype(&self) -> bool { false }
}

#[derive(Debug, Clone)]
pub struct AbstractAnalyzer { name: String, description: String, analysis_type: AnalyzerType, priority: AnalysisPriority, supports_one_time: bool, is_prototype: bool, default_enabled: bool }
impl AbstractAnalyzer {
    pub fn new(name: &str, description: &str, analysis_type: AnalyzerType) -> Self { Self { name: name.to_string(), description: description.to_string(), analysis_type, priority: AnalysisPriority::LOW_PRIORITY, supports_one_time: false, is_prototype: false, default_enabled: true } }
    pub fn set_priority(&mut self, p: AnalysisPriority) { self.priority = p; }
    pub fn set_supports_one_time_analysis(&mut self, e: bool) { self.supports_one_time = e; }
    pub fn set_is_prototype(&mut self, p: bool) { self.is_prototype = p; }
    pub fn set_default_enablement(&mut self, e: bool) { self.default_enabled = e; }
    pub fn name(&self) -> &str { &self.name }
    pub fn description(&self) -> &str { &self.description }
    pub fn analysis_type(&self) -> AnalyzerType { self.analysis_type }
    pub fn priority(&self) -> AnalysisPriority { self.priority }
    pub fn supports_one_time_analysis(&self) -> bool { self.supports_one_time }
    pub fn is_prototype(&self) -> bool { self.is_prototype }
    pub fn default_enablement(&self, _program: &Program) -> bool { self.default_enabled }
}
