//! Analysis scheduler, task list, and scheduled task types.

use super::core::*;
use super::priority::*;
use super::r#trait::*;

#[derive(Debug, Clone)]
pub struct AnalysisResults { pub tasks_executed: usize, pub was_cancelled: bool, pub total_time_ms: u64, pub task_times: Vec<(String, u64)> }
impl AnalysisResults { pub fn has_changes(&self) -> bool { self.tasks_executed > 0 && !self.was_cancelled } }

pub(crate) struct AnalysisSchedulerState { pub analyzer: Box<dyn Analyzer>, pub enabled: bool, pub default_enablement: bool, pub add_set: AddressSet, pub remove_set: AddressSet, pub scheduled: bool }
impl AnalysisSchedulerState {
    pub(crate) fn new(analyzer: Box<dyn Analyzer>, program: &Program) -> Self {
        let default_enablement = analyzer.default_enablement(program);
        let lang = program.get_language();
        let enabled = if lang.has_property("DisableAllAnalyzers") { lang.get_property_as_bool(&format!("Analyzers.{}", analyzer.name()), default_enablement) } else { default_enablement };
        Self { analyzer, enabled, default_enablement, add_set: AddressSet::new(), remove_set: AddressSet::new(), scheduled: false }
    }
    pub(crate) fn priority(&self) -> i32 { self.analyzer.priority().priority() }
    pub(crate) fn notify_added(&mut self, addr: Address) { if !self.enabled { return; } self.add_set.add(addr); }
    pub(crate) fn notify_added_set(&mut self, set: &AddressSet) { if !self.enabled { return; } self.add_set.add_all(set); }
    pub(crate) fn notify_removed(&mut self, addr: Address) { if !self.enabled { return; } self.remove_set.add(addr); }
    pub(crate) fn notify_removed_set(&mut self, set: &AddressSet) { if !self.enabled { return; } self.remove_set.add_all(set); }
    pub(crate) fn get_added(&mut self) -> AddressSet { std::mem::take(&mut self.add_set) }
    pub(crate) fn get_removed(&mut self) -> AddressSet { std::mem::take(&mut self.remove_set) }
    pub(crate) fn has_pending_work(&self) -> bool { !self.add_set.is_empty() || !self.remove_set.is_empty() }
    pub(crate) fn run(&mut self, program: &mut Program, monitor: &dyn TaskMonitor, log: &mut MessageLog) -> Result<bool, CancelledError> {
        let add_set = self.get_added(); let remove_set = self.get_removed(); self.scheduled = false;
        monitor.set_message(self.analyzer.name()); monitor.set_progress(0);
        let mut result = false;
        if !add_set.is_empty() { result |= self.analyzer.added(program, &add_set, monitor, log)?; }
        if !remove_set.is_empty() { result |= self.analyzer.removed(program, &remove_set, monitor, log)?; }
        Ok(result)
    }
    pub(crate) fn run_cancelled(&mut self) { self.get_added(); self.get_removed(); self.scheduled = false; }
}

pub(crate) struct AnalysisTaskList { pub(crate) analyzer_type: AnalyzerType, pub(crate) schedulers: Vec<AnalysisSchedulerState> }
impl AnalysisTaskList {
    pub(crate) fn new(analyzer_type: AnalyzerType) -> Self { Self { analyzer_type, schedulers: Vec::new() } }
    pub(crate) fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>, program: &Program) { assert!(!analyzer.name().contains('.'), "Analyzer name may not contain a period: {}", analyzer.name()); self.schedulers.push(AnalysisSchedulerState::new(analyzer, program)); }
    pub(crate) fn notify_added(&mut self, addr: Address) { for s in &mut self.schedulers { s.notify_added(addr); } }
    pub(crate) fn notify_added_set(&mut self, set: &AddressSet) { for s in &mut self.schedulers { s.notify_added_set(set); } }
    pub(crate) fn notify_removed(&mut self, addr: Address) { for s in &mut self.schedulers { s.notify_removed(addr); } }
    pub(crate) fn notify_analysis_ended(&self, program: &Program) { for s in &self.schedulers { s.analyzer.analysis_ended(program); } }
    pub(crate) fn clear(&mut self) { for s in &mut self.schedulers { s.run_cancelled(); } }
    pub(crate) fn get_pending_schedulers(&mut self) -> Vec<(i32, usize)> { let mut p: Vec<(i32, usize)> = self.schedulers.iter().enumerate().filter(|(_, s)| s.has_pending_work() && !s.scheduled).map(|(i, s)| (s.priority(), i)).collect(); p.sort_by_key(|(p, _)| *p); p }
    pub(crate) fn len(&self) -> usize { self.schedulers.len() }
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut AnalysisSchedulerState> { self.schedulers.iter_mut() }
}

pub(crate) struct ScheduledTask { pub priority: i32, pub scheduler_index: usize, pub task_list_index: usize, pub seq: u64 }
impl PartialEq for ScheduledTask { fn eq(&self, other: &Self) -> bool { self.seq == other.seq } }
impl Eq for ScheduledTask {}
impl PartialOrd for ScheduledTask { fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) } }
impl Ord for ScheduledTask { fn cmp(&self, other: &Self) -> std::cmp::Ordering { other.priority.cmp(&self.priority).then_with(|| other.seq.cmp(&self.seq)) } }

#[cfg(test)]
mod tests {
    use super::*;

    fn make_program() -> Program {
        let lang = Language { processor: "x86".into(), variant: "LE".into(), size: 64 };
        let mut p = Program::new("test", lang);
        p.memory.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));
        p
    }

    struct SimpleAnalyzer { name: String }
    impl SimpleAnalyzer { fn new(name: &str) -> Self { Self { name: name.to_string() } } }
    impl Analyzer for SimpleAnalyzer {
        fn name(&self) -> &str { &self.name }
        fn description(&self) -> &str { "test" }
        fn analysis_type(&self) -> AnalyzerType { AnalyzerType::Byte }
        fn priority(&self) -> AnalysisPriority { AnalysisPriority::DATA_TYPE_PROPAGATION }
        fn can_analyze(&self, _: &Program) -> bool { true }
        fn default_enablement(&self, _: &Program) -> bool { true }
        fn added(&self, _p: &mut Program, _s: &AddressSet, _m: &dyn TaskMonitor, _l: &mut MessageLog) -> Result<bool, CancelledError> { Ok(true) }
    }

    #[test]
    fn test_scheduler_state_notify_added() {
        let prog = make_program();
        let mut state = AnalysisSchedulerState::new(Box::new(SimpleAnalyzer::new("Test")), &prog);
        assert!(!state.has_pending_work());
        state.notify_added(Address::new(0x1000));
        assert!(state.has_pending_work());
        let added = state.get_added();
        assert!(added.contains(&Address::new(0x1000)));
        assert!(!state.has_pending_work());
    }

    #[test]
    fn test_scheduler_state_notify_added_set() {
        let prog = make_program();
        let mut state = AnalysisSchedulerState::new(Box::new(SimpleAnalyzer::new("Test")), &prog);
        let set = AddressSet::from_range(AddressRange::new(Address::new(0x1000), Address::new(0x100F)));
        state.notify_added_set(&set);
        assert!(state.has_pending_work());
        let added = state.get_added();
        assert_eq!(added.num_addresses(), 16);
    }

    #[test]
    fn test_scheduler_state_disabled() {
        let prog = make_program();
        let mut state = AnalysisSchedulerState::new(Box::new(SimpleAnalyzer::new("Test")), &prog);
        state.enabled = false;
        state.notify_added(Address::new(0x1000));
        assert!(!state.has_pending_work());
    }

    #[test]
    fn test_task_list_add_and_pending() {
        let prog = make_program();
        let mut list = AnalysisTaskList::new(AnalyzerType::Byte);
        list.add_analyzer(Box::new(SimpleAnalyzer::new("Test")), &prog);
        assert_eq!(list.len(), 1);
        list.notify_added(Address::new(0x1000));
        let pending = list.get_pending_schedulers();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_task_list_clear() {
        let prog = make_program();
        let mut list = AnalysisTaskList::new(AnalyzerType::Byte);
        list.add_analyzer(Box::new(SimpleAnalyzer::new("Test")), &prog);
        list.notify_added(Address::new(0x1000));
        list.clear();
        let pending = list.get_pending_schedulers();
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn test_scheduled_task_ordering() {
        let t1 = ScheduledTask { priority: 1, scheduler_index: 0, task_list_index: 0, seq: 0 };
        let t2 = ScheduledTask { priority: 2, scheduler_index: 0, task_list_index: 0, seq: 1 };
        // Lower priority number = higher priority (BinaryHeap pops max, Ord reverses)
        assert!(t1 > t2); // t1 has lower priority value -> Ord says t1 > t2
    }

    #[test]
    fn test_scheduled_task_same_priority_seq_ordering() {
        let t1 = ScheduledTask { priority: 1, scheduler_index: 0, task_list_index: 0, seq: 0 };
        let t2 = ScheduledTask { priority: 1, scheduler_index: 0, task_list_index: 0, seq: 1 };
        // Same priority, earlier seq should come first (higher in Ord)
        assert!(t1 > t2);
    }

    #[test]
    fn test_analysis_results_has_changes() {
        let r = AnalysisResults { tasks_executed: 3, was_cancelled: false, total_time_ms: 100, task_times: vec![("A".into(), 50)] };
        assert!(r.has_changes());
    }
}
