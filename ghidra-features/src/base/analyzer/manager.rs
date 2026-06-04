//! The AutoAnalysisManager -- orchestrates all analysis.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::{Duration, Instant};

use super::core::*;
use super::priority::*;
use super::scheduler::*;
use super::r#trait::*;

#[derive(Debug, Clone)]
pub struct AnalysisOptions { pub max_iterations: u32, pub timeout_ms: u64, pub enabled_analyzers: HashSet<String>, pub print_task_times: bool }
impl Default for AnalysisOptions { fn default() -> Self { Self { max_iterations: 100, timeout_ms: 300_000, enabled_analyzers: HashSet::new(), print_task_times: true } } }

pub struct AutoAnalysisManager {
    program: Program, task_lists: Vec<AnalysisTaskList>, queue: BinaryHeap<ScheduledTask>, seq_counter: u64,
    options: AnalysisOptions, ignore_changes: bool, is_analyzing: bool,
    cumulative_tasks: HashMap<String, Duration>, timed_tasks: HashMap<String, Duration>,
    protected_locations: AddressSet, tasks_executed: usize, was_cancelled: bool, total_time_ms: u64,
}

impl AutoAnalysisManager {
    pub fn new(program: Program) -> Self {
        let task_lists = vec![AnalysisTaskList::new(AnalyzerType::Byte), AnalysisTaskList::new(AnalyzerType::Instruction), AnalysisTaskList::new(AnalyzerType::Function), AnalysisTaskList::new(AnalyzerType::FunctionModifiers), AnalysisTaskList::new(AnalyzerType::FunctionSignatures), AnalysisTaskList::new(AnalyzerType::Data)];
        Self { program, task_lists, queue: BinaryHeap::new(), seq_counter: 0, options: AnalysisOptions::default(), ignore_changes: false, is_analyzing: false, cumulative_tasks: HashMap::new(), timed_tasks: HashMap::new(), protected_locations: AddressSet::new(), tasks_executed: 0, was_cancelled: false, total_time_ms: 0 }
    }
    pub fn program(&self) -> &Program { &self.program }
    pub fn program_mut(&mut self) -> &mut Program { &mut self.program }
    pub fn set_options(&mut self, options: AnalysisOptions) { self.options = options; }
    pub fn options(&self) -> &AnalysisOptions { &self.options }
    pub fn get_message_log(&mut self) -> MessageLog { MessageLog::new() }
    pub fn get_analyzer(&self, name: &str) -> Option<&dyn Analyzer> { for list in &self.task_lists { for s in &list.schedulers { if s.analyzer.name() == name { return Some(&*s.analyzer); } } } None }
    pub fn num_analyzers(&self) -> usize { self.task_lists.iter().map(|l| l.len()).sum() }
    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) { if !analyzer.can_analyze(&self.program) { return; } let i = self.idx(analyzer.analysis_type()); self.task_lists[i].add_analyzer(analyzer, &self.program); }
    pub fn schedule_one_time_analysis(&mut self, analyzer: Box<dyn Analyzer>, set: &AddressSet) { let i = self.idx(analyzer.analysis_type()); let l = &mut self.task_lists[i]; let si = l.schedulers.len(); l.add_analyzer(analyzer, &self.program); l.schedulers[si].notify_added_set(set); }
    pub fn set_ignore_changes(&mut self, state: bool) { self.ignore_changes = state; }
    pub fn is_analyzing(&self) -> bool { self.is_analyzing }
    pub fn set_debug(&mut self, _d: bool) {}
    pub fn is_enabled(&self) -> bool { true }
    pub fn block_added(&mut self, set: &AddressSet) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::Byte); self.task_lists[i].notify_added_set(set); }
    pub fn external_added(&mut self, addr: Option<Address>) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::Byte); match addr { Some(a) => self.task_lists[i].notify_added(a), None => { let s = AddressSet::from_range(AddressRange::new(Address::in_space(Address::EXTERNAL_SPACE, 0), Address::in_space(Address::EXTERNAL_SPACE, u64::MAX))); self.task_lists[i].notify_added_set(&s); } } }
    pub fn code_defined(&mut self, addr: Address) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::Instruction); self.task_lists[i].notify_added(addr); }
    pub fn code_defined_set(&mut self, set: &AddressSet) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::Instruction); self.task_lists[i].notify_added_set(set); }
    pub fn data_defined(&mut self, set: &AddressSet) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::Data); self.task_lists[i].notify_added_set(set); }
    pub fn function_defined(&mut self, addr: Address) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::Function); self.task_lists[i].notify_added(addr); }
    pub fn function_defined_set(&mut self, set: &AddressSet) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::Function); self.task_lists[i].notify_added_set(set); }
    pub fn function_modifier_changed(&mut self, addr: Address) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::FunctionModifiers); self.task_lists[i].notify_added(addr); }
    pub fn function_modifier_changed_set(&mut self, set: &AddressSet) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::FunctionModifiers); self.task_lists[i].notify_added_set(set); }
    pub fn function_signature_changed(&mut self, addr: Address) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::FunctionSignatures); self.task_lists[i].notify_added(addr); }
    pub fn function_signature_changed_set(&mut self, set: &AddressSet) { if self.ignore_changes { return; } let i = self.idx(AnalyzerType::FunctionSignatures); self.task_lists[i].notify_added_set(set); }
    pub fn re_analyze_all(&mut self, restrict_set: Option<&AddressSet>) {
        let set = match restrict_set { Some(s) if !s.is_empty() => s.clone(), _ => self.program.memory.clone() };
        self.external_added(None); self.block_added(&set);
        if self.program.listing.num_instructions() > 0 { self.code_defined_set(&set); }
        if self.program.listing.num_defined_data() > 0 { self.data_defined(&set); }
        if self.program.function_manager.get_functions(true).next().is_some() { self.function_defined_set(&set); self.function_signature_changed_set(&set); }
    }
    pub fn set_protected_location(&mut self, addr: Address) { self.protected_locations.add(addr); }
    pub fn protected_locations(&self) -> &AddressSet { &self.protected_locations }
    pub fn protected_locations_mut(&mut self) -> &mut AddressSet { &mut self.protected_locations }
    pub fn run_analysis(&mut self, monitor: &dyn TaskMonitor) -> Result<AnalysisResults, CancelledError> {
        let start = Instant::now(); self.is_analyzing = true; self.tasks_executed = 0; self.was_cancelled = false; self.timed_tasks.clear(); self.protected_locations.clear();
        self.enqueue_pending(); monitor.check_cancelled()?;
        let mut iteration = 0u32;
        while !self.queue.is_empty() && iteration < self.options.max_iterations {
            monitor.check_cancelled()?;
            if start.elapsed().as_millis() as u64 > self.options.timeout_ms { log::warn!("Analysis timeout reached after {}ms", self.options.timeout_ms); self.was_cancelled = true; break; }
            let task = self.queue.pop().expect("queue is non-empty"); iteration += 1;
            let task_start = Instant::now();
            let task_name = { let list = &mut self.task_lists[task.task_list_index]; let s = &mut list.schedulers[task.scheduler_index]; s.analyzer.name().to_string() };
            let mut log = MessageLog::new();
            let result = { let list = &mut self.task_lists[task.task_list_index]; let s = &mut list.schedulers[task.scheduler_index]; s.run(&mut self.program, monitor, &mut log) };
            let elapsed = task_start.elapsed();
            match result { Ok(_) => { self.tasks_executed += 1; } Err(CancelledError) => { self.was_cancelled = true; break; } }
            *self.timed_tasks.entry(task_name.clone()).or_insert(Duration::ZERO) += elapsed;
            *self.cumulative_tasks.entry(task_name).or_insert(Duration::ZERO) += elapsed;
            self.enqueue_pending();
        }
        self.is_analyzing = false; self.total_time_ms = start.elapsed().as_millis() as u64;
        if !self.was_cancelled { for list in &self.task_lists { list.notify_analysis_ended(&self.program); } }
        Ok(AnalysisResults { tasks_executed: self.tasks_executed, was_cancelled: self.was_cancelled, total_time_ms: self.total_time_ms, task_times: self.timed_tasks.iter().map(|(n, d)| (n.clone(), d.as_millis() as u64)).collect() })
    }
    fn enqueue_pending(&mut self) { for (li, list) in self.task_lists.iter_mut().enumerate() { let pending = list.get_pending_schedulers(); for (p, si) in pending { list.schedulers[si].scheduled = true; self.queue.push(ScheduledTask { priority: p, scheduler_index: si, task_list_index: li, seq: self.seq_counter }); self.seq_counter += 1; } } }
    pub fn cancel_queued_tasks(&mut self) { self.queue.clear(); for l in &mut self.task_lists { l.clear(); } }
    pub fn cumulative_task_time(&self, name: &str) -> Option<Duration> { self.cumulative_tasks.get(name).copied() }
    pub fn task_times(&self) -> &HashMap<String, Duration> { &self.timed_tasks }
    pub fn cumulative_tasks(&self) -> &HashMap<String, Duration> { &self.cumulative_tasks }
    pub fn total_time_ms(&self) -> u64 { self.total_time_ms }
    pub fn tasks_executed(&self) -> usize { self.tasks_executed }
    pub fn was_cancelled(&self) -> bool { self.was_cancelled }
    fn idx(&self, at: AnalyzerType) -> usize { match at { AnalyzerType::Byte => 0, AnalyzerType::Instruction => 1, AnalyzerType::Function => 2, AnalyzerType::FunctionModifiers => 3, AnalyzerType::FunctionSignatures => 4, AnalyzerType::Data => 5 } }
}
