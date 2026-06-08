//! Auto-analysis manager -- orchestrates all automatic analysis.
//!
//! Ported from Ghidra's `ghidra.framework.analysis.AutoAnalysisManager`.
//!
//! The [`AutoAnalysisManager`] maintains a priority queue of pending
//! analysis tasks, runs them in priority order, and reports results.
//! It responds to program change notifications (block added, code
//! defined, function created, etc.) by scheduling the appropriate
//! analyzers.

use std::collections::HashMap;

use super::analyzer::{
    Address, AddressRange, AddressSet, AnalysisOptionValue, AnalysisPriority, AnalysisResults,
    Analyzer, AnalyzerType, BasicTaskMonitor, CancelledError, MessageLog, Program, TaskMonitor,
};

/// Configuration for the analysis manager.
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    /// Maximum number of analyzer invocations per run.
    pub max_iterations: u32,
    /// Wall-clock timeout in milliseconds.
    pub timeout_ms: u64,
    /// Set of analyzer names that are enabled (empty = all enabled).
    pub enabled_analyzers: std::collections::HashSet<String>,
    /// Whether to print per-task timing information.
    pub print_task_times: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            max_iterations: 100,
            timeout_ms: 300_000,
            enabled_analyzers: std::collections::HashSet::new(),
            print_task_times: true,
        }
    }
}

/// A pending analysis task in the queue.
#[derive(Debug, Clone)]
struct PendingTask {
    analyzer_name: String,
    analyzer_type: AnalyzerType,
    priority: AnalysisPriority,
    set: AddressSet,
}

/// The auto-analysis manager.
///
/// Collects program change events, schedules matching analyzers, and
/// runs them to completion.
pub struct AutoAnalysisManager {
    program: Program,
    analyzers: Vec<Box<dyn Analyzer>>,
    pending: Vec<PendingTask>,
    options: AnalysisOptions,
    ignore_changes: bool,
    is_analyzing: bool,
    protected_locations: AddressSet,
    tasks_executed: usize,
    was_cancelled: bool,
    total_time_ms: u64,
    task_times: HashMap<String, u64>,
    cumulative_task_times: HashMap<String, u64>,
}

impl AutoAnalysisManager {
    /// Create a new manager for the given program.
    pub fn new(program: Program) -> Self {
        Self {
            program,
            analyzers: Vec::new(),
            pending: Vec::new(),
            options: AnalysisOptions::default(),
            ignore_changes: false,
            is_analyzing: false,
            protected_locations: AddressSet::new(),
            tasks_executed: 0,
            was_cancelled: false,
            total_time_ms: 0,
            task_times: HashMap::new(),
            cumulative_task_times: HashMap::new(),
        }
    }

    /// Reference to the managed program.
    pub fn program(&self) -> &Program {
        &self.program
    }

    /// Mutable reference to the managed program.
    pub fn program_mut(&mut self) -> &mut Program {
        &mut self.program
    }

    /// Set analysis options.
    pub fn set_options(&mut self, options: AnalysisOptions) {
        self.options = options;
    }

    /// Current analysis options.
    pub fn options(&self) -> &AnalysisOptions {
        &self.options
    }

    /// Whether the manager is currently running analyzers.
    pub fn is_analyzing(&self) -> bool {
        self.is_analyzing
    }

    /// Whether the manager is enabled (always true).
    pub fn is_enabled(&self) -> bool {
        true
    }

    /// Get a message log (creates a new empty one).
    pub fn get_message_log(&mut self) -> MessageLog {
        MessageLog::new()
    }

    /// Register an analyzer.
    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        if !analyzer.can_analyze(&self.program) {
            return;
        }
        self.analyzers.push(analyzer);
    }

    /// Find an analyzer by name.
    pub fn get_analyzer(&self, name: &str) -> Option<&dyn Analyzer> {
        self.analyzers
            .iter()
            .find(|a| a.name() == name)
            .map(|a| &**a)
    }

    /// Number of registered analyzers.
    pub fn num_analyzers(&self) -> usize {
        self.analyzers.len()
    }

    /// Set whether change notifications are ignored.
    pub fn set_ignore_changes(&mut self, state: bool) {
        self.ignore_changes = state;
    }

    /// Mark an address as protected (analyzers should skip it).
    pub fn set_protected_location(&mut self, addr: Address) {
        self.protected_locations.add(addr);
    }

    /// Protected locations set.
    pub fn protected_locations(&self) -> &AddressSet {
        &self.protected_locations
    }

    /// Mutable protected locations set.
    pub fn protected_locations_mut(&mut self) -> &mut AddressSet {
        &mut self.protected_locations
    }

    // -- Change notification methods -----------------------------------------

    /// A new memory block was added.
    pub fn block_added(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        self.schedule_for_type(AnalyzerType::Byte, set.clone());
    }

    /// External addresses were added.
    pub fn external_added(&mut self, addr: Option<Address>) {
        if self.ignore_changes {
            return;
        }
        match addr {
            Some(a) => {
                self.schedule_for_type(AnalyzerType::Byte, AddressSet::from_address(a));
            }
            None => {
                let full = AddressSet::from_range(AddressRange::new(
                    Address::new(0),
                    Address::new(u64::MAX),
                ));
                self.schedule_for_type(AnalyzerType::Byte, full);
            }
        }
    }

    /// Code was defined at an address.
    pub fn code_defined(&mut self, addr: Address) {
        if self.ignore_changes {
            return;
        }
        self.schedule_for_type(AnalyzerType::Instruction, AddressSet::from_address(addr));
    }

    /// Code was defined over a set of addresses.
    pub fn code_defined_set(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        self.schedule_for_type(AnalyzerType::Instruction, set.clone());
    }

    /// Data was defined over a set of addresses.
    pub fn data_defined(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        self.schedule_for_type(AnalyzerType::Data, set.clone());
    }

    /// A function was defined at an address.
    pub fn function_defined(&mut self, addr: Address) {
        if self.ignore_changes {
            return;
        }
        self.schedule_for_type(AnalyzerType::Function, AddressSet::from_address(addr));
    }

    /// Functions were defined over a set.
    pub fn function_defined_set(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        self.schedule_for_type(AnalyzerType::Function, set.clone());
    }

    /// A function's modifier changed at an address.
    pub fn function_modifier_changed(&mut self, addr: Address) {
        if self.ignore_changes {
            return;
        }
        self.schedule_for_type(
            AnalyzerType::FunctionModifiers,
            AddressSet::from_address(addr),
        );
    }

    /// Function modifiers changed over a set.
    pub fn function_modifier_changed_set(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        self.schedule_for_type(AnalyzerType::FunctionModifiers, set.clone());
    }

    /// A function's signature changed at an address.
    pub fn function_signature_changed(&mut self, addr: Address) {
        if self.ignore_changes {
            return;
        }
        self.schedule_for_type(
            AnalyzerType::FunctionSignatures,
            AddressSet::from_address(addr),
        );
    }

    /// Function signatures changed over a set.
    pub fn function_signature_changed_set(&mut self, set: &AddressSet) {
        if self.ignore_changes {
            return;
        }
        self.schedule_for_type(AnalyzerType::FunctionSignatures, set.clone());
    }

    /// Schedule all analyzers to re-analyze everything.
    pub fn re_analyze_all(&mut self, restrict_set: Option<&AddressSet>) {
        let set = match restrict_set {
            Some(s) if !s.is_empty() => s.clone(),
            _ => self.program.memory.clone(),
        };
        self.external_added(None);
        self.block_added(&set);
        if self.program.listing.num_instructions() > 0 {
            self.code_defined_set(&set);
        }
        if self.program.listing.num_defined_data() > 0 {
            self.data_defined(&set);
        }
        if self
            .program
            .function_manager
            .get_functions(true)
            .next()
            .is_some()
        {
            self.function_defined_set(&set);
            self.function_signature_changed_set(&set);
        }
    }

    /// Cancel all queued tasks.
    pub fn cancel_queued_tasks(&mut self) {
        self.pending.clear();
    }

    /// Cumulative time for a named analyzer.
    pub fn cumulative_task_time(&self, name: &str) -> Option<u64> {
        self.cumulative_task_times.get(name).copied()
    }

    /// Task times from the last run.
    pub fn task_times(&self) -> &HashMap<String, u64> {
        &self.task_times
    }

    /// Cumulative task times across all runs.
    pub fn cumulative_tasks(&self) -> &HashMap<String, u64> {
        &self.cumulative_task_times
    }

    /// Total time of the last analysis run in milliseconds.
    pub fn total_time_ms(&self) -> u64 {
        self.total_time_ms
    }

    /// Number of tasks executed in the last run.
    pub fn tasks_executed(&self) -> usize {
        self.tasks_executed
    }

    /// Whether the last run was cancelled.
    pub fn was_cancelled(&self) -> bool {
        self.was_cancelled
    }

    // -- Analysis execution --------------------------------------------------

    /// Run all pending analysis tasks.
    pub fn run_analysis(
        &mut self,
        monitor: &dyn TaskMonitor,
    ) -> Result<AnalysisResults, CancelledError> {
        let start = std::time::Instant::now();
        self.is_analyzing = true;
        self.tasks_executed = 0;
        self.was_cancelled = false;
        self.task_times.clear();
        self.protected_locations.clear();

        monitor.check_cancelled()?;

        // Sort pending by priority (lower value first)
        self.pending.sort_by(|a, b| a.priority.cmp(&b.priority));

        let pending: Vec<PendingTask> = self.pending.drain(..).collect();
        let mut iteration = 0u32;

        for task in &pending {
            monitor.check_cancelled()?;
            if iteration >= self.options.max_iterations {
                break;
            }
            if start.elapsed().as_millis() as u64 > self.options.timeout_ms {
                self.was_cancelled = true;
                break;
            }

            let task_start = std::time::Instant::now();
            let mut log = MessageLog::new();

            // Find matching analyzer
            if let Some(analyzer) = self
                .analyzers
                .iter()
                .find(|a| a.name() == task.analyzer_name)
            {
                let result = analyzer.added(&mut self.program, &task.set, monitor, &mut log);
                match result {
                    Ok(_) => self.tasks_executed += 1,
                    Err(CancelledError) => {
                        self.was_cancelled = true;
                        break;
                    }
                }
            }

            let elapsed_ms = task_start.elapsed().as_millis() as u64;
            *self
                .task_times
                .entry(task.analyzer_name.clone())
                .or_insert(0) += elapsed_ms;
            *self
                .cumulative_task_times
                .entry(task.analyzer_name.clone())
                .or_insert(0) += elapsed_ms;

            iteration += 1;
        }

        self.is_analyzing = false;
        self.total_time_ms = start.elapsed().as_millis() as u64;

        if !self.was_cancelled {
            for analyzer in &self.analyzers {
                analyzer.analysis_ended(&self.program);
            }
        }

        Ok(AnalysisResults {
            tasks_executed: self.tasks_executed,
            was_cancelled: self.was_cancelled,
            total_time_ms: self.total_time_ms,
            task_times: self
                .task_times
                .iter()
                .map(|(n, d)| (n.clone(), *d))
                .collect(),
        })
    }

    // -- Internal helpers ----------------------------------------------------

    fn schedule_for_type(&mut self, atype: AnalyzerType, set: AddressSet) {
        for analyzer in &self.analyzers {
            if analyzer.analysis_type() == atype {
                self.pending.push(PendingTask {
                    analyzer_name: analyzer.name().to_string(),
                    analyzer_type: atype,
                    priority: analyzer.priority(),
                    set: set.clone(),
                });
            }
        }
    }
}

impl std::fmt::Debug for AutoAnalysisManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoAnalysisManager")
            .field("num_analyzers", &self.analyzers.len())
            .field("num_pending", &self.pending.len())
            .field("is_analyzing", &self.is_analyzing)
            .field("tasks_executed", &self.tasks_executed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::super::analyzer::{
        CodeBoundaryAnalyzer, DataReferenceAnalyzer, FunctionStartAnalyzer, Language,
    };
    use super::*;

    fn make_test_program() -> Program {
        let lang = Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let mut prog = Program::new("test", lang);
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        prog
    }

    #[test]
    fn test_manager_creation() {
        let m = AutoAnalysisManager::new(make_test_program());
        assert!(!m.is_analyzing());
        assert!(m.is_enabled());
        assert_eq!(m.num_analyzers(), 0);
    }

    #[test]
    fn test_add_analyzer() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        m.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        m.add_analyzer(Box::new(CodeBoundaryAnalyzer::new()));
        assert_eq!(m.num_analyzers(), 2);
    }

    #[test]
    fn test_find_analyzer() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        m.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        assert!(m.get_analyzer("Function Start Analyzer").is_some());
        assert!(m.get_analyzer("Nope").is_none());
    }

    #[test]
    fn test_run_empty() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap();
        assert_eq!(r.tasks_executed, 0);
        assert!(!r.was_cancelled);
    }

    #[test]
    fn test_run_with_analyzers() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        m.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        m.add_analyzer(Box::new(CodeBoundaryAnalyzer::new()));
        m.add_analyzer(Box::new(DataReferenceAnalyzer::new()));
        let b = AddressRange::new(Address::new(0x401000), Address::new(0x402000));
        m.block_added(&AddressSet::from_range(b));
        let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap();
        assert!(r.tasks_executed >= 2);
    }

    #[test]
    fn test_cancellation() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        m.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        let mon = BasicTaskMonitor::new();
        mon.cancel();
        assert!(m.run_analysis(&mon).is_err());
    }

    #[test]
    fn test_ignore_changes() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        m.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        m.set_ignore_changes(true);
        let b = AddressRange::new(Address::new(0x401000), Address::new(0x402000));
        m.block_added(&AddressSet::from_range(b));
        let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap();
        assert_eq!(r.tasks_executed, 0);
    }

    #[test]
    fn test_cancel_queued() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        m.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        let b = AddressRange::new(Address::new(0x401000), Address::new(0x402000));
        m.block_added(&AddressSet::from_range(b));
        m.cancel_queued_tasks();
        let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap();
        assert_eq!(r.tasks_executed, 0);
    }

    #[test]
    fn test_external_added() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        m.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        m.external_added(Some(Address::new(1)));
        m.external_added(None);
    }

    #[test]
    fn test_event_notifications() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        let s = AddressSet::from_range(AddressRange::new(
            Address::new(0x401000),
            Address::new(0x402000),
        ));
        m.block_added(&s);
        m.code_defined(Address::new(0x401000));
        m.code_defined_set(&s);
        m.data_defined(&s);
        m.function_defined(Address::new(0x401000));
        m.function_defined_set(&s);
        m.function_modifier_changed(Address::new(0x401000));
        m.function_modifier_changed_set(&s);
        m.function_signature_changed(Address::new(0x401000));
        m.function_signature_changed_set(&s);
    }

    #[test]
    fn test_protected_locations() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        m.set_protected_location(Address::new(0x401000));
        assert!(m.protected_locations().contains(&Address::new(0x401000)));
    }

    #[test]
    fn test_re_analyze() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        m.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        m.re_analyze_all(None);
        let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap();
        assert!(!r.was_cancelled);
    }

    #[test]
    fn test_options() {
        let mut m = AutoAnalysisManager::new(make_test_program());
        let opts = AnalysisOptions {
            max_iterations: 50,
            timeout_ms: 60_000,
            enabled_analyzers: std::collections::HashSet::new(),
            print_task_times: false,
        };
        m.set_options(opts);
        assert_eq!(m.options().max_iterations, 50);
    }

    #[test]
    fn test_full_workflow() {
        let mut prog = make_test_program();
        prog.memory_blocks
            .push(super::super::analyzer::MemoryBlock {
                name: ".text".into(),
                start: Address::new(0x401000),
                size: 0x1000,
                is_read: true,
                is_write: false,
                is_execute: true,
                is_initialized: true,
            });
        let mut m = AutoAnalysisManager::new(prog);
        m.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
        m.add_analyzer(Box::new(CodeBoundaryAnalyzer::new()));
        m.add_analyzer(Box::new(DataReferenceAnalyzer::new()));
        let text = AddressSet::from_range(AddressRange::new(
            Address::new(0x401000),
            Address::new(0x402000),
        ));
        m.block_added(&text);
        m.code_defined_set(&text);
        let r = m.run_analysis(&BasicTaskMonitor::new()).unwrap();
        assert!(!r.was_cancelled);
        assert!(r.tasks_executed > 0);
        m.re_analyze_all(None);
        let r2 = m.run_analysis(&BasicTaskMonitor::new()).unwrap();
        assert!(!r2.was_cancelled);
    }
}
