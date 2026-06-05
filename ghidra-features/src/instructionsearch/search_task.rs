//! Search task for running instruction searches asynchronously.
//!
//! Ported from `ghidra.app.plugin.core.instructionsearch.ui.SearchInstructionsTask`
//! and `SearchAllInstructionsTask`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{SearchOptions, SearchResult};
use super::model::MaskContainer;
use ghidra_core::Address;

/// State of a search task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchTaskState {
    /// Task has not started.
    Pending,
    /// Task is running.
    Running,
    /// Task completed successfully.
    Completed,
    /// Task was cancelled.
    Cancelled,
    /// Task failed.
    Failed,
}

/// Progress information for a search task.
#[derive(Debug, Clone)]
pub struct SearchTaskProgress {
    /// Number of bytes searched so far.
    pub bytes_searched: u64,
    /// Total bytes to search (0 = unknown).
    pub total_bytes: u64,
    /// Number of matches found so far.
    pub matches_found: u64,
    /// Current address being searched.
    pub current_address: Option<Address>,
}

impl SearchTaskProgress {
    /// Create a new progress.
    pub fn new(bytes_searched: u64, total_bytes: u64, matches_found: u64) -> Self {
        Self {
            bytes_searched,
            total_bytes,
            matches_found,
            current_address: None,
        }
    }

    /// Progress fraction (0.0 to 1.0).
    pub fn fraction(&self) -> Option<f64> {
        if self.total_bytes > 0 {
            Some(self.bytes_searched as f64 / self.total_bytes as f64)
        } else {
            None
        }
    }
}

/// A task for searching instructions in a program.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.SearchInstructionsTask`.
#[derive(Debug)]
pub struct SearchInstructionsTask {
    /// Search options.
    pub options: SearchOptions,
    /// Search pattern (mask containers).
    pub pattern: Vec<MaskContainer>,
    /// Current state.
    state: SearchTaskState,
    /// Results found.
    results: Vec<SearchResult>,
    /// Cancellation flag.
    cancelled: Arc<AtomicBool>,
    /// Counter for bytes searched.
    bytes_searched: Arc<AtomicU64>,
    /// Counter for matches.
    matches_found: Arc<AtomicU64>,
    /// Start time.
    start_time: Option<Instant>,
    /// Address range to search (start, end).
    pub search_range: (Address, Address),
    /// Maximum results to return (0 = unlimited).
    pub max_results: usize,
}

impl SearchInstructionsTask {
    /// Create a new search instructions task.
    pub fn new(
        options: SearchOptions,
        pattern: Vec<MaskContainer>,
        search_range: (Address, Address),
    ) -> Self {
        Self {
            options,
            pattern,
            state: SearchTaskState::Pending,
            results: Vec::new(),
            cancelled: Arc::new(AtomicBool::new(false)),
            bytes_searched: Arc::new(AtomicU64::new(0)),
            matches_found: Arc::new(AtomicU64::new(0)),
            start_time: None,
            search_range,
            max_results: 0,
        }
    }

    /// Start the task.
    pub fn start(&mut self) {
        self.state = SearchTaskState::Running;
        self.start_time = Some(Instant::now());
    }

    /// Cancel the task.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether the task was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    /// Get the current state.
    pub fn state(&self) -> SearchTaskState {
        self.state
    }

    /// Get the results found so far.
    pub fn results(&self) -> &[SearchResult] {
        &self.results
    }

    /// Add a result.
    pub fn add_result(&mut self, result: SearchResult) {
        self.results.push(result);
        self.matches_found.fetch_add(1, Ordering::SeqCst);
    }

    /// Update bytes searched.
    pub fn add_bytes_searched(&self, count: u64) {
        self.bytes_searched.fetch_add(count, Ordering::SeqCst);
    }

    /// Get the current progress.
    pub fn progress(&self) -> SearchTaskProgress {
        let range_size = self.search_range.1.offset.saturating_sub(self.search_range.0.offset);
        SearchTaskProgress {
            bytes_searched: self.bytes_searched.load(Ordering::SeqCst),
            total_bytes: range_size,
            matches_found: self.matches_found.load(Ordering::SeqCst),
            current_address: None,
        }
    }

    /// Mark the task as completed.
    pub fn complete(&mut self) {
        self.state = SearchTaskState::Completed;
    }

    /// Mark the task as failed.
    pub fn fail(&mut self) {
        self.state = SearchTaskState::Failed;
    }

    /// Mark the task as cancelled.
    pub fn mark_cancelled(&mut self) {
        self.state = SearchTaskState::Cancelled;
    }

    /// Whether the task is in a terminal state.
    pub fn is_finished(&self) -> bool {
        matches!(
            self.state,
            SearchTaskState::Completed | SearchTaskState::Cancelled | SearchTaskState::Failed
        )
    }

    /// Get elapsed time.
    pub fn elapsed(&self) -> Option<Duration> {
        self.start_time.map(|t| t.elapsed())
    }

    /// Get the result count.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }
}

/// A task for searching all instructions in a program.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.ui.SearchAllInstructionsTask`.
///
/// This variant searches the entire address space without restriction.
#[derive(Debug)]
pub struct SearchAllInstructionsTask {
    /// The inner search task.
    pub inner: SearchInstructionsTask,
    /// Memory block names to search.
    pub block_names: Vec<String>,
}

impl SearchAllInstructionsTask {
    /// Create a new search-all task.
    pub fn new(
        options: SearchOptions,
        pattern: Vec<MaskContainer>,
        total_range: (Address, Address),
    ) -> Self {
        Self {
            inner: SearchInstructionsTask::new(options, pattern, total_range),
            block_names: Vec::new(),
        }
    }

    /// Start the task.
    pub fn start(&mut self) {
        self.inner.start();
    }

    /// Cancel the task.
    pub fn cancel(&self) {
        self.inner.cancel();
    }

    /// Whether the task was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_task_state() {
        assert!(matches!(SearchTaskState::Pending, SearchTaskState::Pending));
        assert!(matches!(SearchTaskState::Running, SearchTaskState::Running));
    }

    #[test]
    fn test_search_task_progress() {
        let p = SearchTaskProgress::new(50, 100, 3);
        assert_eq!(p.fraction(), Some(0.5));
        assert_eq!(p.matches_found, 3);

        let unknown = SearchTaskProgress::new(50, 0, 3);
        assert!(unknown.fraction().is_none());
    }

    #[test]
    fn test_search_instructions_task_lifecycle() {
        let start_addr = Address::new(0x1000);
        let end_addr = Address::new(0x2000);
        let mut task = SearchInstructionsTask::new(
            SearchOptions::default(),
            Vec::new(),
            (start_addr, end_addr),
        );
        assert_eq!(task.state(), SearchTaskState::Pending);
        assert!(!task.is_finished());

        task.start();
        assert_eq!(task.state(), SearchTaskState::Running);
        assert!(task.elapsed().is_some());

        task.add_result(SearchResult::new(Address::new(0x1004), 4, vec![0x89, 0xe5, 0x83, 0xec]));
        assert_eq!(task.result_count(), 1);

        task.complete();
        assert!(task.is_finished());
        assert_eq!(task.state(), SearchTaskState::Completed);
    }

    #[test]
    fn test_search_instructions_task_cancel() {
        let mut task = SearchInstructionsTask::new(
            SearchOptions::default(),
            Vec::new(),
            (Address::new(0), Address::new(0x10000)),
        );
        task.start();
        assert!(!task.is_cancelled());
        task.cancel();
        assert!(task.is_cancelled());
        task.mark_cancelled();
        assert_eq!(task.state(), SearchTaskState::Cancelled);
    }

    #[test]
    fn test_search_instructions_task_fail() {
        let mut task = SearchInstructionsTask::new(
            SearchOptions::default(),
            Vec::new(),
            (Address::new(0), Address::new(0x10000)),
        );
        task.start();
        task.fail();
        assert!(task.is_finished());
        assert_eq!(task.state(), SearchTaskState::Failed);
    }

    #[test]
    fn test_search_instructions_task_progress() {
        let mut task = SearchInstructionsTask::new(
            SearchOptions::default(),
            Vec::new(),
            (Address::new(0), Address::new(0x1000)),
        );
        task.start();
        task.add_bytes_searched(256);
        let p = task.progress();
        assert_eq!(p.bytes_searched, 256);
        assert_eq!(p.total_bytes, 0x1000);
    }

    #[test]
    fn test_search_all_instructions_task() {
        let mut task = SearchAllInstructionsTask::new(
            SearchOptions::default(),
            Vec::new(),
            (Address::new(0), Address::new(0x10000)),
        );
        task.block_names.push(".text".to_string());
        task.start();
        assert!(!task.is_cancelled());
    }

    #[test]
    fn test_search_instructions_task_max_results() {
        let mut task = SearchInstructionsTask::new(
            SearchOptions::default(),
            Vec::new(),
            (Address::new(0), Address::new(0x10000)),
        );
        task.max_results = 100;
        assert_eq!(task.max_results, 100);
    }
}
