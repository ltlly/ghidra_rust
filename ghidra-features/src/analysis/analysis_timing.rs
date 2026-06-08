//! Analysis timing utilities.
//!
//! Ported from `AutoAnalysisManager`'s task timing and `StoredAnalyzerTimes`.
//!
//! Provides utilities for tracking, formatting, and persisting analysis
//! task execution times. Used for performance monitoring and for displaying
//! analysis summary reports.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

// ---------------------------------------------------------------------------
// TaskTimer -- tracks execution time for a single task
// ---------------------------------------------------------------------------

/// Tracks execution time for a single analysis task.
///
/// Supports pause/resume for tasks that yield to other tasks.
#[derive(Debug, Clone)]
pub struct TaskTimer {
    /// Name of the task.
    name: String,
    /// Accumulated time in nanoseconds (from completed intervals).
    accumulated_ns: u64,
    /// Start time of the current interval, if running.
    start_ns: Option<u64>,
    /// Whether the timer is currently paused.
    paused: bool,
}

impl TaskTimer {
    /// Create a new timer for the named task.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            accumulated_ns: 0,
            start_ns: None,
            paused: false,
        }
    }

    /// Start the timer.
    pub fn start(&mut self, timestamp_ns: u64) {
        self.start_ns = Some(timestamp_ns);
        self.paused = false;
    }

    /// Pause the timer (accumulates elapsed time).
    pub fn pause(&mut self, timestamp_ns: u64) {
        if let Some(start) = self.start_ns.take() {
            self.accumulated_ns += timestamp_ns.saturating_sub(start);
        }
        self.paused = true;
    }

    /// Resume the timer after a pause.
    pub fn resume(&mut self, timestamp_ns: u64) {
        self.start_ns = Some(timestamp_ns);
        self.paused = false;
    }

    /// Stop the timer and return the total elapsed time in nanoseconds.
    pub fn stop(&mut self, timestamp_ns: u64) -> u64 {
        if let Some(start) = self.start_ns.take() {
            self.accumulated_ns += timestamp_ns.saturating_sub(start);
        }
        self.paused = false;
        self.accumulated_ns
    }

    /// Get the accumulated time in nanoseconds.
    pub fn elapsed_ns(&self) -> u64 {
        self.accumulated_ns
    }

    /// Get the accumulated time in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.accumulated_ns / 1_000_000
    }

    /// Get the accumulated time as a Duration.
    pub fn elapsed_duration(&self) -> Duration {
        Duration::from_nanos(self.accumulated_ns)
    }

    /// Get the task name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the timer is currently paused.
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Whether the timer has been started at least once.
    pub fn has_elapsed(&self) -> bool {
        self.accumulated_ns > 0 || self.start_ns.is_some()
    }
}

// ---------------------------------------------------------------------------
// TaskTimingReport -- formatted report of task execution times
// ---------------------------------------------------------------------------

/// A formatted report of analysis task execution times.
///
/// Ported from the `getTaskTimesString()` method in `AutoAnalysisManager`.
#[derive(Debug, Clone)]
pub struct TaskTimingReport {
    /// Task name to elapsed time in milliseconds.
    entries: BTreeMap<String, u64>,
    /// Total time in milliseconds.
    total_ms: u64,
}

impl TaskTimingReport {
    /// Create a new empty report.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            total_ms: 0,
        }
    }

    /// Add a task time entry.
    pub fn add_entry(&mut self, name: impl Into<String>, time_ms: u64) {
        let name = name.into();
        let current = self.entries.entry(name).or_insert(0);
        *current += time_ms;
        self.total_ms += time_ms;
    }

    /// Get the total time in milliseconds.
    pub fn total_ms(&self) -> u64 {
        self.total_ms
    }

    /// Get the total time formatted as seconds.
    pub fn total_secs(&self) -> f64 {
        self.total_ms as f64 / 1000.0
    }

    /// Get all entries sorted by name.
    pub fn entries(&self) -> Vec<(&str, u64)> {
        self.entries
            .iter()
            .map(|(name, &time)| (name.as_str(), time))
            .collect()
    }

    /// Get entries sorted by time (descending).
    pub fn entries_by_time(&self) -> Vec<(&str, u64)> {
        let mut entries: Vec<(&str, u64)> = self
            .entries
            .iter()
            .map(|(name, &time)| (name.as_str(), time))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries
    }

    /// Whether the report is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Get the time for a specific task.
    pub fn get_time(&self, name: &str) -> Option<u64> {
        self.entries.get(name).copied()
    }

    /// Format the report as a human-readable string.
    ///
    /// Output format matches Ghidra's `getTaskTimesString()`.
    pub fn format_report(&self) -> String {
        if self.entries.is_empty() {
            return "No analysis tasks recorded.".to_string();
        }

        let mut buf = String::new();
        buf.push_str("-----------------------------------------------------\n");

        for (name, &time_ms) in &self.entries {
            let secs = format_time_ms(time_ms);
            buf.push_str(&format!("    {:<50}{}\n", name, secs));
        }

        buf.push_str("-----------------------------------------------------\n");
        buf.push_str(&format!(
            "     Total Time   {} secs\n",
            self.total_ms / 1000
        ));
        buf.push_str("-----------------------------------------------------\n");

        buf
    }
}

impl Default for TaskTimingReport {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TaskTimingReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_report())
    }
}

// ---------------------------------------------------------------------------
// StoredAnalyzerTimes -- persisted cumulative task times
// ---------------------------------------------------------------------------

/// Stores cumulative analysis times across multiple analysis runs.
///
/// Ported from `StoredAnalyzerTimes.java`. Provides a persistent record
/// of how long each analyzer has taken across all analysis sessions.
#[derive(Debug, Clone)]
pub struct StoredAnalyzerTimes {
    /// Per-task cumulative times in milliseconds.
    task_times: BTreeMap<String, u64>,
    /// Cached total time.
    total_time: Option<u64>,
    /// Cached sorted names.
    cached_names: Option<Vec<String>>,
}

impl StoredAnalyzerTimes {
    /// Create a new empty stored times.
    pub fn new() -> Self {
        Self {
            task_times: BTreeMap::new(),
            total_time: None,
            cached_names: None,
        }
    }

    /// Add time for a task.
    pub fn add_time(&mut self, task_name: impl Into<String>, time_ms: u64) {
        let name = task_name.into();
        let current = self.task_times.entry(name).or_insert(0);
        *current += time_ms;
        self.total_time = None;
        self.cached_names = None;
    }

    /// Get the cumulative time for a task.
    pub fn get_time(&self, task_name: &str) -> Option<u64> {
        self.task_times.get(task_name).copied()
    }

    /// Get the total cumulative time across all tasks.
    pub fn total_time(&mut self) -> u64 {
        if let Some(total) = self.total_time {
            return total;
        }
        let total = self.task_times.values().sum();
        self.total_time = Some(total);
        total
    }

    /// Get all task names sorted alphabetically.
    pub fn task_names(&mut self) -> &[String] {
        if self.cached_names.is_none() {
            let mut names: Vec<String> = self.task_times.keys().cloned().collect();
            names.sort();
            self.cached_names = Some(names);
        }
        self.cached_names.as_ref().unwrap()
    }

    /// Whether the stored times are empty.
    pub fn is_empty(&self) -> bool {
        self.task_times.is_empty()
    }

    /// Clear all stored times.
    pub fn clear(&mut self) {
        self.task_times.clear();
        self.total_time = None;
        self.cached_names = None;
    }

    /// Clear time for a specific task.
    pub fn clear_task(&mut self, task_name: &str) {
        self.task_times.remove(task_name);
        self.total_time = None;
        self.cached_names = None;
    }

    /// Get the number of tracked tasks.
    pub fn len(&self) -> usize {
        self.task_times.len()
    }

    /// Merge times from another StoredAnalyzerTimes.
    pub fn merge(&mut self, other: &StoredAnalyzerTimes) {
        for (name, &time) in &other.task_times {
            let current = self.task_times.entry(name.clone()).or_insert(0);
            *current += time;
        }
        self.total_time = None;
        self.cached_names = None;
    }
}

impl Default for StoredAnalyzerTimes {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Format a time in milliseconds as a string with seconds and milliseconds.
///
/// Ported from `StoredAnalyzerTimes.formatTimeMS()`.
pub fn format_time_ms(time_ms: u64) -> String {
    let secs = time_ms / 1000;
    let ms = time_ms % 1000;
    format!("{}.{:03} secs", secs, ms)
}

/// Format a duration as a human-readable string.
pub fn format_duration(duration: Duration) -> String {
    let total_ms = duration.as_millis() as u64;
    format_time_ms(total_ms)
}

// ---------------------------------------------------------------------------
// AnalysisTimingCollector -- convenience wrapper for collecting timings
// ---------------------------------------------------------------------------

/// Collects task timings during an analysis run and produces a report.
///
/// This is a higher-level wrapper around [`TaskTimer`] and
/// [`TaskTimingReport`] that simplifies the common pattern of
/// timing individual analysis tasks and producing a summary.
#[derive(Debug)]
pub struct AnalysisTimingCollector {
    /// Active timers by task name.
    timers: BTreeMap<String, TaskTimer>,
    /// Accumulated report of completed tasks.
    report: TaskTimingReport,
    /// Monotonic timestamp counter.
    timestamp: u64,
}

impl AnalysisTimingCollector {
    /// Create a new timing collector.
    pub fn new() -> Self {
        Self {
            timers: BTreeMap::new(),
            report: TaskTimingReport::new(),
            timestamp: 0,
        }
    }

    /// Start timing a task.
    pub fn start_task(&mut self, name: impl Into<String>) {
        let name = name.into();
        let mut timer = TaskTimer::new(&name);
        timer.start(self.timestamp);
        self.timers.insert(name, timer);
    }

    /// Stop timing a task and record its time.
    pub fn stop_task(&mut self, name: &str) {
        if let Some(mut timer) = self.timers.remove(name) {
            let elapsed = timer.stop(self.timestamp);
            let ms = elapsed / 1_000_000;
            if ms > 0 {
                self.report.add_entry(name, ms);
            }
        }
    }

    /// Advance the internal timestamp.
    pub fn advance_time(&mut self, ns: u64) {
        self.timestamp += ns;
    }

    /// Set the internal timestamp.
    pub fn set_timestamp(&mut self, ns: u64) {
        self.timestamp = ns;
    }

    /// Get the accumulated report.
    pub fn report(&self) -> &TaskTimingReport {
        &self.report
    }

    /// Consume the collector and return the report.
    pub fn into_report(self) -> TaskTimingReport {
        self.report
    }

    /// Get the number of currently active timers.
    pub fn active_timer_count(&self) -> usize {
        self.timers.len()
    }

    /// Whether the report should be printed (total time >= 1 second).
    pub fn should_print_report(&self) -> bool {
        self.report.total_ms() >= 1000
    }
}

impl Default for AnalysisTimingCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_timer_basic() {
        let mut timer = TaskTimer::new("test");
        timer.start(0);
        timer.stop(1_000_000); // 1ms in ns
        assert_eq!(timer.elapsed_ms(), 1);
    }

    #[test]
    fn test_task_timer_pause_resume() {
        let mut timer = TaskTimer::new("test");
        timer.start(0);
        timer.pause(500_000_000); // 500ms
        assert!(timer.is_paused());
        assert_eq!(timer.elapsed_ms(), 500);

        timer.resume(1_000_000_000); // resume at 1s
        timer.stop(1_500_000_000); // stop at 1.5s
        assert_eq!(timer.elapsed_ms(), 1000); // 500ms + 500ms
    }

    #[test]
    fn test_task_timer_name() {
        let timer = TaskTimer::new("MyTimer");
        assert_eq!(timer.name(), "MyTimer");
    }

    #[test]
    fn test_timing_report() {
        let mut report = TaskTimingReport::new();
        report.add_entry("Task1", 1000);
        report.add_entry("Task2", 2000);

        assert_eq!(report.total_ms(), 3000);
        assert_eq!(report.len(), 2);
        assert!(!report.is_empty());
    }

    #[test]
    fn test_timing_report_cumulative() {
        let mut report = TaskTimingReport::new();
        report.add_entry("Task1", 1000);
        report.add_entry("Task1", 500);

        assert_eq!(report.get_time("Task1"), Some(1500));
    }

    #[test]
    fn test_timing_report_format() {
        let mut report = TaskTimingReport::new();
        report.add_entry("TestAnalyzer", 1500);

        let formatted = report.format_report();
        assert!(formatted.contains("TestAnalyzer"));
        assert!(formatted.contains("1.500 secs"));
        assert!(formatted.contains("Total Time"));
    }

    #[test]
    fn test_timing_report_sorted_by_time() {
        let mut report = TaskTimingReport::new();
        report.add_entry("Fast", 100);
        report.add_entry("Slow", 5000);
        report.add_entry("Medium", 1000);

        let sorted = report.entries_by_time();
        assert_eq!(sorted[0].0, "Slow");
        assert_eq!(sorted[1].0, "Medium");
        assert_eq!(sorted[2].0, "Fast");
    }

    #[test]
    fn test_format_time_ms() {
        assert_eq!(format_time_ms(0), "0.000 secs");
        assert_eq!(format_time_ms(1500), "1.500 secs");
        assert_eq!(format_time_ms(60000), "60.000 secs");
        assert_eq!(format_time_ms(42), "0.042 secs");
    }

    #[test]
    fn test_stored_analyzer_times() {
        let mut stored = StoredAnalyzerTimes::new();
        assert!(stored.is_empty());

        stored.add_time("Analyzer1", 1000);
        stored.add_time("Analyzer1", 500);
        stored.add_time("Analyzer2", 2000);

        assert_eq!(stored.get_time("Analyzer1"), Some(1500));
        assert_eq!(stored.get_time("Analyzer2"), Some(2000));
        assert_eq!(stored.len(), 2);
    }

    #[test]
    fn test_stored_analyzer_times_names() {
        let mut stored = StoredAnalyzerTimes::new();
        stored.add_time("Zebra", 1);
        stored.add_time("Alpha", 2);
        stored.add_time("Middle", 3);

        let names = stored.task_names().to_vec();
        assert_eq!(names, vec!["Alpha", "Middle", "Zebra"]);
    }

    #[test]
    fn test_stored_analyzer_times_clear() {
        let mut stored = StoredAnalyzerTimes::new();
        stored.add_time("A", 100);
        stored.add_time("B", 200);

        stored.clear_task("A");
        assert_eq!(stored.len(), 1);
        assert!(stored.get_time("A").is_none());

        stored.clear();
        assert!(stored.is_empty());
    }

    #[test]
    fn test_stored_analyzer_times_merge() {
        let mut s1 = StoredAnalyzerTimes::new();
        s1.add_time("A", 100);

        let mut s2 = StoredAnalyzerTimes::new();
        s2.add_time("A", 50);
        s2.add_time("B", 200);

        s1.merge(&s2);
        assert_eq!(s1.get_time("A"), Some(150));
        assert_eq!(s1.get_time("B"), Some(200));
    }

    #[test]
    fn test_timing_collector() {
        let mut collector = AnalysisTimingCollector::new();
        collector.set_timestamp(0);
        collector.start_task("task1");

        collector.advance_time(5_000_000_000); // 5 seconds
        collector.stop_task("task1");

        let report = collector.report();
        assert_eq!(report.total_ms(), 5000);
    }

    #[test]
    fn test_timing_collector_should_print() {
        let mut collector = AnalysisTimingCollector::new();
        assert!(!collector.should_print_report());

        collector.report.add_entry("test", 500);
        assert!(!collector.should_print_report());

        collector.report.add_entry("test2", 600);
        assert!(collector.should_print_report());
    }
}
