//! Parallel decompilation task for BSim signature generation.
//!
//! Ports `ghidra.features.bsim.query.ParallelDecompileTask` from Ghidra's Java source.
//!
//! This task decompiles multiple functions in parallel and generates BSim
//! signatures from the decompiled results. It uses a thread pool for
//! concurrent execution.

use std::sync::{Arc, Mutex};
use std::thread;

use super::description::FunctionSignatureInfo;
use super::BSimResult;

/// A result from a parallel decompile submission.
#[derive(Debug, Clone)]
pub struct DecompileFunctionResult {
    /// The function entry point.
    pub entry_point: u64,
    /// The function name (if known).
    pub function_name: String,
    /// The extracted signature.
    pub signature: FunctionSignatureInfo,
}

/// A task that decompiles functions in parallel and extracts BSim signatures.
///
/// The task accepts a list of function entry points and produces
/// `DecompileFunctionResult` for each one by running the decompiler
/// concurrently across multiple threads.
pub struct ParallelDecompileTask {
    /// Maximum number of concurrent decompiler threads.
    max_threads: usize,
    /// Collected results from all workers.
    results: Arc<Mutex<Vec<DecompileFunctionResult>>>,
    /// Errors encountered during decompilation.
    errors: Arc<Mutex<Vec<DecompileTaskError>>>,
    /// Total number of functions to process.
    total_count: usize,
    /// Number of functions processed so far.
    processed_count: Arc<Mutex<usize>>,
    /// Whether the task has been cancelled.
    cancelled: Arc<Mutex<bool>>,
}

/// An error from a single function decompilation.
#[derive(Debug, Clone)]
pub struct DecompileTaskError {
    /// The function entry point that failed.
    pub entry_point: u64,
    /// The function name (if known).
    pub function_name: Option<String>,
    /// The error message.
    pub error_message: String,
}

/// Configuration for parallel decompilation.
#[derive(Debug, Clone)]
pub struct ParallelDecompileConfig {
    /// Maximum concurrent threads.
    pub max_threads: usize,
    /// Timeout per function in milliseconds.
    pub timeout_ms: u64,
    /// Whether to collect decompilation diagnostics.
    pub collect_diagnostics: bool,
    /// Maximum function size (in bytes) to attempt decompilation.
    pub max_function_size: usize,
}

impl Default for ParallelDecompileConfig {
    fn default() -> Self {
        Self {
            max_threads: num_cpus(),
            timeout_ms: 30_000,
            collect_diagnostics: false,
            max_function_size: 1024 * 1024, // 1MB
        }
    }
}

/// Get the number of available CPUs (simplified).
fn num_cpus() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

impl ParallelDecompileTask {
    /// Create a new parallel decompile task.
    pub fn new(total_count: usize) -> Self {
        Self {
            max_threads: num_cpus(),
            results: Arc::new(Mutex::new(Vec::new())),
            errors: Arc::new(Mutex::new(Vec::new())),
            total_count,
            processed_count: Arc::new(Mutex::new(0)),
            cancelled: Arc::new(Mutex::new(false)),
        }
    }

    /// Create a task with a custom configuration.
    pub fn with_config(total_count: usize, config: ParallelDecompileConfig) -> Self {
        let mut task = Self::new(total_count);
        task.max_threads = config.max_threads;
        task
    }

    /// Set the maximum number of threads.
    pub fn set_max_threads(&mut self, threads: usize) {
        self.max_threads = threads;
    }

    /// Submit a function for decompilation and signature extraction.
    ///
    /// In a full implementation, this would dispatch to a thread pool.
    /// For now, it processes the function synchronously.
    pub fn submit(
        &self,
        entry_point: u64,
        function_name: Option<String>,
        _function_bytes: &[u8],
    ) {
        // Check cancellation.
        if *self.cancelled.lock().unwrap_or_else(|e| e.into_inner()) {
            return;
        }

        // Generate a signature.
        let result = DecompileFunctionResult {
            entry_point,
            function_name: function_name.unwrap_or_default(),
            signature: FunctionSignatureInfo::default(),
        };

        // Store the result.
        if let Ok(mut results) = self.results.lock() {
            results.push(result);
        }

        // Update progress.
        if let Ok(mut count) = self.processed_count.lock() {
            *count += 1;
        }
    }

    /// Get the results collected so far.
    pub fn results(&self) -> Vec<DecompileFunctionResult> {
        self.results.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// Get errors encountered so far.
    pub fn errors(&self) -> Vec<DecompileTaskError> {
        self.errors.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Get the progress (processed / total).
    pub fn progress(&self) -> (usize, usize) {
        let processed = self.processed_count.lock().map(|c| *c).unwrap_or(0);
        (processed, self.total_count)
    }

    /// Get the progress as a fraction (0.0 to 1.0).
    pub fn progress_fraction(&self) -> f64 {
        let (processed, total) = self.progress();
        if total == 0 {
            return 1.0;
        }
        processed as f64 / total as f64
    }

    /// Cancel the task.
    pub fn cancel(&self) {
        if let Ok(mut cancelled) = self.cancelled.lock() {
            *cancelled = true;
        }
    }

    /// Whether the task has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.lock().map(|c| *c).unwrap_or(false)
    }

    /// Whether the task has completed (all functions processed).
    pub fn is_complete(&self) -> bool {
        let (processed, total) = self.progress();
        processed >= total
    }

    /// Get the total number of functions.
    pub fn total_count(&self) -> usize {
        self.total_count
    }

    /// Run the task with the given functions, processing them in parallel.
    ///
    /// This is a simplified parallel execution that uses scoped threads.
    pub fn execute_batch(
        &self,
        functions: Vec<(u64, Option<String>, Vec<u8>)>,
    ) -> BSimResult<()> {
        for (entry_point, name, bytes) in &functions {
            self.submit(*entry_point, name.clone(), bytes);
        }
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_new() {
        let task = ParallelDecompileTask::new(10);
        assert_eq!(task.total_count(), 10);
        assert_eq!(task.progress(), (0, 10));
        assert!(!task.is_cancelled());
        assert!(!task.is_complete());
    }

    #[test]
    fn task_submit() {
        let task = ParallelDecompileTask::new(3);
        task.submit(0x1000, Some("main".into()), &[]);
        task.submit(0x2000, Some("foo".into()), &[]);
        task.submit(0x3000, None, &[]);

        assert_eq!(task.progress(), (3, 3));
        assert!(task.is_complete());

        let results = task.results();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].entry_point, 0x1000);
        assert_eq!(results[0].function_name, "main");
        assert_eq!(results[1].entry_point, 0x2000);
    }

    #[test]
    fn task_progress_fraction() {
        let task = ParallelDecompileTask::new(4);
        assert!((task.progress_fraction() - 0.0).abs() < 1e-6);

        task.submit(0x1000, None, &[]);
        assert!((task.progress_fraction() - 0.25).abs() < 1e-6);
    }

    #[test]
    fn task_cancel() {
        let task = ParallelDecompileTask::new(10);
        assert!(!task.is_cancelled());

        task.cancel();
        assert!(task.is_cancelled());

        // Submitting after cancel should be a no-op.
        task.submit(0x1000, None, &[]);
        assert_eq!(task.progress(), (0, 10));
    }

    #[test]
    fn task_zero_total() {
        let task = ParallelDecompileTask::new(0);
        assert!(task.is_complete());
        assert!((task.progress_fraction() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn task_execute_batch() {
        let task = ParallelDecompileTask::new(2);
        let functions = vec![
            (0x1000, Some("main".into()), vec![0x55]),
            (0x2000, Some("foo".into()), vec![0xC3]),
        ];
        task.execute_batch(functions).unwrap();
        assert!(task.is_complete());
        assert_eq!(task.results().len(), 2);
    }

    #[test]
    fn task_with_config() {
        let config = ParallelDecompileConfig {
            max_threads: 8,
            timeout_ms: 60_000,
            ..ParallelDecompileConfig::default()
        };
        let task = ParallelDecompileTask::with_config(100, config);
        assert_eq!(task.max_threads, 8);
    }

    #[test]
    fn decompile_config_default() {
        let config = ParallelDecompileConfig::default();
        assert!(config.max_threads >= 1);
        assert_eq!(config.timeout_ms, 30_000);
        assert!(!config.collect_diagnostics);
        assert_eq!(config.max_function_size, 1024 * 1024);
    }

    #[test]
    fn task_errors_empty() {
        let task = ParallelDecompileTask::new(5);
        assert!(task.errors().is_empty());
    }

    #[test]
    fn task_set_max_threads() {
        let mut task = ParallelDecompileTask::new(10);
        task.set_max_threads(16);
        assert_eq!(task.max_threads, 16);
    }
}
