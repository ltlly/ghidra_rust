//! BSim parallel decompilation extensions.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.ParallelDecompileTask` and
//! `ghidra.features.bsim.query.DecompileFunctionTask` extensions.
//!
//! This module provides supplementary types that extend the base
//! `DecompileFunctionTask` and `ParallelDecompileTask` defined in
//! `bsim::query` with richer configuration, progress tracking,
//! and result aggregation.

use serde::{Deserialize, Serialize};

use super::description::{ExecutableRecord, FunctionDescription, SignatureRecord};

/// Result of decompiling a single function for BSim.
///
/// Richer than the basic task result in `bsim::query` -- this version
/// includes timing information and error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompileFunctionResult {
    /// The function description that was decompiled.
    pub function: FunctionDescription,
    /// The resulting signature (feature vector), if successful.
    pub signature: Option<SignatureRecord>,
    /// Whether decompilation succeeded.
    pub success: bool,
    /// Error message, if decompilation failed.
    pub error: Option<String>,
    /// Time taken to decompile this function (microseconds).
    pub elapsed_us: u64,
}

impl DecompileFunctionResult {
    /// Create a successful result.
    pub fn success(function: FunctionDescription, signature: SignatureRecord) -> Self {
        Self {
            function,
            signature: Some(signature),
            success: true,
            error: None,
            elapsed_us: 0,
        }
    }

    /// Create an error result.
    pub fn error(function: FunctionDescription, error: impl Into<String>) -> Self {
        Self {
            function,
            signature: None,
            success: false,
            error: Some(error.into()),
            elapsed_us: 0,
        }
    }
}

/// Configuration for a parallel decompile task.
///
/// Controls how many functions are decompiled concurrently and
/// what analysis options to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParallelDecompileConfig {
    /// Maximum number of concurrent decompilation threads.
    pub max_threads: usize,
    /// Timeout per function decompilation (seconds).
    pub timeout_secs: u32,
    /// Whether to produce debug signatures (varnode-level).
    pub debug_mode: bool,
    /// Whether to include callgraph edges in signatures.
    pub include_callgraph: bool,
    /// Minimum function size (in bytes) to decompile.
    pub min_function_size: u32,
    /// Maximum function size (in bytes) to decompile.
    pub max_function_size: u32,
}

impl Default for ParallelDecompileConfig {
    fn default() -> Self {
        Self {
            max_threads: 4,
            timeout_secs: 30,
            debug_mode: false,
            include_callgraph: true,
            min_function_size: 0,
            max_function_size: 1024 * 1024, // 1 MB
        }
    }
}

/// Task that decompiles multiple functions in parallel for BSim signature generation.
///
/// This is an extended version of the `ParallelDecompileTask` from `bsim::query`,
/// adding configuration, progress tracking, and rich result aggregation.
#[derive(Debug)]
pub struct ParallelDecompileTaskRunner {
    /// Configuration.
    config: ParallelDecompileConfig,
    /// The executable containing the functions to decompile.
    executable: ExecutableRecord,
    /// Results collected so far.
    results: Vec<DecompileFunctionResult>,
    /// Total number of functions to process.
    total_count: usize,
    /// Number of functions completed (success or failure).
    completed_count: usize,
    /// Whether the task was cancelled.
    cancelled: bool,
}

impl ParallelDecompileTaskRunner {
    /// Create a new parallel decompile task runner.
    pub fn new(executable: ExecutableRecord, config: ParallelDecompileConfig) -> Self {
        Self {
            config,
            executable,
            results: Vec::new(),
            total_count: 0,
            completed_count: 0,
            cancelled: false,
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &ParallelDecompileConfig {
        &self.config
    }

    /// Get the executable record.
    pub fn executable(&self) -> &ExecutableRecord {
        &self.executable
    }

    /// Set the total number of functions expected.
    pub fn set_total_count(&mut self, count: usize) {
        self.total_count = count;
    }

    /// Get the total number of functions.
    pub fn total_count(&self) -> usize {
        self.total_count
    }

    /// Get the number of completed functions.
    pub fn completed_count(&self) -> usize {
        self.completed_count
    }

    /// Get the progress as a fraction [0.0, 1.0].
    pub fn progress(&self) -> f64 {
        if self.total_count == 0 {
            0.0
        } else {
            self.completed_count as f64 / self.total_count as f64
        }
    }

    /// Cancel the task.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Whether the task was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Add a result for a decompiled function.
    pub fn add_result(&mut self, result: DecompileFunctionResult) {
        self.completed_count += 1;
        self.results.push(result);
    }

    /// Get the collected results.
    pub fn results(&self) -> &[DecompileFunctionResult] {
        &self.results
    }

    /// Consume the task runner and take the results.
    pub fn into_results(self) -> Vec<DecompileFunctionResult> {
        self.results
    }

    /// Get only the successful results with signatures.
    pub fn successful_results(&self) -> Vec<&DecompileFunctionResult> {
        self.results.iter().filter(|r| r.success).collect()
    }

    /// Get the number of successful results.
    pub fn success_count(&self) -> usize {
        self.results.iter().filter(|r| r.success).count()
    }

    /// Get the number of failed results.
    pub fn failure_count(&self) -> usize {
        self.results.iter().filter(|r| !r.success).count()
    }

    /// Collect all successful signatures into a Vec.
    pub fn collect_signatures(&self) -> Vec<(&FunctionDescription, &SignatureRecord)> {
        self.results
            .iter()
            .filter_map(|r| {
                r.signature
                    .as_ref()
                    .map(|s| (&r.function, s))
            })
            .collect()
    }
}

/// A single-function decompile task with rich configuration.
///
/// This extends the basic `DecompileFunctionTask` from `bsim::query`
/// with timeout, debug mode, and callgraph options.
#[derive(Debug, Clone)]
pub struct RichDecompileFunctionTask {
    /// The function to decompile.
    pub function: FunctionDescription,
    /// Whether to produce debug-level signatures.
    pub debug_mode: bool,
    /// Whether to include callgraph information.
    pub include_callgraph: bool,
    /// Timeout in seconds for this function.
    pub timeout_secs: u32,
}

impl RichDecompileFunctionTask {
    /// Create a new task for a single function.
    pub fn new(function: FunctionDescription) -> Self {
        Self {
            function,
            debug_mode: false,
            include_callgraph: true,
            timeout_secs: 30,
        }
    }

    /// Enable debug mode for this task.
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug_mode = debug;
        self
    }

    /// Set the timeout for this task.
    pub fn with_timeout(mut self, timeout_secs: u32) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Execute the decompilation (stub for actual implementation).
    ///
    /// In the real implementation, this would invoke the decompiler,
    /// extract feature vectors, and produce a `DecompileFunctionResult`.
    pub fn execute(&self) -> DecompileFunctionResult {
        // Stub: in a real implementation, this would decompile the function
        // and extract a feature vector. For now, produce an error result
        // since we don't have a live decompiler connection.
        DecompileFunctionResult::error(
            self.function.clone(),
            "decompiler not connected",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bsim::FeatureVector;

    fn make_function(name: &str, addr: u64) -> FunctionDescription {
        FunctionDescription::new(0, name, Some(addr))
    }

    #[test]
    fn decompile_function_result_success() {
        let func = make_function("main", 0x1000);
        let sig = SignatureRecord::new(FeatureVector::from_pairs(
            vec![1, 2, 3],
            vec![1.0, 1.0, 1.0],
        ));
        let result = DecompileFunctionResult::success(func, sig);
        assert!(result.success);
        assert!(result.signature.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn decompile_function_result_error() {
        let func = make_function("bad_fn", 0x2000);
        let result = DecompileFunctionResult::error(func, "timeout");
        assert!(!result.success);
        assert!(result.signature.is_none());
        assert_eq!(result.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn parallel_decompile_config_default() {
        let config = ParallelDecompileConfig::default();
        assert_eq!(config.max_threads, 4);
        assert_eq!(config.timeout_secs, 30);
        assert!(!config.debug_mode);
        assert!(config.include_callgraph);
        assert_eq!(config.min_function_size, 0);
    }

    #[test]
    fn parallel_decompile_task_runner_new() {
        let exe = ExecutableRecord::new("abc123", "prog", "x86", "gcc");
        let config = ParallelDecompileConfig::default();
        let runner = ParallelDecompileTaskRunner::new(exe, config);
        assert_eq!(runner.total_count(), 0);
        assert_eq!(runner.completed_count(), 0);
        assert!(!runner.is_cancelled());
    }

    #[test]
    fn parallel_decompile_task_runner_progress() {
        let exe = ExecutableRecord::new("abc123", "prog", "x86", "gcc");
        let config = ParallelDecompileConfig::default();
        let mut runner = ParallelDecompileTaskRunner::new(exe, config);
        runner.set_total_count(10);

        let func = make_function("fn0", 0x1000);
        runner.add_result(DecompileFunctionResult::success(
            func,
            SignatureRecord::new(FeatureVector::from_pairs(vec![1], vec![1.0])),
        ));

        assert_eq!(runner.completed_count(), 1);
        assert!((runner.progress() - 0.1).abs() < 1e-9);
    }

    #[test]
    fn parallel_decompile_task_runner_cancel() {
        let exe = ExecutableRecord::new("abc123", "prog", "x86", "gcc");
        let config = ParallelDecompileConfig::default();
        let mut runner = ParallelDecompileTaskRunner::new(exe, config);
        assert!(!runner.is_cancelled());
        runner.cancel();
        assert!(runner.is_cancelled());
    }

    #[test]
    fn parallel_decompile_task_runner_collect_signatures() {
        let exe = ExecutableRecord::new("abc123", "prog", "x86", "gcc");
        let config = ParallelDecompileConfig::default();
        let mut runner = ParallelDecompileTaskRunner::new(exe, config);

        runner.add_result(DecompileFunctionResult::success(
            make_function("f1", 0x1000),
            SignatureRecord::new(FeatureVector::from_pairs(vec![1], vec![1.0])),
        ));
        runner.add_result(DecompileFunctionResult::error(
            make_function("f2", 0x2000),
            "timeout",
        ));
        runner.add_result(DecompileFunctionResult::success(
            make_function("f3", 0x3000),
            SignatureRecord::new(FeatureVector::from_pairs(vec![2, 3], vec![0.5, 0.8])),
        ));

        assert_eq!(runner.success_count(), 2);
        assert_eq!(runner.failure_count(), 1);

        let sigs = runner.collect_signatures();
        assert_eq!(sigs.len(), 2);
    }

    #[test]
    fn parallel_decompile_task_runner_into_results() {
        let exe = ExecutableRecord::new("abc123", "prog", "x86", "gcc");
        let config = ParallelDecompileConfig::default();
        let mut runner = ParallelDecompileTaskRunner::new(exe, config);
        runner.add_result(DecompileFunctionResult::error(
            make_function("f1", 0x1000),
            "err",
        ));
        let results = runner.into_results();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn rich_decompile_function_task_new() {
        let func = make_function("main", 0x1000);
        let task = RichDecompileFunctionTask::new(func);
        assert!(!task.debug_mode);
        assert!(task.include_callgraph);
        assert_eq!(task.timeout_secs, 30);
    }

    #[test]
    fn rich_decompile_function_task_with_options() {
        let func = make_function("main", 0x1000);
        let task = RichDecompileFunctionTask::new(func)
            .with_debug(true)
            .with_timeout(60);
        assert!(task.debug_mode);
        assert_eq!(task.timeout_secs, 60);
    }

    #[test]
    fn rich_decompile_function_task_execute_stub() {
        let func = make_function("test_fn", 0x1000);
        let task = RichDecompileFunctionTask::new(func);
        let result = task.execute();
        // Stub returns an error since no decompiler is connected.
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn parallel_decompile_progress_zero_total() {
        let exe = ExecutableRecord::new("abc123", "prog", "x86", "gcc");
        let config = ParallelDecompileConfig::default();
        let runner = ParallelDecompileTaskRunner::new(exe, config);
        assert!((runner.progress() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parallel_decompile_results_after_completion() {
        let exe = ExecutableRecord::new("abc123", "prog", "x86", "gcc");
        let config = ParallelDecompileConfig::default();
        let mut runner = ParallelDecompileTaskRunner::new(exe, config);
        runner.set_total_count(3);

        for i in 0..3 {
            let func = make_function(&format!("fn_{}", i), 0x1000 + i as u64 * 0x100);
            runner.add_result(DecompileFunctionResult::success(
                func,
                SignatureRecord::new(FeatureVector::from_pairs(vec![i as u32], vec![1.0])),
            ));
        }

        assert!((runner.progress() - 1.0).abs() < f64::EPSILON);
        assert_eq!(runner.results().len(), 3);
        assert_eq!(runner.success_count(), 3);
        assert_eq!(runner.failure_count(), 0);
    }
}
