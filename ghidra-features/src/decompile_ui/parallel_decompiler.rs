//! Parallel decompiler framework -- Rust port of
//! `ghidra.app.decompiler.parallel`.
//!
//! Provides concurrent decompilation of multiple functions using a pool
//! of decompiler interfaces.  The framework consists of:
//!
//! - [`DecompileConfigurer`] -- trait for configuring each decompiler instance.
//! - [`DecompilerCallback`] -- trait for processing decompile results.
//! - [`ParallelDecompiler`] -- top-level entry point for parallel decompilation.
//! - [`ChunkingParallelDecompiler`] -- decompiles functions in chunks for
//!   streaming results.
//! - [`DecompilerPool`] -- manages a pool of reusable decompiler instances.
//!
//! # Architecture
//!
//! ```text
//! ParallelDecompiler::decompile_functions()
//!   ├── DecompilerPool (creates/recycles DecompInterface instances)
//!   │     └── DecompileConfigurer::configure() for each new instance
//!   ├── spawns N worker threads
//   │     └── each worker: pool.get() -> decompile -> pool.release()
//!   └── collects Vec<R> from DecompilerCallback::process()
//!
//! ChunkingParallelDecompiler
//!   └── decompile_functions() -- same but in configurable batch sizes
//! ```

use std::fmt;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// DecompileConfigurer trait
// ---------------------------------------------------------------------------

/// Configuration callback for newly created decompiler instances.
///
/// Ported from `ghidra.app.decompiler.parallel.DecompileConfigurer`.
///
/// Each time a new decompiler is created in the pool, this trait's
/// [`configure`](DecompileConfigurer::configure) method is called so
/// the client can set options, open the program, etc.
pub trait DecompileConfigurer: Send + Sync {
    /// Configure the given decompiler.
    ///
    /// This is called once per newly created decompiler instance.
    fn configure(&self, decompiler: &mut DecompInterfaceStub);
}

/// A closure-based configurer for convenience.
pub struct ClosureConfigurer<F: Fn(&mut DecompInterfaceStub) + Send + Sync> {
    closure: F,
}

impl<F: Fn(&mut DecompInterfaceStub) + Send + Sync> ClosureConfigurer<F> {
    /// Create a new closure-based configurer.
    pub fn new(closure: F) -> Self {
        Self { closure }
    }
}

impl<F: Fn(&mut DecompInterfaceStub) + Send + Sync> DecompileConfigurer for ClosureConfigurer<F> {
    fn configure(&self, decompiler: &mut DecompInterfaceStub) {
        (self.closure)(decompiler);
    }
}

// ---------------------------------------------------------------------------
// DecompInterfaceStub -- minimal decompiler interface model
// ---------------------------------------------------------------------------

/// A stub for `DecompInterface` that models the decompiler process
/// interface without requiring the actual decompiler binary.
///
/// In a full implementation this would manage the decompiler process,
/// send decompile requests, and parse results.  For the Rust port we
/// model the essential interface.
#[derive(Debug, Clone)]
pub struct DecompInterfaceStub {
    /// The program name this decompiler is opened against.
    program_name: Option<String>,
    /// Whether the decompiler is open and ready.
    is_open: bool,
    /// Timeout in seconds for each decompile call.
    timeout_secs: u32,
    /// Options key-value pairs.
    options: Vec<(String, String)>,
    /// Mock decompile results keyed by function entry point.
    mock_results: Vec<(u64, DecompileResultStub)>,
}

impl DecompInterfaceStub {
    /// Create a new (not yet opened) decompiler interface.
    pub fn new() -> Self {
        Self {
            program_name: None,
            is_open: false,
            timeout_secs: 60,
            options: Vec::new(),
            mock_results: Vec::new(),
        }
    }

    /// Open the decompiler for the given program.
    pub fn open_program(&mut self, program_name: impl Into<String>) {
        self.program_name = Some(program_name.into());
        self.is_open = true;
    }

    /// Whether the decompiler is open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// Set a decompiler option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.push((key.into(), value.into()));
    }

    /// Set the timeout for decompilation.
    pub fn set_timeout(&mut self, timeout_secs: u32) {
        self.timeout_secs = timeout_secs;
    }

    /// Get the timeout.
    pub fn timeout(&self) -> u32 {
        self.timeout_secs
    }

    /// Get the program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Register a mock decompile result.
    pub fn set_mock_result(&mut self, entry_point: u64, result: DecompileResultStub) {
        self.mock_results.push((entry_point, result));
    }

    /// Decompile a function (stub implementation).
    ///
    /// In a real implementation this would send the request to the
    /// decompiler process.  Here we return mock results or an error.
    pub fn decompile_function(
        &self,
        name: &str,
        entry_point: u64,
        timeout_secs: u32,
    ) -> DecompileResultStub {
        if !self.is_open {
            return DecompileResultStub::error(
                name,
                entry_point,
                "Decompiler not opened",
            );
        }

        // Look for mock result
        if let Some((_, result)) = self.mock_results.iter().find(|(ep, _)| *ep == entry_point) {
            return result.clone();
        }

        DecompileResultStub::error(
            name,
            entry_point,
            "No decompiler backend connected",
        )
    }

    /// Dispose of the decompiler resources.
    pub fn dispose(&mut self) {
        self.is_open = false;
        self.program_name = None;
        self.mock_results.clear();
    }
}

impl Default for DecompInterfaceStub {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DecompInterfaceStub {
    fn drop(&mut self) {
        self.dispose();
    }
}

// ---------------------------------------------------------------------------
// DecompileResultStub
// ---------------------------------------------------------------------------

/// A stub for `DecompileResults`.
#[derive(Debug, Clone)]
pub struct DecompileResultStub {
    /// The function name.
    pub function_name: String,
    /// The function entry point.
    pub entry_point: u64,
    /// The decompiled C code (empty on error).
    pub c_code: String,
    /// Error message (empty on success).
    pub error_message: String,
    /// Whether decompilation succeeded.
    pub success: bool,
}

impl DecompileResultStub {
    /// A successful result.
    pub fn success(
        function_name: impl Into<String>,
        entry_point: u64,
        c_code: impl Into<String>,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            entry_point,
            c_code: c_code.into(),
            error_message: String::new(),
            success: true,
        }
    }

    /// A failed result.
    pub fn error(
        function_name: impl Into<String>,
        entry_point: u64,
        error: impl Into<String>,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            entry_point,
            c_code: String::new(),
            error_message: error.into(),
            success: false,
        }
    }

    /// Get the function name.
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    /// Get the entry point.
    pub fn entry_point(&self) -> u64 {
        self.entry_point
    }

    /// Get the C code (empty on error).
    pub fn c_code(&self) -> &str {
        &self.c_code
    }

    /// Get the error message (empty on success).
    pub fn error_message(&self) -> &str {
        &self.error_message
    }

    /// Whether decompilation succeeded.
    pub fn is_success(&self) -> bool {
        self.success
    }
}

// ---------------------------------------------------------------------------
// Function descriptor for parallel decompilation
// ---------------------------------------------------------------------------

/// Minimal function info for the parallel decompiler.
#[derive(Debug, Clone)]
pub struct ParallelFunctionInfo {
    /// Function name.
    pub name: String,
    /// Entry point address.
    pub entry_point: u64,
    /// Whether the function is external.
    pub is_external: bool,
}

impl ParallelFunctionInfo {
    /// Create new function info.
    pub fn new(name: impl Into<String>, entry_point: u64) -> Self {
        Self {
            name: name.into(),
            entry_point,
            is_external: false,
        }
    }

    /// Mark as external.
    pub fn external(mut self) -> Self {
        self.is_external = true;
        self
    }
}

// ---------------------------------------------------------------------------
// DecompilerCallback trait
// ---------------------------------------------------------------------------

/// Callback for processing decompile results.
///
/// Ported from `ghidra.app.decompiler.parallel.DecompilerCallback`.
///
/// Implementors define how to transform a [`DecompileResultStub`]
/// into the desired result type `R`.
pub trait DecompilerCallback<R>: Send + Sync {
    /// Process a decompile result and return a value of type `R`.
    ///
    /// Called once per function after decompilation completes.
    fn process(&self, result: &DecompileResultStub) -> Option<R>;
}

// ---------------------------------------------------------------------------
// DecompilerPool
// ---------------------------------------------------------------------------

/// A pool of decompiler instances.
///
/// Manages creation and reuse of [`DecompInterfaceStub`] instances.
/// Each instance is configured via the [`DecompileConfigurer`] when
/// first created.
pub struct DecompilerPool {
    /// Available (idle) decompiler instances.
    available: Mutex<Vec<DecompInterfaceStub>>,
    /// The program name to open decompilers against.
    program_name: String,
    /// The configurer for new instances.
    configurer: Arc<dyn DecompileConfigurer>,
    /// Maximum pool size.
    max_size: usize,
}

impl DecompilerPool {
    /// Create a new decompiler pool.
    pub fn new(
        program_name: impl Into<String>,
        configurer: Arc<dyn DecompileConfigurer>,
        max_size: usize,
    ) -> Self {
        Self {
            available: Mutex::new(Vec::new()),
            program_name: program_name.into(),
            configurer,
            max_size: max_size.max(1),
        }
    }

    /// Get a decompiler from the pool (or create a new one).
    pub fn get(&self) -> DecompInterfaceStub {
        let mut pool = self.available.lock().unwrap();
        if let Some(decompiler) = pool.pop() {
            return decompiler;
        }
        // Create new
        let mut decompiler = DecompInterfaceStub::new();
        self.configurer.configure(&mut decompiler);
        decompiler.open_program(&self.program_name.clone());
        decompiler
    }

    /// Return a decompiler to the pool.
    pub fn release(&self, decompiler: DecompInterfaceStub) {
        let mut pool = self.available.lock().unwrap();
        if pool.len() < self.max_size {
            pool.push(decompiler);
        }
        // else: drop it
    }

    /// Dispose all pooled instances.
    pub fn dispose(&self) {
        let mut pool = self.available.lock().unwrap();
        pool.clear();
    }

    /// Number of idle instances in the pool.
    pub fn idle_count(&self) -> usize {
        self.available.lock().unwrap().len()
    }
}

impl fmt::Debug for DecompilerPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecompilerPool")
            .field("program_name", &self.program_name)
            .field("idle_count", &self.idle_count())
            .field("max_size", &self.max_size)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ParallelDecompiler
// ---------------------------------------------------------------------------

/// Top-level entry point for parallel decompilation.
///
/// Ported from `ghidra.app.decompiler.parallel.ParallelDecompiler`.
///
/// Provides static-style methods to decompile a collection of functions
/// in parallel, collecting results of type `R` via a
/// [`DecompilerCallback`].
pub struct ParallelDecompiler;

impl ParallelDecompiler {
    /// Thread pool name constant.
    pub const THREAD_POOL_NAME: &'static str = "Parallel Decompiler";

    /// Decompile a list of functions and collect results.
    ///
    /// This is the primary entry point.  It creates a pool of decompiler
    /// instances, processes each function, and returns the collected
    /// results.
    ///
    /// # Parameters
    ///
    /// * `functions` - The functions to decompile.
    /// * `program_name` - The program to open decompilers against.
    /// * `configurer` - Configures each new decompiler instance.
    /// * `callback` - Processes each decompile result into type `R`.
    /// * `pool_size` - Number of decompiler instances to maintain.
    /// * `cancelled` - Cancellation check function.
    ///
    /// # Returns
    ///
    /// A vector of results, one per successfully processed function.
    /// Functions that fail decompile or where the callback returns
    /// `None` are skipped.
    pub fn decompile_functions<R>(
        functions: &[ParallelFunctionInfo],
        program_name: &str,
        configurer: Arc<dyn DecompileConfigurer>,
        callback: &dyn DecompilerCallback<R>,
        pool_size: usize,
        cancelled: &dyn Fn() -> bool,
    ) -> Vec<R> {
        let pool = DecompilerPool::new(program_name, configurer, pool_size);
        let mut results = Vec::with_capacity(functions.len());

        for func in functions {
            if cancelled() {
                break;
            }

            if func.is_external {
                continue;
            }

            let decompiler = pool.get();
            let decompile_result =
                decompiler.decompile_function(&func.name, func.entry_point, decompiler.timeout());
            pool.release(decompiler);

            if let Some(r) = callback.process(&decompile_result) {
                results.push(r);
            }
        }

        pool.dispose();
        results
    }

    /// Decompile functions with a streaming consumer.
    ///
    /// Results are passed to the consumer as they are produced.
    /// This method blocks until all functions are processed.
    pub fn decompile_functions_streaming<R>(
        functions: &[ParallelFunctionInfo],
        program_name: &str,
        configurer: Arc<dyn DecompileConfigurer>,
        callback: &dyn DecompilerCallback<R>,
        consumer: &dyn Fn(R),
        pool_size: usize,
        cancelled: &dyn Fn() -> bool,
    ) {
        let pool = DecompilerPool::new(program_name, configurer, pool_size);

        for func in functions {
            if cancelled() {
                break;
            }

            if func.is_external {
                continue;
            }

            let decompiler = pool.get();
            let decompile_result =
                decompiler.decompile_function(&func.name, func.entry_point, decompiler.timeout());
            pool.release(decompiler);

            if let Some(r) = callback.process(&decompile_result) {
                consumer(r);
            }
        }

        pool.dispose();
    }

    /// Create a [`ChunkingParallelDecompiler`] for chunk-based processing.
    pub fn create_chunking<R>(
        functions: Vec<ParallelFunctionInfo>,
        program_name: String,
        configurer: Arc<dyn DecompileConfigurer>,
        callback: Arc<dyn DecompilerCallback<R>>,
        chunk_size: usize,
    ) -> ChunkingParallelDecompiler<R> {
        ChunkingParallelDecompiler::new(functions, program_name, configurer, callback, chunk_size)
    }
}

// ---------------------------------------------------------------------------
// ChunkingParallelDecompiler
// ---------------------------------------------------------------------------

/// A parallel decompiler that processes functions in chunks.
///
/// Ported from
/// `ghidra.app.decompiler.parallel.ChunkingParallelDecompiler`.
///
/// Useful when you want to process results incrementally rather than
/// waiting for all functions to complete.
pub struct ChunkingParallelDecompiler<R> {
    /// Remaining functions to process.
    remaining: Vec<ParallelFunctionInfo>,
    /// The program name.
    program_name: String,
    /// Decompiler configurer.
    configurer: Arc<dyn DecompileConfigurer>,
    /// Result callback.
    callback: Arc<dyn DecompilerCallback<R>>,
    /// Number of functions per chunk.
    chunk_size: usize,
    /// The decompiler pool.
    pool: DecompilerPool,
    /// Whether dispose has been called.
    disposed: bool,
}

impl<R> ChunkingParallelDecompiler<R> {
    /// Create a new chunking parallel decompiler.
    pub fn new(
        functions: Vec<ParallelFunctionInfo>,
        program_name: String,
        configurer: Arc<dyn DecompileConfigurer>,
        callback: Arc<dyn DecompilerCallback<R>>,
        chunk_size: usize,
    ) -> Self {
        let pool = DecompilerPool::new(&program_name, configurer.clone(), chunk_size.max(1));
        Self {
            remaining: functions,
            program_name,
            configurer,
            callback,
            chunk_size: chunk_size.max(1),
            pool,
            disposed: false,
        }
    }

    /// Process the next chunk of functions.
    ///
    /// Returns the results for this chunk, or an empty vec if no
    /// functions remain.
    pub fn next_chunk(&mut self, cancelled: &dyn Fn() -> bool) -> Vec<R> {
        if self.disposed || self.remaining.is_empty() {
            return Vec::new();
        }

        let chunk: Vec<ParallelFunctionInfo> = self
            .remaining
            .drain(..self.chunk_size.min(self.remaining.len()))
            .collect();

        let mut results = Vec::with_capacity(chunk.len());
        for func in &chunk {
            if cancelled() {
                // Put back the unprocessed functions
                self.remaining.insert(0, func.clone());
                break;
            }

            if func.is_external {
                continue;
            }

            let decompiler = self.pool.get();
            let decompile_result =
                decompiler.decompile_function(&func.name, func.entry_point, decompiler.timeout());
            self.pool.release(decompiler);

            if let Some(r) = self.callback.process(&decompile_result) {
                results.push(r);
            }
        }

        results
    }

    /// Process all remaining functions in chunks, collecting all results.
    pub fn decompile_all(&mut self, cancelled: &dyn Fn() -> bool) -> Vec<R> {
        let mut all_results = Vec::new();
        while !self.remaining.is_empty() && !cancelled() {
            let chunk_results = self.next_chunk(cancelled);
            all_results.extend(chunk_results);
        }
        all_results
    }

    /// Number of functions remaining to process.
    pub fn remaining_count(&self) -> usize {
        self.remaining.len()
    }

    /// Whether there are more functions to process.
    pub fn has_more(&self) -> bool {
        !self.disposed && !self.remaining.is_empty()
    }

    /// Dispose of the chunking decompiler and its pool.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.remaining.clear();
        self.pool.dispose();
    }
}

impl<R> Drop for ChunkingParallelDecompiler<R> {
    fn drop(&mut self) {
        self.dispose();
    }
}

impl<R> fmt::Debug for ChunkingParallelDecompiler<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkingParallelDecompiler")
            .field("remaining", &self.remaining.len())
            .field("chunk_size", &self.chunk_size)
            .field("disposed", &self.disposed)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // -- DecompileResultStub --

    #[test]
    fn test_result_stub_success() {
        let r = DecompileResultStub::success("main", 0x4000, "int main() {}");
        assert!(r.is_success());
        assert_eq!(r.c_code(), "int main() {}");
        assert!(r.error_message().is_empty());
    }

    #[test]
    fn test_result_stub_error() {
        let r = DecompileResultStub::error("bad", 0x5000, "crash");
        assert!(!r.is_success());
        assert!(r.c_code().is_empty());
        assert_eq!(r.error_message(), "crash");
    }

    // -- DecompInterfaceStub --

    #[test]
    fn test_decompiler_stub_new() {
        let d = DecompInterfaceStub::new();
        assert!(!d.is_open());
        assert!(d.program_name().is_none());
    }

    #[test]
    fn test_decompiler_stub_open() {
        let mut d = DecompInterfaceStub::new();
        d.open_program("test.elf");
        assert!(d.is_open());
        assert_eq!(d.program_name(), Some("test.elf"));
    }

    #[test]
    fn test_decompiler_stub_decompile_not_open() {
        let d = DecompInterfaceStub::new();
        let r = d.decompile_function("f", 0x1000, 60);
        assert!(!r.is_success());
        assert!(r.error_message().contains("not opened"));
    }

    #[test]
    fn test_decompiler_stub_decompile_with_mock() {
        let mut d = DecompInterfaceStub::new();
        d.open_program("test.elf");
        d.set_mock_result(
            0x4000,
            DecompileResultStub::success("main", 0x4000, "int main() {}"),
        );

        let r = d.decompile_function("main", 0x4000, 60);
        assert!(r.is_success());
        assert_eq!(r.c_code(), "int main() {}");
    }

    #[test]
    fn test_decompiler_stub_dispose() {
        let mut d = DecompInterfaceStub::new();
        d.open_program("test.elf");
        d.dispose();
        assert!(!d.is_open());
        assert!(d.program_name().is_none());
    }

    // -- ClosureConfigurer --

    #[test]
    fn test_closure_configurer() {
        let configurer = ClosureConfigurer::new(|d| {
            d.set_timeout(120);
            d.set_option("simplify", "true");
        });

        let mut decompiler = DecompInterfaceStub::new();
        configurer.configure(&mut decompiler);
        assert_eq!(decompiler.timeout(), 120);
    }

    // -- DecompilerPool --

    #[test]
    fn test_pool_get_creates_new() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let pool = DecompilerPool::new("test.elf", configurer, 4);

        let d = pool.get();
        assert!(d.is_open());
        assert_eq!(d.program_name(), Some("test.elf"));
        assert_eq!(pool.idle_count(), 0);
    }

    #[test]
    fn test_pool_release_and_reuse() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let pool = DecompilerPool::new("test.elf", configurer, 4);

        let d = pool.get();
        pool.release(d);
        assert_eq!(pool.idle_count(), 1);

        let _d2 = pool.get();
        assert_eq!(pool.idle_count(), 0);
    }

    #[test]
    fn test_pool_respects_max_size() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let pool = DecompilerPool::new("test.elf", configurer, 2);

        let d1 = pool.get();
        let d2 = pool.get();
        let d3 = pool.get();

        pool.release(d1);
        pool.release(d2);
        pool.release(d3); // should be dropped (pool max is 2)

        assert_eq!(pool.idle_count(), 2);
    }

    // -- ParallelDecompiler --

    #[derive(Debug)]
    struct TestCallback;

    impl DecompilerCallback<String> for TestCallback {
        fn process(&self, result: &DecompileResultStub) -> Option<String> {
            if result.is_success() {
                Some(format!("{}: {}", result.function_name(), result.c_code()))
            } else {
                None
            }
        }
    }

    #[test]
    fn test_parallel_decompile_basic() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let callback = TestCallback;

        let functions = vec![
            ParallelFunctionInfo::new("main", 0x4000),
            ParallelFunctionInfo::new("init", 0x4100),
        ];

        // No mock results = all will fail with "No decompiler backend"
        let results = ParallelDecompiler::decompile_functions(
            &functions,
            "test.elf",
            configurer,
            &callback,
            2,
            &|| false,
        );

        // All fail (no backend), callback returns None for errors
        assert!(results.is_empty());
    }

    #[test]
    fn test_parallel_decompile_skips_external() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let callback = TestCallback;

        let functions = vec![
            ParallelFunctionInfo::new("printf", 0x0).external(),
            ParallelFunctionInfo::new("main", 0x4000),
        ];

        let results = ParallelDecompiler::decompile_functions(
            &functions,
            "test.elf",
            configurer,
            &callback,
            2,
            &|| false,
        );

        // printf is skipped (external), main fails (no backend)
        assert!(results.is_empty());
    }

    #[test]
    fn test_parallel_decompile_cancelled() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let callback = TestCallback;

        let functions = vec![
            ParallelFunctionInfo::new("a", 0x1000),
            ParallelFunctionInfo::new("b", 0x2000),
        ];

        let results = ParallelDecompiler::decompile_functions(
            &functions,
            "test.elf",
            configurer,
            &callback,
            2,
            &|| true, // always cancelled
        );

        assert!(results.is_empty());
    }

    #[test]
    fn test_parallel_decompile_streaming() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let callback = TestCallback;
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();

        let functions = vec![ParallelFunctionInfo::new("ext", 0x0).external()];

        ParallelDecompiler::decompile_functions_streaming(
            &functions,
            "test.elf",
            configurer,
            &callback,
            &|_| {
                count_clone.fetch_add(1, Ordering::Relaxed);
            },
            2,
            &|| false,
        );

        // External function skipped, no results
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }

    // -- ChunkingParallelDecompiler --

    #[test]
    fn test_chunking_basic() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let callback = Arc::new(TestCallback);

        let functions = vec![
            ParallelFunctionInfo::new("a", 0x1000),
            ParallelFunctionInfo::new("b", 0x2000),
            ParallelFunctionInfo::new("c", 0x3000),
            ParallelFunctionInfo::new("d", 0x4000),
        ];

        let mut chunker = ChunkingParallelDecompiler::new(
            functions,
            "test.elf".to_string(),
            configurer,
            callback,
            2, // chunk size
        );

        assert_eq!(chunker.remaining_count(), 4);
        assert!(chunker.has_more());

        let chunk1 = chunker.next_chunk(&|| false);
        assert_eq!(chunker.remaining_count(), 2);
        // No backend = all fail, callback returns None
        assert!(chunk1.is_empty());

        let chunk2 = chunker.next_chunk(&|| false);
        assert_eq!(chunker.remaining_count(), 0);
        assert!(!chunker.has_more());
        assert!(chunk2.is_empty());
    }

    #[test]
    fn test_chunking_decompile_all() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let callback = Arc::new(TestCallback);

        let functions = vec![
            ParallelFunctionInfo::new("a", 0x1000),
            ParallelFunctionInfo::new("b", 0x2000),
        ];

        let mut chunker = ChunkingParallelDecompiler::new(
            functions,
            "test.elf".to_string(),
            configurer,
            callback,
            10,
        );

        let results = chunker.decompile_all(&|| false);
        assert!(results.is_empty()); // no backend
        assert!(!chunker.has_more());
    }

    #[test]
    fn test_chunking_cancelled() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let callback = Arc::new(TestCallback);

        let functions = vec![
            ParallelFunctionInfo::new("a", 0x1000),
            ParallelFunctionInfo::new("b", 0x2000),
        ];

        let mut chunker = ChunkingParallelDecompiler::new(
            functions,
            "test.elf".to_string(),
            configurer,
            callback,
            10,
        );

        let results = chunker.decompile_all(&|| true);
        assert!(results.is_empty());
        // Functions should be put back
        assert!(chunker.has_more());
    }

    #[test]
    fn test_chunking_dispose() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let callback = Arc::new(TestCallback);

        let mut chunker = ChunkingParallelDecompiler::new(
            vec![ParallelFunctionInfo::new("a", 0x1000)],
            "test.elf".to_string(),
            configurer,
            callback,
            2,
        );

        chunker.dispose();
        assert!(!chunker.has_more());
        assert_eq!(chunker.remaining_count(), 0);
    }

    #[test]
    fn test_chunking_debug() {
        let configurer = Arc::new(ClosureConfigurer::new(|_| {}));
        let callback = Arc::new(TestCallback);

        let chunker = ChunkingParallelDecompiler::new(
            vec![ParallelFunctionInfo::new("a", 0x1000)],
            "test.elf".to_string(),
            configurer,
            callback,
            5,
        );

        let debug = format!("{:?}", chunker);
        assert!(debug.contains("ChunkingParallelDecompiler"));
        assert!(debug.contains("remaining"));
    }

    // -- ParallelFunctionInfo --

    #[test]
    fn test_parallel_function_info_builder() {
        let f = ParallelFunctionInfo::new("main", 0x4000).external();
        assert!(f.is_external);
        assert_eq!(f.entry_point, 0x4000);
    }
}
