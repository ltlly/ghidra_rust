//! Parallel decompilation support.
//!
//! Port of Ghidra's `ghidra.app.decompiler.parallel` package.
//!
//! Provides utilities for decompiling multiple functions in parallel
//! using a chunked approach.


/// Configuration for a single decompile operation.
#[derive(Debug, Clone)]
pub struct DecompileConfigurer {
    /// Whether to produce syntax trees.
    pub syntax_tree: bool,
    /// Whether to produce C code.
    pub c_code: bool,
    /// Timeout in seconds per function.
    pub timeout_secs: u32,
}

impl Default for DecompileConfigurer {
    fn default() -> Self {
        Self {
            syntax_tree: true,
            c_code: true,
            timeout_secs: 30,
        }
    }
}

/// A function to be decompiled.
#[derive(Debug, Clone)]
pub struct DecompilerMapFunction {
    /// Entry point address.
    pub entry_point: u64,
    /// Function name.
    pub name: Option<String>,
    /// Processor spec XML.
    pub pspec_xml: Option<String>,
    /// Compiler spec XML.
    pub cspec_xml: Option<String>,
}

impl DecompilerMapFunction {
    /// Create a new DecompilerMapFunction.
    pub fn new(entry_point: u64) -> Self {
        Self {
            entry_point,
            name: None,
            pspec_xml: None,
            cspec_xml: None,
        }
    }
}

/// Result type for parallel decompilation.
#[derive(Debug, Clone)]
pub struct DecompilerResult<T> {
    /// The function that was decompiled.
    pub function: DecompilerMapFunction,
    /// The result (if successful).
    pub result: Option<T>,
    /// Error message (if failed).
    pub error: Option<String>,
}

impl<T> DecompilerResult<T> {
    /// Create a successful result.
    pub fn success(function: DecompilerMapFunction, result: T) -> Self {
        Self {
            function,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error result.
    pub fn error(function: DecompilerMapFunction, error: String) -> Self {
        Self {
            function,
            result: None,
            error: Some(error),
        }
    }

    /// Whether this result is successful.
    pub fn is_success(&self) -> bool {
        self.result.is_some()
    }
}

/// Callback trait for parallel decompilation.
///
/// Called for each function being decompiled.  Can be used to
/// configure the decompiler instance for that function.
pub trait DecompilerCallback: Send + Sync + 'static {
    /// Configure the decompiler for the given function.
    fn configure(&self, _configurer: &mut DecompileConfigurer, _function: &DecompilerMapFunction) {}
}

/// Default callback that applies no configuration.
#[derive(Debug, Clone, Default)]
pub struct NullDecompilerCallback;

impl DecompilerCallback for NullDecompilerCallback {}

/// Reducer trait for combining results from parallel decompilation.
pub trait DecompilerReducer<T, R>: Send + 'static {
    /// Combine a single result into the accumulator.
    fn reduce(&self, accumulator: &mut R, result: DecompilerResult<T>);

    /// Create the initial accumulator value.
    fn identity(&self) -> R;
}

/// A simple collector that gathers all results into a Vec.
#[derive(Debug, Clone, Default)]
pub struct CollectReducer;

impl<T: Send + 'static> DecompilerReducer<T, Vec<DecompilerResult<T>>> for CollectReducer {
    fn reduce(&self, accumulator: &mut Vec<DecompilerResult<T>>, result: DecompilerResult<T>) {
        accumulator.push(result);
    }

    fn identity(&self) -> Vec<DecompilerResult<T>> {
        Vec::new()
    }
}

/// Parallel decompiler that processes functions in chunks.
///
/// This is the Rust equivalent of Ghidra's `ChunkingParallelDecompiler`.
/// It decompiles a batch of functions and collects the results.
pub struct ChunkingParallelDecompiler<T: Clone + Send + 'static> {
    /// Chunk size (number of functions per batch).
    chunk_size: usize,
    /// Decompile configurer.
    configurer: DecompileConfigurer,
    /// Phantom data for the result type.
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Clone + Send + 'static> ChunkingParallelDecompiler<T> {
    /// Create a new ChunkingParallelDecompiler.
    pub fn new(chunk_size: usize, configurer: DecompileConfigurer) -> Self {
        Self {
            chunk_size,
            configurer,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get the chunk size.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Get the configurer.
    pub fn configurer(&self) -> &DecompileConfigurer {
        &self.configurer
    }
}

/// Simple parallel decompiler helper that processes a list of functions.
///
/// This is a simplified version that doesn't actually use threads
/// (for compatibility with the single-threaded model), but provides
/// the same API.
pub struct ParallelDecompiler;

impl ParallelDecompiler {
    /// Decompile a list of functions sequentially (placeholder for parallel).
    pub fn decompile_batch<F, R>(
        functions: &[DecompilerMapFunction],
        mut decompile_fn: F,
    ) -> Vec<DecompilerResult<R>>
    where
        F: FnMut(&DecompilerMapFunction) -> Result<R, String>,
    {
        functions
            .iter()
            .map(|func| match decompile_fn(func) {
                Ok(result) => DecompilerResult::success(func.clone(), result),
                Err(err) => DecompilerResult::error(func.clone(), err),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decompile_configurer_default() {
        let config = DecompileConfigurer::default();
        assert!(config.syntax_tree);
        assert!(config.c_code);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_decompiler_map_function() {
        let f = DecompilerMapFunction::new(0x1000);
        assert_eq!(f.entry_point, 0x1000);
        assert!(f.name.is_none());
    }

    #[test]
    fn test_decompiler_result_success() {
        let func = DecompilerMapFunction::new(0x1000);
        let result = DecompilerResult::success(func, "int main() {}");
        assert!(result.is_success());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_decompiler_result_error() {
        let func = DecompilerMapFunction::new(0x2000);
        let result: DecompilerResult<String> = DecompilerResult::error(func, "timeout".to_string());
        assert!(!result.is_success());
        assert_eq!(result.error.as_deref(), Some("timeout"));
    }

    #[test]
    fn test_collect_reducer() {
        let reducer = CollectReducer;
        let mut acc = reducer.identity();
        let func = DecompilerMapFunction::new(0x1000);
        reducer.reduce(&mut acc, DecompilerResult::success(func, "ok"));
        assert_eq!(acc.len(), 1);
    }

    #[test]
    fn test_parallel_decompile_batch() {
        let functions = vec![
            DecompilerMapFunction::new(0x1000),
            DecompilerMapFunction::new(0x2000),
        ];
        let results = ParallelDecompiler::decompile_batch(&functions, |func| {
            Ok(format!("decompiled_{}", func.entry_point))
        });
        assert_eq!(results.len(), 2);
        assert!(results[0].is_success());
        assert!(results[1].is_success());
    }

    #[test]
    fn test_parallel_decompile_batch_with_errors() {
        let functions = vec![
            DecompilerMapFunction::new(0x1000),
            DecompilerMapFunction::new(0x2000),
        ];
        let results = ParallelDecompiler::decompile_batch(&functions, |func| {
            if func.entry_point == 0x2000 {
                Err("timeout".to_string())
            } else {
                Ok("ok".to_string())
            }
        });
        assert_eq!(results.len(), 2);
        assert!(results[0].is_success());
        assert!(!results[1].is_success());
    }

    #[test]
    fn test_chunking_parallel_decompiler() {
        let config = DecompileConfigurer::default();
        let cpd = ChunkingParallelDecompiler::<String>::new(10, config);
        assert_eq!(cpd.chunk_size(), 10);
    }
}
