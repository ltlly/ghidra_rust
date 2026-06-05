//! The decompile task that runs on a background thread.
//!
//! Ports `ghidra.app.decompiler.component.DecompileRunnable`.

use std::time::Instant;

/// The result of a decompile task.
#[derive(Debug, Clone)]
pub struct DecompileRunnableResult {
    /// The function entry point.
    pub function_entry: u64,
    /// Whether decompilation was successful.
    pub success: bool,
    /// Error message if failed.
    pub error_message: Option<String>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// The decompiled C code (if successful).
    pub c_code: Option<String>,
    /// The XML markup (if successful).
    pub markup: Option<String>,
}

impl DecompileRunnableResult {
    /// Create a success result.
    pub fn success(function_entry: u64, c_code: String, markup: String, duration_ms: u64) -> Self {
        Self {
            function_entry,
            success: true,
            error_message: None,
            duration_ms,
            c_code: Some(c_code),
            markup: Some(markup),
        }
    }

    /// Create a failure result.
    pub fn failure(function_entry: u64, error: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            function_entry,
            success: false,
            error_message: Some(error.into()),
            duration_ms,
            c_code: None,
            markup: None,
        }
    }
}

/// A decompile task that can be run on a background thread.
pub struct DecompileRunnable {
    /// The function entry point to decompile.
    pub function_entry: u64,
    /// Whether this is a forced re-decompile.
    pub force: bool,
    /// Start time (set when the task begins).
    start_time: Option<Instant>,
}

impl DecompileRunnable {
    /// Create a new decompile task.
    pub fn new(function_entry: u64, force: bool) -> Self {
        Self {
            function_entry,
            force,
            start_time: None,
        }
    }

    /// Mark the task as started.
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }

    /// Get the elapsed time since start in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.start_time
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runnable_creation() {
        let r = DecompileRunnable::new(0x1000, false);
        assert_eq!(r.function_entry, 0x1000);
        assert!(!r.force);
    }

    #[test]
    fn test_runnable_forced() {
        let r = DecompileRunnable::new(0x2000, true);
        assert!(r.force);
    }

    #[test]
    fn test_result_success() {
        let r = DecompileRunnableResult::success(0x1000, "int main() {}".into(), "<xml>".into(), 100);
        assert!(r.success);
        assert!(r.c_code.is_some());
    }

    #[test]
    fn test_result_failure() {
        let r = DecompileRunnableResult::failure(0x1000, "timeout", 5000);
        assert!(!r.success);
        assert!(r.error_message.is_some());
    }
}
