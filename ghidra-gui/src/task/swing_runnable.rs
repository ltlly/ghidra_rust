//! Port of `SwingRunnable` from `ghidra.util.task`.
//!
//! A runnable interface for executing code on the Swing EDT (Event Dispatch
//! Thread) or within a monitored task context.

/// Trait for code that runs within a task context.
///
/// Ports `ghidra.util.task.SwingRunnable`. In the Java implementation,
/// this runs on the Swing EDT. In Rust with egui, we use the main thread.
pub trait SwingRunnable: Send + Sync {
    /// Execute the runnable's main work.
    fn run(&self);

    /// Called after `run()` completes, typically on the UI thread.
    fn finished(&self) {}

    /// Get the name of this runnable for debugging.
    fn name(&self) -> &str {
        "SwingRunnable"
    }
}

/// A closure-based implementation of SwingRunnable.
#[derive(Debug)]
pub struct ClosureRunnable<F>
where
    F: Fn() + Send + Sync,
{
    closure: F,
    label: String,
}

impl<F> ClosureRunnable<F>
where
    F: Fn() + Send + Sync,
{
    /// Create a new closure-based runnable.
    pub fn new(closure: F, label: &str) -> Self {
        Self {
            closure,
            label: label.to_string(),
        }
    }
}

impl<F> SwingRunnable for ClosureRunnable<F>
where
    F: Fn() + Send + Sync,
{
    fn run(&self) {
        (self.closure)();
    }

    fn name(&self) -> &str {
        &self.label
    }
}

/// Create a SwingRunnable from a closure.
pub fn swing_runnable<F: Fn() + Send + Sync>(f: F, name: &str) -> ClosureRunnable<F> {
    ClosureRunnable::new(f, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_closure_runnable() {
        let executed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&executed);
        let runnable = swing_runnable(move || {
            flag.store(true, Ordering::SeqCst);
        }, "test");

        assert_eq!(runnable.name(), "test");
        runnable.run();
        assert!(executed.load(Ordering::SeqCst));
    }
}
