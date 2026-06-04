//! DecompilerDisposer: background thread disposal of decompiler processes.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompilerDisposer`.
//!
//! Handles the rare case where the DecompInterface's synchronized methods
//! are blocking while a decompile operation has died and maintained the lock.

use std::sync::mpsc;
use std::thread;

/// Manages background disposal of decompiler resources.
///
/// In Ghidra Java, this uses a `ConcurrentQ` to dispose resources on a
/// background thread.  In Rust, we use a simple channel-based approach.
pub struct DecompilerDisposer {
    sender: Option<mpsc::Sender<DisposeAction>>,
    _handle: Option<thread::JoinHandle<()>>,
}

/// An action to dispose.
enum DisposeAction {
    /// Dispose a process (by pid or handle).
    Process(u32),
    /// Shutdown the disposer thread.
    Shutdown,
}

impl DecompilerDisposer {
    /// Create a new DecompilerDisposer.
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel::<DisposeAction>();

        let handle = thread::spawn(move || {
            while let Ok(action) = receiver.recv() {
                match action {
                    DisposeAction::Process(_pid) => {
                        // In a real implementation, this would kill the process
                        // and close its I/O streams.
                    }
                    DisposeAction::Shutdown => break,
                }
            }
        });

        Self {
            sender: Some(sender),
            _handle: Some(handle),
        }
    }

    /// Schedule a process for disposal on the background thread.
    pub fn dispose_process(&self, pid: u32) {
        if let Some(ref sender) = self.sender {
            let _ = sender.send(DisposeAction::Process(pid));
        }
    }
}

impl Default for DecompilerDisposer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DecompilerDisposer {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(DisposeAction::Shutdown);
        }
    }
}

/// Global disposer instance.
static DISPOSER: once_cell::sync::Lazy<DecompilerDisposer> =
    once_cell::sync::Lazy::new(DecompilerDisposer::new);

/// Dispose a process using the global disposer.
pub fn dispose(pid: u32) {
    DISPOSER.dispose_process(pid);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disposer_new() {
        let _disposer = DecompilerDisposer::new();
        // Should not panic
    }

    #[test]
    fn test_dispose_process() {
        let disposer = DecompilerDisposer::new();
        disposer.dispose_process(1234);
        // Should not panic, action is queued
    }

    #[test]
    fn test_global_dispose() {
        dispose(5678);
        // Should not panic
    }
}
