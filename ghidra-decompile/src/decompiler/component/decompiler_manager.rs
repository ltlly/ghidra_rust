#![allow(dead_code)]
//! Manages threading for the decompiler.
//!
//! Ports `ghidra.app.decompiler.component.DecompilerManager`.

use std::collections::VecDeque;

/// State of the decompile manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecompileManagerState {
    /// Idle, not decompiling.
    Idle,
    /// Currently decompiling a function.
    Decompiling,
    /// Waiting for a pending decompile request.
    Pending,
    /// Disposed.
    Disposed,
}

/// A pending decompile request.
#[derive(Debug, Clone)]
pub struct DecompileRequest {
    /// The function entry point address.
    pub function_entry: u64,
    /// The function name (optional).
    pub function_name: Option<String>,
    /// Whether to force re-decompilation even if results exist.
    pub force_decompile: bool,
}

impl DecompileRequest {
    /// Create a new decompile request.
    pub fn new(function_entry: u64) -> Self {
        Self {
            function_entry,
            function_name: None,
            force_decompile: false,
        }
    }

    /// Create with force flag.
    pub fn forced(function_entry: u64) -> Self {
        Self {
            function_entry,
            function_name: None,
            force_decompile: true,
        }
    }
}

/// Manages the threading involved with the decompiler.
///
/// Only one decompile is active at a time. If a new request comes in
/// while one is in progress, it checks if the same function is being
/// decompiled. If so, the location is updated. Otherwise, the current
/// decompile is stopped and a new one scheduled.
pub struct DecompilerManager {
    /// Current state.
    state: DecompileManagerState,
    /// The currently active request.
    current_request: Option<DecompileRequest>,
    /// Queue of pending requests.
    pending_queue: VecDeque<DecompileRequest>,
    /// Debounce delay in milliseconds.
    _debounce_ms: u64,
}

impl DecompilerManager {
    /// Create a new decompiler manager.
    pub fn new() -> Self {
        Self {
            state: DecompileManagerState::Idle,
            current_request: None,
            pending_queue: VecDeque::new(),
            _debounce_ms: 500,
        }
    }

    /// Get the current state.
    pub fn state(&self) -> DecompileManagerState {
        self.state
    }

    /// Check if the manager is idle.
    pub fn is_idle(&self) -> bool {
        self.state == DecompileManagerState::Idle
    }

    /// Check if currently decompiling.
    pub fn is_decompiling(&self) -> bool {
        self.state == DecompileManagerState::Decompiling
    }

    /// Schedule a new decompile request.
    ///
    /// If the same function is already being decompiled and force is false,
    /// this is a no-op. Otherwise, the current decompile is cancelled
    /// and a new one is scheduled.
    pub fn schedule_decompile(&mut self, request: DecompileRequest) {
        if self.state == DecompileManagerState::Disposed {
            return;
        }

        // Check if same function is already being decompiled
        if let Some(ref current) = self.current_request {
            if current.function_entry == request.function_entry && !request.force_decompile {
                return;
            }
        }

        self.pending_queue.push_back(request);

        if self.state == DecompileManagerState::Idle {
            self.start_next();
        }
    }

    /// Cancel the current decompile.
    pub fn cancel(&mut self) {
        self.current_request = None;
        self.pending_queue.clear();
        self.state = DecompileManagerState::Idle;
    }

    /// Mark the current decompile as complete.
    pub fn decompile_complete(&mut self) {
        self.current_request = None;
        if self.pending_queue.is_empty() {
            self.state = DecompileManagerState::Idle;
        } else {
            self.start_next();
        }
    }

    /// Dispose the manager.
    pub fn dispose(&mut self) {
        self.cancel();
        self.state = DecompileManagerState::Disposed;
    }

    /// Get the current request.
    pub fn current_request(&self) -> Option<&DecompileRequest> {
        self.current_request.as_ref()
    }

    fn start_next(&mut self) {
        if let Some(request) = self.pending_queue.pop_front() {
            self.current_request = Some(request);
            self.state = DecompileManagerState::Decompiling;
        }
    }
}

impl Default for DecompilerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_idle() {
        let mgr = DecompilerManager::new();
        assert!(mgr.is_idle());
        assert!(!mgr.is_decompiling());
    }

    #[test]
    fn test_schedule_decompile() {
        let mut mgr = DecompilerManager::new();
        mgr.schedule_decompile(DecompileRequest::new(0x1000));
        assert!(mgr.is_decompiling());
        assert_eq!(mgr.current_request().unwrap().function_entry, 0x1000);
    }

    #[test]
    fn test_same_function_dedup() {
        let mut mgr = DecompilerManager::new();
        mgr.schedule_decompile(DecompileRequest::new(0x1000));
        mgr.schedule_decompile(DecompileRequest::new(0x1000));
        // Should still be decompiling 0x1000, no second request queued
        assert!(mgr.is_decompiling());
    }

    #[test]
    fn test_different_function_queues() {
        let mut mgr = DecompilerManager::new();
        mgr.schedule_decompile(DecompileRequest::new(0x1000));
        mgr.schedule_decompile(DecompileRequest::new(0x2000));
        assert!(mgr.is_decompiling());
    }

    #[test]
    fn test_complete_and_next() {
        let mut mgr = DecompilerManager::new();
        mgr.schedule_decompile(DecompileRequest::new(0x1000));
        mgr.schedule_decompile(DecompileRequest::new(0x2000));
        mgr.decompile_complete();
        assert!(mgr.is_decompiling());
        assert_eq!(mgr.current_request().unwrap().function_entry, 0x2000);
        mgr.decompile_complete();
        assert!(mgr.is_idle());
    }

    #[test]
    fn test_cancel() {
        let mut mgr = DecompilerManager::new();
        mgr.schedule_decompile(DecompileRequest::new(0x1000));
        mgr.cancel();
        assert!(mgr.is_idle());
        assert!(mgr.current_request().is_none());
    }

    #[test]
    fn test_dispose() {
        let mut mgr = DecompilerManager::new();
        mgr.dispose();
        assert_eq!(mgr.state(), DecompileManagerState::Disposed);
        mgr.schedule_decompile(DecompileRequest::new(0x1000));
        assert_eq!(mgr.state(), DecompileManagerState::Disposed);
    }
}
