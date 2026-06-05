//! JDI manager interface and supporting types.
//!
//! Ported from Ghidra's `ghidra.dbg.jdi.manager` package.
//!
//! The `JdiManager` trait models the controlling side of a JDI session,
//! managing virtual machines, threads, and debug events. Supporting
//! types include `JdiEventsListener`, `JdiStateListener`, `JdiCause`,
//! `JdiReason`, `DebugStatus`, and breakpoint info.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Channel
// ---------------------------------------------------------------------------

/// Output channel for JDI console output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Channel {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

// ---------------------------------------------------------------------------
// DebugStatus
// ---------------------------------------------------------------------------

/// The status returned by event handlers to indicate how to proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugStatus {
    /// Continue processing events.
    Continue,
    /// Handled; stop processing further events in this set.
    Handled,
    /// Something went wrong.
    Error,
}

// ---------------------------------------------------------------------------
// JdiCause
// ---------------------------------------------------------------------------

/// The cause of a JDI event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiCause {
    /// Human-readable reason.
    pub reason: String,
    /// Whether this was a user-initiated action.
    pub user_initiated: bool,
}

impl JdiCause {
    /// Create a cause with a reason.
    pub fn new(reason: impl Into<String>, user_initiated: bool) -> Self {
        Self {
            reason: reason.into(),
            user_initiated,
        }
    }

    /// A user-initiated cause.
    pub fn user(reason: impl Into<String>) -> Self {
        Self::new(reason, true)
    }

    /// An automatic cause.
    pub fn automatic(reason: impl Into<String>) -> Self {
        Self::new(reason, false)
    }
}

// ---------------------------------------------------------------------------
// JdiReason
// ---------------------------------------------------------------------------

/// The reason for a thread state change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiReason {
    /// The reason text.
    pub reason: String,
}

impl JdiReason {
    /// Create a new reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// JdiThreadInfo
// ---------------------------------------------------------------------------

/// Information about a thread in a JDI virtual machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiThreadInfo {
    /// Thread unique ID.
    pub thread_id: u64,
    /// Thread name.
    pub name: String,
    /// Thread group name.
    pub group: Option<String>,
    /// Whether this thread is suspended.
    pub is_suspended: bool,
    /// Whether this thread is at a breakpoint.
    pub at_breakpoint: bool,
    /// Current status string.
    pub status: String,
}

impl JdiThreadInfo {
    /// Create a new thread info.
    pub fn new(thread_id: u64, name: impl Into<String>) -> Self {
        Self {
            thread_id,
            name: name.into(),
            group: None,
            is_suspended: false,
            at_breakpoint: false,
            status: "running".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// JdiBreakpointType
// ---------------------------------------------------------------------------

/// The type of a JDI breakpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JdiBreakpointType {
    /// Line breakpoint.
    Line,
    /// Method entry breakpoint.
    MethodEntry,
    /// Method exit breakpoint.
    MethodExit,
    /// Exception breakpoint.
    Exception,
    /// Field access watchpoint.
    FieldAccess,
    /// Field modification watchpoint.
    FieldModification,
}

// ---------------------------------------------------------------------------
// JdiBreakpointInfo
// ---------------------------------------------------------------------------

/// Information about a JDI breakpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiBreakpointInfo {
    /// Breakpoint ID.
    pub breakpoint_id: u64,
    /// The breakpoint type.
    pub breakpoint_type: JdiBreakpointType,
    /// Class name (for line breakpoints).
    pub class_name: Option<String>,
    /// Method name (for method breakpoints).
    pub method_name: Option<String>,
    /// Line number (for line breakpoints).
    pub line_number: Option<u32>,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
    /// Hit count.
    pub hit_count: u64,
    /// Condition expression (if any).
    pub condition: Option<String>,
}

impl JdiBreakpointInfo {
    /// Create a line breakpoint.
    pub fn line(
        breakpoint_id: u64,
        class_name: impl Into<String>,
        line_number: u32,
    ) -> Self {
        Self {
            breakpoint_id,
            breakpoint_type: JdiBreakpointType::Line,
            class_name: Some(class_name.into()),
            method_name: None,
            line_number: Some(line_number),
            enabled: true,
            hit_count: 0,
            condition: None,
        }
    }

    /// Create a method entry breakpoint.
    pub fn method_entry(
        breakpoint_id: u64,
        class_name: impl Into<String>,
        method_name: impl Into<String>,
    ) -> Self {
        Self {
            breakpoint_id,
            breakpoint_type: JdiBreakpointType::MethodEntry,
            class_name: Some(class_name.into()),
            method_name: Some(method_name.into()),
            line_number: None,
            enabled: true,
            hit_count: 0,
            condition: None,
        }
    }

    /// Create an exception breakpoint.
    pub fn exception(breakpoint_id: u64, class_name: impl Into<String>) -> Self {
        Self {
            breakpoint_id,
            breakpoint_type: JdiBreakpointType::Exception,
            class_name: Some(class_name.into()),
            method_name: None,
            line_number: None,
            enabled: true,
            hit_count: 0,
            condition: None,
        }
    }
}

// ---------------------------------------------------------------------------
// JdiEventsListener (trait)
// ---------------------------------------------------------------------------

/// A listener for events related to objects known to the JDI manager.
///
/// Ported from Ghidra's `JdiEventsListener` interface.
pub trait JdiEventsListener {
    /// A virtual machine was selected (gained focus).
    fn vm_selected(&mut self, vm_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (vm_id, cause);
        DebugStatus::Continue
    }

    /// A thread was selected (gained focus).
    fn thread_selected(&mut self, thread_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (thread_id, cause);
        DebugStatus::Continue
    }

    /// A breakpoint was hit.
    fn breakpoint_hit(&mut self, bp_id: u64, thread_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (bp_id, thread_id, cause);
        DebugStatus::Continue
    }

    /// A step has completed.
    fn step_complete(&mut self, thread_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (thread_id, cause);
        DebugStatus::Continue
    }

    /// A thread has started.
    fn thread_started(&mut self, thread_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (thread_id, cause);
        DebugStatus::Continue
    }

    /// A thread has exited.
    fn thread_exited(&mut self, thread_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (thread_id, cause);
        DebugStatus::Continue
    }

    /// A thread has changed state.
    fn thread_state_changed(
        &mut self,
        thread_id: u64,
        state: i32,
        cause: &JdiCause,
        reason: &JdiReason,
    ) -> DebugStatus {
        let _ = (thread_id, state, cause, reason);
        DebugStatus::Continue
    }

    /// A virtual machine has started.
    fn vm_started(&mut self, vm_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (vm_id, cause);
        DebugStatus::Continue
    }

    /// A virtual machine has died.
    fn vm_died(&mut self, vm_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (vm_id, cause);
        DebugStatus::Continue
    }

    /// A virtual machine has been disconnected.
    fn vm_disconnected(&mut self, vm_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (vm_id, cause);
        DebugStatus::Continue
    }

    /// The process has stopped.
    fn process_stop(&mut self, cause: &JdiCause) -> DebugStatus {
        let _ = cause;
        DebugStatus::Continue
    }

    /// The process has shut down.
    fn process_shutdown(&mut self, cause: &JdiCause) -> DebugStatus {
        let _ = cause;
        DebugStatus::Continue
    }
}

// ---------------------------------------------------------------------------
// JdiStateListener (trait)
// ---------------------------------------------------------------------------

/// A listener for changes in the JDI session state.
pub trait JdiStateListener {
    /// The session's state has changed.
    fn state_changed(&mut self, vm_id: u64);
}

// ---------------------------------------------------------------------------
// JdiConsoleOutputListener (trait)
// ---------------------------------------------------------------------------

/// A listener for console output from the debug target.
pub trait JdiConsoleOutputListener {
    /// Output received on a channel.
    fn output_received(&mut self, channel: Channel, text: &str);
}

// ---------------------------------------------------------------------------
// JdiTargetOutputListener (trait)
// ---------------------------------------------------------------------------

/// A listener for output from the debug target.
pub trait JdiTargetOutputListener {
    /// Output received.
    fn output_received(&mut self, text: &str);
}

// ---------------------------------------------------------------------------
// JdiManager (trait)
// ---------------------------------------------------------------------------

/// The controlling side of a JDI session.
///
/// Ported from Ghidra's `JdiManager` interface.
pub trait JdiManager {
    /// Terminate the JDI session.
    fn terminate(&mut self);

    /// Add a listener for JDI state events.
    fn add_state_listener(&mut self, vm_id: u64, listener: Box<dyn JdiStateListener>);

    /// Remove a JDI state listener.
    fn remove_state_listener(&mut self, vm_id: u64, listener_id: usize);

    /// Add a listener for JDI debug events.
    fn add_events_listener(&mut self, vm_id: u64, listener: Box<dyn JdiEventsListener>);

    /// Remove an events listener.
    fn remove_events_listener(&mut self, vm_id: u64, listener_id: usize);

    /// List all virtual machines.
    fn list_vms(&self) -> BTreeMap<u64, String>;

    /// Remove a virtual machine.
    fn remove_vm(&mut self, vm_id: u64);

    /// Execute a console command.
    fn console(&mut self, command: &str) -> Result<(), String>;

    /// Execute a console command and capture output.
    fn console_capture(&mut self, command: &str) -> Result<String, String>;

    /// Set a breakpoint.
    fn set_breakpoint(&mut self, bp: JdiBreakpointInfo) -> Result<u64, String>;

    /// Delete a breakpoint.
    fn delete_breakpoint(&mut self, bp_id: u64) -> Result<(), String>;

    /// Resume execution.
    fn resume(&mut self, vm_id: u64) -> Result<(), String>;

    /// Suspend execution.
    fn suspend(&mut self, vm_id: u64) -> Result<(), String>;

    /// Step into.
    fn step_into(&mut self, vm_id: u64, thread_id: u64) -> Result<(), String>;

    /// Step over.
    fn step_over(&mut self, vm_id: u64, thread_id: u64) -> Result<(), String>;

    /// Step out.
    fn step_out(&mut self, vm_id: u64, thread_id: u64) -> Result<(), String>;
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_variants() {
        assert_ne!(Channel::Stdout, Channel::Stderr);
    }

    #[test]
    fn test_debug_status_variants() {
        assert_ne!(DebugStatus::Continue, DebugStatus::Handled);
        assert_ne!(DebugStatus::Handled, DebugStatus::Error);
    }

    #[test]
    fn test_jdi_cause() {
        let cause = JdiCause::user("step over");
        assert!(cause.user_initiated);
        assert_eq!(cause.reason, "step over");

        let auto = JdiCause::automatic("breakpoint hit");
        assert!(!auto.user_initiated);
    }

    #[test]
    fn test_jdi_reason() {
        let reason = JdiReason::new("step");
        assert_eq!(reason.reason, "step");
    }

    #[test]
    fn test_jdi_thread_info() {
        let mut info = JdiThreadInfo::new(42, "main");
        assert_eq!(info.thread_id, 42);
        assert_eq!(info.name, "main");
        assert!(!info.is_suspended);

        info.is_suspended = true;
        info.group = Some("main-group".into());
        assert!(info.is_suspended);
    }

    #[test]
    fn test_jdi_breakpoint_line() {
        let bp = JdiBreakpointInfo::line(1, "com.example.Main", 42);
        assert_eq!(bp.breakpoint_type, JdiBreakpointType::Line);
        assert_eq!(bp.class_name.as_deref(), Some("com.example.Main"));
        assert_eq!(bp.line_number, Some(42));
        assert!(bp.enabled);
    }

    #[test]
    fn test_jdi_breakpoint_method_entry() {
        let bp = JdiBreakpointInfo::method_entry(2, "com.example.Main", "run");
        assert_eq!(bp.breakpoint_type, JdiBreakpointType::MethodEntry);
        assert_eq!(bp.method_name.as_deref(), Some("run"));
    }

    #[test]
    fn test_jdi_breakpoint_exception() {
        let bp = JdiBreakpointInfo::exception(3, "java.lang.NullPointerException");
        assert_eq!(bp.breakpoint_type, JdiBreakpointType::Exception);
    }

    #[test]
    fn test_jdi_breakpoint_type_variants() {
        let types = [
            JdiBreakpointType::Line,
            JdiBreakpointType::MethodEntry,
            JdiBreakpointType::MethodExit,
            JdiBreakpointType::Exception,
            JdiBreakpointType::FieldAccess,
            JdiBreakpointType::FieldModification,
        ];
        for t in &types {
            let json = serde_json::to_string(t).unwrap();
            let back: JdiBreakpointType = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    // -- Mock listener tests --

    struct TestEventsListener {
        vm_ids: Vec<u64>,
    }

    impl JdiEventsListener for TestEventsListener {
        fn vm_started(&mut self, vm_id: u64, _cause: &JdiCause) -> DebugStatus {
            self.vm_ids.push(vm_id);
            DebugStatus::Handled
        }
    }

    #[test]
    fn test_events_listener_default() {
        let mut listener = TestEventsListener { vm_ids: vec![] };
        // Default methods should return Continue
        let cause = JdiCause::user("test");
        assert_eq!(listener.thread_selected(1, &cause), DebugStatus::Continue);
        assert_eq!(listener.step_complete(1, &cause), DebugStatus::Continue);

        // vm_started is overridden
        assert_eq!(listener.vm_started(42, &cause), DebugStatus::Handled);
        assert_eq!(listener.vm_ids, vec![42]);
    }

    #[test]
    fn test_events_listener_all_defaults() {
        struct EmptyListener;
        impl JdiEventsListener for EmptyListener {}

        let mut listener = EmptyListener;
        let cause = JdiCause::user("test");
        let reason = JdiReason::new("step");

        assert_eq!(listener.breakpoint_hit(1, 1, &cause), DebugStatus::Continue);
        assert_eq!(listener.thread_started(1, &cause), DebugStatus::Continue);
        assert_eq!(listener.thread_exited(1, &cause), DebugStatus::Continue);
        assert_eq!(listener.thread_state_changed(1, 0, &cause, &reason), DebugStatus::Continue);
        assert_eq!(listener.vm_died(1, &cause), DebugStatus::Continue);
        assert_eq!(listener.vm_disconnected(1, &cause), DebugStatus::Continue);
        assert_eq!(listener.process_stop(&cause), DebugStatus::Continue);
        assert_eq!(listener.process_shutdown(&cause), DebugStatus::Continue);
    }

    #[test]
    fn test_jdi_manager_trait_object() {
        struct MockManager;
        impl JdiManager for MockManager {
            fn terminate(&mut self) {}
            fn add_state_listener(&mut self, _: u64, _: Box<dyn JdiStateListener>) {}
            fn remove_state_listener(&mut self, _: u64, _: usize) {}
            fn add_events_listener(&mut self, _: u64, _: Box<dyn JdiEventsListener>) {}
            fn remove_events_listener(&mut self, _: u64, _: usize) {}
            fn list_vms(&self) -> BTreeMap<u64, String> { BTreeMap::new() }
            fn remove_vm(&mut self, _: u64) {}
            fn console(&mut self, _: &str) -> Result<(), String> { Ok(()) }
            fn console_capture(&mut self, _: &str) -> Result<String, String> { Ok(String::new()) }
            fn set_breakpoint(&mut self, _: JdiBreakpointInfo) -> Result<u64, String> { Ok(1) }
            fn delete_breakpoint(&mut self, _: u64) -> Result<(), String> { Ok(()) }
            fn resume(&mut self, _: u64) -> Result<(), String> { Ok(()) }
            fn suspend(&mut self, _: u64) -> Result<(), String> { Ok(()) }
            fn step_into(&mut self, _: u64, _: u64) -> Result<(), String> { Ok(()) }
            fn step_over(&mut self, _: u64, _: u64) -> Result<(), String> { Ok(()) }
            fn step_out(&mut self, _: u64, _: u64) -> Result<(), String> { Ok(()) }
        }

        let mut mgr = MockManager;
        assert!(mgr.list_vms().is_empty());
        assert!(mgr.console("help").is_ok());
        mgr.terminate();

        let bp = JdiBreakpointInfo::line(1, "Main", 10);
        let id = mgr.set_breakpoint(bp).unwrap();
        assert_eq!(id, 1);
        mgr.delete_breakpoint(id).unwrap();
    }
}
