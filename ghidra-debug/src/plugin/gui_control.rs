//! Debugger control actions (resume, step, interrupt, etc.).
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.control` package.
//! Provides action types for controlling target execution.

use serde::{Deserialize, Serialize};

/// The kind of control action to perform on a debug target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlActionKind {
    /// Resume (continue) execution.
    Resume,
    /// Step into (single step, entering calls).
    StepInto,
    /// Step over (single step, skipping calls).
    StepOver,
    /// Step out (run until current function returns).
    StepOut,
    /// Step to an extended location.
    StepExt,
    /// Interrupt/pause execution.
    Interrupt,
    /// Kill the target process.
    Kill,
    /// Disconnect from the target.
    Disconnect,
    /// Skip over the current instruction.
    SkipOver,
}

/// Whether this action targets the live debugger, the emulator, or both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlActionTarget {
    /// Action on the live debugger target.
    Live,
    /// Action on the p-code emulator.
    Emulator,
    /// Action on trace time (snapshot navigation).
    TraceTime,
}

/// A single control action to be dispatched.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAction {
    /// The kind of action.
    pub kind: ControlActionKind,
    /// What this action targets.
    pub target: ControlActionTarget,
    /// The trace ID.
    pub trace_id: Option<String>,
    /// The thread key (None = all threads).
    pub thread_key: Option<i64>,
}

impl ControlAction {
    /// Create a new control action.
    pub fn new(kind: ControlActionKind, target: ControlActionTarget) -> Self {
        Self {
            kind,
            target,
            trace_id: None,
            thread_key: None,
        }
    }

    /// Set the trace.
    pub fn with_trace(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Set the thread.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Whether this is a stepping action.
    pub fn is_step(&self) -> bool {
        matches!(
            self.kind,
            ControlActionKind::StepInto
                | ControlActionKind::StepOver
                | ControlActionKind::StepOut
                | ControlActionKind::StepExt
                | ControlActionKind::SkipOver
        )
    }

    /// Whether this is a resume/continue action.
    pub fn is_resume(&self) -> bool {
        self.kind == ControlActionKind::Resume
    }

    /// Whether this is a stop/interrupt action.
    pub fn is_interrupt(&self) -> bool {
        self.kind == ControlActionKind::Interrupt
    }
}

/// Builder for constructing control action sequences.
#[derive(Debug, Clone, Default)]
pub struct ControlActionBuilder {
    actions: Vec<ControlAction>,
}

impl ControlActionBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a resume action.
    pub fn resume(mut self, target: ControlActionTarget) -> Self {
        self.actions.push(ControlAction::new(ControlActionKind::Resume, target));
        self
    }

    /// Add a step-into action.
    pub fn step_into(mut self, target: ControlActionTarget) -> Self {
        self.actions.push(ControlAction::new(ControlActionKind::StepInto, target));
        self
    }

    /// Add a step-over action.
    pub fn step_over(mut self, target: ControlActionTarget) -> Self {
        self.actions.push(ControlAction::new(ControlActionKind::StepOver, target));
        self
    }

    /// Add a step-out action.
    pub fn step_out(mut self, target: ControlActionTarget) -> Self {
        self.actions.push(ControlAction::new(ControlActionKind::StepOut, target));
        self
    }

    /// Add an interrupt action.
    pub fn interrupt(mut self, target: ControlActionTarget) -> Self {
        self.actions.push(ControlAction::new(ControlActionKind::Interrupt, target));
        self
    }

    /// Add a kill action.
    pub fn kill(mut self, target: ControlActionTarget) -> Self {
        self.actions.push(ControlAction::new(ControlActionKind::Kill, target));
        self
    }

    /// Add a disconnect action.
    pub fn disconnect(mut self, target: ControlActionTarget) -> Self {
        self.actions
            .push(ControlAction::new(ControlActionKind::Disconnect, target));
        self
    }

    /// Build the action list.
    pub fn build(self) -> Vec<ControlAction> {
        self.actions
    }
}

/// Trace snapshot navigation actions (forward/backward).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotNavigation {
    /// Go to the next snapshot.
    Forward,
    /// Go to the previous snapshot.
    Backward,
    /// Go to the first snapshot.
    First,
    /// Go to the last snapshot.
    Last,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_action_kinds() {
        let resume = ControlAction::new(ControlActionKind::Resume, ControlActionTarget::Live);
        assert!(resume.is_resume());
        assert!(!resume.is_step());

        let step = ControlAction::new(ControlActionKind::StepInto, ControlActionTarget::Live);
        assert!(step.is_step());
        assert!(!step.is_resume());
    }

    #[test]
    fn test_control_action_builder() {
        let actions = ControlActionBuilder::new()
            .resume(ControlActionTarget::Live)
            .step_into(ControlActionTarget::Emulator)
            .interrupt(ControlActionTarget::Live)
            .build();

        assert_eq!(actions.len(), 3);
        assert!(actions[0].is_resume());
        assert!(actions[1].is_step());
        assert!(actions[2].is_interrupt());
    }

    #[test]
    fn test_control_action_with_context() {
        let action = ControlAction::new(ControlActionKind::StepOver, ControlActionTarget::Emulator)
            .with_trace("trace1")
            .with_thread(42);

        assert_eq!(action.trace_id.as_deref(), Some("trace1"));
        assert_eq!(action.thread_key, Some(42));
    }

    #[test]
    fn test_snapshot_navigation() {
        assert_ne!(SnapshotNavigation::Forward, SnapshotNavigation::Backward);
        assert_ne!(SnapshotNavigation::First, SnapshotNavigation::Last);
    }

    #[test]
    fn test_control_action_serde() {
        let action = ControlAction::new(ControlActionKind::Resume, ControlActionTarget::Live);
        let json = serde_json::to_string(&action).unwrap();
        let back: ControlAction = serde_json::from_str(&json).unwrap();
        assert!(back.is_resume());
    }
}
