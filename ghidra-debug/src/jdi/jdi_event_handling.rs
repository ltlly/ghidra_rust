//! JDI event set processing and event dispatch.
//!
//! Ported from Ghidra's `ghidra.dbg.jdi.manager.impl` event handling
//! classes, including `JdiEventSet`, `JdiEventHandler`, and the various
//! JDI event wrappers.
//!
//! In the Java JDI model, the target VM sends composite events (EventSets)
//! that the debugger must process. This module models that event pipeline
//! in Rust: event sets contain individual events, each of which is dispatched
//! to registered listeners, and the resulting `DebugStatus` determines how
//! the event set continues to be processed.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt;

use super::manager::{DebugStatus, JdiCause, JdiEventsListener};

// ---------------------------------------------------------------------------
// JdiEventKind
// ---------------------------------------------------------------------------

/// The kind of a single JDI event, mirroring the JDWP event kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JdiEventKind {
    /// VM started.
    VmStart,
    /// Single step completed.
    Step,
    /// Breakpoint reached.
    Breakpoint,
    /// Method entry.
    MethodEntry,
    /// Method exit.
    MethodExit,
    /// Exception thrown.
    Exception,
    /// Thread started.
    ThreadStart,
    /// Thread death.
    ThreadDeath,
    /// Class prepared (loaded and linked).
    ClassPrepare,
    /// Class unloaded.
    ClassUnload,
    /// Field access watchpoint.
    FieldAccess,
    /// Field modification watchpoint.
    FieldModification,
    /// VM death.
    VmDeath,
    /// VM disconnected.
    VmDisconnect,
    /// Monitor contended entered.
    MonitorContendedEntered,
    /// Monitor contended enter.
    MonitorContendedEnter,
    /// Monitor waited.
    MonitorWaited,
    /// Monitor wait.
    MonitorWait,
    /// Garbage collection.
    Gc,
}

impl fmt::Display for JdiEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::VmStart => "VM Start",
            Self::Step => "Step",
            Self::Breakpoint => "Breakpoint",
            Self::MethodEntry => "Method Entry",
            Self::MethodExit => "Method Exit",
            Self::Exception => "Exception",
            Self::ThreadStart => "Thread Start",
            Self::ThreadDeath => "Thread Death",
            Self::ClassPrepare => "Class Prepare",
            Self::ClassUnload => "Class Unload",
            Self::FieldAccess => "Field Access",
            Self::FieldModification => "Field Modification",
            Self::VmDeath => "VM Death",
            Self::VmDisconnect => "VM Disconnect",
            Self::MonitorContendedEntered => "Monitor Contended Entered",
            Self::MonitorContendedEnter => "Monitor Contended Enter",
            Self::MonitorWaited => "Monitor Waited",
            Self::MonitorWait => "Monitor Wait",
            Self::Gc => "GC",
        };
        write!(f, "{name}")
    }
}

// ---------------------------------------------------------------------------
// JdiSuspendPolicy
// ---------------------------------------------------------------------------

/// The suspend policy for an event set, indicating which threads are
/// suspended when the events in the set are delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JdiSuspendPolicy {
    /// No threads are suspended.
    None,
    /// Only the event thread is suspended.
    EventThread,
    /// All threads are suspended.
    All,
}

// ---------------------------------------------------------------------------
// JdiEvent
// ---------------------------------------------------------------------------

/// A single JDI event within an event set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiEvent {
    /// The kind of event.
    pub kind: JdiEventKind,
    /// The request ID that generated this event.
    pub request_id: u64,
    /// The thread in which the event occurred (if applicable).
    pub thread_id: Option<u64>,
    /// The VM in which the event occurred.
    pub vm_id: u64,
    /// Breakpoint ID (for breakpoint events).
    pub breakpoint_id: Option<u64>,
    /// Exception class name (for exception events).
    pub exception_class: Option<String>,
    /// Location reference type ID (for location-based events).
    pub location_class_id: Option<u64>,
    /// Location method ID.
    pub location_method_id: Option<u64>,
    /// Location index within the method.
    pub location_index: Option<u64>,
    /// Class name (for class events).
    pub class_name: Option<String>,
    /// Error message (for error-type events).
    pub error_message: Option<String>,
}

impl JdiEvent {
    /// Create a breakpoint event.
    pub fn breakpoint(vm_id: u64, request_id: u64, thread_id: u64, bp_id: u64) -> Self {
        Self {
            kind: JdiEventKind::Breakpoint,
            request_id,
            thread_id: Some(thread_id),
            vm_id,
            breakpoint_id: Some(bp_id),
            exception_class: None,
            location_class_id: None,
            location_method_id: None,
            location_index: None,
            class_name: None,
            error_message: None,
        }
    }

    /// Create a step event.
    pub fn step(vm_id: u64, request_id: u64, thread_id: u64) -> Self {
        Self {
            kind: JdiEventKind::Step,
            request_id,
            thread_id: Some(thread_id),
            vm_id,
            breakpoint_id: None,
            exception_class: None,
            location_class_id: None,
            location_method_id: None,
            location_index: None,
            class_name: None,
            error_message: None,
        }
    }

    /// Create a thread start event.
    pub fn thread_start(vm_id: u64, request_id: u64, thread_id: u64) -> Self {
        Self {
            kind: JdiEventKind::ThreadStart,
            request_id,
            thread_id: Some(thread_id),
            vm_id,
            breakpoint_id: None,
            exception_class: None,
            location_class_id: None,
            location_method_id: None,
            location_index: None,
            class_name: None,
            error_message: None,
        }
    }

    /// Create a thread death event.
    pub fn thread_death(vm_id: u64, request_id: u64, thread_id: u64) -> Self {
        Self {
            kind: JdiEventKind::ThreadDeath,
            request_id,
            thread_id: Some(thread_id),
            vm_id,
            breakpoint_id: None,
            exception_class: None,
            location_class_id: None,
            location_method_id: None,
            location_index: None,
            class_name: None,
            error_message: None,
        }
    }

    /// Create a VM start event.
    pub fn vm_start(vm_id: u64, request_id: u64, thread_id: u64) -> Self {
        Self {
            kind: JdiEventKind::VmStart,
            request_id,
            thread_id: Some(thread_id),
            vm_id,
            breakpoint_id: None,
            exception_class: None,
            location_class_id: None,
            location_method_id: None,
            location_index: None,
            class_name: None,
            error_message: None,
        }
    }

    /// Create a VM death event.
    pub fn vm_death(vm_id: u64, request_id: u64) -> Self {
        Self {
            kind: JdiEventKind::VmDeath,
            request_id,
            thread_id: None,
            vm_id,
            breakpoint_id: None,
            exception_class: None,
            location_class_id: None,
            location_method_id: None,
            location_index: None,
            class_name: None,
            error_message: None,
        }
    }

    /// Create an exception event.
    pub fn exception(
        vm_id: u64,
        request_id: u64,
        thread_id: u64,
        exception_class: impl Into<String>,
    ) -> Self {
        Self {
            kind: JdiEventKind::Exception,
            request_id,
            thread_id: Some(thread_id),
            vm_id,
            breakpoint_id: None,
            exception_class: Some(exception_class.into()),
            location_class_id: None,
            location_method_id: None,
            location_index: None,
            class_name: None,
            error_message: None,
        }
    }

    /// Create a class prepare event.
    pub fn class_prepare(
        vm_id: u64,
        request_id: u64,
        thread_id: u64,
        class_name: impl Into<String>,
    ) -> Self {
        Self {
            kind: JdiEventKind::ClassPrepare,
            request_id,
            thread_id: Some(thread_id),
            vm_id,
            breakpoint_id: None,
            exception_class: None,
            location_class_id: None,
            location_method_id: None,
            location_index: None,
            class_name: Some(class_name.into()),
            error_message: None,
        }
    }

    /// Is this a lifecycle event (VM start, VM death, disconnect)?
    pub fn is_lifecycle(&self) -> bool {
        matches!(
            self.kind,
            JdiEventKind::VmStart | JdiEventKind::VmDeath | JdiEventKind::VmDisconnect
        )
    }

    /// Is this a thread-related event?
    pub fn is_thread_event(&self) -> bool {
        matches!(
            self.kind,
            JdiEventKind::ThreadStart | JdiEventKind::ThreadDeath
        )
    }

    /// Is this a suspension-causing event?
    pub fn causes_suspend(&self, policy: JdiSuspendPolicy) -> bool {
        match policy {
            JdiSuspendPolicy::None => false,
            JdiSuspendPolicy::EventThread => self.thread_id.is_some(),
            JdiSuspendPolicy::All => true,
        }
    }
}

// ---------------------------------------------------------------------------
// JdiEventSet
// ---------------------------------------------------------------------------

/// A composite set of JDI events delivered together by the target VM.
///
/// In the JDWP protocol, events are grouped into EventSets. An EventSet has
/// a shared suspend policy, and its events are processed in order. The
/// `DebugStatus` returned by the event handler determines whether to continue
/// processing events within the set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiEventSet {
    /// The suspend policy for this event set.
    pub suspend_policy: JdiSuspendPolicy,
    /// The individual events in this set.
    pub events: Vec<JdiEvent>,
}

impl JdiEventSet {
    /// Create a new event set.
    pub fn new(suspend_policy: JdiSuspendPolicy) -> Self {
        Self {
            suspend_policy,
            events: Vec::new(),
        }
    }

    /// Create an event set with the given events.
    pub fn with_events(suspend_policy: JdiSuspendPolicy, events: Vec<JdiEvent>) -> Self {
        Self {
            suspend_policy,
            events,
        }
    }

    /// Add an event to this set.
    pub fn push(&mut self, event: JdiEvent) {
        self.events.push(event);
    }

    /// The number of events in this set.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether this event set is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Iterate over the events.
    pub fn iter(&self) -> impl Iterator<Item = &JdiEvent> {
        self.events.iter()
    }

    /// Whether this event set contains a VM death event.
    pub fn has_vm_death(&self) -> bool {
        self.events.iter().any(|e| e.kind == JdiEventKind::VmDeath)
    }

    /// Whether this event set contains a breakpoint event.
    pub fn has_breakpoint(&self) -> bool {
        self.events
            .iter()
            .any(|e| e.kind == JdiEventKind::Breakpoint)
    }

    /// Whether this event set contains a step event.
    pub fn has_step(&self) -> bool {
        self.events.iter().any(|e| e.kind == JdiEventKind::Step)
    }

    /// Get all thread IDs referenced by events in this set.
    pub fn referenced_threads(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self
            .events
            .iter()
            .filter_map(|e| e.thread_id)
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Get the VM ID (all events in a set share the same VM).
    pub fn vm_id(&self) -> Option<u64> {
        self.events.first().map(|e| e.vm_id)
    }
}

// ---------------------------------------------------------------------------
// JdiEventHandler
// ---------------------------------------------------------------------------

/// Processes a `JdiEventSet` by dispatching individual events to the
/// appropriate callbacks.
///
/// Ported from Ghidra's event processing loop in the JDI manager
/// implementation. The handler walks the event set, maps each event kind
/// to the corresponding `JdiEventsListener` callback, and accumulates the
/// resulting `DebugStatus`.
pub trait JdiEventHandler {
    /// Handle a breakpoint event.
    fn handle_breakpoint(
        &mut self,
        vm_id: u64,
        bp_id: u64,
        thread_id: u64,
        cause: &JdiCause,
    ) -> DebugStatus {
        let _ = (vm_id, bp_id, thread_id, cause);
        DebugStatus::Continue
    }

    /// Handle a step event.
    fn handle_step(&mut self, vm_id: u64, thread_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (vm_id, thread_id, cause);
        DebugStatus::Continue
    }

    /// Handle a thread start event.
    fn handle_thread_start(
        &mut self,
        vm_id: u64,
        thread_id: u64,
        cause: &JdiCause,
    ) -> DebugStatus {
        let _ = (vm_id, thread_id, cause);
        DebugStatus::Continue
    }

    /// Handle a thread death event.
    fn handle_thread_death(
        &mut self,
        vm_id: u64,
        thread_id: u64,
        cause: &JdiCause,
    ) -> DebugStatus {
        let _ = (vm_id, thread_id, cause);
        DebugStatus::Continue
    }

    /// Handle a VM start event.
    fn handle_vm_start(&mut self, vm_id: u64, thread_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (vm_id, thread_id, cause);
        DebugStatus::Continue
    }

    /// Handle a VM death event.
    fn handle_vm_death(&mut self, vm_id: u64, cause: &JdiCause) -> DebugStatus {
        let _ = (vm_id, cause);
        DebugStatus::Continue
    }

    /// Handle an exception event.
    fn handle_exception(
        &mut self,
        vm_id: u64,
        thread_id: u64,
        exception_class: &str,
        cause: &JdiCause,
    ) -> DebugStatus {
        let _ = (vm_id, thread_id, exception_class, cause);
        DebugStatus::Continue
    }

    /// Handle a class prepare event.
    fn handle_class_prepare(
        &mut self,
        vm_id: u64,
        thread_id: u64,
        class_name: &str,
        cause: &JdiCause,
    ) -> DebugStatus {
        let _ = (vm_id, thread_id, class_name, cause);
        DebugStatus::Continue
    }

    /// Handle a method entry event.
    fn handle_method_entry(
        &mut self,
        vm_id: u64,
        thread_id: u64,
        cause: &JdiCause,
    ) -> DebugStatus {
        let _ = (vm_id, thread_id, cause);
        DebugStatus::Continue
    }

    /// Handle a method exit event.
    fn handle_method_exit(
        &mut self,
        vm_id: u64,
        thread_id: u64,
        cause: &JdiCause,
    ) -> DebugStatus {
        let _ = (vm_id, thread_id, cause);
        DebugStatus::Continue
    }

    /// Handle an unhandled event kind. Returns Continue by default.
    fn handle_other(&mut self, event: &JdiEvent) -> DebugStatus {
        let _ = event;
        DebugStatus::Continue
    }
}

// ---------------------------------------------------------------------------
// Event set processing
// ---------------------------------------------------------------------------

/// Process an event set by dispatching each event to the given handler.
///
/// Returns the final `DebugStatus` after all events have been processed.
/// If any event returns a status other than `Continue`, processing stops
/// immediately and that status is returned.
pub fn process_event_set(
    handler: &mut dyn JdiEventHandler,
    event_set: &JdiEventSet,
) -> DebugStatus {
    let cause = JdiCause::automatic("event set");
    let mut final_status = DebugStatus::Continue;

    for event in &event_set.events {
        let status = match event.kind {
            JdiEventKind::Breakpoint => {
                let bp_id = event.breakpoint_id.unwrap_or(0);
                let thread_id = event.thread_id.unwrap_or(0);
                handler.handle_breakpoint(event.vm_id, bp_id, thread_id, &cause)
            }
            JdiEventKind::Step => {
                let thread_id = event.thread_id.unwrap_or(0);
                handler.handle_step(event.vm_id, thread_id, &cause)
            }
            JdiEventKind::ThreadStart => {
                let thread_id = event.thread_id.unwrap_or(0);
                handler.handle_thread_start(event.vm_id, thread_id, &cause)
            }
            JdiEventKind::ThreadDeath => {
                let thread_id = event.thread_id.unwrap_or(0);
                handler.handle_thread_death(event.vm_id, thread_id, &cause)
            }
            JdiEventKind::VmStart => {
                let thread_id = event.thread_id.unwrap_or(0);
                handler.handle_vm_start(event.vm_id, thread_id, &cause)
            }
            JdiEventKind::VmDeath => handler.handle_vm_death(event.vm_id, &cause),
            JdiEventKind::Exception => {
                let thread_id = event.thread_id.unwrap_or(0);
                let class = event.exception_class.as_deref().unwrap_or("Unknown");
                handler.handle_exception(event.vm_id, thread_id, class, &cause)
            }
            JdiEventKind::ClassPrepare => {
                let thread_id = event.thread_id.unwrap_or(0);
                let class = event.class_name.as_deref().unwrap_or("Unknown");
                handler.handle_class_prepare(event.vm_id, thread_id, class, &cause)
            }
            JdiEventKind::MethodEntry => {
                let thread_id = event.thread_id.unwrap_or(0);
                handler.handle_method_entry(event.vm_id, thread_id, &cause)
            }
            JdiEventKind::MethodExit => {
                let thread_id = event.thread_id.unwrap_or(0);
                handler.handle_method_exit(event.vm_id, thread_id, &cause)
            }
            _ => handler.handle_other(event),
        };

        if status != DebugStatus::Continue {
            return status;
        }
        final_status = status;
    }

    final_status
}

// ---------------------------------------------------------------------------
// JdiEventRequest
// ---------------------------------------------------------------------------

/// A request to the target VM to generate events matching certain criteria.
///
/// Maps to JDWP EventRequest commands. Each request has an ID, a kind, a
/// suspend policy, and a list of filter modifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiEventRequest {
    /// Unique request ID.
    pub request_id: u64,
    /// The kind of event to request.
    pub event_kind: JdiEventKind,
    /// The suspend policy for matching events.
    pub suspend_policy: JdiSuspendPolicy,
    /// Filters/modifiers on this request.
    pub modifiers: Vec<JdiEventModifier>,
    /// Whether this request is currently active (enabled).
    pub enabled: bool,
}

impl JdiEventRequest {
    /// Create a new event request.
    pub fn new(request_id: u64, event_kind: JdiEventKind, suspend_policy: JdiSuspendPolicy) -> Self {
        Self {
            request_id,
            event_kind,
            suspend_policy,
            modifiers: Vec::new(),
            enabled: true,
        }
    }

    /// Add a modifier/filter.
    pub fn with_modifier(mut self, modifier: JdiEventModifier) -> Self {
        self.modifiers.push(modifier);
        self
    }

    /// Enable or disable this request.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

// ---------------------------------------------------------------------------
// JdiEventModifier
// ---------------------------------------------------------------------------

/// A filter modifier on a JDI event request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JdiEventModifier {
    /// Restrict to a specific thread.
    Thread(u64),
    /// Restrict to a specific class.
    ClassRefType(u64),
    /// Restrict to a specific class pattern (e.g., "com.example.*").
    ClassPattern(String),
    /// Restrict to a specific location.
    Location {
        /// Class ID.
        class_id: u64,
        /// Method ID.
        method_id: u64,
        /// Index within the method.
        index: u64,
    },
    /// Exception class filter.
    ExceptionOnly {
        /// Exception class to catch (None = all exceptions).
        exception_class_id: Option<u64>,
        /// Whether to catch caught exceptions.
        caught: bool,
        /// Whether to catch uncaught exceptions.
        uncaught: bool,
    },
    /// Count filter -- only fire after N occurrences.
    Count(u32),
    /// Conditional filter -- only fire when condition is true.
    Conditional(String),
}

// ---------------------------------------------------------------------------
// JdiEventsListenerAdapter
// ---------------------------------------------------------------------------

/// A default implementation of `JdiEventsListener` that returns `Continue`
/// for every callback. Concrete implementations can override only the methods
/// they care about.
///
/// Ported from Ghidra's `JdiEventsListenerAdapter`.
pub struct JdiEventsListenerAdapter;

impl JdiEventsListener for JdiEventsListenerAdapter {}

// ---------------------------------------------------------------------------
// JdiWatchpointInfo
// ---------------------------------------------------------------------------

/// Information about a watchpoint (field access or modification).
///
/// Ported from Ghidra's `AccessWatchpointEvent` / `ModificationWatchpointEvent`
/// usage in the JDI event handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiWatchpointInfo {
    /// The field being watched.
    pub field_name: String,
    /// The declaring type of the field.
    pub declaring_type: String,
    /// The object reference (if an instance field).
    pub object_id: Option<u64>,
    /// The value current at the time of the watchpoint.
    pub value_current: Option<String>,
    /// The value to be written (for modification watchpoints).
    pub value_to_be: Option<String>,
}

impl JdiWatchpointInfo {
    /// Create a new watchpoint info.
    pub fn new(
        field_name: impl Into<String>,
        declaring_type: impl Into<String>,
    ) -> Self {
        Self {
            field_name: field_name.into(),
            declaring_type: declaring_type.into(),
            object_id: None,
            value_current: None,
            value_to_be: None,
        }
    }
}

// ---------------------------------------------------------------------------
// JdiEventRequestManager
// ---------------------------------------------------------------------------

/// Manages event requests for a single VM, mirroring the JDWP
/// `EventRequestManager`.
///
/// Ported from Ghidra's `EventRequestManager` usage in `JdiConnector`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiEventRequestManager {
    /// VM this manager belongs to.
    pub vm_id: u64,
    /// Active event requests.
    pub requests: BTreeMap<u64, JdiEventRequest>,
    /// Next request ID.
    next_request_id: u64,
}

impl JdiEventRequestManager {
    /// Create a new event request manager.
    pub fn new(vm_id: u64) -> Self {
        Self {
            vm_id,
            requests: BTreeMap::new(),
            next_request_id: 1,
        }
    }

    /// Create a breakpoint request at a location.
    pub fn create_breakpoint_request(
        &mut self,
        class_id: u64,
        method_id: u64,
        index: u64,
    ) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = JdiEventRequest::new(id, JdiEventKind::Breakpoint, JdiSuspendPolicy::All)
            .with_modifier(JdiEventModifier::Location {
                class_id,
                method_id,
                index,
            });
        self.requests.insert(id, req);
        id
    }

    /// Create a step request.
    pub fn create_step_request(
        &mut self,
        thread_id: u64,
        suspend_policy: JdiSuspendPolicy,
    ) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = JdiEventRequest::new(id, JdiEventKind::Step, suspend_policy)
            .with_modifier(JdiEventModifier::Thread(thread_id));
        self.requests.insert(id, req);
        id
    }

    /// Create a thread start request.
    pub fn create_thread_start_request(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = JdiEventRequest::new(id, JdiEventKind::ThreadStart, JdiSuspendPolicy::None);
        self.requests.insert(id, req);
        id
    }

    /// Create a thread death request.
    pub fn create_thread_death_request(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = JdiEventRequest::new(id, JdiEventKind::ThreadDeath, JdiSuspendPolicy::None);
        self.requests.insert(id, req);
        id
    }

    /// Create a VM death request.
    pub fn create_vm_death_request(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = JdiEventRequest::new(id, JdiEventKind::VmDeath, JdiSuspendPolicy::All);
        self.requests.insert(id, req);
        id
    }

    /// Create an exception request.
    pub fn create_exception_request(
        &mut self,
        exception_class_id: Option<u64>,
        caught: bool,
        uncaught: bool,
    ) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = JdiEventRequest::new(id, JdiEventKind::Exception, JdiSuspendPolicy::All)
            .with_modifier(JdiEventModifier::ExceptionOnly {
                exception_class_id,
                caught,
                uncaught,
            });
        self.requests.insert(id, req);
        id
    }

    /// Create a class prepare request.
    pub fn create_class_prepare_request(
        &mut self,
        class_pattern: Option<String>,
    ) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let mut req = JdiEventRequest::new(id, JdiEventKind::ClassPrepare, JdiSuspendPolicy::All);
        if let Some(pattern) = class_pattern {
            req = req.with_modifier(JdiEventModifier::ClassPattern(pattern));
        }
        self.requests.insert(id, req);
        id
    }

    /// Create a method entry request.
    pub fn create_method_entry_request(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = JdiEventRequest::new(id, JdiEventKind::MethodEntry, JdiSuspendPolicy::None);
        self.requests.insert(id, req);
        id
    }

    /// Create a method exit request.
    pub fn create_method_exit_request(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = JdiEventRequest::new(id, JdiEventKind::MethodExit, JdiSuspendPolicy::None);
        self.requests.insert(id, req);
        id
    }

    /// Create a monitor contended enter request.
    pub fn create_monitor_contended_enter_request(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = JdiEventRequest::new(
            id,
            JdiEventKind::MonitorContendedEnter,
            JdiSuspendPolicy::None,
        );
        self.requests.insert(id, req);
        id
    }

    /// Create a monitor contended entered request.
    pub fn create_monitor_contended_entered_request(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req = JdiEventRequest::new(
            id,
            JdiEventKind::MonitorContendedEntered,
            JdiSuspendPolicy::None,
        );
        self.requests.insert(id, req);
        id
    }

    /// Create a monitor wait request.
    pub fn create_monitor_wait_request(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req =
            JdiEventRequest::new(id, JdiEventKind::MonitorWait, JdiSuspendPolicy::None);
        self.requests.insert(id, req);
        id
    }

    /// Create a monitor waited request.
    pub fn create_monitor_waited_request(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        let req =
            JdiEventRequest::new(id, JdiEventKind::MonitorWaited, JdiSuspendPolicy::None);
        self.requests.insert(id, req);
        id
    }

    /// Enable a request.
    pub fn enable_request(&mut self, request_id: u64) -> Result<(), String> {
        let req = self
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| format!("Unknown request id {request_id}"))?;
        req.set_enabled(true);
        Ok(())
    }

    /// Disable a request.
    pub fn disable_request(&mut self, request_id: u64) -> Result<(), String> {
        let req = self
            .requests
            .get_mut(&request_id)
            .ok_or_else(|| format!("Unknown request id {request_id}"))?;
        req.set_enabled(false);
        Ok(())
    }

    /// Delete a request.
    pub fn delete_request(&mut self, request_id: u64) -> Result<(), String> {
        if self.requests.remove(&request_id).is_none() {
            return Err(format!("Unknown request id {request_id}"));
        }
        Ok(())
    }

    /// Get all enabled requests of a given kind.
    pub fn enabled_requests_of(&self, kind: JdiEventKind) -> Vec<&JdiEventRequest> {
        self.requests
            .values()
            .filter(|r| r.event_kind == kind && r.enabled)
            .collect()
    }

    /// Get all breakpoint requests.
    pub fn breakpoint_requests(&self) -> Vec<&JdiEventRequest> {
        self.enabled_requests_of(JdiEventKind::Breakpoint)
    }

    /// Get all step requests.
    pub fn step_requests(&self) -> Vec<&JdiEventRequest> {
        self.enabled_requests_of(JdiEventKind::Step)
    }
}

// ---------------------------------------------------------------------------
// JdiVmEventHandlerState
// ---------------------------------------------------------------------------

/// Per-VM event handler state, tracking which data needs refreshing.
///
/// Ported from Ghidra's `VmState` class in `JdiHooks.java`.
#[derive(Debug, Clone)]
pub struct JdiVmEventHandlerState {
    /// Whether classes need refreshing.
    pub classes_dirty: bool,
    /// Whether modules need refreshing.
    pub modules_dirty: bool,
    /// Whether memory regions need refreshing.
    pub regions_dirty: bool,
    /// Whether threads need refreshing.
    pub threads_dirty: bool,
    /// Whether breakpoints need refreshing.
    pub breakpoints_dirty: bool,
    /// Whether events need refreshing.
    pub events_dirty: bool,
    /// Visited objects for deduplication during a single stop.
    pub visited: HashSet<String>,
    /// Whether this is the first pass (initial load).
    pub first_pass: bool,
}

impl JdiVmEventHandlerState {
    /// Create a new handler state (first pass).
    pub fn new() -> Self {
        Self {
            classes_dirty: false,
            modules_dirty: false,
            regions_dirty: false,
            threads_dirty: false,
            breakpoints_dirty: false,
            events_dirty: false,
            visited: HashSet::new(),
            first_pass: true,
        }
    }

    /// Mark all data as dirty (needs refresh).
    pub fn mark_all_dirty(&mut self) {
        self.classes_dirty = true;
        self.modules_dirty = true;
        self.regions_dirty = true;
        self.threads_dirty = true;
        self.breakpoints_dirty = true;
        self.events_dirty = true;
    }

    /// Clear the visited set (called at start of a new stop event).
    pub fn clear_visited(&mut self) {
        self.visited.clear();
    }

    /// Mark the first pass as complete.
    pub fn complete_first_pass(&mut self) {
        self.first_pass = false;
    }
}

impl Default for JdiVmEventHandlerState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JdiHookEventProcessor
// ---------------------------------------------------------------------------

/// High-level event processor that coordinates VM state updates when
/// debug events occur.
///
/// Ported from Ghidra's `JdiHooks` class which handles `onStop`,
/// `onContinue`, `enableCurrentVM`, `disableCurrentVM`.
#[derive(Debug)]
pub struct JdiHookEventProcessor {
    /// Per-VM handler states.
    vm_states: BTreeMap<u64, JdiVmEventHandlerState>,
    /// Shutdown message key.
    shutdown_message: Option<String>,
    /// Whether the VM has died.
    vm_died: bool,
    /// Connected flag.
    connected: bool,
}

impl JdiHookEventProcessor {
    /// Create a new hook event processor.
    pub fn new() -> Self {
        Self {
            vm_states: BTreeMap::new(),
            shutdown_message: None,
            vm_died: false,
            connected: true,
        }
    }

    /// Enable tracking for a VM (called when a VM starts).
    pub fn enable_vm(&mut self, vm_id: u64) {
        let mut state = JdiVmEventHandlerState::new();
        state.mark_all_dirty();
        self.vm_states.insert(vm_id, state);
    }

    /// Disable tracking for a VM (called when a VM disconnects).
    pub fn disable_vm(&mut self, vm_id: u64) {
        self.vm_states.remove(&vm_id);
    }

    /// Get the handler state for a VM.
    pub fn vm_state(&self, vm_id: u64) -> Option<&JdiVmEventHandlerState> {
        self.vm_states.get(&vm_id)
    }

    /// Get a mutable reference to the handler state for a VM.
    pub fn vm_state_mut(&mut self, vm_id: u64) -> Option<&mut JdiVmEventHandlerState> {
        self.vm_states.get_mut(&vm_id)
    }

    /// Process a stop event: clear visited, mark threads dirty.
    ///
    /// Ported from `JdiHooks.onStop`.
    pub fn on_stop(&mut self, vm_id: u64) {
        if let Some(state) = self.vm_states.get_mut(&vm_id) {
            state.clear_visited();
            state.threads_dirty = true;
            state.breakpoints_dirty = true;
            state.events_dirty = true;
        }
    }

    /// Process a continue event.
    ///
    /// Ported from `JdiHooks.onContinue`.
    pub fn on_continue(&mut self, _vm_id: u64) {
        // In the full implementation, this would update thread state
        // to RUNNING and snapshot the trace.
    }

    /// Process a VM death event.
    pub fn on_vm_death(&mut self, vm_id: u64) {
        self.vm_died = true;
        self.shutdown_message = Some("The application exited".into());
        if let Some(state) = self.vm_states.get_mut(&vm_id) {
            state.mark_all_dirty();
        }
    }

    /// Process a VM disconnect event.
    pub fn on_vm_disconnect(&mut self, vm_id: u64) {
        self.connected = false;
        if !self.vm_died {
            self.shutdown_message = Some("The application has been disconnected".into());
        }
        self.disable_vm(vm_id);
    }

    /// Whether the processor is still connected.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Get the shutdown message, if any.
    pub fn shutdown_message(&self) -> Option<&str> {
        self.shutdown_message.as_deref()
    }

    /// Get the number of tracked VMs.
    pub fn vm_count(&self) -> usize {
        self.vm_states.len()
    }
}

impl Default for JdiHookEventProcessor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// JdiEventQueue
// ---------------------------------------------------------------------------

/// A queue for buffering incoming JDI event sets.
///
/// Ported from Ghidra's `EventQueue` usage in `JdiEventHandler.run()`.
#[derive(Debug)]
pub struct JdiEventQueue {
    /// Buffered event sets.
    queue: Vec<JdiEventSet>,
    /// Maximum capacity.
    capacity: usize,
}

impl JdiEventQueue {
    /// Create a new event queue with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            queue: Vec::new(),
            capacity,
        }
    }

    /// Push an event set onto the queue. Returns `false` if the queue is full.
    pub fn push(&mut self, event_set: JdiEventSet) -> bool {
        if self.queue.len() >= self.capacity {
            return false;
        }
        self.queue.push(event_set);
        true
    }

    /// Pop the next event set from the queue.
    pub fn pop(&mut self) -> Option<JdiEventSet> {
        if self.queue.is_empty() {
            None
        } else {
            Some(self.queue.remove(0))
        }
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// The number of buffered event sets.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Drain all event sets.
    pub fn drain(&mut self) -> Vec<JdiEventSet> {
        std::mem::take(&mut self.queue)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_kind_display() {
        assert_eq!(JdiEventKind::Breakpoint.to_string(), "Breakpoint");
        assert_eq!(JdiEventKind::VmDeath.to_string(), "VM Death");
        assert_eq!(JdiEventKind::ThreadStart.to_string(), "Thread Start");
    }

    #[test]
    fn test_suspend_policy_variants() {
        assert_ne!(JdiSuspendPolicy::None, JdiSuspendPolicy::All);
        assert_ne!(JdiSuspendPolicy::EventThread, JdiSuspendPolicy::All);
    }

    #[test]
    fn test_event_constructors() {
        let bp = JdiEvent::breakpoint(1, 10, 100, 5);
        assert_eq!(bp.kind, JdiEventKind::Breakpoint);
        assert_eq!(bp.breakpoint_id, Some(5));
        assert_eq!(bp.thread_id, Some(100));
        assert_eq!(bp.vm_id, 1);

        let step = JdiEvent::step(1, 11, 100);
        assert_eq!(step.kind, JdiEventKind::Step);

        let ts = JdiEvent::thread_start(1, 12, 200);
        assert_eq!(ts.kind, JdiEventKind::ThreadStart);

        let td = JdiEvent::thread_death(1, 13, 200);
        assert_eq!(td.kind, JdiEventKind::ThreadDeath);

        let vs = JdiEvent::vm_start(1, 14, 100);
        assert_eq!(vs.kind, JdiEventKind::VmStart);

        let vd = JdiEvent::vm_death(1, 15);
        assert_eq!(vd.kind, JdiEventKind::VmDeath);
        assert!(vd.thread_id.is_none());

        let exc = JdiEvent::exception(1, 16, 100, "java.lang.NullPointerException");
        assert_eq!(exc.kind, JdiEventKind::Exception);
        assert_eq!(
            exc.exception_class.as_deref(),
            Some("java.lang.NullPointerException")
        );

        let cp = JdiEvent::class_prepare(1, 17, 100, "com.example.Main");
        assert_eq!(cp.kind, JdiEventKind::ClassPrepare);
        assert_eq!(cp.class_name.as_deref(), Some("com.example.Main"));
    }

    #[test]
    fn test_event_is_lifecycle() {
        assert!(JdiEvent::vm_start(1, 1, 1).is_lifecycle());
        assert!(JdiEvent::vm_death(1, 1).is_lifecycle());
        let disconnect = JdiEvent {
            kind: JdiEventKind::VmDisconnect,
            request_id: 1,
            thread_id: None,
            vm_id: 1,
            breakpoint_id: None,
            exception_class: None,
            location_class_id: None,
            location_method_id: None,
            location_index: None,
            class_name: None,
            error_message: None,
        };
        assert!(disconnect.is_lifecycle());
        assert!(!JdiEvent::step(1, 1, 1).is_lifecycle());
    }

    #[test]
    fn test_event_is_thread_event() {
        assert!(JdiEvent::thread_start(1, 1, 1).is_thread_event());
        assert!(JdiEvent::thread_death(1, 1, 1).is_thread_event());
        assert!(!JdiEvent::breakpoint(1, 1, 1, 1).is_thread_event());
    }

    #[test]
    fn test_event_causes_suspend() {
        let event = JdiEvent::step(1, 1, 100);
        assert!(!event.causes_suspend(JdiSuspendPolicy::None));
        assert!(event.causes_suspend(JdiSuspendPolicy::EventThread));
        assert!(event.causes_suspend(JdiSuspendPolicy::All));

        let vm_event = JdiEvent::vm_death(1, 1);
        assert!(!vm_event.causes_suspend(JdiSuspendPolicy::None));
        assert!(!vm_event.causes_suspend(JdiSuspendPolicy::EventThread));
        assert!(vm_event.causes_suspend(JdiSuspendPolicy::All));
    }

    #[test]
    fn test_event_set_basic() {
        let mut es = JdiEventSet::new(JdiSuspendPolicy::All);
        assert!(es.is_empty());
        assert_eq!(es.len(), 0);

        es.push(JdiEvent::breakpoint(1, 1, 10, 5));
        es.push(JdiEvent::step(1, 2, 10));
        assert_eq!(es.len(), 2);
        assert!(!es.is_empty());
    }

    #[test]
    fn test_event_set_with_events() {
        let events = vec![
            JdiEvent::vm_start(1, 1, 10),
            JdiEvent::thread_start(1, 2, 20),
        ];
        let es = JdiEventSet::with_events(JdiSuspendPolicy::All, events);
        assert_eq!(es.len(), 2);
        assert_eq!(es.vm_id(), Some(1));
    }

    #[test]
    fn test_event_set_queries() {
        let es = JdiEventSet::with_events(
            JdiSuspendPolicy::All,
            vec![
                JdiEvent::breakpoint(1, 1, 10, 5),
                JdiEvent::thread_death(1, 2, 20),
                JdiEvent::vm_death(1, 3),
            ],
        );

        assert!(es.has_vm_death());
        assert!(es.has_breakpoint());
        assert!(!es.has_step());

        let threads = es.referenced_threads();
        assert_eq!(threads, vec![10, 20]);
    }

    #[test]
    fn test_event_set_empty() {
        let es = JdiEventSet::new(JdiSuspendPolicy::None);
        assert!(es.is_empty());
        assert!(!es.has_vm_death());
        assert!(!es.has_breakpoint());
        assert!(es.referenced_threads().is_empty());
        assert!(es.vm_id().is_none());
    }

    #[test]
    fn test_process_event_set_breakpoint() {
        struct TestHandler {
            breakpoints_hit: Vec<(u64, u64)>,
        }
        impl JdiEventHandler for TestHandler {
            fn handle_breakpoint(
                &mut self,
                _vm_id: u64,
                bp_id: u64,
                thread_id: u64,
                _cause: &JdiCause,
            ) -> DebugStatus {
                self.breakpoints_hit.push((bp_id, thread_id));
                DebugStatus::Continue
            }
        }

        let mut handler = TestHandler {
            breakpoints_hit: vec![],
        };
        let es = JdiEventSet::with_events(
            JdiSuspendPolicy::All,
            vec![JdiEvent::breakpoint(1, 1, 10, 5)],
        );

        let status = process_event_set(&mut handler, &es);
        assert_eq!(status, DebugStatus::Continue);
        assert_eq!(handler.breakpoints_hit, vec![(5, 10)]);
    }

    #[test]
    fn test_process_event_set_early_stop() {
        struct StopOnStep;
        impl JdiEventHandler for StopOnStep {
            fn handle_step(
                &mut self,
                _vm_id: u64,
                _thread_id: u64,
                _cause: &JdiCause,
            ) -> DebugStatus {
                DebugStatus::Handled
            }
        }

        let mut handler = StopOnStep;
        let es = JdiEventSet::with_events(
            JdiSuspendPolicy::EventThread,
            vec![
                JdiEvent::step(1, 1, 10),
                // This event should not be processed
                JdiEvent::breakpoint(1, 2, 10, 3),
            ],
        );

        let status = process_event_set(&mut handler, &es);
        assert_eq!(status, DebugStatus::Handled);
    }

    #[test]
    fn test_process_event_set_vm_death() {
        struct DeathHandler {
            died: bool,
        }
        impl JdiEventHandler for DeathHandler {
            fn handle_vm_death(&mut self, _vm_id: u64, _cause: &JdiCause) -> DebugStatus {
                self.died = true;
                DebugStatus::Handled
            }
        }

        let mut handler = DeathHandler { died: false };
        let es = JdiEventSet::with_events(
            JdiSuspendPolicy::All,
            vec![JdiEvent::vm_death(1, 1)],
        );

        process_event_set(&mut handler, &es);
        assert!(handler.died);
    }

    #[test]
    fn test_process_event_set_mixed() {
        struct MixedHandler {
            events: Vec<String>,
        }
        impl JdiEventHandler for MixedHandler {
            fn handle_thread_start(
                &mut self,
                _vm_id: u64,
                _thread_id: u64,
                _cause: &JdiCause,
            ) -> DebugStatus {
                self.events.push("thread_start".into());
                DebugStatus::Continue
            }
            fn handle_step(
                &mut self,
                _vm_id: u64,
                _thread_id: u64,
                _cause: &JdiCause,
            ) -> DebugStatus {
                self.events.push("step".into());
                DebugStatus::Continue
            }
            fn handle_breakpoint(
                &mut self,
                _vm_id: u64,
                _bp_id: u64,
                _thread_id: u64,
                _cause: &JdiCause,
            ) -> DebugStatus {
                self.events.push("breakpoint".into());
                DebugStatus::Continue
            }
        }

        let mut handler = MixedHandler { events: vec![] };
        let es = JdiEventSet::with_events(
            JdiSuspendPolicy::All,
            vec![
                JdiEvent::thread_start(1, 1, 10),
                JdiEvent::step(1, 2, 10),
                JdiEvent::breakpoint(1, 3, 10, 5),
            ],
        );

        let status = process_event_set(&mut handler, &es);
        assert_eq!(status, DebugStatus::Continue);
        assert_eq!(
            handler.events,
            vec!["thread_start", "step", "breakpoint"]
        );
    }

    #[test]
    fn test_process_event_set_exception() {
        struct ExcHandler {
            caught: Vec<String>,
        }
        impl JdiEventHandler for ExcHandler {
            fn handle_exception(
                &mut self,
                _vm_id: u64,
                _thread_id: u64,
                exception_class: &str,
                _cause: &JdiCause,
            ) -> DebugStatus {
                self.caught.push(exception_class.to_string());
                DebugStatus::Continue
            }
        }

        let mut handler = ExcHandler { caught: vec![] };
        let es = JdiEventSet::with_events(
            JdiSuspendPolicy::All,
            vec![JdiEvent::exception(
                1,
                1,
                10,
                "java.lang.NullPointerException",
            )],
        );

        process_event_set(&mut handler, &es);
        assert_eq!(handler.caught, vec!["java.lang.NullPointerException"]);
    }

    #[test]
    fn test_process_event_set_unhandled() {
        struct DefaultHandler;
        impl JdiEventHandler for DefaultHandler {}

        let mut handler = DefaultHandler;
        let gc_event = JdiEvent {
            kind: JdiEventKind::Gc,
            request_id: 1,
            thread_id: None,
            vm_id: 1,
            breakpoint_id: None,
            exception_class: None,
            location_class_id: None,
            location_method_id: None,
            location_index: None,
            class_name: None,
            error_message: None,
        };
        let es = JdiEventSet::with_events(JdiSuspendPolicy::None, vec![gc_event]);

        let status = process_event_set(&mut handler, &es);
        assert_eq!(status, DebugStatus::Continue);
    }

    #[test]
    fn test_event_request() {
        let req = JdiEventRequest::new(1, JdiEventKind::Breakpoint, JdiSuspendPolicy::All)
            .with_modifier(JdiEventModifier::ClassPattern("com.example.Main".into()))
            .with_modifier(JdiEventModifier::Count(1));

        assert_eq!(req.request_id, 1);
        assert_eq!(req.event_kind, JdiEventKind::Breakpoint);
        assert_eq!(req.suspend_policy, JdiSuspendPolicy::All);
        assert_eq!(req.modifiers.len(), 2);
        assert!(req.enabled);
    }

    #[test]
    fn test_event_request_enable_disable() {
        let mut req = JdiEventRequest::new(1, JdiEventKind::Step, JdiSuspendPolicy::EventThread);
        assert!(req.enabled);

        req.set_enabled(false);
        assert!(!req.enabled);

        req.set_enabled(true);
        assert!(req.enabled);
    }

    #[test]
    fn test_event_modifier_variants() {
        let modifiers = vec![
            JdiEventModifier::Thread(1),
            JdiEventModifier::ClassRefType(100),
            JdiEventModifier::ClassPattern("java.lang.*".into()),
            JdiEventModifier::Location {
                class_id: 10,
                method_id: 20,
                index: 30,
            },
            JdiEventModifier::ExceptionOnly {
                exception_class_id: Some(50),
                caught: true,
                uncaught: true,
            },
            JdiEventModifier::Count(5),
            JdiEventModifier::Conditional("x > 10".into()),
        ];

        assert_eq!(modifiers.len(), 7);
    }

    #[test]
    fn test_event_set_serde() {
        let es = JdiEventSet::with_events(
            JdiSuspendPolicy::All,
            vec![
                JdiEvent::breakpoint(1, 1, 10, 5),
                JdiEvent::step(1, 2, 10),
            ],
        );
        let json = serde_json::to_string(&es).unwrap();
        let back: JdiEventSet = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back.suspend_policy, JdiSuspendPolicy::All);
    }

    #[test]
    fn test_event_request_serde() {
        let req = JdiEventRequest::new(1, JdiEventKind::Exception, JdiSuspendPolicy::All);
        let json = serde_json::to_string(&req).unwrap();
        let back: JdiEventRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.request_id, 1);
        assert_eq!(back.event_kind, JdiEventKind::Exception);
    }

    #[test]
    fn test_all_event_kinds_covered() {
        let kinds = [
            JdiEventKind::VmStart,
            JdiEventKind::Step,
            JdiEventKind::Breakpoint,
            JdiEventKind::MethodEntry,
            JdiEventKind::MethodExit,
            JdiEventKind::Exception,
            JdiEventKind::ThreadStart,
            JdiEventKind::ThreadDeath,
            JdiEventKind::ClassPrepare,
            JdiEventKind::ClassUnload,
            JdiEventKind::FieldAccess,
            JdiEventKind::FieldModification,
            JdiEventKind::VmDeath,
            JdiEventKind::VmDisconnect,
            JdiEventKind::MonitorContendedEntered,
            JdiEventKind::MonitorContendedEnter,
            JdiEventKind::MonitorWaited,
            JdiEventKind::MonitorWait,
            JdiEventKind::Gc,
        ];
        // Each kind should produce a distinct display string
        let mut strings: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
        let original_len = strings.len();
        strings.sort();
        strings.dedup();
        assert_eq!(strings.len(), original_len);
    }

    #[test]
    fn test_events_listener_adapter() {
        let mut adapter = JdiEventsListenerAdapter;
        let cause = JdiCause::user("test");
        // All default methods on JdiEventsListener return Continue
        assert_eq!(adapter.breakpoint_hit(1, 1, &cause), DebugStatus::Continue);
        assert_eq!(adapter.step_complete(1, &cause), DebugStatus::Continue);
        assert_eq!(adapter.vm_died(1, &cause), DebugStatus::Continue);
        assert_eq!(adapter.thread_started(1, &cause), DebugStatus::Continue);
    }

    #[test]
    fn test_watchpoint_info() {
        let wp = JdiWatchpointInfo::new("count", "com.example.Counter");
        assert_eq!(wp.field_name, "count");
        assert_eq!(wp.declaring_type, "com.example.Counter");
        assert!(wp.object_id.is_none());
        assert!(wp.value_current.is_none());
    }

    #[test]
    fn test_event_request_manager_create() {
        let mut mgr = JdiEventRequestManager::new(1);

        let bp_id = mgr.create_breakpoint_request(10, 20, 30);
        assert_eq!(bp_id, 1);
        assert!(mgr.requests.contains_key(&bp_id));

        let step_id = mgr.create_step_request(100, JdiSuspendPolicy::EventThread);
        assert_eq!(step_id, 2);

        let ts_id = mgr.create_thread_start_request();
        assert_eq!(ts_id, 3);

        let td_id = mgr.create_thread_death_request();
        assert_eq!(td_id, 4);

        let vd_id = mgr.create_vm_death_request();
        assert_eq!(vd_id, 5);

        let exc_id = mgr.create_exception_request(Some(50), true, true);
        assert_eq!(exc_id, 6);

        let cp_id = mgr.create_class_prepare_request(Some("com.example.*".into()));
        assert_eq!(cp_id, 7);

        let me_id = mgr.create_method_entry_request();
        assert_eq!(me_id, 8);

        let mx_id = mgr.create_method_exit_request();
        assert_eq!(mx_id, 9);
    }

    #[test]
    fn test_event_request_manager_enable_disable_delete() {
        let mut mgr = JdiEventRequestManager::new(1);
        let id = mgr.create_thread_start_request();

        assert!(mgr.requests.get(&id).unwrap().enabled);

        mgr.disable_request(id).unwrap();
        assert!(!mgr.requests.get(&id).unwrap().enabled);

        mgr.enable_request(id).unwrap();
        assert!(mgr.requests.get(&id).unwrap().enabled);

        mgr.delete_request(id).unwrap();
        assert!(!mgr.requests.contains_key(&id));
    }

    #[test]
    fn test_event_request_manager_queries() {
        let mut mgr = JdiEventRequestManager::new(1);
        mgr.create_breakpoint_request(1, 2, 3);
        mgr.create_breakpoint_request(4, 5, 6);
        mgr.create_step_request(10, JdiSuspendPolicy::EventThread);

        assert_eq!(mgr.breakpoint_requests().len(), 2);
        assert_eq!(mgr.step_requests().len(), 1);

        let all_bp = mgr.enabled_requests_of(JdiEventKind::Breakpoint);
        assert_eq!(all_bp.len(), 2);
    }

    #[test]
    fn test_event_request_manager_errors() {
        let mut mgr = JdiEventRequestManager::new(1);
        assert!(mgr.enable_request(999).is_err());
        assert!(mgr.disable_request(999).is_err());
        assert!(mgr.delete_request(999).is_err());
    }

    #[test]
    fn test_vm_event_handler_state() {
        let mut state = JdiVmEventHandlerState::new();
        assert!(state.first_pass);
        assert!(!state.classes_dirty);

        state.mark_all_dirty();
        assert!(state.classes_dirty);
        assert!(state.modules_dirty);
        assert!(state.breakpoints_dirty);

        state.visited.insert("test".into());
        assert!(!state.visited.is_empty());
        state.clear_visited();
        assert!(state.visited.is_empty());

        state.complete_first_pass();
        assert!(!state.first_pass);
    }

    #[test]
    fn test_hook_event_processor() {
        let mut proc = JdiHookEventProcessor::new();
        assert!(proc.is_connected());
        assert_eq!(proc.vm_count(), 0);

        proc.enable_vm(1);
        assert_eq!(proc.vm_count(), 1);

        let state = proc.vm_state(1).unwrap();
        assert!(state.first_pass);

        proc.on_stop(1);
        let state = proc.vm_state(1).unwrap();
        assert!(state.threads_dirty);

        proc.on_vm_death(1);
        assert!(proc.shutdown_message().is_some());
        assert_eq!(proc.shutdown_message(), Some("The application exited"));

        proc.on_vm_disconnect(1);
        assert!(!proc.is_connected());
    }

    #[test]
    fn test_hook_event_processor_enable_disable() {
        let mut proc = JdiHookEventProcessor::new();
        proc.enable_vm(1);
        proc.enable_vm(2);
        assert_eq!(proc.vm_count(), 2);

        proc.disable_vm(1);
        assert_eq!(proc.vm_count(), 1);
        assert!(proc.vm_state(1).is_none());
        assert!(proc.vm_state(2).is_some());
    }

    #[test]
    fn test_event_queue() {
        let mut queue = JdiEventQueue::new(10);
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);

        let es = JdiEventSet::with_events(
            JdiSuspendPolicy::All,
            vec![JdiEvent::breakpoint(1, 1, 10, 5)],
        );
        assert!(queue.push(es));
        assert_eq!(queue.len(), 1);

        let popped = queue.pop().unwrap();
        assert_eq!(popped.len(), 1);
        assert!(queue.is_empty());
    }

    #[test]
    fn test_event_queue_capacity() {
        let mut queue = JdiEventQueue::new(2);
        let es1 = JdiEventSet::new(JdiSuspendPolicy::None);
        let es2 = JdiEventSet::new(JdiSuspendPolicy::None);
        let es3 = JdiEventSet::new(JdiSuspendPolicy::None);

        assert!(queue.push(es1));
        assert!(queue.push(es2));
        assert!(!queue.push(es3)); // full
        assert_eq!(queue.len(), 2);
    }

    #[test]
    fn test_event_queue_drain() {
        let mut queue = JdiEventQueue::new(10);
        queue.push(JdiEventSet::new(JdiSuspendPolicy::None));
        queue.push(JdiEventSet::new(JdiSuspendPolicy::All));

        let drained = queue.drain();
        assert_eq!(drained.len(), 2);
        assert!(queue.is_empty());
    }
}
