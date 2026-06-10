//! JDI debugger client for connecting to and controlling JVM debug targets.
//!
//! Ported from Ghidra's `ghidra.dbg.jdi.manager.impl.JdiDebuggerClient`
//! and related JPDA connection management classes.
//!
//! The `JdiDebuggerClient` manages the lifecycle of a JDI debug session:
//! establishing connections via the JDWP protocol, issuing commands to the
//! target VM, and coordinating state between the Ghidra debugger framework
//! and the underlying JDI VirtualMachine.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use super::manager::{
    DebugStatus, JdiBreakpointInfo, JdiCause, JdiEventsListener, JdiStateListener, JdiThreadInfo,
};
use super::rmi::{JdiArch, JdiArguments, JdiConnectorType};

// ---------------------------------------------------------------------------
// JdiProcessInfo
// ---------------------------------------------------------------------------

/// Information about a JVM process attached to or launched by the client.
///
/// Ported from Ghidra's `VirtualMachine.process()` usage in `JdiManagerImpl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiProcessInfo {
    /// OS-level process ID.
    pub pid: u64,
    /// Command line used to launch the process.
    pub command: Option<String>,
    /// Full command line (including arguments).
    pub command_line: Option<String>,
    /// Whether the process is still alive.
    pub is_alive: bool,
    /// Exit code, if the process has terminated.
    pub exit_code: Option<i32>,
}

impl JdiProcessInfo {
    /// Create a new process info entry.
    pub fn new(pid: u64) -> Self {
        Self {
            pid,
            command: None,
            command_line: None,
            is_alive: true,
            exit_code: None,
        }
    }
}

// ---------------------------------------------------------------------------
// JdiStackFrameInfo
// ---------------------------------------------------------------------------

/// Summary information about a stack frame on a suspended thread.
///
/// Ported from Ghidra's `StackFrame` usage in `JdiCommands`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiStackFrameInfo {
    /// Zero-based frame index.
    pub index: u32,
    /// Method name.
    pub method_name: String,
    /// Declaring type (class) name.
    pub declaring_type: String,
    /// Code index (bytecode offset within the method).
    pub code_index: i64,
    /// Source file line number, if available.
    pub line_number: Option<u32>,
    /// Source file name, if available.
    pub source_name: Option<String>,
    /// Register values captured for this frame: register name -> value.
    pub registers: BTreeMap<String, u64>,
}

impl JdiStackFrameInfo {
    /// Create a new stack frame info.
    pub fn new(
        index: u32,
        method_name: impl Into<String>,
        declaring_type: impl Into<String>,
        code_index: i64,
    ) -> Self {
        Self {
            index,
            method_name: method_name.into(),
            declaring_type: declaring_type.into(),
            code_index,
            line_number: None,
            source_name: None,
            registers: BTreeMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// JdiThreadState
// ---------------------------------------------------------------------------

/// Thread state constants mirroring JDI's `ThreadReference` status values.
///
/// Ported from `com.sun.jdi.ThreadReference` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JdiThreadState {
    /// Thread has not yet been started.
    NotStarted,
    /// Thread is runnable.
    Running,
    /// Thread is sleeping (Thread.sleep).
    Sleeping,
    /// Thread is blocked on monitor entry.
    Blocked,
    /// Thread is waiting (Object.wait).
    Waiting,
    /// Thread is in a timed wait.
    TimedWaiting,
    /// Thread has exited.
    Zombie,
}

impl fmt::Display for JdiThreadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::NotStarted => "NOT_STARTED",
            Self::Running => "RUNNING",
            Self::Sleeping => "SLEEPING",
            Self::Blocked => "BLOCKED",
            Self::Waiting => "WAITING",
            Self::TimedWaiting => "TIMED_WAITING",
            Self::Zombie => "ZOMBIE",
        };
        write!(f, "{name}")
    }
}

// ---------------------------------------------------------------------------
// JdiDebuggerClientConfig
// ---------------------------------------------------------------------------

/// Configuration for a JDI debugger client session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiDebuggerClientConfig {
    /// Connection arguments.
    pub arguments: JdiArguments,
    /// Target architecture.
    pub arch: JdiArch,
    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Command timeout.
    pub command_timeout: Duration,
    /// Whether to automatically resume the VM after attaching.
    pub auto_resume: bool,
    /// Whether to redirect target output to the Ghidra console.
    pub redirect_output: bool,
    /// Maximum number of pending events to buffer.
    pub event_buffer_size: usize,
}

impl Default for JdiDebuggerClientConfig {
    fn default() -> Self {
        Self {
            arguments: JdiArguments::listen(5005),
            arch: JdiArch::amd64(),
            connect_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(10),
            auto_resume: true,
            redirect_output: true,
            event_buffer_size: 4096,
        }
    }
}

impl JdiDebuggerClientConfig {
    /// Create a config for attaching to a running JVM.
    pub fn attach(host: impl Into<String>, port: u16) -> Self {
        Self {
            arguments: JdiArguments::attach(host, port),
            ..Default::default()
        }
    }

    /// Create a config for launching a new JVM.
    pub fn launch(main_class: impl Into<String>) -> Self {
        Self {
            arguments: JdiArguments::launch(main_class),
            ..Default::default()
        }
    }

    /// Create a config for listening for an incoming JVM connection.
    pub fn listen(port: u16) -> Self {
        Self {
            arguments: JdiArguments::listen(port),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// JdiClientState
// ---------------------------------------------------------------------------

/// The lifecycle state of a JDI debugger client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JdiClientState {
    /// Client is not yet connected.
    Disconnected,
    /// Client is attempting to connect.
    Connecting,
    /// Client is connected but VM is not yet initialized.
    Connected,
    /// VM is initialized and running.
    Running,
    /// VM is suspended (breakpoint, step, or user request).
    Suspended,
    /// VM has exited.
    Exited,
    /// An error has occurred.
    Error,
}

// ---------------------------------------------------------------------------
// JdiVmInfo
// ---------------------------------------------------------------------------

/// Summary information about a connected JVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JdiVmInfo {
    /// Unique VM identifier assigned by the client.
    pub vm_id: u64,
    /// JDWP version string from the target VM.
    pub jdwp_version: String,
    /// Target VM description.
    pub description: String,
    /// Current state.
    pub state: JdiClientState,
    /// All threads known to the VM.
    pub threads: BTreeMap<u64, JdiThreadInfo>,
    /// Loaded classes (class name -> class ID).
    pub classes: BTreeMap<String, u64>,
}

impl JdiVmInfo {
    /// Create a new VM info entry.
    pub fn new(vm_id: u64, description: impl Into<String>) -> Self {
        Self {
            vm_id,
            jdwp_version: String::new(),
            description: description.into(),
            state: JdiClientState::Connected,
            threads: BTreeMap::new(),
            classes: BTreeMap::new(),
        }
    }

    /// Get all thread IDs.
    pub fn thread_ids(&self) -> Vec<u64> {
        self.threads.keys().copied().collect()
    }

    /// Get a thread by ID.
    pub fn thread(&self, thread_id: u64) -> Option<&JdiThreadInfo> {
        self.threads.get(&thread_id)
    }

    /// Get all class names.
    pub fn class_names(&self) -> Vec<String> {
        self.classes.keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// JdiDebuggerClient
// ---------------------------------------------------------------------------

/// A JDI debugger client that manages a debug session against one or more
/// JVM targets.
///
/// Ported from Ghidra's `JdiDebuggerClient` which wraps a JDI
/// `VirtualMachine` and bridges it into Ghidra's `DebuggerModel`.
pub struct JdiDebuggerClient {
    /// Client configuration.
    config: JdiDebuggerClientConfig,
    /// Overall client state.
    state: JdiClientState,
    /// Connected VMs keyed by VM ID.
    vms: BTreeMap<u64, JdiVmInfo>,
    /// Next VM ID to assign.
    next_vm_id: u64,
    /// Next breakpoint ID to assign.
    next_bp_id: u64,
    /// Active breakpoints: bp_id -> info.
    breakpoints: BTreeMap<u64, JdiBreakpointInfo>,
    /// Event listeners keyed by VM ID.
    events_listeners: BTreeMap<u64, Vec<Box<dyn JdiEventsListener>>>,
    /// State listeners keyed by VM ID.
    state_listeners: BTreeMap<u64, Vec<Box<dyn JdiStateListener>>>,

    // -- Ported from JdiManagerImpl state tracking --
    /// Currently focused VM ID (the "current VM").
    current_vm_id: Option<u64>,
    /// Currently focused thread ID within the current VM.
    current_thread_id: Option<u64>,
    /// Stack frames for the current thread, populated when suspended.
    current_frames: Vec<JdiStackFrameInfo>,
    /// Process info keyed by VM ID.
    processes: BTreeMap<u64, JdiProcessInfo>,
    /// Console output buffer (channel, text).
    console_output: Vec<(String, String)>,
    /// Whether the event handler loop is running for a given VM.
    event_handler_running: BTreeMap<u64, bool>,
}

impl JdiDebuggerClient {
    /// Create a new debugger client with the given configuration.
    pub fn new(config: JdiDebuggerClientConfig) -> Self {
        Self {
            config,
            state: JdiClientState::Disconnected,
            vms: BTreeMap::new(),
            next_vm_id: 1,
            next_bp_id: 1,
            breakpoints: BTreeMap::new(),
            events_listeners: BTreeMap::new(),
            state_listeners: BTreeMap::new(),
            current_vm_id: None,
            current_thread_id: None,
            current_frames: Vec::new(),
            processes: BTreeMap::new(),
            console_output: Vec::new(),
            event_handler_running: BTreeMap::new(),
        }
    }

    /// Get the current client state.
    pub fn state(&self) -> JdiClientState {
        self.state
    }

    /// Get the client configuration.
    pub fn config(&self) -> &JdiDebuggerClientConfig {
        &self.config
    }

    /// Get a reference to a connected VM by ID.
    pub fn vm(&self, vm_id: u64) -> Option<&JdiVmInfo> {
        self.vms.get(&vm_id)
    }

    /// Get all connected VMs.
    pub fn vms(&self) -> &BTreeMap<u64, JdiVmInfo> {
        &self.vms
    }

    /// Initiate a connection to the target VM.
    ///
    /// For `Attach` and `Listen` connectors, this blocks until the connection
    /// is established or the connect timeout expires. For `Launch`, a new JVM
    /// process is started.
    pub fn connect(&mut self) -> Result<u64, String> {
        if self.state != JdiClientState::Disconnected
            && self.state != JdiClientState::Exited
            && self.state != JdiClientState::Error
        {
            return Err(format!(
                "Cannot connect from state {:?}",
                self.state
            ));
        }

        self.state = JdiClientState::Connecting;

        // In a full implementation this would perform the JDWP handshake.
        // For the Rust port we model the state transitions.
        let vm_id = self.next_vm_id;
        self.next_vm_id += 1;

        let mut vm_info = JdiVmInfo::new(vm_id, self.config.arguments.connector_type.connector_type_label());
        vm_info.state = JdiClientState::Connected;
        self.vms.insert(vm_id, vm_info);

        self.state = JdiClientState::Connected;

        if self.config.auto_resume {
            self.do_resume(vm_id)?;
        }

        Ok(vm_id)
    }

    /// Disconnect from all VMs and shut down the client.
    pub fn disconnect(&mut self) {
        for vm in self.vms.values_mut() {
            vm.state = JdiClientState::Exited;
        }
        self.state = JdiClientState::Disconnected;
    }

    /// Remove a specific VM from the client.
    pub fn remove_vm(&mut self, vm_id: u64) -> Result<(), String> {
        if self.vms.remove(&vm_id).is_none() {
            return Err(format!("Unknown VM id {vm_id}"));
        }
        self.events_listeners.remove(&vm_id);
        self.state_listeners.remove(&vm_id);
        if self.vms.is_empty() {
            self.state = JdiClientState::Disconnected;
        }
        Ok(())
    }

    /// Resume a suspended VM.
    pub fn do_resume(&mut self, vm_id: u64) -> Result<(), String> {
        let vm = self
            .vms
            .get_mut(&vm_id)
            .ok_or_else(|| format!("Unknown VM id {vm_id}"))?;

        if vm.state != JdiClientState::Suspended && vm.state != JdiClientState::Connected {
            return Err(format!("Cannot resume VM in state {:?}", vm.state));
        }

        vm.state = JdiClientState::Running;
        self.state = JdiClientState::Running;
        self.fire_state_changed(vm_id);
        Ok(())
    }

    /// Suspend a running VM.
    pub fn do_suspend(&mut self, vm_id: u64) -> Result<(), String> {
        let vm = self
            .vms
            .get_mut(&vm_id)
            .ok_or_else(|| format!("Unknown VM id {vm_id}"))?;

        if vm.state != JdiClientState::Running {
            return Err(format!("Cannot suspend VM in state {:?}", vm.state));
        }

        vm.state = JdiClientState::Suspended;
        self.state = JdiClientState::Suspended;
        self.fire_state_changed(vm_id);
        Ok(())
    }

    /// Step into on a specific thread.
    pub fn step_into(&mut self, vm_id: u64, thread_id: u64) -> Result<(), String> {
        self.ensure_suspended(vm_id)?;
        self.ensure_thread(vm_id, thread_id)?;
        // In a full implementation, this sends a JDWP Step command with
        // StepDepth=INTO. Here we model the state transition.
        self.fire_state_changed(vm_id);
        Ok(())
    }

    /// Step over on a specific thread.
    pub fn step_over(&mut self, vm_id: u64, thread_id: u64) -> Result<(), String> {
        self.ensure_suspended(vm_id)?;
        self.ensure_thread(vm_id, thread_id)?;
        self.fire_state_changed(vm_id);
        Ok(())
    }

    /// Step out on a specific thread.
    pub fn step_out(&mut self, vm_id: u64, thread_id: u64) -> Result<(), String> {
        self.ensure_suspended(vm_id)?;
        self.ensure_thread(vm_id, thread_id)?;
        self.fire_state_changed(vm_id);
        Ok(())
    }

    /// Set a breakpoint on the target VM.
    pub fn set_breakpoint(&mut self, bp: JdiBreakpointInfo) -> Result<u64, String> {
        let bp_id = bp.breakpoint_id;
        self.breakpoints.insert(bp_id, bp);
        Ok(bp_id)
    }

    /// Delete a breakpoint.
    pub fn delete_breakpoint(&mut self, bp_id: u64) -> Result<(), String> {
        if self.breakpoints.remove(&bp_id).is_none() {
            return Err(format!("Unknown breakpoint id {bp_id}"));
        }
        Ok(())
    }

    /// Get all active breakpoints.
    pub fn breakpoints(&self) -> &BTreeMap<u64, JdiBreakpointInfo> {
        &self.breakpoints
    }

    /// Add an events listener for a VM.
    pub fn add_events_listener(&mut self, vm_id: u64, listener: Box<dyn JdiEventsListener>) {
        self.events_listeners
            .entry(vm_id)
            .or_default()
            .push(listener);
    }

    /// Add a state listener for a VM.
    pub fn add_state_listener(&mut self, vm_id: u64, listener: Box<dyn JdiStateListener>) {
        self.state_listeners
            .entry(vm_id)
            .or_default()
            .push(listener);
    }

    /// Update thread info for a VM.
    pub fn update_thread(
        &mut self,
        vm_id: u64,
        thread_id: u64,
        info: JdiThreadInfo,
    ) -> Result<(), String> {
        let vm = self
            .vms
            .get_mut(&vm_id)
            .ok_or_else(|| format!("Unknown VM id {vm_id}"))?;
        vm.threads.insert(thread_id, info);
        Ok(())
    }

    /// Remove a thread from a VM.
    pub fn remove_thread(&mut self, vm_id: u64, thread_id: u64) -> Result<(), String> {
        let vm = self
            .vms
            .get_mut(&vm_id)
            .ok_or_else(|| format!("Unknown VM id {vm_id}"))?;
        vm.threads.remove(&thread_id);
        Ok(())
    }

    /// Notify the client that a breakpoint was hit.
    ///
    /// This transitions the VM to suspended state and fires breakpoint_hit
    /// on all registered listeners.
    pub fn notify_breakpoint_hit(
        &mut self,
        vm_id: u64,
        bp_id: u64,
        thread_id: u64,
    ) -> Result<DebugStatus, String> {
        self.ensure_vm(vm_id)?;

        if let Some(vm) = self.vms.get_mut(&vm_id) {
            vm.state = JdiClientState::Suspended;
            if let Some(thread) = vm.threads.get_mut(&thread_id) {
                thread.is_suspended = true;
                thread.at_breakpoint = true;
            }
        }

        if let Some(bp) = self.breakpoints.get_mut(&bp_id) {
            bp.hit_count += 1;
        }

        let cause = JdiCause::automatic("breakpoint hit");
        let mut status = DebugStatus::Continue;
        if let Some(listeners) = self.events_listeners.get_mut(&vm_id) {
            for listener in listeners.iter_mut() {
                status = listener.breakpoint_hit(bp_id, thread_id, &cause);
                if status != DebugStatus::Continue {
                    break;
                }
            }
        }

        self.state = JdiClientState::Suspended;
        Ok(status)
    }

    /// Notify the client that a thread has started.
    pub fn notify_thread_started(
        &mut self,
        vm_id: u64,
        thread_id: u64,
    ) -> Result<DebugStatus, String> {
        let cause = JdiCause::automatic("thread started");
        let mut status = DebugStatus::Continue;
        if let Some(listeners) = self.events_listeners.get_mut(&vm_id) {
            for listener in listeners.iter_mut() {
                status = listener.thread_started(thread_id, &cause);
                if status != DebugStatus::Continue {
                    break;
                }
            }
        }
        Ok(status)
    }

    /// Notify the client that a thread has exited.
    pub fn notify_thread_exited(
        &mut self,
        vm_id: u64,
        thread_id: u64,
    ) -> Result<DebugStatus, String> {
        self.remove_thread(vm_id, thread_id).ok();

        let cause = JdiCause::automatic("thread exited");
        let mut status = DebugStatus::Continue;
        if let Some(listeners) = self.events_listeners.get_mut(&vm_id) {
            for listener in listeners.iter_mut() {
                status = listener.thread_exited(thread_id, &cause);
                if status != DebugStatus::Continue {
                    break;
                }
            }
        }
        Ok(status)
    }

    /// Notify the client that the VM has died.
    pub fn notify_vm_died(&mut self, vm_id: u64) -> Result<DebugStatus, String> {
        if let Some(vm) = self.vms.get_mut(&vm_id) {
            vm.state = JdiClientState::Exited;
        }

        let cause = JdiCause::automatic("vm died");
        let mut status = DebugStatus::Continue;
        if let Some(listeners) = self.events_listeners.get_mut(&vm_id) {
            for listener in listeners.iter_mut() {
                status = listener.vm_died(vm_id, &cause);
                if status != DebugStatus::Continue {
                    break;
                }
            }
        }

        if self.vms.values().all(|v| v.state == JdiClientState::Exited) {
            self.state = JdiClientState::Exited;
        }

        Ok(status)
    }

    // -- Ported from JdiManagerImpl: current context tracking --

    /// Get the currently focused VM ID.
    pub fn current_vm_id(&self) -> Option<u64> {
        self.current_vm_id
    }

    /// Set the currently focused VM.
    pub fn set_current_vm(&mut self, vm_id: u64) -> Result<(), String> {
        self.ensure_vm(vm_id)?;
        self.current_vm_id = Some(vm_id);
        Ok(())
    }

    /// Get the currently focused thread ID.
    pub fn current_thread_id(&self) -> Option<u64> {
        self.current_thread_id
    }

    /// Set the currently focused thread.
    pub fn set_current_thread(&mut self, thread_id: u64) {
        self.current_thread_id = Some(thread_id);
    }

    /// Get the stack frames for the current thread.
    pub fn current_frames(&self) -> &[JdiStackFrameInfo] {
        &self.current_frames
    }

    /// Set the stack frames for the current thread (populated on suspend).
    pub fn set_current_frames(&mut self, frames: Vec<JdiStackFrameInfo>) {
        self.current_frames = frames;
    }

    /// Get process info for a VM.
    pub fn process(&self, vm_id: u64) -> Option<&JdiProcessInfo> {
        self.processes.get(&vm_id)
    }

    /// Register process info for a VM.
    pub fn set_process(&mut self, vm_id: u64, info: JdiProcessInfo) {
        self.processes.insert(vm_id, info);
    }

    /// Append console output.
    pub fn append_console_output(&mut self, channel: impl Into<String>, text: impl Into<String>) {
        self.console_output.push((channel.into(), text.into()));
    }

    /// Drain and return all buffered console output.
    pub fn drain_console_output(&mut self) -> Vec<(String, String)> {
        std::mem::take(&mut self.console_output)
    }

    /// Check if the event handler is running for a VM.
    pub fn is_event_handler_running(&self, vm_id: u64) -> bool {
        self.event_handler_running.get(&vm_id).copied().unwrap_or(false)
    }

    /// Mark the event handler as running/stopped for a VM.
    pub fn set_event_handler_running(&mut self, vm_id: u64, running: bool) {
        self.event_handler_running.insert(vm_id, running);
    }

    /// Interrupt all threads in all connected VMs (ported from
    /// `JdiManagerImpl.sendInterruptNow`).
    pub fn interrupt_all_threads(&mut self) {
        for vm in self.vms.values_mut() {
            for thread in vm.threads.values_mut() {
                thread.is_suspended = false;
            }
        }
    }

    /// Get the number of connected VMs.
    pub fn vm_count(&self) -> usize {
        self.vms.len()
    }

    /// List all VM names (IDs as strings for compatibility).
    pub fn list_vm_names(&self) -> Vec<String> {
        self.vms.keys().map(|id| id.to_string()).collect()
    }

    /// Get the description of a VM.
    pub fn vm_description(&self, vm_id: u64) -> Option<&str> {
        self.vms.get(&vm_id).map(|vm| vm.description.as_str())
    }

    /// Update the state of a specific thread.
    pub fn set_thread_state(
        &mut self,
        vm_id: u64,
        thread_id: u64,
        state: JdiThreadState,
    ) -> Result<(), String> {
        let vm = self
            .vms
            .get_mut(&vm_id)
            .ok_or_else(|| format!("Unknown VM id {vm_id}"))?;
        if let Some(thread) = vm.threads.get_mut(&thread_id) {
            thread.status = state.to_string();
        }
        Ok(())
    }

    /// Get the total number of active breakpoints across all VMs.
    pub fn total_breakpoint_count(&self) -> usize {
        self.breakpoints.len()
    }

    // -- private helpers --

    fn ensure_vm(&self, vm_id: u64) -> Result<(), String> {
        if self.vms.contains_key(&vm_id) {
            Ok(())
        } else {
            Err(format!("Unknown VM id {vm_id}"))
        }
    }

    fn ensure_suspended(&self, vm_id: u64) -> Result<(), String> {
        let vm = self
            .vms
            .get(&vm_id)
            .ok_or_else(|| format!("Unknown VM id {vm_id}"))?;
        if vm.state == JdiClientState::Suspended || vm.state == JdiClientState::Connected {
            Ok(())
        } else {
            Err(format!("VM must be suspended, but is {:?}", vm.state))
        }
    }

    fn ensure_thread(&self, vm_id: u64, thread_id: u64) -> Result<(), String> {
        let vm = self
            .vms
            .get(&vm_id)
            .ok_or_else(|| format!("Unknown VM id {vm_id}"))?;
        if vm.threads.contains_key(&thread_id) {
            Ok(())
        } else {
            Err(format!("Unknown thread id {thread_id} in VM {vm_id}"))
        }
    }

    fn fire_state_changed(&mut self, vm_id: u64) {
        if let Some(listeners) = self.state_listeners.get_mut(&vm_id) {
            for listener in listeners.iter_mut() {
                listener.state_changed(vm_id);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JdiConnectorType helper
// ---------------------------------------------------------------------------

impl JdiConnectorType {
    /// Human-readable label for the connector type.
    fn connector_type_label(&self) -> &'static str {
        match self {
            JdiConnectorType::Attach => "JDWP Attach",
            JdiConnectorType::Launch => "JDWP Launch",
            JdiConnectorType::Listen => "JDWP Listen",
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jdi::manager::JdiThreadInfo;

    fn default_config() -> JdiDebuggerClientConfig {
        JdiDebuggerClientConfig::default()
    }

    #[test]
    fn test_client_default_state() {
        let client = JdiDebuggerClient::new(default_config());
        assert_eq!(client.state(), JdiClientState::Disconnected);
        assert!(client.vms().is_empty());
    }

    #[test]
    fn test_client_connect_listen() {
        let config = JdiDebuggerClientConfig::listen(8000);
        let mut client = JdiDebuggerClient::new(config);
        let vm_id = client.connect().unwrap();
        assert_eq!(vm_id, 1);
        assert_eq!(client.state(), JdiClientState::Running); // auto_resume
        assert!(client.vm(vm_id).is_some());
    }

    #[test]
    fn test_client_connect_attach() {
        let config = JdiDebuggerClientConfig::attach("localhost", 5005);
        let mut client = JdiDebuggerClient::new(config);
        let vm_id = client.connect().unwrap();
        assert_eq!(client.state(), JdiClientState::Running);
        let vm = client.vm(vm_id).unwrap();
        assert_eq!(vm.state, JdiClientState::Running);
    }

    #[test]
    fn test_client_disconnect() {
        let mut client = JdiDebuggerClient::new(default_config());
        let _ = client.connect().unwrap();
        client.disconnect();
        assert_eq!(client.state(), JdiClientState::Disconnected);
        for vm in client.vms().values() {
            assert_eq!(vm.state, JdiClientState::Exited);
        }
    }

    #[test]
    fn test_client_remove_vm() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();
        client.remove_vm(vm_id).unwrap();
        assert!(client.vms().is_empty());
        assert_eq!(client.state(), JdiClientState::Disconnected);
    }

    #[test]
    fn test_client_suspend_resume() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();
        client.do_suspend(vm_id).unwrap();
        assert_eq!(client.vm(vm_id).unwrap().state, JdiClientState::Suspended);

        client.do_resume(vm_id).unwrap();
        assert_eq!(client.vm(vm_id).unwrap().state, JdiClientState::Running);
    }

    #[test]
    fn test_client_cannot_resume_while_running() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();
        // Already running after connect with auto_resume
        let result = client.do_resume(vm_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_breakpoints() {
        let mut client = JdiDebuggerClient::new(default_config());
        let bp = JdiBreakpointInfo::line(1, "com.example.Main", 42);
        let bp_id = client.set_breakpoint(bp).unwrap();
        assert_eq!(bp_id, 1);
        assert_eq!(client.breakpoints().len(), 1);

        client.delete_breakpoint(bp_id).unwrap();
        assert!(client.breakpoints().is_empty());
    }

    #[test]
    fn test_client_delete_nonexistent_breakpoint() {
        let mut client = JdiDebuggerClient::new(default_config());
        let result = client.delete_breakpoint(999);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_thread_management() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();

        let info = JdiThreadInfo::new(10, "main");
        client.update_thread(vm_id, 10, info).unwrap();
        assert!(client.vm(vm_id).unwrap().threads.contains_key(&10));

        client.remove_thread(vm_id, 10).unwrap();
        assert!(!client.vm(vm_id).unwrap().threads.contains_key(&10));
    }

    #[test]
    fn test_client_notify_breakpoint_hit() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();

        let info = JdiThreadInfo::new(1, "main");
        client.update_thread(vm_id, 1, info).unwrap();

        let bp = JdiBreakpointInfo::line(1, "Main", 10);
        client.set_breakpoint(bp).unwrap();

        // Need to suspend first for step operations context
        client.do_suspend(vm_id).unwrap();

        let status = client.notify_breakpoint_hit(vm_id, 1, 1).unwrap();
        assert_eq!(status, DebugStatus::Continue);

        let bp = client.breakpoints().get(&1).unwrap();
        assert_eq!(bp.hit_count, 1);

        let thread = client.vm(vm_id).unwrap().threads.get(&1).unwrap();
        assert!(thread.is_suspended);
        assert!(thread.at_breakpoint);
    }

    #[test]
    fn test_client_notify_vm_died() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();

        let status = client.notify_vm_died(vm_id).unwrap();
        assert_eq!(status, DebugStatus::Continue);
        assert_eq!(client.vm(vm_id).unwrap().state, JdiClientState::Exited);
        assert_eq!(client.state(), JdiClientState::Exited);
    }

    #[test]
    fn test_client_step_requires_suspended() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();
        let info = JdiThreadInfo::new(1, "main");
        client.update_thread(vm_id, 1, info).unwrap();

        // Running state -> step should fail
        let result = client.step_into(vm_id, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_step_on_unknown_thread() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();
        client.do_suspend(vm_id).unwrap();

        let result = client.step_over(vm_id, 999);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_step_when_suspended() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();
        let info = JdiThreadInfo::new(1, "main");
        client.update_thread(vm_id, 1, info).unwrap();
        client.do_suspend(vm_id).unwrap();

        assert!(client.step_into(vm_id, 1).is_ok());
        assert!(client.step_over(vm_id, 1).is_ok());
        assert!(client.step_out(vm_id, 1).is_ok());
    }

    #[test]
    fn test_client_config_presets() {
        let cfg = JdiDebuggerClientConfig::launch("com.example.Main");
        assert_eq!(cfg.arguments.connector_type, JdiConnectorType::Launch);
        assert_eq!(
            cfg.arguments.main_class.as_deref(),
            Some("com.example.Main")
        );

        let cfg = JdiDebuggerClientConfig::attach("10.0.0.1", 5005);
        assert_eq!(cfg.arguments.connector_type, JdiConnectorType::Attach);
        assert_eq!(cfg.arguments.host.as_deref(), Some("10.0.0.1"));

        let cfg = JdiDebuggerClientConfig::listen(9001);
        assert_eq!(cfg.arguments.connector_type, JdiConnectorType::Listen);
        assert_eq!(cfg.arguments.port, Some(9001));
    }

    #[test]
    fn test_vm_info_creation() {
        let info = JdiVmInfo::new(1, "HotSpot 17.0.1");
        assert_eq!(info.vm_id, 1);
        assert_eq!(info.description, "HotSpot 17.0.1");
        assert_eq!(info.state, JdiClientState::Connected);
        assert!(info.threads.is_empty());
        assert!(info.classes.is_empty());
    }

    #[test]
    fn test_client_state_variants_distinct() {
        let states = [
            JdiClientState::Disconnected,
            JdiClientState::Connecting,
            JdiClientState::Connected,
            JdiClientState::Running,
            JdiClientState::Suspended,
            JdiClientState::Exited,
            JdiClientState::Error,
        ];
        for (i, a) in states.iter().enumerate() {
            for b in states.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn test_process_info() {
        let mut info = JdiProcessInfo::new(1234);
        assert_eq!(info.pid, 1234);
        assert!(info.is_alive);
        assert!(info.exit_code.is_none());

        info.command = Some("java".into());
        info.command_line = Some("java -jar app.jar".into());
        info.is_alive = false;
        info.exit_code = Some(0);
        assert_eq!(info.exit_code, Some(0));
    }

    #[test]
    fn test_stack_frame_info() {
        let frame = JdiStackFrameInfo::new(0, "main", "com.example.Main", 42);
        assert_eq!(frame.index, 0);
        assert_eq!(frame.method_name, "main");
        assert_eq!(frame.declaring_type, "com.example.Main");
        assert_eq!(frame.code_index, 42);
        assert!(frame.line_number.is_none());
    }

    #[test]
    fn test_thread_state_display() {
        assert_eq!(JdiThreadState::Running.to_string(), "RUNNING");
        assert_eq!(JdiThreadState::Blocked.to_string(), "BLOCKED");
        assert_eq!(JdiThreadState::Zombie.to_string(), "ZOMBIE");
    }

    #[test]
    fn test_thread_state_variants_distinct() {
        let states = [
            JdiThreadState::NotStarted,
            JdiThreadState::Running,
            JdiThreadState::Sleeping,
            JdiThreadState::Blocked,
            JdiThreadState::Waiting,
            JdiThreadState::TimedWaiting,
            JdiThreadState::Zombie,
        ];
        for (i, a) in states.iter().enumerate() {
            for b in states.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn test_client_current_vm_and_thread() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();

        assert_eq!(client.current_vm_id(), None);
        client.set_current_vm(vm_id).unwrap();
        assert_eq!(client.current_vm_id(), Some(vm_id));

        assert_eq!(client.current_thread_id(), None);
        client.set_current_thread(42);
        assert_eq!(client.current_thread_id(), Some(42));
    }

    #[test]
    fn test_client_stack_frames() {
        let mut client = JdiDebuggerClient::new(default_config());
        assert!(client.current_frames().is_empty());

        let frames = vec![
            JdiStackFrameInfo::new(0, "main", "Main", 0),
            JdiStackFrameInfo::new(1, "run", "Worker", 100),
        ];
        client.set_current_frames(frames);
        assert_eq!(client.current_frames().len(), 2);
        assert_eq!(client.current_frames()[0].method_name, "main");
    }

    #[test]
    fn test_client_process_management() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();

        assert!(client.process(vm_id).is_none());

        let mut proc = JdiProcessInfo::new(5678);
        proc.command = Some("java".into());
        client.set_process(vm_id, proc);

        let proc = client.process(vm_id).unwrap();
        assert_eq!(proc.pid, 5678);
        assert_eq!(proc.command.as_deref(), Some("java"));
    }

    #[test]
    fn test_client_console_output() {
        let mut client = JdiDebuggerClient::new(default_config());
        assert!(client.drain_console_output().is_empty());

        client.append_console_output("stdout", "hello");
        client.append_console_output("stderr", "error");
        let output = client.drain_console_output();
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].1, "hello");
        assert_eq!(output[1].0, "stderr");

        // drain clears the buffer
        assert!(client.drain_console_output().is_empty());
    }

    #[test]
    fn test_client_event_handler_running() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();

        assert!(!client.is_event_handler_running(vm_id));
        client.set_event_handler_running(vm_id, true);
        assert!(client.is_event_handler_running(vm_id));
        client.set_event_handler_running(vm_id, false);
        assert!(!client.is_event_handler_running(vm_id));
    }

    #[test]
    fn test_client_vm_count_and_names() {
        let mut client = JdiDebuggerClient::new(default_config());
        assert_eq!(client.vm_count(), 0);

        let vm1 = client.connect().unwrap();
        assert_eq!(client.vm_count(), 1);

        let names = client.list_vm_names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], vm1.to_string());
    }

    #[test]
    fn test_client_vm_description() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();
        let desc = client.vm_description(vm_id).unwrap();
        assert!(!desc.is_empty());
    }

    #[test]
    fn test_client_thread_state_update() {
        let mut client = JdiDebuggerClient::new(default_config());
        let vm_id = client.connect().unwrap();

        let info = JdiThreadInfo::new(10, "main");
        client.update_thread(vm_id, 10, info).unwrap();

        client.set_thread_state(vm_id, 10, JdiThreadState::Blocked).unwrap();
        let thread = client.vm(vm_id).unwrap().thread(10).unwrap();
        assert_eq!(thread.status, "BLOCKED");
    }

    #[test]
    fn test_client_total_breakpoint_count() {
        let mut client = JdiDebuggerClient::new(default_config());
        assert_eq!(client.total_breakpoint_count(), 0);

        let bp1 = JdiBreakpointInfo::line(1, "Main", 10);
        let bp2 = JdiBreakpointInfo::line(2, "Main", 20);
        client.set_breakpoint(bp1).unwrap();
        client.set_breakpoint(bp2).unwrap();
        assert_eq!(client.total_breakpoint_count(), 2);
    }

    #[test]
    fn test_vm_info_thread_queries() {
        let mut vm = JdiVmInfo::new(1, "test");
        assert!(vm.thread_ids().is_empty());

        let t1 = JdiThreadInfo::new(10, "main");
        let t2 = JdiThreadInfo::new(20, "worker");
        vm.threads.insert(10, t1);
        vm.threads.insert(20, t2);

        let ids = vm.thread_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&10));
        assert!(ids.contains(&20));

        assert!(vm.thread(10).is_some());
        assert!(vm.thread(999).is_none());
    }

    #[test]
    fn test_vm_info_class_queries() {
        let mut vm = JdiVmInfo::new(1, "test");
        vm.classes.insert("java.lang.String".into(), 100);
        vm.classes.insert("java.lang.Integer".into(), 200);

        let names = vm.class_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"java.lang.String".to_string()));
    }
}
