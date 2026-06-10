//! GDB agent trace commands.
//!
//! Implements the trace put commands that synchronize GDB state into
//! the Ghidra trace. These correspond to the `commands.py` functions
//! in the original Python agent.
//!
//! GDB uses "Inferiors[N]" as its process path prefix.

use super::paths;
use crate::agents::{
    BreakpointInfo, BreakpointType, MemoryRegion, ModuleInfo, ProcessInfo,
    RegisterValue, StackFrameInfo, ThreadInfo,
};

/// GDB-specific trace commands.
///
/// Each command gathers state from GDB and writes it to the Ghidra trace
/// via the RMI protocol.
pub struct GdbCommands;

impl GdbCommands {
    /// Put environment information (OS, language, endian) into the trace.
    ///
    /// Creates the `Environment` object under each inferior's path.
    pub fn build_environment_objects(
        os: &str,
        lang: &str,
        endian: &str,
    ) -> Vec<(String, Vec<(String, String)>)> {
        let mut result = Vec::new();
        // The environment is stored at Processes[].Environment
        // but we don't know the process count here; caller provides path.
        result.push((
            paths::ENVIRONMENT.to_string(),
            vec![
                ("_os".to_string(), os.to_string()),
                ("_lang".to_string(), lang.to_string()),
                ("_endian".to_string(), endian.to_string()),
            ],
        ));
        result
    }

    /// Put processes into the trace.
    ///
    /// Creates `Inferiors[]` entries with their execution state.
    pub fn build_process_objects(processes: &[ProcessInfo]) -> Vec<(String, Vec<(String, String)>)> {
        processes
            .iter()
            .map(|p| {
                let path = format!("Inferiors[{}]", p.id);
                let values = vec![
                    ("_state".to_string(), p.state.as_trace_str().to_string()),
                    ("_display".to_string(), format!("Process {}", p.id)),
                ];
                (path, values)
            })
            .collect()
    }

    /// Put threads into the trace for an inferior.
    pub fn build_thread_objects(
        inferior_id: u32,
        threads: &[ThreadInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        threads
            .iter()
            .map(|t| {
                let path = format!("Inferiors[{}].Threads[{}]", inferior_id, t.id);
                let mut values = vec![
                    ("_state".to_string(), t.state.as_trace_str().to_string()),
                ];
                if let Some(ref name) = t.name {
                    values.push(("_display".to_string(), name.clone()));
                }
                (path, values)
            })
            .collect()
    }

    /// Put stack frames into the trace for a thread.
    pub fn build_frame_objects(
        inferior_id: u32,
        thread_id: u32,
        frames: &[StackFrameInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        frames
            .iter()
            .map(|f| {
                let path = format!(
                    "Inferiors[{}].Threads[{}].Stack[{}]",
                    inferior_id, thread_id, f.level
                );
                let values = vec![
                    ("_display".to_string(), format!("#{} 0x{:x}", f.level, f.pc)),
                ];
                (path, values)
            })
            .collect()
    }

    /// Put register values into the trace for a frame.
    pub fn build_register_objects(
        inferior_id: u32,
        thread_id: u32,
        frame_level: u32,
        registers: &[RegisterValue],
    ) -> Vec<(String, Vec<u8>)> {
        registers
            .iter()
            .map(|r| {
                let path = format!(
                    "Inferiors[{}].Threads[{}].Stack[{}].Registers.{}",
                    inferior_id, thread_id, frame_level, r.name
                );
                (path, r.bytes.clone())
            })
            .collect()
    }

    /// Put memory bytes into the trace.
    pub fn build_memory_write(
        inferior_id: u32,
        address: u64,
        data: &[u8],
    ) -> (String, u64, Vec<u8>) {
        let path = format!("Inferiors[{}].Memory", inferior_id);
        (path, address, data.to_vec())
    }

    /// Put memory regions (mappings) into the trace.
    pub fn build_memory_regions(
        inferior_id: u32,
        regions: &[MemoryRegion],
    ) -> Vec<(String, Vec<(String, String)>)> {
        regions
            .iter()
            .map(|r| {
                let path = format!(
                    "Inferiors[{}].Memory[0x{:x}]",
                    inferior_id, r.base
                );
                let values = vec![
                    ("Range".to_string(), format!("0x{:x}:0x{:x}", r.base, r.base + r.size)),
                    ("Name".to_string(), r.object_file.clone()),
                    ("_display".to_string(), format!("0x{:x} {}", r.base, r.object_file)),
                ];
                (path, values)
            })
            .collect()
    }

    /// Put loaded modules (objfiles) into the trace.
    pub fn build_module_objects(
        inferior_id: u32,
        modules: &[ModuleInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        modules
            .iter()
            .map(|m| {
                let path = format!(
                    "Inferiors[{}].Modules[{}]",
                    inferior_id, m.name
                );
                let mut values = vec![
                    ("Range".to_string(), format!("0x{:x}:0x{:x}", m.base, m.base + m.size)),
                    ("Name".to_string(), m.name.clone()),
                    ("_display".to_string(), format!("0x{:x} {}", m.base, m.name)),
                ];
                if let Some(ref bid) = m.build_id {
                    values.push(("BuildId".to_string(), bid.clone()));
                }
                if let Some(ref dp) = m.debug_path {
                    values.push(("DebugPath".to_string(), dp.clone()));
                }
                if let Some(ref lp) = m.load_path {
                    values.push(("LoadPath".to_string(), lp.clone()));
                }
                (path, values)
            })
            .collect()
    }

    /// Put breakpoints into the trace.
    pub fn build_breakpoint_objects(
        breakpoints: &[BreakpointInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        breakpoints
            .iter()
            .map(|bp| {
                let path = format!("Breakpoints[{}]", bp.id);
                let kind = match bp.bp_type {
                    BreakpointType::Software => "Software",
                    BreakpointType::Hardware => "Hardware",
                    BreakpointType::Memory => "Memory",
                };
                let values = vec![
                    ("Type".to_string(), kind.to_string()),
                    ("Address".to_string(), format!("0x{:x}", bp.address)),
                    ("Enabled".to_string(), bp.enabled.to_string()),
                    ("HitCount".to_string(), bp.hit_count.to_string()),
                    ("_display".to_string(), format!("{} 0x{:x}", kind, bp.address)),
                ];
                (path, values)
            })
            .collect()
    }

    /// Build the PC (program counter) register query command.
    pub fn get_pc_command(_inferior_id: u32, _thread_id: u32) -> String {
        "p/x $pc".to_string()
    }

    /// Build the SP (stack pointer) register query command.
    pub fn get_sp_command() -> String {
        "p/x $sp".to_string()
    }

    /// Build a command to read memory bytes.
    pub fn read_memory_command(address: u64, length: usize) -> String {
        format!("x/{}bx 0x{:x}", length, address)
    }

    /// Build a command to write memory bytes.
    pub fn write_memory_command(address: u64, data: &[u8]) -> String {
        let bytes: Vec<String> = data.iter().map(|b| format!("set *((char*) 0x{:x}) = 0x{:02x}", address, b)).collect();
        bytes.join("\n")
    }

    /// Build a command to fetch /proc/pid/maps from a remote gdbserver.
    ///
    /// This is the Rust equivalent of the `remote-proc-mappings` GDB command.
    pub fn remote_proc_mappings_command(pid: u32) -> String {
        format!("remote get /proc/{}/maps /dev/stdout", pid)
    }
}

/// Transaction helper for batched trace writes.
pub struct TraceTransaction {
    /// Transaction name.
    pub name: String,
    /// Operations to execute.
    pub operations: Vec<TraceOperation>,
}

/// A single trace operation.
pub enum TraceOperation {
    /// Create an object at the given path.
    CreateObject { path: String },
    /// Set a string value on an object.
    SetStringValue { path: String, key: String, value: String },
    /// Set a byte value on an object.
    SetByteValue { path: String, bytes: Vec<u8> },
    /// Insert an object.
    InsertObject { path: String },
    /// Retain values (remove others).
    RetainValues { path: String, keys: Vec<String> },
}

impl TraceTransaction {
    /// Create a new transaction.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            operations: Vec::new(),
        }
    }

    /// Add a create object operation.
    pub fn create_object(&mut self, path: impl Into<String>) {
        self.operations.push(TraceOperation::CreateObject {
            path: path.into(),
        });
    }

    /// Add a set string value operation.
    pub fn set_string(&mut self, path: impl Into<String>, key: impl Into<String>, value: impl Into<String>) {
        self.operations.push(TraceOperation::SetStringValue {
            path: path.into(),
            key: key.into(),
            value: value.into(),
        });
    }

    /// Add a set bytes operation.
    pub fn set_bytes(&mut self, path: impl Into<String>, bytes: Vec<u8>) {
        self.operations.push(TraceOperation::SetByteValue {
            path: path.into(),
            bytes,
        });
    }

    /// Add an insert object operation.
    pub fn insert_object(&mut self, path: impl Into<String>) {
        self.operations.push(TraceOperation::InsertObject {
            path: path.into(),
        });
    }

    /// Add a retain values operation.
    pub fn retain_values(&mut self, path: impl Into<String>, keys: Vec<String>) {
        self.operations.push(TraceOperation::RetainValues {
            path: path.into(),
            keys,
        });
    }

    /// Get the number of operations.
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_process_objects() {
        let procs = vec![ProcessInfo {
            id: 1,
            state: ExecutionState::Stopped,
        }];
        let objs = GdbCommands::build_process_objects(&procs);
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].0, "Inferiors[1]");
        assert!(objs[0].1.iter().any(|(k, v)| k == "_state" && v == "STOPPED"));
    }

    #[test]
    fn test_build_thread_objects() {
        let threads = vec![
            ThreadInfo { id: 1, name: Some("main".to_string()), state: ExecutionState::Stopped },
            ThreadInfo { id: 2, name: None, state: ExecutionState::Running },
        ];
        let objs = GdbCommands::build_thread_objects(1, &threads);
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[0].0, "Inferiors[1].Threads[1]");
        assert_eq!(objs[1].0, "Inferiors[1].Threads[2]");
    }

    #[test]
    fn test_build_frame_objects() {
        let frames = vec![
            StackFrameInfo { level: 0, pc: 0x401000, sp: 0x7fff00, fp: 0x7fff10, return_address: 0x401100, function_name: Some("main".to_string()) },
            StackFrameInfo { level: 1, pc: 0x402000, sp: 0x7fff20, fp: 0x7fff30, return_address: 0x402100, function_name: None },
        ];
        let objs = GdbCommands::build_frame_objects(1, 1, &frames);
        assert_eq!(objs.len(), 2);
        assert!(objs[0].1[0].1.contains("0x401000"));
    }

    #[test]
    fn test_build_register_objects() {
        let regs = vec![
            RegisterValue::from_u64("rax", 0x1234),
            RegisterValue::from_u64("rbx", 0x5678),
        ];
        let objs = GdbCommands::build_register_objects(1, 1, 0, &regs);
        assert_eq!(objs.len(), 2);
        assert_eq!(objs[0].0, "Inferiors[1].Threads[1].Stack[0].Registers.rax");
    }

    #[test]
    fn test_build_breakpoint_objects() {
        let bps = vec![BreakpointInfo {
            id: 1,
            bp_type: BreakpointType::Software,
            address: 0x401000,
            enabled: true,
            hit_count: 0,
            condition: None,
        }];
        let objs = GdbCommands::build_breakpoint_objects(&bps);
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].0, "Breakpoints[1]");
    }

    #[test]
    fn test_build_module_objects() {
        let mods = vec![ModuleInfo {
            name: "libc.so.6".to_string(),
            base: 0x7ffff7a00000,
            size: 0x1e6000,
            build_id: Some("abc123".to_string()),
            debug_path: None,
            load_path: Some("/usr/lib/libc.so.6".to_string()),
        }];
        let objs = GdbCommands::build_module_objects(1, &mods);
        assert_eq!(objs.len(), 1);
        assert!(objs[0].1.iter().any(|(k, _)| k == "BuildId"));
    }

    #[test]
    fn test_read_memory_command() {
        let cmd = GdbCommands::read_memory_command(0x401000, 16);
        assert_eq!(cmd, "x/16bx 0x401000");
    }

    #[test]
    fn test_transaction() {
        let mut tx = TraceTransaction::new("Test");
        assert!(tx.is_empty());
        tx.create_object("Inferiors[1]");
        tx.set_string("Inferiors[1]", "_state", "STOPPED");
        tx.insert_object("Inferiors[1]");
        assert_eq!(tx.len(), 3);
    }
}
