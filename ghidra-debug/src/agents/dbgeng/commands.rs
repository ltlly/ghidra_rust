//! Dbgeng agent trace commands.
//!
//! Implements the trace put commands that synchronize dbgeng state
//! into the Ghidra trace. These correspond to the `commands.py`
//! functions in the original Python agent.
//!
//! Dbgeng uses "Processes[N]" as its process path prefix.

use super::paths;
use crate::agents::{
    BreakpointInfo, BreakpointType, MemoryRegion, ModuleInfo, ProcessInfo,
    RegisterValue, StackFrameInfo, ThreadInfo,
};

/// Dbgeng-specific trace commands.
pub struct DbgEngCommands;

impl DbgEngCommands {
    /// Put environment information into the trace.
    pub fn build_environment_objects(
        os: &str,
        arch: &str,
        endian: &str,
    ) -> Vec<(String, Vec<(String, String)>)> {
        vec![(
            paths::ENVIRONMENT.to_string(),
            vec![
                ("_os".to_string(), os.to_string()),
                ("_lang".to_string(), "Language.C".to_string()),
                ("_endian".to_string(), endian.to_string()),
                ("_arch".to_string(), arch.to_string()),
            ],
        )]
    }

    /// Put processes into the trace.
    pub fn build_process_objects(processes: &[ProcessInfo]) -> Vec<(String, Vec<(String, String)>)> {
        processes
            .iter()
            .map(|p| {
                let path = format!("Processes[{}]", p.id);
                let values = vec![
                    ("_state".to_string(), p.state.as_trace_str().to_string()),
                    ("_display".to_string(), format!("Process {}", p.id)),
                ];
                (path, values)
            })
            .collect()
    }

    /// Put threads into the trace for a process.
    pub fn build_thread_objects(
        process_id: u32,
        threads: &[ThreadInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        threads
            .iter()
            .map(|t| {
                let path = format!("Processes[{}].Threads[{}]", process_id, t.id);
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
    ///
    /// Dbgeng provides _DEBUG_STACK_FRAME structures with instruction offset,
    /// stack offset, frame offset, and return offset.
    pub fn build_frame_objects(
        process_id: u32,
        thread_id: u32,
        frames: &[StackFrameInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        frames
            .iter()
            .map(|f| {
                let path = format!(
                    "Processes[{}].Threads[{}].Stack[{}]",
                    process_id, thread_id, f.level
                );
                let values = vec![
                    ("_display".to_string(), format!("#{} 0x{:x}", f.level, f.pc)),
                ];
                (path, values)
            })
            .collect()
    }

    /// Put register values into the trace.
    ///
    /// Dbgeng register names are case-insensitive; we normalize to lowercase.
    pub fn build_register_objects(
        process_id: u32,
        thread_id: u32,
        frame_level: u32,
        registers: &[RegisterValue],
    ) -> Vec<(String, Vec<u8>)> {
        registers
            .iter()
            .map(|r| {
                let name_lower = r.name.to_lowercase();
                let path = format!(
                    "Processes[{}].Threads[{}].Stack[{}].Registers.{}",
                    process_id, thread_id, frame_level, name_lower
                );
                (path, r.bytes.clone())
            })
            .collect()
    }

    /// Put memory bytes into the trace.
    pub fn build_memory_write(
        process_id: u32,
        address: u64,
        data: &[u8],
    ) -> (String, u64, Vec<u8>) {
        let path = format!("Processes[{}].Memory", process_id);
        (path, address, data.to_vec())
    }

    /// Put memory regions (virtual memory mappings) into the trace.
    pub fn build_memory_regions(
        process_id: u32,
        regions: &[MemoryRegion],
    ) -> Vec<(String, Vec<(String, String)>)> {
        regions
            .iter()
            .map(|r| {
                let path = format!(
                    "Processes[{}].Memory[0x{:x}]",
                    process_id, r.base
                );
                let values = vec![
                    ("Range".to_string(), format!("0x{:x}:0x{:x}", r.base, r.base + r.size)),
                    ("Name".to_string(), r.object_file.clone()),
                    ("_display".to_string(), format!("0x{:x} {}", r.base, r.object_file)),
                    ("Permissions".to_string(), r.permissions.clone()),
                ];
                (path, values)
            })
            .collect()
    }

    /// Put loaded modules into the trace.
    ///
    /// Dbgeng provides _DEBUG_MODULE_PARAMETERS for each loaded module.
    pub fn build_module_objects(
        process_id: u32,
        modules: &[ModuleInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        modules
            .iter()
            .map(|m| {
                let hbase = format!("0x{:x}", m.base);
                let path = format!("Processes[{}].Modules[{}]", process_id, hbase);
                let values = vec![
                    ("Range".to_string(), format!("0x{:x}:0x{:x}", m.base, m.base + m.size)),
                    ("Name".to_string(), m.name.clone()),
                    ("_display".to_string(), format!("{:x} {}", m.base, m.name)),
                ];
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
                ];
                (path, values)
            })
            .collect()
    }

    /// Build a dbgeng command to read memory.
    pub fn read_memory_command(address: u64, length: usize) -> String {
        format!("db 0x{:x} L{:x}", address, length)
    }

    /// Build a dbgeng command to write memory.
    pub fn write_memory_command(address: u64, data: &[u8]) -> String {
        let bytes: Vec<String> = data.iter().map(|b| format!("{:02x}", b)).collect();
        format!("eb 0x{:x} {}", address, bytes.join(" "))
    }

    /// Build a dbgeng command to get a register value.
    pub fn get_register_command(name: &str) -> String {
        format!("r {}", name)
    }

    /// Build a dbgeng command to set a register value.
    pub fn set_register_command(name: &str, value: u64) -> String {
        format!("r {}={:x}", name, value)
    }

    /// Build a dbgeng command to set a breakpoint.
    pub fn set_breakpoint_command(address: u64) -> String {
        format!("bp 0x{:x}", address)
    }

    /// Build a dbgeng command to delete a breakpoint.
    pub fn delete_breakpoint_command(id: u32) -> String {
        format!("bc {}", id)
    }

    /// Build a dbgeng command to get the backtrace.
    pub fn backtrace_command() -> &'static str {
        "k"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::ExecutionState;

    #[test]
    fn test_build_process_objects() {
        let procs = vec![ProcessInfo {
            id: 1,
            state: ExecutionState::Stopped,
        }];
        let objs = DbgEngCommands::build_process_objects(&procs);
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].0, "Processes[1]");
    }

    #[test]
    fn test_build_register_objects_normalize() {
        let regs = vec![RegisterValue::from_u64("RAX", 0x1234)];
        let objs = DbgEngCommands::build_register_objects(1, 1, 0, &regs);
        assert_eq!(objs.len(), 1);
        // Should be lowercase
        assert!(objs[0].0.contains(".rax"));
    }

    #[test]
    fn test_build_module_objects() {
        let mods = vec![ModuleInfo {
            name: "ntdll.dll".to_string(),
            base: 0x7ff800000000,
            size: 0x1e6000,
            build_id: None,
            debug_path: None,
            load_path: Some("C:\\Windows\\System32\\ntdll.dll".to_string()),
        }];
        let objs = DbgEngCommands::build_module_objects(1, &mods);
        assert_eq!(objs.len(), 1);
        assert!(objs[0].0.contains("Modules"));
    }

    #[test]
    fn test_read_memory_command() {
        let cmd = DbgEngCommands::read_memory_command(0x401000, 32);
        assert_eq!(cmd, "db 0x401000 L20");
    }

    #[test]
    fn test_set_register_command() {
        let cmd = DbgEngCommands::set_register_command("rax", 0x1234);
        assert_eq!(cmd, "r rax=1234");
    }

    #[test]
    fn test_set_breakpoint_command() {
        let cmd = DbgEngCommands::set_breakpoint_command(0x401000);
        assert_eq!(cmd, "bp 0x401000");
    }
}
