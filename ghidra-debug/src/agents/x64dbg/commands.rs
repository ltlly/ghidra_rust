//! x64dbg agent trace commands.
//!
//! Implements the trace put commands that synchronize x64dbg state
//! into the Ghidra trace. These correspond to the `commands.py`
//! functions in the original Python agent.
//!
//! x64dbg uses "Processes[N]" as its process path prefix.

use super::paths;
use crate::agents::{
    BreakpointInfo, BreakpointType, MemoryRegion, ModuleInfo, ProcessInfo,
    RegisterValue, StackFrameInfo, ThreadInfo,
};

/// x64dbg-specific trace commands.
pub struct X64DbgCommands;

impl X64DbgCommands {
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

    /// Put threads into the trace.
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

    /// Put stack frames into the trace.
    ///
    /// x64dbg provides _DEBUG_STACK_FRAME structures with instruction offset,
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
    /// x64dbg provides register dumps via RegDump structures.
    pub fn build_register_objects(
        process_id: u32,
        thread_id: u32,
        frame_level: u32,
        registers: &[RegisterValue],
    ) -> Vec<(String, Vec<u8>)> {
        registers
            .iter()
            .map(|r| {
                let path = format!(
                    "Processes[{}].Threads[{}].Stack[{}].Registers.{}",
                    process_id, thread_id, frame_level, r.name
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

    /// Put memory regions (virtual memory pages) into the trace.
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

    /// Build an x64dbg command to execute.
    pub fn exec_command(cmd: &str) -> String {
        cmd.to_string()
    }

    /// Build a command to disassemble at address.
    pub fn disassemble_command(address: u64) -> String {
        format!("disasm 0x{:x}", address)
    }

    /// Build a command to read memory.
    pub fn read_memory_command(address: u64, length: usize) -> String {
        format!("dump 0x{:x} {:x}", address, length)
    }

    /// Build a command to set a breakpoint.
    pub fn set_breakpoint_command(address: u64) -> String {
        format!("bp 0x{:x}", address)
    }

    /// Build a command to delete a breakpoint.
    pub fn delete_breakpoint_command(address: u64) -> String {
        format!("bc 0x{:x}", address)
    }

    /// Build a command to step into.
    pub fn step_into_command() -> &'static str {
        "step"
    }

    /// Build a command to step over.
    pub fn step_over_command() -> &'static str {
        "stepover"
    }

    /// Build a command to continue execution.
    pub fn continue_command() -> &'static str {
        "continue"
    }

    /// Build a command to pause execution.
    pub fn pause_command() -> &'static str {
        "pause"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::ExecutionState;

    #[test]
    fn test_build_process_objects() {
        let procs = vec![ProcessInfo { id: 1, state: ExecutionState::Stopped }];
        let objs = X64DbgCommands::build_process_objects(&procs);
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].0, "Processes[1]");
    }

    #[test]
    fn test_build_frame_objects() {
        let frames = vec![StackFrameInfo {
            level: 0,
            pc: 0x401000,
            sp: 0x7fff00,
            fp: 0x7fff10,
            return_address: 0x401100,
            function_name: None,
        }];
        let objs = X64DbgCommands::build_frame_objects(1, 1, &frames);
        assert_eq!(objs.len(), 1);
        assert!(objs[0].1[0].1.contains("0x401000"));
    }

    #[test]
    fn test_read_memory_command() {
        let cmd = X64DbgCommands::read_memory_command(0x401000, 32);
        assert_eq!(cmd, "dump 0x401000 20");
    }

    #[test]
    fn test_set_breakpoint_command() {
        let cmd = X64DbgCommands::set_breakpoint_command(0x401000);
        assert_eq!(cmd, "bp 0x401000");
    }

    #[test]
    fn test_step_commands() {
        assert_eq!(X64DbgCommands::step_into_command(), "step");
        assert_eq!(X64DbgCommands::step_over_command(), "stepover");
        assert_eq!(X64DbgCommands::continue_command(), "continue");
        assert_eq!(X64DbgCommands::pause_command(), "pause");
    }
}
