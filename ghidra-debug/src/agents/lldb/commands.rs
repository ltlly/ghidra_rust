//! LLDB agent trace commands.
//!
//! Implements the trace put commands that synchronize LLDB state into
//! the Ghidra trace.

use super::paths;
use crate::agents::{
    BreakpointInfo, BreakpointType, ModuleInfo, ProcessInfo,
    RegisterValue, StackFrameInfo, ThreadInfo,
};

/// LLDB-specific trace commands.
pub struct LldbCommands;

impl LldbCommands {
    /// Put environment information into the trace.
    pub fn build_environment_objects(
        os: &str,
        lang: &str,
        endian: &str,
    ) -> Vec<(String, Vec<(String, String)>)> {
        vec![(
            paths::ENVIRONMENT.to_string(),
            vec![
                ("_os".to_string(), os.to_string()),
                ("_lang".to_string(), lang.to_string()),
                ("_endian".to_string(), endian.to_string()),
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
                let mut values = vec![
                    ("_display".to_string(), format!("#{} 0x{:x}", f.level, f.pc)),
                ];
                if let Some(ref fname) = f.function_name {
                    values.push(("Function".to_string(), fname.clone()));
                }
                (path, values)
            })
            .collect()
    }

    /// Put register values into the trace.
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

    /// Put loaded modules (images) into the trace.
    pub fn build_module_objects(
        process_id: u32,
        modules: &[ModuleInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        modules
            .iter()
            .map(|m| {
                let path = format!("Processes[{}].Modules[{}]", process_id, m.name);
                let values = vec![
                    ("Range".to_string(), format!("0x{:x}:0x{:x}", m.base, m.base + m.size)),
                    ("Name".to_string(), m.name.clone()),
                    ("_display".to_string(), format!("0x{:x} {}", m.base, m.name)),
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

    /// Build an LLDB expression command to read a register.
    pub fn read_register_command(name: &str) -> String {
        format!("register read {}", name)
    }

    /// Build an LLDB expression command to write a register.
    pub fn write_register_command(name: &str, value: u64) -> String {
        format!("register write {} 0x{:x}", name, value)
    }

    /// Build an LLDB memory read command.
    pub fn read_memory_command(address: u64, length: usize) -> String {
        format!("memory read --count {} 0x{:x}", length, address)
    }

    /// Build an LLDB memory write command.
    pub fn write_memory_command(address: u64, data: &[u8]) -> String {
        let hex: Vec<String> = data.iter().map(|b| format!("0x{:02x}", b)).collect();
        format!("memory write 0x{:x} {}", address, hex.join(" "))
    }

    /// Build an LLDB breakpoint set command.
    pub fn set_breakpoint_command(address: u64) -> String {
        format!("breakpoint set --address 0x{:x}", address)
    }

    /// Build an LLDB backtrace command.
    pub fn backtrace_command() -> &'static str {
        "bt"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::ExecutionState;

    #[test]
    fn test_build_process_objects() {
        let procs = vec![ProcessInfo { id: 1, state: ExecutionState::Stopped }];
        let objs = LldbCommands::build_process_objects(&procs);
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].0, "Processes[1]");
    }

    #[test]
    fn test_build_frame_with_function() {
        let frames = vec![StackFrameInfo {
            level: 0,
            pc: 0x401000,
            sp: 0x7fff00,
            fp: 0x7fff10,
            return_address: 0x401100,
            function_name: Some("main".to_string()),
        }];
        let objs = LldbCommands::build_frame_objects(1, 1, &frames);
        assert!(objs[0].1.iter().any(|(k, v)| k == "Function" && v == "main"));
    }

    #[test]
    fn test_read_register_command() {
        let cmd = LldbCommands::read_register_command("x0");
        assert_eq!(cmd, "register read x0");
    }

    #[test]
    fn test_read_memory_command() {
        let cmd = LldbCommands::read_memory_command(0x401000, 64);
        assert_eq!(cmd, "memory read --count 64 0x401000");
    }
}
