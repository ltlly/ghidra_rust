//! drgn agent trace commands.
//!
//! Implements the trace put commands that synchronize drgn state into
//! the Ghidra trace. These correspond to the `commands.py` functions
//! in the original Python agent.
//!
//! drgn uses "Processes[N]" as its process path prefix.

use super::paths;
use crate::agents::{
    BreakpointInfo, BreakpointType, MemoryRegion, ProcessInfo,
    RegisterValue, StackFrameInfo, ThreadInfo,
};
use super::{DrgnModuleInfo, DrgnSectionInfo, DrgnSymbolInfo};

/// drgn-specific trace commands.
pub struct DrgnCommands;

impl DrgnCommands {
    /// Put environment information into the trace.
    ///
    /// For kernel debugging, this includes the kernel version and architecture.
    pub fn build_environment_objects(
        os: &str,
        lang: &str,
        endian: &str,
        kernel_version: Option<&str>,
    ) -> Vec<(String, Vec<(String, String)>)> {
        let mut values = vec![
            ("_os".to_string(), os.to_string()),
            ("_lang".to_string(), lang.to_string()),
            ("_endian".to_string(), endian.to_string()),
        ];
        if let Some(kv) = kernel_version {
            values.push(("_kernel_version".to_string(), kv.to_string()));
        }
        vec![(paths::ENVIRONMENT.to_string(), values)]
    }

    /// Put processes into the trace.
    ///
    /// For kernel debugging, the single process (PID 0) represents the kernel.
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
    ///
    /// For kernel debugging, each CPU may appear as a separate thread.
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
                let values = vec![
                    ("_display".to_string(), format!("#{} 0x{:x}", f.level, f.pc)),
                ];
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

    /// Put memory regions into the trace.
    pub fn build_memory_regions(
        process_id: u32,
        regions: &[MemoryRegion],
    ) -> Vec<(String, Vec<(String, String)>)> {
        regions
            .iter()
            .map(|r| {
                let path = format!("Processes[{}].Memory[0x{:x}]", process_id, r.base);
                let values = vec![
                    ("Range".to_string(), format!("0x{:x}:0x{:x}", r.base, r.base + r.size)),
                    ("Name".to_string(), r.object_file.clone()),
                    ("_display".to_string(), format!("0x{:x} {}", r.base, r.object_file)),
                ];
                (path, values)
            })
            .collect()
    }

    /// Put loaded modules into the trace.
    ///
    /// drgn provides Module and RelocatableModule types. RelocatableModule
    /// supports section information (used for kernel modules).
    pub fn build_module_objects(
        process_id: u32,
        modules: &[DrgnModuleInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        modules
            .iter()
            .map(|m| {
                let hbase = format!("0x{:x}", m.base());
                let path = format!("Processes[{}].Modules[{}]", process_id, hbase);
                let mut values = vec![
                    ("Range".to_string(), format!("0x{:x}:0x{:x}", m.base(), m.base() + m.size())),
                    ("Name".to_string(), m.name.clone()),
                    ("_display".to_string(), format!("{:x} {}", m.base(), m.name)),
                ];
                if let Some(ref bid) = m.build_id {
                    values.push(("BuildId".to_string(), bid.clone()));
                }
                if let Some(ref dp) = m.debug_file_path {
                    values.push(("DebugPath".to_string(), dp.clone()));
                }
                if let Some(ref lp) = m.loaded_file_path {
                    values.push(("LoadPath".to_string(), lp.clone()));
                }
                (path, values)
            })
            .collect()
    }

    /// Put sections for a relocatable module.
    pub fn build_section_objects(
        process_id: u32,
        module_base: u64,
        sections: &[DrgnSectionInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        let modbase = format!("0x{:x}", module_base);
        sections
            .iter()
            .map(|s| {
                let path = format!(
                    "Processes[{}].Modules[{}].Sections[{}]",
                    process_id, modbase, s.name
                );
                let values = vec![
                    ("Address".to_string(), format!("0x{:x}", s.address)),
                    ("Size".to_string(), format!("0x{:x}", s.size)),
                    ("_display".to_string(), format!("{} 0x{:x}", s.name, s.address)),
                ];
                (path, values)
            })
            .collect()
    }

    /// Put symbols into the trace.
    pub fn build_symbol_objects(
        process_id: u32,
        symbols: &[DrgnSymbolInfo],
    ) -> Vec<(String, Vec<(String, String)>)> {
        symbols
            .iter()
            .map(|s| {
                let path = format!("Processes[{}].Symbols[{}]", process_id, s.name);
                let values = vec![
                    ("Address".to_string(), format!("0x{:x}", s.address)),
                    ("Size".to_string(), format!("0x{:x}", s.size)),
                    ("_display".to_string(), format!("{} 0x{:x}", s.name, s.address)),
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
                ];
                (path, values)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::ExecutionState;

    #[test]
    fn test_build_process_objects() {
        let procs = vec![ProcessInfo { id: 0, state: ExecutionState::Running }];
        let objs = DrgnCommands::build_process_objects(&procs);
        assert_eq!(objs.len(), 1);
        assert_eq!(objs[0].0, "Processes[0]");
    }

    #[test]
    fn test_build_environment_kernel() {
        let objs = DrgnCommands::build_environment_objects("Linux", "Language.C", "little", Some("5.15.0"));
        assert_eq!(objs.len(), 1);
        assert!(objs[0].1.iter().any(|(k, v)| k == "_kernel_version" && v == "5.15.0"));
    }

    #[test]
    fn test_build_module_objects() {
        let mods = vec![DrgnModuleInfo {
            name: "virtio_net".to_string(),
            address_range: (0xffffffffa0000000, 0xffffffffa0010000),
            build_id: Some("abc123".to_string()),
            debug_file_bias: None,
            debug_file_path: None,
            debug_file_status: None,
            loaded_file_bias: None,
            loaded_file_path: Some("/lib/modules/5.15.0/kernel/drivers/net/virtio_net.ko".to_string()),
            loaded_file_status: None,
            is_relocatable: true,
        }];
        let objs = DrgnCommands::build_module_objects(0, &mods);
        assert_eq!(objs.len(), 1);
        assert!(objs[0].1.iter().any(|(k, _)| k == "BuildId"));
    }

    #[test]
    fn test_build_section_objects() {
        let sections = vec![
            DrgnSectionInfo { name: ".text".to_string(), address: 0xffffffffa0000000, size: 0x5000 },
            DrgnSectionInfo { name: ".data".to_string(), address: 0xffffffffa0005000, size: 0x1000 },
        ];
        let objs = DrgnCommands::build_section_objects(0, 0xffffffffa0000000, &sections);
        assert_eq!(objs.len(), 2);
        assert!(objs[0].0.contains(".text"));
    }

    #[test]
    fn test_build_symbol_objects() {
        let syms = vec![DrgnSymbolInfo {
            name: "do_sys_open".to_string(),
            address: 0xffffffff81234567,
            size: 0x100,
        }];
        let objs = DrgnCommands::build_symbol_objects(0, &syms);
        assert_eq!(objs.len(), 1);
        assert!(objs[0].0.contains("do_sys_open"));
    }
}
