//! Enhanced Target trait - additional methods for trace management,
//! thread/process queries, and advanced operations.
//!
//! Ported from Ghidra's `Target` interface (716 lines in Java).
//! This module extends the basic Target trait with additional methods for
//! attaching, launching, connecting, focusing, querying threads/processes,
//! stack frames, memory regions, and more.

use serde::{Deserialize, Serialize};

use crate::model::TraceExecutionState;

/// Description of a thread in the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadInfo {
    /// Thread key.
    pub key: i64,
    /// Thread name.
    pub name: String,
    /// Thread ID as reported by the OS.
    pub tid: Option<u64>,
    /// Whether this thread is currently focused/selected.
    pub is_focused: bool,
    /// The execution state of this thread.
    pub state: TraceExecutionState,
}

/// Description of a process in the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    /// Process key.
    pub key: i64,
    /// Process name.
    pub name: String,
    /// Process ID as reported by the OS.
    pub pid: Option<u64>,
    /// Whether this process is currently focused/selected.
    pub is_focused: bool,
}

/// Description of a stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrameInfo {
    /// Frame level (0 = innermost).
    pub level: u32,
    /// The program counter at this frame.
    pub pc: u64,
    /// The stack pointer at this frame.
    pub sp: u64,
    /// The function name at this frame, if known.
    pub function_name: Option<String>,
}

/// Description of a memory region in the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegionInfo {
    /// Region name.
    pub name: String,
    /// Start address.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
    /// Whether the region is readable.
    pub readable: bool,
    /// Whether the region is writable.
    pub writable: bool,
    /// Whether the region is executable.
    pub executable: bool,
    /// Whether this region is volatile (e.g., memory-mapped I/O).
    pub volatile: bool,
}

/// Description of a register in the target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterInfo {
    /// Register name.
    pub name: String,
    /// Register size in bytes.
    pub size: u32,
    /// Register category (general, floating-point, etc.).
    pub category: String,
}

/// Result of an attach operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachResult {
    /// The process key assigned by the target.
    pub process_key: i64,
    /// Any message from the debugger.
    pub message: Option<String>,
}

/// Result of a launch operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchResult {
    /// The process key assigned by the target.
    pub process_key: i64,
    /// The thread key of the main thread.
    pub main_thread_key: Option<i64>,
    /// Any message from the debugger.
    pub message: Option<String>,
}

/// Result of a connect operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectResult {
    /// A unique identifier for this connection.
    pub connection_id: String,
    /// Any message from the debugger.
    pub message: Option<String>,
}

/// A trait for extended target operations.
///
/// This extends the basic Target trait with additional methods that
/// correspond to the full Java Target interface.
pub trait TargetExtended {
    /// Interrupt execution of the target.
    fn interrupt(&mut self) -> Result<(), String>;

    /// Kill the target process.
    fn kill(&mut self) -> Result<(), String>;

    /// Attach to a running process by PID.
    fn attach(&mut self, pid: u64) -> Result<AttachResult, String>;

    /// Launch a new process.
    fn launch(
        &mut self,
        program: &str,
        args: &[String],
        working_dir: Option<&str>,
    ) -> Result<LaunchResult, String>;

    /// Connect to a remote target.
    fn connect(&mut self, address: &str, port: u16) -> Result<ConnectResult, String>;

    /// Focus/activate a specific thread.
    fn activate_thread(&mut self, thread_key: i64) -> Result<(), String>;

    /// Focus/activate a specific process.
    fn activate_process(&mut self, process_key: i64) -> Result<(), String>;

    /// Get all threads for the focused process.
    fn get_threads(&self) -> Result<Vec<ThreadInfo>, String>;

    /// Get all processes.
    fn get_processes(&self) -> Result<Vec<ProcessInfo>, String>;

    /// Get stack frames for a thread.
    fn get_stack_frames(&self, thread_key: i64) -> Result<Vec<StackFrameInfo>, String>;

    /// Get memory regions.
    fn get_memory_regions(&self) -> Result<Vec<MemoryRegionInfo>, String>;

    /// Get available registers.
    fn get_registers(&self, thread_key: i64) -> Result<Vec<RegisterInfo>, String>;

    /// Step back (reverse execution).
    fn step_back(&mut self, thread_key: Option<i64>) -> Result<(), String>;

    /// Skip over the current instruction/call.
    fn skip_over(&mut self, thread_key: Option<i64>) -> Result<(), String>;

    /// Execute a custom command.
    fn execute_command(&mut self, command: &str, args: &[String]) -> Result<String, String>;

    /// Get the target's reported capabilities.
    fn capabilities(&self) -> TargetCapabilities;
}

/// Describes what a target implementation supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetCapabilities {
    /// Can this target launch new processes?
    pub can_launch: bool,
    /// Can this target attach to running processes?
    pub can_attach: bool,
    /// Can this target connect to remote targets?
    pub can_connect: bool,
    /// Can this target step backward?
    pub can_step_back: bool,
    /// Can this target execute custom commands?
    pub can_execute_commands: bool,
    /// Does this target support multiple processes?
    pub supports_multi_process: bool,
    /// Does this target support reverse execution?
    pub supports_reverse: bool,
    /// Does this target support hardware breakpoints?
    pub supports_hw_breakpoints: bool,
    /// Does this target support conditional breakpoints?
    pub supports_conditional_breakpoints: bool,
}

impl Default for TargetCapabilities {
    fn default() -> Self {
        Self {
            can_launch: true,
            can_attach: true,
            can_connect: true,
            can_step_back: false,
            can_execute_commands: false,
            supports_multi_process: false,
            supports_reverse: false,
            supports_hw_breakpoints: false,
            supports_conditional_breakpoints: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockExtendedTarget {
        threads: Vec<ThreadInfo>,
        processes: Vec<ProcessInfo>,
    }

    impl MockExtendedTarget {
        fn new() -> Self {
            Self {
                threads: vec![
                    ThreadInfo {
                        key: 1,
                        name: "main".into(),
                        tid: Some(100),
                        is_focused: true,
                        state: TraceExecutionState::Running,
                    },
                    ThreadInfo {
                        key: 2,
                        name: "worker".into(),
                        tid: Some(101),
                        is_focused: false,
                        state: TraceExecutionState::Stopped,
                    },
                ],
                processes: vec![ProcessInfo {
                    key: 1,
                    name: "test_program".into(),
                    pid: Some(1000),
                    is_focused: true,
                }],
            }
        }
    }

    impl TargetExtended for MockExtendedTarget {
        fn interrupt(&mut self) -> Result<(), String> {
            for t in &mut self.threads {
                t.state = TraceExecutionState::Stopped;
            }
            Ok(())
        }

        fn kill(&mut self) -> Result<(), String> {
            self.threads.clear();
            Ok(())
        }

        fn attach(&mut self, pid: u64) -> Result<AttachResult, String> {
            Ok(AttachResult {
                process_key: pid as i64,
                message: Some("Attached".into()),
            })
        }

        fn launch(
            &mut self,
            program: &str,
            _args: &[String],
            _working_dir: Option<&str>,
        ) -> Result<LaunchResult, String> {
            Ok(LaunchResult {
                process_key: 42,
                main_thread_key: Some(100),
                message: Some(format!("Launched {}", program)),
            })
        }

        fn connect(&mut self, address: &str, port: u16) -> Result<ConnectResult, String> {
            Ok(ConnectResult {
                connection_id: format!("{}:{}", address, port),
                message: Some("Connected".into()),
            })
        }

        fn activate_thread(&mut self, thread_key: i64) -> Result<(), String> {
            for t in &mut self.threads {
                t.is_focused = t.key == thread_key;
            }
            Ok(())
        }

        fn activate_process(&mut self, process_key: i64) -> Result<(), String> {
            for p in &mut self.processes {
                p.is_focused = p.key == process_key;
            }
            Ok(())
        }

        fn get_threads(&self) -> Result<Vec<ThreadInfo>, String> {
            Ok(self.threads.clone())
        }

        fn get_processes(&self) -> Result<Vec<ProcessInfo>, String> {
            Ok(self.processes.clone())
        }

        fn get_stack_frames(&self, _thread_key: i64) -> Result<Vec<StackFrameInfo>, String> {
            Ok(vec![
                StackFrameInfo {
                    level: 0,
                    pc: 0x400100,
                    sp: 0x7fff00,
                    function_name: Some("main".into()),
                },
                StackFrameInfo {
                    level: 1,
                    pc: 0x400200,
                    sp: 0x7fff10,
                    function_name: Some("_start".into()),
                },
            ])
        }

        fn get_memory_regions(&self) -> Result<Vec<MemoryRegionInfo>, String> {
            Ok(vec![
                MemoryRegionInfo {
                    name: ".text".into(),
                    start: 0x400000,
                    length: 0x10000,
                    readable: true,
                    writable: false,
                    executable: true,
                    volatile: false,
                },
                MemoryRegionInfo {
                    name: ".data".into(),
                    start: 0x600000,
                    length: 0x1000,
                    readable: true,
                    writable: true,
                    executable: false,
                    volatile: false,
                },
            ])
        }

        fn get_registers(&self, _thread_key: i64) -> Result<Vec<RegisterInfo>, String> {
            Ok(vec![
                RegisterInfo {
                    name: "RIP".into(),
                    size: 8,
                    category: "Program Counter".into(),
                },
                RegisterInfo {
                    name: "RSP".into(),
                    size: 8,
                    category: "Stack Pointer".into(),
                },
            ])
        }

        fn step_back(&mut self, _thread_key: Option<i64>) -> Result<(), String> {
            Err("Reverse execution not supported".into())
        }

        fn skip_over(&mut self, _thread_key: Option<i64>) -> Result<(), String> {
            Ok(())
        }

        fn execute_command(&mut self, command: &str, _args: &[String]) -> Result<String, String> {
            Ok(format!("Executed: {}", command))
        }

        fn capabilities(&self) -> TargetCapabilities {
            TargetCapabilities {
                can_launch: true,
                can_attach: true,
                can_connect: true,
                can_step_back: false,
                can_execute_commands: true,
                supports_multi_process: true,
                supports_reverse: false,
                supports_hw_breakpoints: true,
                supports_conditional_breakpoints: true,
            }
        }
    }

    #[test]
    fn test_thread_info() {
        let target = MockExtendedTarget::new();
        let threads = target.get_threads().unwrap();
        assert_eq!(threads.len(), 2);
        assert_eq!(threads[0].name, "main");
        assert!(threads[0].is_focused);
        assert_eq!(threads[0].tid, Some(100));
    }

    #[test]
    fn test_process_info() {
        let target = MockExtendedTarget::new();
        let procs = target.get_processes().unwrap();
        assert_eq!(procs.len(), 1);
        assert_eq!(procs[0].name, "test_program");
        assert_eq!(procs[0].pid, Some(1000));
    }

    #[test]
    fn test_stack_frames() {
        let target = MockExtendedTarget::new();
        let frames = target.get_stack_frames(1).unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].level, 0);
        assert_eq!(frames[0].pc, 0x400100);
        assert_eq!(frames[0].function_name.as_deref(), Some("main"));
        assert_eq!(frames[1].level, 1);
    }

    #[test]
    fn test_memory_regions() {
        let target = MockExtendedTarget::new();
        let regions = target.get_memory_regions().unwrap();
        assert_eq!(regions.len(), 2);
        assert!(regions[0].executable);
        assert!(!regions[0].writable);
        assert!(regions[1].writable);
        assert!(!regions[1].executable);
    }

    #[test]
    fn test_registers() {
        let target = MockExtendedTarget::new();
        let regs = target.get_registers(1).unwrap();
        assert_eq!(regs.len(), 2);
        assert_eq!(regs[0].name, "RIP");
        assert_eq!(regs[0].size, 8);
    }

    #[test]
    fn test_interrupt() {
        let mut target = MockExtendedTarget::new();
        assert!(target.interrupt().is_ok());
        let threads = target.get_threads().unwrap();
        assert!(threads.iter().all(|t| t.state == TraceExecutionState::Stopped));
    }

    #[test]
    fn test_kill() {
        let mut target = MockExtendedTarget::new();
        assert!(target.kill().is_ok());
        assert!(target.get_threads().unwrap().is_empty());
    }

    #[test]
    fn test_attach() {
        let mut target = MockExtendedTarget::new();
        let result = target.attach(1234).unwrap();
        assert_eq!(result.process_key, 1234);
    }

    #[test]
    fn test_launch() {
        let mut target = MockExtendedTarget::new();
        let result = target.launch("/usr/bin/test", &["--flag".into()], None).unwrap();
        assert_eq!(result.process_key, 42);
        assert_eq!(result.main_thread_key, Some(100));
    }

    #[test]
    fn test_connect() {
        let mut target = MockExtendedTarget::new();
        let result = target.connect("localhost", 12345).unwrap();
        assert_eq!(result.connection_id, "localhost:12345");
    }

    #[test]
    fn test_activate_thread() {
        let mut target = MockExtendedTarget::new();
        target.activate_thread(2).unwrap();
        let threads = target.get_threads().unwrap();
        assert!(threads.iter().find(|t| t.key == 2).unwrap().is_focused);
        assert!(!threads.iter().find(|t| t.key == 1).unwrap().is_focused);
    }

    #[test]
    fn test_activate_process() {
        let mut target = MockExtendedTarget::new();
        target.activate_process(1).unwrap();
        let procs = target.get_processes().unwrap();
        assert!(procs[0].is_focused);
    }

    #[test]
    fn test_step_back_not_supported() {
        let mut target = MockExtendedTarget::new();
        let result = target.step_back(None);
        assert!(result.is_err());
    }

    #[test]
    fn test_skip_over() {
        let mut target = MockExtendedTarget::new();
        assert!(target.skip_over(None).is_ok());
        assert!(target.skip_over(Some(1)).is_ok());
    }

    #[test]
    fn test_execute_command() {
        let mut target = MockExtendedTarget::new();
        let result = target.execute_command("info registers", &[]).unwrap();
        assert!(result.contains("info registers"));
    }

    #[test]
    fn test_capabilities() {
        let target = MockExtendedTarget::new();
        let caps = target.capabilities();
        assert!(caps.can_launch);
        assert!(caps.can_attach);
        assert!(!caps.supports_reverse);
        assert!(caps.supports_hw_breakpoints);
    }

    #[test]
    fn test_target_capabilities_default() {
        let caps = TargetCapabilities::default();
        assert!(caps.can_launch);
        assert!(caps.can_attach);
        assert!(caps.can_connect);
        assert!(!caps.can_step_back);
        assert!(!caps.supports_multi_process);
    }

    #[test]
    fn test_memory_region_info_serialization() {
        let region = MemoryRegionInfo {
            name: ".text".into(),
            start: 0x400000,
            length: 0x10000,
            readable: true,
            writable: false,
            executable: true,
            volatile: false,
        };
        let json = serde_json::to_string(&region).unwrap();
        let back: MemoryRegionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, ".text");
        assert_eq!(back.start, 0x400000);
    }

    #[test]
    fn test_stack_frame_info_serialization() {
        let frame = StackFrameInfo {
            level: 0,
            pc: 0x400100,
            sp: 0x7fff00,
            function_name: Some("main".into()),
        };
        let json = serde_json::to_string(&frame).unwrap();
        let back: StackFrameInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pc, 0x400100);
    }
}
