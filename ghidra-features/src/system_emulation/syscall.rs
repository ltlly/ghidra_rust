//! Syscall emulation libraries.
//!
//! Ported from Ghidra's `SyscallLibrary`, `SyscallEmulationLibrary`, and
//! related classes.
//!
//! A `SyscallLibrary` provides emulation handlers for OS-level system calls.
//! Each syscall is identified by a number (or name) and has an associated
//! handler function that updates the emulated machine state.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::pcode_emu::{EmuException, EmulatedMachine};

// ---------------------------------------------------------------------------
// SyscallDefinition
// ---------------------------------------------------------------------------

/// Definition of a single system call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallDefinition {
    /// The syscall number.
    pub number: u64,
    /// The name of the syscall (e.g., "read", "write", "mmap").
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Parameter descriptions: (name, size_hint).
    pub parameters: Vec<(String, usize)>,
    /// Whether this syscall can block.
    pub may_block: bool,
}

// ---------------------------------------------------------------------------
// SyscallResult
// ---------------------------------------------------------------------------

/// The result of emulating a syscall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallResult {
    /// The return value to place in the return register.
    pub return_value: u64,
    /// Optional side effects (memory writes, register changes) that were applied.
    pub side_effects: Vec<SideEffect>,
    /// Whether the syscall should cause the emulation to stop.
    pub should_stop: bool,
    /// An error message if the syscall failed.
    pub error_message: Option<String>,
}

/// A side effect produced by a syscall handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SideEffect {
    /// A memory write.
    MemoryWrite { address: u64, data: Vec<u8> },
    /// A register write.
    RegisterWrite { name: String, value: u64 },
    /// An output message (for debugging).
    Output(String),
}

// ---------------------------------------------------------------------------
// SyscallLibrary -- trait and default implementation
// ---------------------------------------------------------------------------

/// Trait for a library of emulated system calls.
pub trait SyscallLibrary: std::fmt::Debug + Send + Sync {
    /// The name of this syscall library (e.g., "Linux", "Windows").
    fn name(&self) -> &str;

    /// The set of syscall definitions provided by this library.
    fn definitions(&self) -> &[SyscallDefinition];

    /// Look up a syscall by number.
    fn get_by_number(&self, number: u64) -> Option<&SyscallDefinition>;

    /// Look up a syscall by name.
    fn get_by_name(&self, name: &str) -> Option<&SyscallDefinition>;

    /// Handle (emulate) a syscall on the given machine.
    fn handle_syscall(
        &self,
        number: u64,
        machine: &mut EmulatedMachine,
    ) -> Result<SyscallResult, EmuException>;
}

// ---------------------------------------------------------------------------
// DefaultSyscallLibrary -- a simple default implementation
// ---------------------------------------------------------------------------

/// A simple syscall library that handles common Linux syscalls.
///
/// This is a stub implementation that provides the structure for syscall
/// emulation. Real syscall handlers would perform actual memory operations
/// on the emulated machine.
#[derive(Debug, Clone)]
pub struct LinuxSyscallLibrary {
    /// Syscall definitions, keyed by number.
    definitions: Vec<SyscallDefinition>,
    /// Index from number to definition index.
    by_number: HashMap<u64, usize>,
    /// Index from name to definition index.
    by_name: HashMap<String, usize>,
}

impl LinuxSyscallLibrary {
    /// Create a new Linux syscall library with common syscalls.
    pub fn new() -> Self {
        let mut lib = Self {
            definitions: Vec::new(),
            by_number: HashMap::new(),
            by_name: HashMap::new(),
        };
        lib.register_common_syscalls();
        lib
    }

    /// Register a syscall definition.
    pub fn register(&mut self, def: SyscallDefinition) {
        let idx = self.definitions.len();
        self.by_number.insert(def.number, idx);
        self.by_name.insert(def.name.clone(), idx);
        self.definitions.push(def);
    }

    fn register_common_syscalls(&mut self) {
        // x86-64 Linux syscall numbers
        self.register(SyscallDefinition {
            number: 0,
            name: "read".into(),
            description: "Read from a file descriptor".into(),
            parameters: vec![
                ("fd".into(), 8),
                ("buf".into(), 8),
                ("count".into(), 8),
            ],
            may_block: true,
        });
        self.register(SyscallDefinition {
            number: 1,
            name: "write".into(),
            description: "Write to a file descriptor".into(),
            parameters: vec![
                ("fd".into(), 8),
                ("buf".into(), 8),
                ("count".into(), 8),
            ],
            may_block: true,
        });
        self.register(SyscallDefinition {
            number: 9,
            name: "mmap".into(),
            description: "Map memory".into(),
            parameters: vec![
                ("addr".into(), 8),
                ("length".into(), 8),
                ("prot".into(), 8),
                ("flags".into(), 8),
                ("fd".into(), 8),
                ("offset".into(), 8),
            ],
            may_block: false,
        });
        self.register(SyscallDefinition {
            number: 11,
            name: "munmap".into(),
            description: "Unmap memory".into(),
            parameters: vec![("addr".into(), 8), ("length".into(), 8)],
            may_block: false,
        });
        self.register(SyscallDefinition {
            number: 60,
            name: "exit".into(),
            description: "Exit the process".into(),
            parameters: vec![("status".into(), 8)],
            may_block: false,
        });
        self.register(SyscallDefinition {
            number: 63,
            name: "uname".into(),
            description: "Get system information".into(),
            parameters: vec![("buf".into(), 8)],
            may_block: false,
        });
        self.register(SyscallDefinition {
            number: 158,
            name: "arch_prctl".into(),
            description: "Set architecture-specific thread state".into(),
            parameters: vec![("code".into(), 8), ("addr".into(), 8)],
            may_block: false,
        });
        self.register(SyscallDefinition {
            number: 231,
            name: "exit_group".into(),
            description: "Exit all threads in the process".into(),
            parameters: vec![("status".into(), 8)],
            may_block: false,
        });
        self.register(SyscallDefinition {
            number: 217,
            name: "getdents64".into(),
            description: "Get directory entries".into(),
            parameters: vec![
                ("fd".into(), 8),
                ("dirp".into(), 8),
                ("count".into(), 8),
            ],
            may_block: false,
        });
    }
}

impl Default for LinuxSyscallLibrary {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallLibrary for LinuxSyscallLibrary {
    fn name(&self) -> &str {
        "Linux"
    }

    fn definitions(&self) -> &[SyscallDefinition] {
        &self.definitions
    }

    fn get_by_number(&self, number: u64) -> Option<&SyscallDefinition> {
        self.by_number.get(&number).map(|&idx| &self.definitions[idx])
    }

    fn get_by_name(&self, name: &str) -> Option<&SyscallDefinition> {
        self.by_name.get(name).map(|&idx| &self.definitions[idx])
    }

    fn handle_syscall(
        &self,
        number: u64,
        machine: &mut EmulatedMachine,
    ) -> Result<SyscallResult, EmuException> {
        let def = self.get_by_number(number);

        match number {
            // read(fd, buf, count) -> 0 (stub)
            0 => {
                let _fd = machine.get_register("RDI");
                let buf = machine.get_register("RSI");
                let count = machine.get_register("RDX");
                // Stub: write zeros
                let zeros = vec![0u8; count as usize];
                machine.mem_write(buf, &zeros);
                Ok(SyscallResult {
                    return_value: count,
                    side_effects: vec![SideEffect::MemoryWrite {
                        address: buf,
                        data: zeros,
                    }],
                    should_stop: false,
                    error_message: None,
                })
            }
            // write(fd, buf, count) -> count (stub)
            1 => {
                let _fd = machine.get_register("RDI");
                let buf = machine.get_register("RSI");
                let count = machine.get_register("RDX");
                let data = machine.mem_read(buf, count as usize);
                Ok(SyscallResult {
                    return_value: count,
                    side_effects: vec![SideEffect::Output(format!(
                        "write: {}",
                        String::from_utf8_lossy(&data)
                    ))],
                    should_stop: false,
                    error_message: None,
                })
            }
            // exit(status)
            60 | 231 => {
                let status = machine.get_register("RDI") as i32;
                Ok(SyscallResult {
                    return_value: status as u64,
                    side_effects: vec![],
                    should_stop: true,
                    error_message: None,
                })
            }
            // mmap(addr, len, prot, flags, fd, off)
            9 => {
                let len = machine.get_register("RSI");
                // Return a fresh heap address
                let result_addr = 0x7F00_0000;
                Ok(SyscallResult {
                    return_value: result_addr,
                    side_effects: vec![SideEffect::Output(format!("mmap: {} bytes", len))],
                    should_stop: false,
                    error_message: None,
                })
            }
            // Default: return ENOSYS
            _ => {
                let name = def.map(|d| d.name.as_str()).unwrap_or("unknown");
                Ok(SyscallResult {
                    return_value: (-38i64) as u64, // -ENOSYS
                    side_effects: vec![SideEffect::Output(format!(
                        "unhandled syscall {} ({})",
                        number, name
                    ))],
                    should_stop: false,
                    error_message: Some(format!("Unhandled syscall {} ({})", number, name)),
                })
            }
        }
    }
}

/// A stub syscall library for Windows (minimal).
#[derive(Debug, Clone)]
pub struct WindowsSyscallLibrary {
    definitions: Vec<SyscallDefinition>,
    by_number: HashMap<u64, usize>,
    by_name: HashMap<String, usize>,
}

impl WindowsSyscallLibrary {
    /// Create a new Windows syscall library.
    pub fn new() -> Self {
        let mut lib = Self {
            definitions: Vec::new(),
            by_number: HashMap::new(),
            by_name: HashMap::new(),
        };
        lib.register_win(SyscallDefinition {
            number: 0x1000,
            name: "NtAllocateVirtualMemory".into(),
            description: "Allocate virtual memory".into(),
            parameters: vec![
                ("ProcessHandle".into(), 8),
                ("BaseAddress".into(), 8),
                ("ZeroBits".into(), 8),
                ("RegionSize".into(), 8),
                ("AllocationType".into(), 8),
                ("Protect".into(), 8),
            ],
            may_block: false,
        });
        lib.register_win(SyscallDefinition {
            number: 0x1001,
            name: "NtFreeVirtualMemory".into(),
            description: "Free virtual memory".into(),
            parameters: vec![
                ("ProcessHandle".into(), 8),
                ("BaseAddress".into(), 8),
                ("RegionSize".into(), 8),
                ("FreeType".into(), 8),
            ],
            may_block: false,
        });
        lib.register_win(SyscallDefinition {
            number: 0x1002,
            name: "NtWriteFile".into(),
            description: "Write to a file handle".into(),
            parameters: vec![
                ("FileHandle".into(), 8),
                ("Event".into(), 8),
                ("ApcRoutine".into(), 8),
                ("ApcContext".into(), 8),
                ("IoStatusBlock".into(), 8),
                ("Buffer".into(), 8),
                ("Length".into(), 8),
                ("ByteOffset".into(), 8),
                ("Key".into(), 8),
            ],
            may_block: true,
        });
        lib
    }

    /// Register a syscall definition.
    fn register_win(&mut self, def: SyscallDefinition) {
        let idx = self.definitions.len();
        self.by_number.insert(def.number, idx);
        self.by_name.insert(def.name.clone(), idx);
        self.definitions.push(def);
    }
}

impl Default for WindowsSyscallLibrary {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallLibrary for WindowsSyscallLibrary {
    fn name(&self) -> &str {
        "Windows"
    }

    fn definitions(&self) -> &[SyscallDefinition] {
        &self.definitions
    }

    fn get_by_number(&self, number: u64) -> Option<&SyscallDefinition> {
        self.by_number.get(&number).map(|&idx| &self.definitions[idx])
    }

    fn get_by_name(&self, name: &str) -> Option<&SyscallDefinition> {
        self.by_name.get(name).map(|&idx| &self.definitions[idx])
    }

    fn handle_syscall(
        &self,
        number: u64,
        _machine: &mut EmulatedMachine,
    ) -> Result<SyscallResult, EmuException> {
        let def = self.get_by_number(number);
        let name = def.map(|d| d.name.as_str()).unwrap_or("unknown");
        Ok(SyscallResult {
            return_value: 0,
            side_effects: vec![SideEffect::Output(format!(
                "Windows syscall {} ({}) - stub",
                number, name
            ))],
            should_stop: false,
            error_message: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_syscall_library_definitions() {
        let lib = LinuxSyscallLibrary::new();
        assert_eq!(lib.name(), "Linux");
        assert!(lib.definitions().len() >= 5);
        assert!(lib.get_by_number(0).is_some()); // read
        assert!(lib.get_by_number(1).is_some()); // write
        assert!(lib.get_by_name("exit").is_some());
        assert!(lib.get_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_linux_syscall_read_stub() {
        let lib = LinuxSyscallLibrary::new();
        let mut emu = EmulatedMachine::new_le(8);
        emu.map_memory(0x700000, 0x1000, "data".into(), true, true, false);

        // Simulate read(0, 0x700000, 4)
        emu.set_register("RDI", 0);        // fd
        emu.set_register("RSI", 0x700000);  // buf
        emu.set_register("RDX", 4);         // count

        let result = lib.handle_syscall(0, &mut emu).unwrap();
        assert_eq!(result.return_value, 4);
        assert!(!result.should_stop);

        // The buffer should be filled with zeros (stub)
        let data = emu.mem_read(0x700000, 4);
        assert_eq!(data, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_linux_syscall_write_stub() {
        let lib = LinuxSyscallLibrary::new();
        let mut emu = EmulatedMachine::new_le(8);
        emu.map_memory(0x700000, 0x1000, "data".into(), true, true, false);
        emu.mem_write(0x700000, b"hi!");

        emu.set_register("RDI", 1);         // fd (stdout)
        emu.set_register("RSI", 0x700000);  // buf
        emu.set_register("RDX", 3);         // count

        let result = lib.handle_syscall(1, &mut emu).unwrap();
        assert_eq!(result.return_value, 3);
        assert!(!result.should_stop);
    }

    #[test]
    fn test_linux_syscall_exit() {
        let lib = LinuxSyscallLibrary::new();
        let mut emu = EmulatedMachine::new_le(8);
        emu.set_register("RDI", 42);

        let result = lib.handle_syscall(60, &mut emu).unwrap();
        assert!(result.should_stop);
        assert_eq!(result.return_value, 42);
    }

    #[test]
    fn test_linux_syscall_unknown() {
        let lib = LinuxSyscallLibrary::new();
        let mut emu = EmulatedMachine::new_le(8);

        let result = lib.handle_syscall(9999, &mut emu).unwrap();
        assert_eq!(result.return_value, (-38i64) as u64); // ENOSYS
        assert!(result.error_message.is_some());
    }

    #[test]
    fn test_windows_syscall_library() {
        let lib = WindowsSyscallLibrary::new();
        assert_eq!(lib.name(), "Windows");
        assert!(lib.get_by_number(0x1000).is_some()); // NtAllocateVirtualMemory
        assert!(lib.get_by_name("NtWriteFile").is_some());
    }

    #[test]
    fn test_syscall_definition_serialization() {
        let def = SyscallDefinition {
            number: 42,
            name: "test".into(),
            description: "test syscall".into(),
            parameters: vec![("arg0".into(), 8)],
            may_block: false,
        };
        let json = serde_json::to_string(&def).unwrap();
        let parsed: SyscallDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.number, 42);
        assert_eq!(parsed.name, "test");
    }
}
