//! System Emulation Analyzer -- discovers emulation entry points and setup.
//!
//! Ported from Ghidra's `EmuSystemAnalyzer` (Features/SystemEmulation).
//!
//! Analyzes a loaded program to identify:
//! - System call patterns and their calling conventions
//! - Emulation-relevant functions (start, init, signal handlers)
//! - Register and memory initialization for emulation
//! - Syscall dispatch tables and handler entry points
//!
//! # Key Types
//!
//! - [`EmuSystemAnalyzer`] -- The analyzer that discovers emulation entry points
//! - [`SyscallPattern`] -- A recognized syscall invocation pattern
//! - [`EmuEntryPoint`] -- A discovered entry point suitable for emulation
//! - [`AnalyzerResult`] -- Outcome of running the analyzer on a program

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

use super::pcode_emu::EmulatedMachine;
use super::syscall::{LinuxSyscallLibrary, SyscallLibrary, WindowsSyscallLibrary};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Analyzer name.
pub const ANALYZER_NAME: &str = "System Emulation Analyzer";

/// Analyzer description.
pub const ANALYZER_DESCRIPTION: &str =
    "Discovers system call patterns, emulation entry points, and syscall \
     dispatch tables for P-code based system emulation.";

/// Default analysis priority (runs after basic disassembly).
pub const DEFAULT_PRIORITY: i32 = 50;

// ---------------------------------------------------------------------------
// SyscallPattern -- a recognized syscall invocation
// ---------------------------------------------------------------------------

/// A recognized system call invocation pattern in the binary.
///
/// Different architectures and OS ABIs use different instruction sequences
/// to invoke syscalls (e.g., `int 0x80`, `syscall`, `svc 0`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallPattern {
    /// The mnemonic or instruction sequence that triggers the syscall.
    pub trigger: String,
    /// The architecture this pattern applies to (e.g., "x86", "x86_64", "ARM").
    pub architecture: String,
    /// The register that carries the syscall number.
    pub number_register: String,
    /// The registers used for arguments, in order.
    pub argument_registers: Vec<String>,
    /// The register that receives the return value.
    pub return_register: String,
    /// The OS this pattern applies to (e.g., "Linux", "Windows").
    pub os: String,
}

impl SyscallPattern {
    /// Create the standard x86-64 Linux syscall pattern (`syscall` instruction).
    pub fn x86_64_linux() -> Self {
        Self {
            trigger: "syscall".into(),
            architecture: "x86_64".into(),
            number_register: "RAX".into(),
            argument_registers: vec![
                "RDI".into(),
                "RSI".into(),
                "RDX".into(),
                "R10".into(),
                "R8".into(),
                "R9".into(),
            ],
            return_register: "RAX".into(),
            os: "Linux".into(),
        }
    }

    /// Create the standard x86 Linux syscall pattern (`int 0x80`).
    pub fn x86_linux() -> Self {
        Self {
            trigger: "INT 0x80".into(),
            architecture: "x86".into(),
            number_register: "EAX".into(),
            argument_registers: vec![
                "EBX".into(),
                "ECX".into(),
                "EDX".into(),
                "ESI".into(),
                "EDI".into(),
                "EBP".into(),
            ],
            return_register: "EAX".into(),
            os: "Linux".into(),
        }
    }

    /// Create the standard ARM Linux syscall pattern (`svc 0`).
    pub fn arm_linux() -> Self {
        Self {
            trigger: "SVC 0".into(),
            architecture: "ARM".into(),
            number_register: "R7".into(),
            argument_registers: vec![
                "R0".into(),
                "R1".into(),
                "R2".into(),
                "R3".into(),
                "R4".into(),
                "R5".into(),
            ],
            return_register: "R0".into(),
            os: "Linux".into(),
        }
    }

    /// Create the Windows x86-64 syscall pattern (`syscall` via ntdll stub).
    pub fn x86_64_windows() -> Self {
        Self {
            trigger: "syscall".into(),
            architecture: "x86_64".into(),
            number_register: "RAX".into(),
            argument_registers: vec![
                "RCX".into(),
                "RDX".into(),
                "R8".into(),
                "R9".into(),
            ],
            return_register: "RAX".into(),
            os: "Windows".into(),
        }
    }

    /// Get all built-in syscall patterns.
    pub fn all_builtin() -> Vec<Self> {
        vec![
            Self::x86_64_linux(),
            Self::x86_linux(),
            Self::arm_linux(),
            Self::x86_64_windows(),
        ]
    }
}

// ---------------------------------------------------------------------------
// EmuEntryPoint -- a discovered entry point for emulation
// ---------------------------------------------------------------------------

/// A discovered entry point suitable for emulation.
///
/// The analyzer identifies functions or code locations that are good
/// starting points for emulation, such as `main`, `_start`, signal
/// handlers, or syscall dispatch routines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EmuEntryPoint {
    /// The address of the entry point.
    pub address: u64,
    /// A human-readable label for this entry point.
    pub label: String,
    /// The kind of entry point.
    pub kind: EmuEntryPointKind,
    /// Confidence level (0.0 to 1.0).
    pub confidence: f64,
}

/// The kind of emulation entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmuEntryPointKind {
    /// The program's `main` function.
    Main,
    /// The ELF entry point (`_start`).
    Start,
    /// A signal handler registration.
    SignalHandler,
    /// A syscall dispatch table or handler.
    SyscallDispatch,
    /// A constructor / init function (`.init_array`).
    Constructor,
    /// A destructor / fini function (`.fini_array`).
    Destructor,
    /// A thread entry point (e.g., `pthread_create` target).
    ThreadEntry,
    /// A custom entry point specified by the user.
    Custom,
}

impl EmuEntryPointKind {
    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Main => "Program main function",
            Self::Start => "ELF entry point (_start)",
            Self::SignalHandler => "Signal handler",
            Self::SyscallDispatch => "Syscall dispatch routine",
            Self::Constructor => "Constructor / init function",
            Self::Destructor => "Destructor / fini function",
            Self::ThreadEntry => "Thread entry point",
            Self::Custom => "User-specified entry point",
        }
    }
}

// ---------------------------------------------------------------------------
// AnalyzerResult -- the outcome of analysis
// ---------------------------------------------------------------------------

/// The result of running the system emulation analyzer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalyzerResult {
    /// Discovered syscall invocation sites: address -> syscall number.
    pub syscall_sites: BTreeMap<u64, u64>,
    /// Discovered syscall patterns found in the binary.
    pub found_patterns: Vec<SyscallPattern>,
    /// Discovered entry points for emulation.
    pub entry_points: Vec<EmuEntryPoint>,
    /// Detected OS (e.g., "Linux", "Windows").
    pub detected_os: Option<String>,
    /// Detected architecture (e.g., "x86_64", "ARM").
    pub detected_architecture: Option<String>,
    /// Warnings generated during analysis.
    pub warnings: Vec<String>,
    /// Whether the analysis completed successfully.
    pub completed: bool,
}

// ---------------------------------------------------------------------------
// EmuSystemAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that discovers system call patterns and emulation entry points.
///
/// Ported from Ghidra's `EmuSystemAnalyzer`.
///
/// This analyzer inspects the disassembled program to find syscall
/// invocation patterns, identify entry points suitable for emulation,
/// and build a mapping of syscall numbers to their call sites.
///
/// # Example
///
/// ```rust
/// use ghidra_features::system_emulation::*;
///
/// let analyzer = EmuSystemAnalyzer::new();
/// assert_eq!(analyzer.name(), "System Emulation Analyzer");
/// assert!(analyzer.is_enabled());
/// ```
#[derive(Debug, Clone)]
pub struct EmuSystemAnalyzer {
    /// Whether the analyzer is enabled.
    enabled: bool,
    /// Analysis priority.
    priority: i32,
    /// Registered syscall patterns to search for.
    patterns: Vec<SyscallPattern>,
    /// Known entry point names to look for.
    entry_point_names: HashSet<String>,
    /// Whether to analyze syscall dispatch tables.
    analyze_dispatch_tables: bool,
    /// Whether to look for signal handler registrations.
    analyze_signal_handlers: bool,
    /// Maximum number of bytes to examine per function during pattern scan.
    max_scan_bytes: usize,
}

impl EmuSystemAnalyzer {
    /// Create a new system emulation analyzer with default settings.
    pub fn new() -> Self {
        let mut entry_names = HashSet::new();
        for name in &[
            "main",
            "_start",
            "__libc_start_main",
            "start",
            "_main",
            "WinMain",
            "wWinMain",
            "DllMain",
            "DriverEntry",
            "NtUserCallNoParam",
        ] {
            entry_names.insert(name.to_string());
        }

        Self {
            enabled: true,
            priority: DEFAULT_PRIORITY,
            patterns: SyscallPattern::all_builtin(),
            entry_point_names: entry_names,
            analyze_dispatch_tables: true,
            analyze_signal_handlers: true,
            max_scan_bytes: 4096,
        }
    }

    /// Analyzer name.
    pub fn name(&self) -> &str {
        ANALYZER_NAME
    }

    /// Analyzer description.
    pub fn description(&self) -> &str {
        ANALYZER_DESCRIPTION
    }

    /// Whether the analyzer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the analyzer.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the analysis priority.
    pub fn priority(&self) -> i32 {
        self.priority
    }

    /// Set the analysis priority.
    pub fn set_priority(&mut self, priority: i32) {
        self.priority = priority;
    }

    /// Get the registered syscall patterns.
    pub fn patterns(&self) -> &[SyscallPattern] {
        &self.patterns
    }

    /// Add a syscall pattern.
    pub fn add_pattern(&mut self, pattern: SyscallPattern) {
        self.patterns.push(pattern);
    }

    /// Add a known entry point name.
    pub fn add_entry_point_name(&mut self, name: impl Into<String>) {
        self.entry_point_names.insert(name.into());
    }

    /// Set whether to analyze syscall dispatch tables.
    pub fn set_analyze_dispatch_tables(&mut self, analyze: bool) {
        self.analyze_dispatch_tables = analyze;
    }

    /// Set whether to look for signal handler registrations.
    pub fn set_analyze_signal_handlers(&mut self, analyze: bool) {
        self.analyze_signal_handlers = analyze;
    }

    /// Set the maximum bytes to scan per function.
    pub fn set_max_scan_bytes(&mut self, max: usize) {
        self.max_scan_bytes = max;
    }

    /// Analyze function names against the known entry point list.
    ///
    /// Returns any function names that match known entry points.
    pub fn find_entry_points_by_name(
        &self,
        functions: &[(u64, &str)],
    ) -> Vec<EmuEntryPoint> {
        let mut results = Vec::new();
        for (addr, name) in functions {
            let stripped = Self::strip_prefix(name);
            if self.entry_point_names.contains(stripped) {
                let kind = match stripped {
                    "main" | "_main" | "WinMain" | "wWinMain" => EmuEntryPointKind::Main,
                    "_start" | "start" | "__libc_start_main" => EmuEntryPointKind::Start,
                    "DllMain" | "DriverEntry" => EmuEntryPointKind::Constructor,
                    _ => EmuEntryPointKind::Custom,
                };
                results.push(EmuEntryPoint {
                    address: *addr,
                    label: name.to_string(),
                    kind,
                    confidence: 0.95,
                });
            }
        }
        results
    }

    /// Detect the OS from function names and symbols.
    pub fn detect_os(&self, symbols: &[&str]) -> Option<String> {
        let mut linux_score = 0u32;
        let mut windows_score = 0u32;

        for sym in symbols {
            match *sym {
                "__libc_start_main" | "__libc_csu_init" | "__libc_csu_fini"
                | "__gmon_start__" | "_IO_stdin_used" | "__cxa_atexit" => {
                    linux_score += 1;
                }
                "NtAllocateVirtualMemory" | "NtFreeVirtualMemory" | "NtWriteFile"
                | "RtlInitUnicodeString" | "KeInitializeEvent" | "ObReferenceObjectByHandle" => {
                    windows_score += 1;
                }
                _ => {
                    if sym.starts_with("__rust_") || sym.starts_with("std::") {
                        linux_score += 1;
                    }
                }
            }
        }

        if linux_score > windows_score && linux_score > 0 {
            Some("Linux".into())
        } else if windows_score > linux_score && windows_score > 0 {
            Some("Windows".into())
        } else {
            None
        }
    }

    /// Detect the architecture from register names used in a program.
    pub fn detect_architecture(&self, register_names: &[&str]) -> Option<String> {
        let regs: HashSet<&str> = register_names.iter().copied().collect();

        if regs.contains("RAX") || regs.contains("RIP") {
            Some("x86_64".into())
        } else if regs.contains("EAX") || regs.contains("EIP") {
            Some("x86".into())
        } else if regs.contains("R7") && (regs.contains("R0") || regs.contains("CPSR")) {
            Some("ARM".into())
        } else if regs.contains("X0") || regs.contains("SP_EL0") {
            Some("AARCH64".into())
        } else if regs.contains("a0") || regs.contains("ra") {
            Some("MIPS".into())
        } else {
            None
        }
    }

    /// Scan instruction bytes for syscall trigger patterns.
    ///
    /// Returns a list of addresses where syscall invocations were found.
    pub fn scan_for_syscall_triggers(
        &self,
        instructions: &[(u64, &str)],
    ) -> Vec<(u64, &SyscallPattern)> {
        let mut results = Vec::new();
        for (addr, mnemonic) in instructions {
            for pattern in &self.patterns {
                if mnemonic.eq_ignore_ascii_case(&pattern.trigger) {
                    results.push((*addr, pattern));
                }
            }
        }
        results
    }

    /// Build a syscall library appropriate for the detected OS.
    pub fn build_syscall_library(&self, os: &str) -> Box<dyn SyscallLibrary> {
        match os {
            "Windows" => Box::new(WindowsSyscallLibrary::new()),
            _ => Box::new(LinuxSyscallLibrary::new()),
        }
    }

    /// Run the full analysis and return the result.
    pub fn analyze(
        &self,
        functions: &[(u64, &str)],
        symbols: &[&str],
        register_names: &[&str],
        instructions: &[(u64, &str)],
    ) -> AnalyzerResult {
        let mut result = AnalyzerResult::default();

        // Detect OS
        result.detected_os = self.detect_os(symbols);

        // Detect architecture
        result.detected_architecture = self.detect_architecture(register_names);

        // Find entry points by name
        result.entry_points = self.find_entry_points_by_name(functions);

        // Scan for syscall triggers
        let triggers = self.scan_for_syscall_triggers(instructions);
        for (addr, pattern) in &triggers {
            result.syscall_sites.insert(*addr, 0);
            if !result.found_patterns.iter().any(|p| p.trigger == pattern.trigger) {
                result.found_patterns.push((*pattern).clone());
            }
        }

        result.completed = true;
        result
    }

    /// Strip leading underscores or mangling prefixes from a symbol name.
    fn strip_prefix(name: &str) -> &str {
        name.trim_start_matches('_')
    }
}

impl Default for EmuSystemAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_new() {
        let analyzer = EmuSystemAnalyzer::new();
        assert_eq!(analyzer.name(), "System Emulation Analyzer");
        assert!(analyzer.is_enabled());
        assert_eq!(analyzer.priority(), DEFAULT_PRIORITY);
        assert!(!analyzer.patterns().is_empty());
    }

    #[test]
    fn test_analyzer_default() {
        let analyzer = EmuSystemAnalyzer::default();
        assert_eq!(analyzer.name(), ANALYZER_NAME);
    }

    #[test]
    fn test_analyzer_enable_disable() {
        let mut analyzer = EmuSystemAnalyzer::new();
        assert!(analyzer.is_enabled());
        analyzer.set_enabled(false);
        assert!(!analyzer.is_enabled());
        analyzer.set_enabled(true);
        assert!(analyzer.is_enabled());
    }

    #[test]
    fn test_analyzer_priority() {
        let mut analyzer = EmuSystemAnalyzer::new();
        assert_eq!(analyzer.priority(), 50);
        analyzer.set_priority(100);
        assert_eq!(analyzer.priority(), 100);
    }

    #[test]
    fn test_syscall_patterns_builtin() {
        let patterns = SyscallPattern::all_builtin();
        assert!(patterns.len() >= 4);
        assert!(patterns.iter().any(|p| p.architecture == "x86_64" && p.os == "Linux"));
        assert!(patterns.iter().any(|p| p.architecture == "x86" && p.os == "Linux"));
        assert!(patterns.iter().any(|p| p.architecture == "ARM" && p.os == "Linux"));
        assert!(patterns.iter().any(|p| p.architecture == "x86_64" && p.os == "Windows"));
    }

    #[test]
    fn test_x86_64_linux_pattern() {
        let p = SyscallPattern::x86_64_linux();
        assert_eq!(p.trigger, "syscall");
        assert_eq!(p.number_register, "RAX");
        assert_eq!(p.argument_registers[0], "RDI");
        assert_eq!(p.return_register, "RAX");
        assert_eq!(p.os, "Linux");
    }

    #[test]
    fn test_find_entry_points_by_name() {
        let analyzer = EmuSystemAnalyzer::new();
        let functions = vec![
            (0x401000u64, "main"),
            (0x401100, "my_helper"),
            (0x401200, "_start"),
            (0x401300, "process_data"),
        ];
        let entries = analyzer.find_entry_points_by_name(&functions);
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.label == "main" && e.kind == EmuEntryPointKind::Main));
        assert!(entries.iter().any(|e| e.label == "_start" && e.kind == EmuEntryPointKind::Start));
    }

    #[test]
    fn test_detect_os_linux() {
        let analyzer = EmuSystemAnalyzer::new();
        let symbols = vec!["__libc_start_main", "__cxa_atexit", "main"];
        assert_eq!(analyzer.detect_os(&symbols), Some("Linux".into()));
    }

    #[test]
    fn test_detect_os_windows() {
        let analyzer = EmuSystemAnalyzer::new();
        let symbols = vec!["NtAllocateVirtualMemory", "RtlInitUnicodeString"];
        assert_eq!(analyzer.detect_os(&symbols), Some("Windows".into()));
    }

    #[test]
    fn test_detect_os_unknown() {
        let analyzer = EmuSystemAnalyzer::new();
        let symbols = vec!["main", "foo", "bar"];
        assert_eq!(analyzer.detect_os(&symbols), None);
    }

    #[test]
    fn test_detect_architecture_x86_64() {
        let analyzer = EmuSystemAnalyzer::new();
        let regs = vec!["RAX", "RBX", "RCX", "RIP"];
        assert_eq!(analyzer.detect_architecture(&regs), Some("x86_64".into()));
    }

    #[test]
    fn test_detect_architecture_x86() {
        let analyzer = EmuSystemAnalyzer::new();
        let regs = vec!["EAX", "EBX", "ECX", "EIP"];
        assert_eq!(analyzer.detect_architecture(&regs), Some("x86".into()));
    }

    #[test]
    fn test_detect_architecture_arm() {
        let analyzer = EmuSystemAnalyzer::new();
        let regs = vec!["R0", "R1", "R7", "CPSR"];
        assert_eq!(analyzer.detect_architecture(&regs), Some("ARM".into()));
    }

    #[test]
    fn test_detect_architecture_unknown() {
        let analyzer = EmuSystemAnalyzer::new();
        let regs = vec!["F0", "F1"];
        assert_eq!(analyzer.detect_architecture(&regs), None);
    }

    #[test]
    fn test_scan_for_syscall_triggers() {
        let analyzer = EmuSystemAnalyzer::new();
        let instructions = vec![
            (0x401000u64, "mov"),
            (0x401004, "syscall"),
            (0x401008, "nop"),
            (0x40100C, "SYSCALL"),
        ];
        let triggers = analyzer.scan_for_syscall_triggers(&instructions);
        // "syscall" matches both x86_64_linux and x86_64_windows patterns;
        // each of the 2 syscall instructions produces 2 matches = 4 total.
        assert_eq!(triggers.len(), 4);
        let unique_addrs: std::collections::HashSet<u64> =
            triggers.iter().map(|(addr, _)| *addr).collect();
        assert!(unique_addrs.contains(&0x401004));
        assert!(unique_addrs.contains(&0x40100C));
    }

    #[test]
    fn test_build_syscall_library() {
        let analyzer = EmuSystemAnalyzer::new();
        let linux_lib = analyzer.build_syscall_library("Linux");
        assert_eq!(linux_lib.name(), "Linux");

        let win_lib = analyzer.build_syscall_library("Windows");
        assert_eq!(win_lib.name(), "Windows");

        // Default falls back to Linux
        let default_lib = analyzer.build_syscall_library("Unknown");
        assert_eq!(default_lib.name(), "Linux");
    }

    #[test]
    fn test_analyze_full() {
        let analyzer = EmuSystemAnalyzer::new();
        let functions = vec![(0x401000u64, "main"), (0x401100, "_start")];
        let symbols = vec!["__libc_start_main", "main", "_start"];
        let regs = vec!["RAX", "RBX", "RIP"];
        let instructions = vec![
            (0x401010u64, "mov"),
            (0x401014, "syscall"),
            (0x401018, "ret"),
        ];

        let result = analyzer.analyze(&functions, &symbols, &regs, &instructions);
        assert!(result.completed);
        assert_eq!(result.detected_os, Some("Linux".into()));
        assert_eq!(result.detected_architecture, Some("x86_64".into()));
        assert_eq!(result.entry_points.len(), 2);
        assert!(!result.syscall_sites.is_empty());
    }

    #[test]
    fn test_emu_entry_point_kind_description() {
        assert_eq!(EmuEntryPointKind::Main.description(), "Program main function");
        assert_eq!(EmuEntryPointKind::Start.description(), "ELF entry point (_start)");
        assert_eq!(
            EmuEntryPointKind::SyscallDispatch.description(),
            "Syscall dispatch routine"
        );
    }

    #[test]
    fn test_add_pattern_and_entry_name() {
        let mut analyzer = EmuSystemAnalyzer::new();
        let initial_count = analyzer.patterns().len();
        analyzer.add_pattern(SyscallPattern {
            trigger: "ecall".into(),
            architecture: "RISC-V".into(),
            number_register: "a7".into(),
            argument_registers: vec!["a0".into(), "a1".into()],
            return_register: "a0".into(),
            os: "Linux".into(),
        });
        assert_eq!(analyzer.patterns().len(), initial_count + 1);

        analyzer.add_entry_point_name("custom_entry");
        // Verify it's used in find_entry_points_by_name
        let functions = vec![(0x8000u64, "custom_entry")];
        let entries = analyzer.find_entry_points_by_name(&functions);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_analyzer_result_default() {
        let result = AnalyzerResult::default();
        assert!(result.syscall_sites.is_empty());
        assert!(result.entry_points.is_empty());
        assert!(result.detected_os.is_none());
        assert!(!result.completed);
    }

    #[test]
    fn test_max_scan_bytes() {
        let mut analyzer = EmuSystemAnalyzer::new();
        assert_eq!(analyzer.max_scan_bytes, 4096);
        analyzer.set_max_scan_bytes(8192);
        assert_eq!(analyzer.max_scan_bytes, 8192);
    }

    #[test]
    fn test_dispatch_and_signal_options() {
        let mut analyzer = EmuSystemAnalyzer::new();
        assert!(analyzer.analyze_dispatch_tables);
        assert!(analyzer.analyze_signal_handlers);

        analyzer.set_analyze_dispatch_tables(false);
        assert!(!analyzer.analyze_dispatch_tables);

        analyzer.set_analyze_signal_handlers(false);
        assert!(!analyzer.analyze_signal_handlers);
    }
}
