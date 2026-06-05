//! Additional emulation service utilities.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.emulation` package.
//!
//! Provides:
//! - `EmulationMode` - the emulation execution mode
//! - `ProgramEmulationUtils` - utilities for program-based emulation
//! - `EmulatorOutOfMemoryException` - out-of-memory error for emulators
//! - `DebuggerEmulationIntegration` - integration between debugger and emulation

use serde::{Deserialize, Serialize};

/// The execution mode for emulation.
///
/// Ported from Ghidra's `Mode` enum in the emulation service package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmulationMode {
    /// Emulate a single instruction.
    SingleInstruction,
    /// Emulate a single step (which may include multiple instructions
    /// for repeated/loop instructions).
    SingleStep,
    /// Run emulation until a breakpoint or other stop condition.
    RunUntilBreak,
    /// Run emulation until a specified address is reached.
    RunUntilAddress,
    /// Emulate for a fixed number of steps.
    FixedSteps,
}

impl Default for EmulationMode {
    fn default() -> Self {
        Self::SingleStep
    }
}

impl std::fmt::Display for EmulationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SingleInstruction => write!(f, "Single Instruction"),
            Self::SingleStep => write!(f, "Single Step"),
            Self::RunUntilBreak => write!(f, "Run Until Break"),
            Self::RunUntilAddress => write!(f, "Run Until Address"),
            Self::FixedSteps => write!(f, "Fixed Steps"),
        }
    }
}

/// Exception thrown when an emulator runs out of memory.
///
/// Ported from Ghidra's `EmulatorOutOfMemoryException`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulatorOutOfMemoryException {
    /// Description of the memory requirement.
    pub message: String,
    /// The amount of memory requested, if known.
    pub requested_bytes: Option<u64>,
    /// The amount of memory available, if known.
    pub available_bytes: Option<u64>,
}

impl EmulatorOutOfMemoryException {
    /// Create a new out-of-memory exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            requested_bytes: None,
            available_bytes: None,
        }
    }

    /// Set the requested and available memory amounts.
    pub fn with_memory_info(mut self, requested: u64, available: u64) -> Self {
        self.requested_bytes = Some(requested);
        self.available_bytes = Some(available);
        self
    }
}

impl std::fmt::Display for EmulatorOutOfMemoryException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Emulator out of memory: {}", self.message)?;
        if let (Some(req), Some(avail)) = (self.requested_bytes, self.available_bytes) {
            write!(f, " (requested: {}, available: {})", req, avail)?;
        }
        Ok(())
    }
}

impl std::error::Error for EmulatorOutOfMemoryException {}

/// Utilities for program-based emulation.
///
/// Ported from Ghidra's `ProgramEmulationUtils`.
pub struct ProgramEmulationUtils;

impl ProgramEmulationUtils {
    /// Compute the maximum memory region that should be mapped for emulation.
    ///
    /// Given the loaded memory blocks of a program, compute the address range
    /// that should be mapped for emulation.
    pub fn compute_emulation_memory_range(
        blocks: &[(String, u64, u64, bool)], // (name, min, max, is_executable)
    ) -> Option<(u64, u64)> {
        let loaded_blocks: Vec<_> = blocks
            .iter()
            .filter(|(_, _, _, is_exec)| *is_exec)
            .collect();

        if loaded_blocks.is_empty() {
            return None;
        }

        let min = loaded_blocks.iter().map(|(_, min, _, _)| *min).min()?;
        let max = loaded_blocks.iter().map(|(_, _, max, _)| *max).max()?;
        Some((min, max))
    }

    /// Estimate the memory required for emulation.
    ///
    /// Returns the estimated number of bytes needed to emulate the given
    /// memory blocks.
    pub fn estimate_memory_required(
        blocks: &[(String, u64, u64)], // (name, min, max)
    ) -> u64 {
        blocks
            .iter()
            .map(|(_, min, max)| max - min + 1)
            .sum()
    }

    /// Check if a program's memory layout is suitable for emulation.
    ///
    /// Returns Ok(()) if the layout is suitable, or an error message if not.
    pub fn validate_emulation_layout(
        blocks: &[(String, u64, u64, bool)],
    ) -> Result<(), String> {
        if blocks.is_empty() {
            return Err("No memory blocks available for emulation".to_string());
        }

        let exec_blocks: Vec<_> = blocks.iter().filter(|(_, _, _, x)| *x).collect();
        if exec_blocks.is_empty() {
            return Err("No executable memory blocks found".to_string());
        }

        // Check for overlapping blocks
        let mut sorted = exec_blocks.clone();
        sorted.sort_by_key(|(_, min, _, _)| *min);
        for i in 0..sorted.len() - 1 {
            let (_, _, max_a, _) = sorted[i];
            let (_, min_b, _, _) = sorted[i + 1];
            if max_a >= min_b {
                return Err(format!(
                    "Overlapping executable blocks: {} and {}",
                    sorted[i].0, sorted[i + 1].0
                ));
            }
        }

        Ok(())
    }
}

/// Integration between the debugger and emulation subsystem.
///
/// Ported from Ghidra's `DebuggerEmulationIntegration`.
pub struct DebuggerEmulationIntegration;

impl DebuggerEmulationIntegration {
    /// Determine if a given address is within an emulatable region.
    pub fn is_emulatable_address(
        addr: u64,
        blocks: &[(String, u64, u64, bool)], // (name, min, max, is_exec)
    ) -> bool {
        blocks.iter().any(|(_, min, max, exec)| *exec && addr >= *min && addr <= *max)
    }

    /// Get the block containing a given address.
    pub fn find_containing_block<'a>(
        addr: u64,
        blocks: &'a [(String, u64, u64, bool)],
    ) -> Option<&'a (String, u64, u64, bool)> {
        blocks
            .iter()
            .find(|(_, min, max, _)| addr >= *min && addr <= *max)
    }

    /// Compute the next instruction boundary for emulation.
    ///
    /// Given the current address and instruction sizes, return the next
    /// address to execute. In practice, this would involve disassembly;
    /// here we provide a simple estimate based on minimum instruction size.
    pub fn estimate_next_address(
        current: u64,
        min_instruction_size: u64,
        _max_instruction_size: u64,
    ) -> u64 {
        current + min_instruction_size
    }
}

/// Configuration for an emulation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationSessionConfig {
    /// The emulation mode.
    pub mode: EmulationMode,
    /// Maximum number of steps for fixed-step mode.
    pub max_steps: u64,
    /// Target address for run-until-address mode.
    pub target_address: Option<u64>,
    /// Memory limit in bytes.
    pub memory_limit: u64,
    /// Whether to trace register writes.
    pub trace_registers: bool,
    /// Whether to trace memory writes.
    pub trace_memory: bool,
}

impl Default for EmulationSessionConfig {
    fn default() -> Self {
        Self {
            mode: EmulationMode::SingleStep,
            max_steps: 1000,
            target_address: None,
            memory_limit: 1024 * 1024 * 64, // 64 MB
            trace_registers: true,
            trace_memory: true,
        }
    }
}

impl EmulationSessionConfig {
    /// Create a config for single-step emulation.
    pub fn single_step() -> Self {
        Self {
            mode: EmulationMode::SingleStep,
            ..Default::default()
        }
    }

    /// Create a config for running until a breakpoint.
    pub fn run_until_break() -> Self {
        Self {
            mode: EmulationMode::RunUntilBreak,
            ..Default::default()
        }
    }

    /// Create a config for running to a specific address.
    pub fn run_until_address(addr: u64) -> Self {
        Self {
            mode: EmulationMode::RunUntilAddress,
            target_address: Some(addr),
            ..Default::default()
        }
    }

    /// Create a config for running a fixed number of steps.
    pub fn fixed_steps(steps: u64) -> Self {
        Self {
            mode: EmulationMode::FixedSteps,
            max_steps: steps,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulation_mode_display() {
        assert_eq!(EmulationMode::SingleStep.to_string(), "Single Step");
        assert_eq!(EmulationMode::RunUntilBreak.to_string(), "Run Until Break");
    }

    #[test]
    fn test_emulation_mode_default() {
        assert_eq!(EmulationMode::default(), EmulationMode::SingleStep);
    }

    #[test]
    fn test_out_of_memory_exception() {
        let e = EmulatorOutOfMemoryException::new("Stack overflow")
            .with_memory_info(1024 * 1024, 512 * 1024);
        let s = format!("{}", e);
        assert!(s.contains("Stack overflow"));
        assert!(s.contains("requested"));
    }

    #[test]
    fn test_compute_emulation_memory_range() {
        let blocks = vec![
            (".text".into(), 0x401000u64, 0x401fffu64, true),
            (".data".into(), 0x403000u64, 0x403fffu64, false),
            (".init".into(), 0x400000u64, 0x400fffu64, true),
        ];
        let range = ProgramEmulationUtils::compute_emulation_memory_range(&blocks);
        assert_eq!(range, Some((0x400000, 0x401fff)));
    }

    #[test]
    fn test_compute_emulation_memory_range_empty() {
        let blocks: Vec<(String, u64, u64, bool)> = vec![];
        let range = ProgramEmulationUtils::compute_emulation_memory_range(&blocks);
        assert!(range.is_none());
    }

    #[test]
    fn test_estimate_memory_required() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x400fffu64),
            (".data".into(), 0x401000u64, 0x4017ffu64),
        ];
        let req = ProgramEmulationUtils::estimate_memory_required(&blocks);
        assert_eq!(req, 0x1000 + 0x800);
    }

    #[test]
    fn test_validate_emulation_layout_ok() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x400fffu64, true),
            (".data".into(), 0x401000u64, 0x4017ffu64, false),
        ];
        assert!(ProgramEmulationUtils::validate_emulation_layout(&blocks).is_ok());
    }

    #[test]
    fn test_validate_emulation_layout_empty() {
        let blocks: Vec<(String, u64, u64, bool)> = vec![];
        assert!(ProgramEmulationUtils::validate_emulation_layout(&blocks).is_err());
    }

    #[test]
    fn test_validate_emulation_layout_no_exec() {
        let blocks = vec![
            (".data".into(), 0x401000u64, 0x4017ffu64, false),
        ];
        assert!(ProgramEmulationUtils::validate_emulation_layout(&blocks).is_err());
    }

    #[test]
    fn test_validate_emulation_layout_overlap() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x401fffu64, true),
            (".init".into(), 0x401000u64, 0x401fffu64, true),
        ];
        assert!(ProgramEmulationUtils::validate_emulation_layout(&blocks).is_err());
    }

    #[test]
    fn test_is_emulatable_address() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x400fffu64, true),
            (".data".into(), 0x401000u64, 0x4017ffu64, false),
        ];
        assert!(DebuggerEmulationIntegration::is_emulatable_address(0x400500, &blocks));
        assert!(!DebuggerEmulationIntegration::is_emulatable_address(0x401100, &blocks));
        assert!(!DebuggerEmulationIntegration::is_emulatable_address(0x500000, &blocks));
    }

    #[test]
    fn test_find_containing_block() {
        let blocks = vec![
            (".text".into(), 0x400000u64, 0x400fffu64, true),
            (".data".into(), 0x401000u64, 0x4017ffu64, false),
        ];
        let block = DebuggerEmulationIntegration::find_containing_block(0x400500, &blocks);
        assert!(block.is_some());
        assert_eq!(block.unwrap().0, ".text");
        assert!(DebuggerEmulationIntegration::find_containing_block(0x500000, &blocks).is_none());
    }

    #[test]
    fn test_estimate_next_address() {
        assert_eq!(
            DebuggerEmulationIntegration::estimate_next_address(0x401000, 4, 8),
            0x401004
        );
    }

    #[test]
    fn test_emulation_session_config_defaults() {
        let config = EmulationSessionConfig::default();
        assert_eq!(config.mode, EmulationMode::SingleStep);
        assert_eq!(config.max_steps, 1000);
        assert_eq!(config.memory_limit, 64 * 1024 * 1024);
    }

    #[test]
    fn test_emulation_session_config_presets() {
        let config = EmulationSessionConfig::run_until_address(0x401000);
        assert_eq!(config.mode, EmulationMode::RunUntilAddress);
        assert_eq!(config.target_address, Some(0x401000));

        let config = EmulationSessionConfig::fixed_steps(100);
        assert_eq!(config.mode, EmulationMode::FixedSteps);
        assert_eq!(config.max_steps, 100);
    }

    #[test]
    fn test_emulation_session_config_serde() {
        let config = EmulationSessionConfig::run_until_break();
        let json = serde_json::to_string(&config).unwrap();
        let back: EmulationSessionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode, EmulationMode::RunUntilBreak);
    }
}
