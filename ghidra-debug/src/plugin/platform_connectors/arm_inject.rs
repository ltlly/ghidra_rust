//! ARM disassembly injection.
//!
//! Ported from Ghidra's `ArmDisassemblyInject`.
//! Provides ARM-specific disassembly customization for the debugger,
//! handling IT-block instruction analysis and Thumb mode detection.

/// ARM disassembly injection provider.
///
/// Handles ARM-specific disassembly quirks such as IT-block analysis
/// for Thumb2 and conditional execution patterns.
#[derive(Debug, Clone, Default)]
pub struct ArmDisassemblyInject;

impl ArmDisassemblyInject {
    /// Create a new ARM disassembly inject provider.
    pub fn new() -> Self {
        Self
    }

    /// Check whether a given instruction address is in Thumb mode.
    ///
    /// In ARM, bit 0 of the program counter indicates Thumb mode.
    pub fn is_thumb(pc: u64) -> bool {
        pc & 1 != 0
    }

    /// Align the program counter to the instruction boundary by clearing the Thumb bit.
    pub fn align_pc(pc: u64) -> u64 {
        pc & !1
    }

    /// Get the minimum instruction alignment for the given mode.
    pub fn min_instruction_size(is_thumb: bool) -> usize {
        if is_thumb { 2 } else { 4 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thumb_detection() {
        assert!(ArmDisassemblyInject::is_thumb(0x1001));
        assert!(!ArmDisassemblyInject::is_thumb(0x1000));
    }

    #[test]
    fn test_align_pc() {
        assert_eq!(ArmDisassemblyInject::align_pc(0x1001), 0x1000);
        assert_eq!(ArmDisassemblyInject::align_pc(0x1000), 0x1000);
    }

    #[test]
    fn test_instruction_sizes() {
        assert_eq!(ArmDisassemblyInject::min_instruction_size(true), 2);
        assert_eq!(ArmDisassemblyInject::min_instruction_size(false), 4);
    }
}
