//! Scalar operand analyzer -- finds references to valid addresses from scalar operands.
//!
//! Ported from `ghidra.app.plugin.core.analysis.ScalarOperandAnalyzer` in Ghidra's
//! Features/Base.
//!
//! This analyzer examines scalar operand values in instructions and checks
//! whether they correspond to valid addresses in the program, adding operand
//! references where appropriate. It is disabled for ELF binaries (which use
//! `ElfScalarOperandAnalyzer` instead) and for programs where addresses do not
//! appear directly in code (e.g., RISC processors).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ScalarOperandAnalyzer
// ---------------------------------------------------------------------------

/// Analyzes scalar operands for references to valid addresses.
///
/// For each instruction, the analyzer examines all scalar operands and checks
/// whether their unsigned value corresponds to a valid address in the program.
/// If so, an operand reference is created. The analyzer respects relocation
/// table entries to guide pointer analysis.
///
/// This analyzer is **disabled** by default for:
/// - ELF programs (use `ElfScalarOperandAnalyzer` instead)
/// - Programs starting at address 0
/// - RISC processors where addresses do not appear directly in code
/// - Programs with address spaces smaller than 32 bits
/// - Programs with instruction alignment > 1 byte
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalarOperandAnalyzer {
    /// Whether to use relocation table entries to guide pointer analysis.
    pub relocation_guide_enabled: bool,
    /// Alignment for table entry checks.
    pub alignment: u32,
}

impl Default for ScalarOperandAnalyzer {
    fn default() -> Self {
        Self {
            relocation_guide_enabled: true,
            alignment: 4,
        }
    }
}

impl ScalarOperandAnalyzer {
    /// Analyzer name.
    pub const NAME: &'static str = "Scalar Operand References";
    /// Analyzer description.
    pub const DESCRIPTION: &'static str = "Analyzes scalar operands for references to valid addresses.";

    /// Maximum negative entries to search for jump tables.
    pub const MAX_NEG_ENTRIES: u32 = 32;

    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a scalar value should be treated as a potential address.
    ///
    /// Filters out common values that are unlikely to be addresses (masks,
    /// small constants, etc.) unless they match a relocation table entry.
    pub fn is_potential_address(value: u64, has_relocation: bool) -> bool {
        if has_relocation {
            return true;
        }
        // Skip common non-address values
        if value < 4096 || value == 0 {
            return false;
        }
        let skip = [
            0xFFFF_u64,
            0xFF00,
            0xFF_FFFF,
            0xFF_0000,
            0xFF_00FF,
            0xFFFF_FFFF,
            0xFFFF_FF00,
            0xFFFF_0000,
            0xFF00_0000,
        ];
        !skip.contains(&value)
    }

    /// Check if a scalar value matches a relocation table entry.
    pub fn check_relocation(value: u64, bit_length: u32, _reloc_offset: u64, memory_value: u64) -> bool {
        match bit_length {
            8 => (memory_value & 0xFF) == (value & 0xFF),
            16 => (memory_value & 0xFFFF) == (value & 0xFFFF),
            32 => (memory_value & 0xFFFF_FFFF) == (value & 0xFFFF_FFFF),
            64 => memory_value == value,
            _ => false,
        }
    }

    /// Check whether the default enablement applies for a given program.
    ///
    /// Returns `false` for programs that should not use this analyzer
    /// (ELF, small address spaces, RISC, aligned code).
    pub fn is_default_enabled(
        is_elf: bool,
        min_address_offset: u64,
        addresses_do_not_appear_in_code: bool,
        instruction_alignment: u32,
        default_space_size: u32,
    ) -> bool {
        if is_elf {
            return false;
        }
        if addresses_do_not_appear_in_code {
            return false;
        }
        if min_address_offset == 0 {
            return false;
        }
        if instruction_alignment != 1 {
            return false;
        }
        default_space_size >= 32
    }
}

// ---------------------------------------------------------------------------
// ScalarRefResult
// ---------------------------------------------------------------------------

/// Result of analyzing a scalar operand for address references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalarRefResult {
    /// A reference was added.
    ReferenceAdded {
        /// Source instruction address.
        from: u64,
        /// Target address.
        to: u64,
        /// Operand index.
        op_index: u32,
    },
    /// An offset reference was added (for jump table entries).
    OffsetReferenceAdded {
        /// Source instruction address.
        from: u64,
        /// Table top address.
        table_addr: u64,
        /// Offset from table base.
        offset: i64,
        /// Operand index.
        op_index: u32,
    },
    /// A jump table was detected.
    JumpTableDetected {
        /// Table entry address.
        table_addr: u64,
        /// Entry length (2, 4, or 8).
        entry_length: u32,
    },
    /// No reference was created.
    Skipped {
        /// Reason for skipping.
        reason: SkipReason,
    },
}

/// Reason a scalar operand was skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// The scalar value is too small to be an address.
    ValueTooSmall,
    /// The scalar value is a well-known constant (mask, flag, etc.).
    WellKnownValue,
    /// The instruction already has operand references at this index.
    AlreadyHasReference,
    /// The target is not in memory and has no symbol.
    NotInMemory,
    /// The target falls inside a defined function (offcut reference).
    OffcutFunctionReference,
    /// The address space is an overlay space.
    OverlaySpace,
    /// The address is out of bounds for the space.
    AddressOutOfBounds,
    /// The program is relocatable and address is not in relocation table.
    NotRelocated,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_defaults() {
        let analyzer = ScalarOperandAnalyzer::new();
        assert!(analyzer.relocation_guide_enabled);
        assert_eq!(analyzer.alignment, 4);
    }

    #[test]
    fn test_is_potential_address() {
        // Has relocation - always potential
        assert!(ScalarOperandAnalyzer::is_potential_address(0, true));
        assert!(ScalarOperandAnalyzer::is_potential_address(100, true));

        // No relocation - filter small values
        assert!(!ScalarOperandAnalyzer::is_potential_address(0, false));
        assert!(!ScalarOperandAnalyzer::is_potential_address(100, false));
        assert!(!ScalarOperandAnalyzer::is_potential_address(0xFF, false));
        assert!(!ScalarOperandAnalyzer::is_potential_address(0xFFFF, false));

        // Valid address
        assert!(ScalarOperandAnalyzer::is_potential_address(0x400000, false));
        assert!(ScalarOperandAnalyzer::is_potential_address(0x1000, false));
    }

    #[test]
    fn test_check_relocation() {
        // 8-bit match
        assert!(ScalarOperandAnalyzer::check_relocation(0xFF, 8, 0, 0xFF));
        assert!(!ScalarOperandAnalyzer::check_relocation(0xFE, 8, 0, 0xFF));

        // 32-bit match
        assert!(ScalarOperandAnalyzer::check_relocation(
            0xDEADBEEF,
            32,
            0,
            0xDEADBEEF
        ));
        assert!(ScalarOperandAnalyzer::check_relocation(
            0xDEADBEEF,
            32,
            0,
            0x1234DEADBEEF
        )); // upper bits masked

        // 64-bit exact
        assert!(ScalarOperandAnalyzer::check_relocation(
            0x1234DEADBEEF,
            64,
            0,
            0x1234DEADBEEF
        ));
        assert!(!ScalarOperandAnalyzer::check_relocation(
            0x1234DEADBEEF,
            64,
            0,
            0x1234DEADBEEE
        ));
    }

    #[test]
    fn test_is_default_enabled() {
        // ELF -> disabled
        assert!(!ScalarOperandAnalyzer::is_default_enabled(
            true, 0x1000, false, 1, 32
        ));

        // Address 0 -> disabled
        assert!(!ScalarOperandAnalyzer::is_default_enabled(
            false, 0, false, 1, 32
        ));

        // RISC -> disabled
        assert!(!ScalarOperandAnalyzer::is_default_enabled(
            false, 0x1000, true, 1, 32
        ));

        // Aligned -> disabled
        assert!(!ScalarOperandAnalyzer::is_default_enabled(
            false, 0x1000, false, 4, 32
        ));

        // 16-bit space -> disabled
        assert!(!ScalarOperandAnalyzer::is_default_enabled(
            false, 0x1000, false, 1, 16
        ));

        // All good -> enabled
        assert!(ScalarOperandAnalyzer::is_default_enabled(
            false, 0x1000, false, 1, 32
        ));
    }
}
