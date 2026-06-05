//! Unwind information for a single stack frame.
//!
//! Ported from Ghidra's `UnwindInfo` record. Contains the information
//! needed to interpret the current frame and unwind to the next one:
//! stack depth, stack adjustment, saved registers, and return address location.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::unwind_warning::UnwindWarningSet;

/// Where the return address can be found, relative to the frame base.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReturnLocation {
    /// Return address is on the stack at (base + offset).
    Stack {
        /// Offset from the frame base.
        offset: i64,
        /// Size in bytes.
        size: u32,
    },
    /// Return address is in a register.
    Register {
        /// Register name.
        name: String,
        /// Bit mask to apply to the return address (often u64::MAX).
        mask: u64,
    },
    /// Return address location could not be determined.
    Unknown,
}

/// Information about a single frame needed to unwind to the next.
///
/// Produced by symbolic analysis of a function's instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnwindInfo {
    /// The name of the function that allocated this frame.
    pub function_name: Option<String>,

    /// The stack depth: change in SP from function entry to the current PC.
    ///
    /// `base = current_SP - depth`. Stack variable offsets are relative
    /// to this base.
    pub depth: Option<i64>,

    /// The stack adjustment: total change in SP from function entry to
    /// the return instruction.
    ///
    /// `next_SP = base + adjust`.
    pub adjust: Option<i64>,

    /// The location of the return address (relative to frame base).
    pub return_location: ReturnLocation,

    /// Mask applied to the return address value (for ISA-mode bits, etc.).
    pub return_mask: u64,

    /// Saved registers: map from register name to (stack offset from base).
    ///
    /// These are registers that the function saves to the stack.
    pub saved_registers: HashMap<String, i64>,

    /// Warnings generated during analysis.
    pub warnings: UnwindWarningSet,

    /// Error that occurred during analysis, if any.
    pub error: Option<String>,
}

impl UnwindInfo {
    /// Create an error-only unwind info.
    pub fn error_only(error: impl Into<String>) -> Self {
        Self {
            function_name: None,
            depth: None,
            adjust: None,
            return_location: ReturnLocation::Unknown,
            return_mask: u64::MAX,
            saved_registers: HashMap::new(),
            warnings: UnwindWarningSet::new(),
            error: Some(error.into()),
        }
    }

    /// Create a complete unwind info.
    pub fn new(
        function_name: Option<String>,
        depth: Option<i64>,
        adjust: Option<i64>,
        return_location: ReturnLocation,
        return_mask: u64,
        saved_registers: HashMap<String, i64>,
        warnings: UnwindWarningSet,
    ) -> Self {
        Self {
            function_name,
            depth,
            adjust,
            return_location,
            return_mask,
            saved_registers,
            warnings,
            error: None,
        }
    }

    /// Whether this info has an error.
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Whether the return address location is known.
    pub fn return_location_known(&self) -> bool {
        !matches!(self.return_location, ReturnLocation::Unknown)
    }

    /// Compute the frame base address from the current stack pointer.
    ///
    /// `base = sp - depth`
    pub fn compute_base(&self, sp: i64) -> Option<i64> {
        self.depth.map(|d| sp.wrapping_sub(d))
    }

    /// Compute the return address offset from the frame base.
    ///
    /// Returns `None` if the return address is not on the stack.
    pub fn return_offset_from_base(&self) -> Option<i64> {
        match &self.return_location {
            ReturnLocation::Stack { offset, .. } => Some(*offset),
            _ => None,
        }
    }

    /// Compute the next stack pointer (for the caller's frame).
    ///
    /// `next_sp = base + adjust`
    pub fn compute_next_sp(&self, base: i64) -> Option<i64> {
        self.adjust.map(|a| base.wrapping_add(a))
    }

    /// Compute the next program counter (return address) from state data.
    ///
    /// This resolves the return address based on where it is stored.
    pub fn compute_return_address(
        &self,
        base: i64,
        stack_values: &dyn Fn(i64, u32) -> Option<u64>,
        register_values: &dyn Fn(&str) -> Option<u64>,
    ) -> Option<u64> {
        match &self.return_location {
            ReturnLocation::Stack { offset, size } => {
                let addr = base.wrapping_add(*offset);
                let value = stack_values(addr, *size)?;
                Some(value & self.return_mask)
            }
            ReturnLocation::Register { name, mask } => {
                let value = register_values(name)?;
                Some(value & (*mask & self.return_mask))
            }
            ReturnLocation::Unknown => None,
        }
    }

    /// Get the total number of saved registers.
    pub fn saved_register_count(&self) -> usize {
        self.saved_registers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_only() {
        let info = UnwindInfo::error_only("test error");
        assert!(info.has_error());
        assert_eq!(info.depth, None);
        assert_eq!(info.adjust, None);
    }

    #[test]
    fn test_compute_base() {
        let info = UnwindInfo::new(
            Some("main".into()),
            Some(32),
            Some(40),
            ReturnLocation::Stack { offset: 0, size: 8 },
            u64::MAX,
            HashMap::new(),
            UnwindWarningSet::new(),
        );
        let sp: i64 = 0x7fff0000;
        let depth: i64 = 32;
        assert_eq!(info.compute_base(sp), Some(sp.wrapping_sub(depth)));
    }

    #[test]
    fn test_compute_next_sp() {
        let info = UnwindInfo::new(
            Some("main".into()),
            Some(32),
            Some(40),
            ReturnLocation::Stack { offset: 0, size: 8 },
            u64::MAX,
            HashMap::new(),
            UnwindWarningSet::new(),
        );
        let base: i64 = 0x7fff0000;
        let adjust: i64 = 40;
        assert_eq!(info.compute_next_sp(base), Some(base.wrapping_add(adjust)));
    }

    #[test]
    fn test_return_address_from_stack() {
        let mut saved = HashMap::new();
        saved.insert("R30".to_string(), -8i64);
        let info = UnwindInfo::new(
            Some("foo".into()),
            Some(64),
            Some(72),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX,
            saved,
            UnwindWarningSet::new(),
        );

        let base = 0x7fff0000i64;
        let stack_values = |addr: i64, _size: u32| -> Option<u64> {
            if addr == base - 8 {
                Some(0x400100)
            } else {
                None
            }
        };
        let register_values = |_name: &str| -> Option<u64> { None };

        let ra = info.compute_return_address(base, &stack_values, &register_values);
        assert_eq!(ra, Some(0x400100));
    }

    #[test]
    fn test_return_address_from_register() {
        let info = UnwindInfo::new(
            Some("bar".into()),
            Some(16),
            Some(24),
            ReturnLocation::Register {
                name: "R30".into(),
                mask: u64::MAX,
            },
            u64::MAX,
            HashMap::new(),
            UnwindWarningSet::new(),
        );

        let stack_values = |_addr: i64, _size: u32| -> Option<u64> { None };
        let register_values = |name: &str| -> Option<u64> {
            if name == "R30" {
                Some(0x400200)
            } else {
                None
            }
        };

        let ra = info.compute_return_address(0, &stack_values, &register_values);
        assert_eq!(ra, Some(0x400200));
    }

    #[test]
    fn test_return_mask() {
        let info = UnwindInfo::new(
            Some("thumb_func".into()),
            Some(32),
            Some(40),
            ReturnLocation::Register {
                name: "LR".into(),
                mask: u64::MAX,
            },
            0xFFFF_FFFF_FFFF_FFFE, // Clear low bit for Thumb mode
            HashMap::new(),
            UnwindWarningSet::new(),
        );

        let stack_values = |_addr: i64, _size: u32| -> Option<u64> { None };
        let register_values = |name: &str| -> Option<u64> {
            if name == "LR" {
                Some(0x400101) // Thumb mode address
            } else {
                None
            }
        };

        let ra = info.compute_return_address(0, &stack_values, &register_values);
        assert_eq!(ra, Some(0x400100)); // Masked to even address
    }

    #[test]
    fn test_saved_registers() {
        let mut saved = HashMap::new();
        saved.insert("R30".to_string(), -8i64);
        saved.insert("R29".to_string(), -16i64);
        saved.insert("R19".to_string(), -24i64);

        let info = UnwindInfo::new(
            Some("func".into()),
            Some(64),
            Some(72),
            ReturnLocation::Stack { offset: -8, size: 8 },
            u64::MAX,
            saved,
            UnwindWarningSet::new(),
        );

        assert_eq!(info.saved_register_count(), 3);
    }

    #[test]
    fn test_return_location_known() {
        let info_stack = UnwindInfo {
            return_location: ReturnLocation::Stack { offset: 0, size: 8 },
            ..UnwindInfo::error_only("")
        };
        assert!(info_stack.return_location_known());

        let info_unknown = UnwindInfo {
            return_location: ReturnLocation::Unknown,
            ..UnwindInfo::error_only("")
        };
        assert!(!info_unknown.return_location_known());
    }

    #[test]
    fn test_serde() {
        let info = UnwindInfo::new(
            Some("main".into()),
            Some(32),
            Some(40),
            ReturnLocation::Stack { offset: 0, size: 8 },
            u64::MAX,
            HashMap::new(),
            UnwindWarningSet::new(),
        );
        let json = serde_json::to_string(&info).unwrap();
        let back: UnwindInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.function_name, Some("main".into()));
        assert_eq!(back.depth, Some(32));
    }
}
