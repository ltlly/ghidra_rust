//! Data conflict resolution -- ported from conflict handling in
//! `ghidra.app.plugin.core.data.DataPlugin`.
//!
//! Provides [`DataConflictResolver`] for handling conflicts when
//! creating data at addresses that already contain defined data or
//! instructions.

use ghidra_core::Address;

/// The result of a conflict check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// No conflict -- proceed with data creation.
    Proceed,
    /// Conflict exists and user chose to clear the conflicting data.
    ClearAndProceed,
    /// Conflict exists and user chose to cancel.
    Cancel,
    /// Conflict exists but cannot be resolved (e.g., instruction in the way).
    CannotResolve,
}

/// Information about a conflict at an address.
#[derive(Debug, Clone)]
pub struct ConflictInfo {
    /// The address where the conflict occurs.
    pub address: Address,
    /// The type of conflict.
    pub conflict_type: ConflictType,
    /// The name of the existing item (data type or instruction mnemonic).
    pub existing_name: String,
    /// Start address of the existing item.
    pub existing_start: Address,
    /// End address of the existing item.
    pub existing_end: Address,
}

/// The type of conflict that occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictType {
    /// An existing data item overlaps.
    Data,
    /// An existing instruction overlaps.
    Instruction,
    /// The address is in an uninitialized memory block.
    UninitializedMemory,
    /// The address is in a read-only memory block.
    ReadOnlyMemory,
}

/// Resolves data creation conflicts.
///
/// Ported from `DataPlugin.dataExists()`, `DataPlugin.instructionExists()`,
/// and related conflict handling methods.
#[derive(Debug, Default)]
pub struct DataConflictResolver {
    /// Whether to auto-clear conflicts (skip confirmation).
    pub auto_clear_conflicts: bool,
}

impl DataConflictResolver {
    /// Create a new conflict resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether a data conflict exists in the given range.
    ///
    /// Returns a `ConflictInfo` if existing data is found between `start` and `end`.
    pub fn check_data_conflict(
        &self,
        existing_start: Option<Address>,
        existing_end: Option<Address>,
        new_start: Address,
        new_end: Address,
        data_type_name: &str,
    ) -> Option<ConflictInfo> {
        let e_start = existing_start?;
        let e_end = existing_end?;

        // No conflict if existing data ends before new data starts
        if e_end < new_start {
            return None;
        }

        Some(ConflictInfo {
            address: e_start,
            conflict_type: ConflictType::Data,
            existing_name: data_type_name.to_string(),
            existing_start: e_start,
            existing_end: e_end,
        })
    }

    /// Check whether an instruction exists in the given range.
    pub fn check_instruction_conflict(
        &self,
        instruction_address: Option<Address>,
        instruction_end: Option<Address>,
        new_start: Address,
        new_end: Address,
        instruction_name: &str,
    ) -> Option<ConflictInfo> {
        let i_addr = instruction_address?;
        let i_end = instruction_end?;

        if i_end < new_start {
            return None;
        }

        Some(ConflictInfo {
            address: i_addr,
            conflict_type: ConflictType::Instruction,
            existing_name: instruction_name.to_string(),
            existing_start: i_addr,
            existing_end: i_end,
        })
    }

    /// Resolve a data conflict.
    ///
    /// If `auto_clear_conflicts` is `true`, returns `ClearAndProceed`.
    /// Otherwise returns `Cancel` (in a real UI, this would show a dialog).
    pub fn resolve_data_conflict(&self, _info: &ConflictInfo) -> ConflictResolution {
        if self.auto_clear_conflicts {
            ConflictResolution::ClearAndProceed
        } else {
            // In a real UI, this would show a Yes/No/Cancel dialog.
            // For headless mode, default to cancel.
            ConflictResolution::Cancel
        }
    }

    /// Resolve an instruction conflict.
    ///
    /// Instruction conflicts cannot be automatically cleared -- the user
    /// must manually clear the instruction first.
    pub fn resolve_instruction_conflict(&self, _info: &ConflictInfo) -> ConflictResolution {
        ConflictResolution::CannotResolve
    }

    /// Compute the size of a data type at an address.
    ///
    /// For fixed-size types, returns the known length.
    /// For dynamic types, returns `None` (caller must resolve).
    pub fn compute_data_type_size(data_type_name: &str) -> Option<usize> {
        match data_type_name {
            "byte" | "undefined1" => Some(1),
            "word" | "short" | "ushort" | "undefined2" => Some(2),
            "dword" | "int" | "uint" | "float" | "undefined4" => Some(4),
            "qword" | "long" | "ulong" | "double" | "undefined8" => Some(8),
            "pointer" | "pointer4" => Some(4),
            "pointer8" => Some(8),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_data_conflict() {
        let resolver = DataConflictResolver::new();
        // Existing data at 0x1000..0x1003, new data at 0x3000..0x3003
        // These don't overlap -> no conflict
        let result = resolver.check_data_conflict(
            Some(Address::new(0x1000)),
            Some(Address::new(0x1003)),
            Address::new(0x3000),
            Address::new(0x3003),
            "dword",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_data_conflict_detected() {
        let resolver = DataConflictResolver::new();
        let result = resolver.check_data_conflict(
            Some(Address::new(0x1000)),
            Some(Address::new(0x1007)),
            Address::new(0x1004),
            Address::new(0x100B),
            "qword",
        );
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.conflict_type, ConflictType::Data);
    }

    #[test]
    fn test_instruction_conflict() {
        let resolver = DataConflictResolver::new();
        let result = resolver.check_instruction_conflict(
            Some(Address::new(0x1000)),
            Some(Address::new(0x1003)),
            Address::new(0x1000),
            Address::new(0x1007),
            "mov",
        );
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.conflict_type, ConflictType::Instruction);
    }

    #[test]
    fn test_resolve_data_conflict_auto_clear() {
        let mut resolver = DataConflictResolver::new();
        resolver.auto_clear_conflicts = true;
        let info = ConflictInfo {
            address: Address::new(0x1000),
            conflict_type: ConflictType::Data,
            existing_name: "dword".into(),
            existing_start: Address::new(0x1000),
            existing_end: Address::new(0x1003),
        };
        assert_eq!(
            resolver.resolve_data_conflict(&info),
            ConflictResolution::ClearAndProceed
        );
    }

    #[test]
    fn test_resolve_data_conflict_default_cancel() {
        let resolver = DataConflictResolver::new();
        let info = ConflictInfo {
            address: Address::new(0x1000),
            conflict_type: ConflictType::Data,
            existing_name: "dword".into(),
            existing_start: Address::new(0x1000),
            existing_end: Address::new(0x1003),
        };
        assert_eq!(
            resolver.resolve_data_conflict(&info),
            ConflictResolution::Cancel
        );
    }

    #[test]
    fn test_resolve_instruction_conflict_cannot_resolve() {
        let resolver = DataConflictResolver::new();
        let info = ConflictInfo {
            address: Address::new(0x1000),
            conflict_type: ConflictType::Instruction,
            existing_name: "mov".into(),
            existing_start: Address::new(0x1000),
            existing_end: Address::new(0x1003),
        };
        assert_eq!(
            resolver.resolve_instruction_conflict(&info),
            ConflictResolution::CannotResolve
        );
    }

    #[test]
    fn test_compute_data_type_size() {
        assert_eq!(
            DataConflictResolver::compute_data_type_size("byte"),
            Some(1)
        );
        assert_eq!(
            DataConflictResolver::compute_data_type_size("dword"),
            Some(4)
        );
        assert_eq!(
            DataConflictResolver::compute_data_type_size("qword"),
            Some(8)
        );
        assert_eq!(
            DataConflictResolver::compute_data_type_size("float"),
            Some(4)
        );
        assert_eq!(
            DataConflictResolver::compute_data_type_size("double"),
            Some(8)
        );
        assert_eq!(
            DataConflictResolver::compute_data_type_size("string"),
            None
        );
    }
}
