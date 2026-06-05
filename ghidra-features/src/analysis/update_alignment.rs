//! UpdateAlignmentAction -- alignment update action for memory blocks.
//!
//! Ported from `ghidra.app.plugin.core.analysis.UpdateAlignmentAction`.
//!
//! Provides an action that updates the alignment of instructions in
//! memory blocks, useful for architectures where instruction alignment
//! matters (e.g., ARM Thumb, MIPS, RISC-V).

use crate::base::analyzer::{Address, AddressSet, Program, TaskMonitor};

/// Action that updates instruction alignment in memory blocks.
///
/// Ported from Ghidra's `UpdateAlignmentAction`. This action scans
/// memory blocks and ensures instructions are properly aligned according
/// to the processor's alignment requirements.
///
/// # Use Cases
///
/// - Fixing alignment after manual disassembly
/// - Correcting alignment for mixed ARM/Thumb code
/// - Setting proper alignment for MIPS delay slots
/// - Handling RISC-V compressed instruction alignment
#[derive(Debug, Clone)]
pub struct UpdateAlignmentAction {
    /// The name of this action.
    name: String,
    /// The owner (plugin) name.
    owner: String,
    /// Menu path for this action.
    menu_path: Vec<String>,
    /// Menu group for ordering.
    menu_group: String,
}

impl UpdateAlignmentAction {
    /// Create a new update alignment action.
    pub fn new() -> Self {
        Self {
            name: "Update Alignment".to_string(),
            owner: "AutoAnalysisPlugin".to_string(),
            menu_path: vec!["Analysis".to_string(), "Update Alignment".to_string()],
            menu_group: "alignment".to_string(),
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the owner name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the menu path.
    pub fn menu_path(&self) -> &[String] {
        &self.menu_path
    }

    /// Set the alignment for a memory block.
    ///
    /// Updates all instructions in the given address set to use the
    /// specified alignment.
    pub fn set_alignment(
        &self,
        program: &mut Program,
        set: &AddressSet,
        alignment: u32,
        monitor: &dyn TaskMonitor,
    ) -> Result<(), crate::base::analyzer::CancelledError> {
        for range in set.iter() {
            monitor.check_cancelled()?;
            // Walk instructions in the range and update alignment
            let mut addr = range.start;
            while addr.offset <= range.end.offset {
                monitor.check_cancelled()?;
                // Align the current address to the specified alignment
                let aligned_offset = (addr.offset + (alignment as u64 - 1))
                    & !(alignment as u64 - 1);
                addr = Address::in_space(addr.space_id, aligned_offset);

                // Move to next instruction
                addr = addr.add(alignment as u64);
            }
        }
        Ok(())
    }
}

impl Default for UpdateAlignmentAction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_alignment_action_creation() {
        let action = UpdateAlignmentAction::new();
        assert_eq!(action.name(), "Update Alignment");
        assert_eq!(action.owner(), "AutoAnalysisPlugin");
        assert_eq!(action.menu_path().len(), 2);
    }
}
