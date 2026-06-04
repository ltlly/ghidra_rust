//! Clear Plugin -- clear code/data at addresses.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.clear` Java package.
//!
//! Provides logic for clearing (removing) code units, data, and analysis
//! results from a program's listing.

use ghidra_core::Address;

/// The type of clear operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearType {
    /// Clear code and data bytes.
    All,
    /// Clear only code (instructions).
    Code,
    /// Clear only data items.
    Data,
    /// Clear only comments.
    Comments,
    /// Clear only labels.
    Labels,
    /// Clear only equates.
    Equates,
    /// Clear only bookmarks.
    Bookmarks,
    /// Clear only properties.
    Properties,
}

/// A clear operation to perform.
#[derive(Debug, Clone)]
pub struct ClearOperation {
    /// The start address.
    pub start: Address,
    /// The end address.
    pub end: Address,
    /// What to clear.
    pub clear_type: ClearType,
    /// Whether to clear the bytes themselves.
    pub clear_bytes: bool,
}

impl ClearOperation {
    /// Create a new clear operation.
    pub fn new(start: Address, end: Address, clear_type: ClearType) -> Self {
        Self {
            start,
            end,
            clear_type,
            clear_bytes: false,
        }
    }

    /// Create a clear operation that also zeroes bytes.
    pub fn with_clear_bytes(mut self, clear_bytes: bool) -> Self {
        self.clear_bytes = clear_bytes;
        self
    }

    /// The number of addresses in the clear range.
    pub fn address_count(&self) -> u64 {
        self.end.offset.saturating_sub(self.start.offset) + 1
    }
}

/// Model for managing clear operations.
#[derive(Debug, Default)]
pub struct ClearModel {
    /// The pending clear operations.
    operations: Vec<ClearOperation>,
}

impl ClearModel {
    /// Create a new clear model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a clear operation.
    pub fn add_operation(&mut self, op: ClearOperation) {
        self.operations.push(op);
    }

    /// Get all pending operations.
    pub fn get_operations(&self) -> &[ClearOperation] {
        &self.operations
    }

    /// Clear all pending operations.
    pub fn clear(&mut self) {
        self.operations.clear();
    }

    /// Get the number of pending operations.
    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clear_operation() {
        let op = ClearOperation::new(Address::new(0x1000), Address::new(0x1FFF), ClearType::All);
        assert_eq!(op.address_count(), 0x1000);
    }

    #[test]
    fn test_clear_operation_with_bytes() {
        let op = ClearOperation::new(Address::new(0x1000), Address::new(0x100F), ClearType::Code)
            .with_clear_bytes(true);
        assert!(op.clear_bytes);
    }

    #[test]
    fn test_clear_model() {
        let mut model = ClearModel::new();
        model.add_operation(ClearOperation::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            ClearType::All,
        ));
        assert_eq!(model.operation_count(), 1);
        model.clear();
        assert_eq!(model.operation_count(), 0);
    }
}
