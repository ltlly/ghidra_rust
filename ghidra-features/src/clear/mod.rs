//! Clear Plugin -- clear code/data at addresses.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.clear` Java package.
//!
//! Provides logic for clearing (removing) code units, data, and analysis
//! results from a program's listing. Includes fine-grained clear options
//! matching Ghidra's `ClearOptions.ClearType` and a command model for
//! applying clear operations with flow-repair support.
//!
//! # Key Types
//!
//! - [`ClearType`] -- fine-grained types matching `ClearOptions.ClearType`
//! - [`ClearOptions`] -- a set of clear type toggles (port of `ClearOptions.java`)
//! - [`ClearOperation`] -- a clear operation over an address range
//! - [`ClearModel`] -- model for managing clear operations

use ghidra_core::Address;
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// ClearType -- fine-grained clear type (matches ClearOptions.ClearType)
// ---------------------------------------------------------------------------

/// Fine-grained clear type matching `ghidra.app.plugin.core.clear.ClearOptions.ClearType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClearType {
    /// Clear instructions.
    Instructions,
    /// Clear data items.
    Data,
    /// Clear symbols / labels.
    Symbols,
    /// Clear comments (all types).
    Comments,
    /// Clear properties.
    Properties,
    /// Clear functions.
    Functions,
    /// Clear register values.
    Registers,
    /// Clear equates.
    Equates,
    /// Clear user-defined references.
    UserReferences,
    /// Clear analysis-discovered references.
    AnalysisReferences,
    /// Clear imported references.
    ImportReferences,
    /// Clear default references.
    DefaultReferences,
    /// Clear bookmarks.
    Bookmarks,
}

impl ClearType {
    /// All clear types.
    pub fn all() -> &'static [ClearType] {
        &[
            Self::Instructions,
            Self::Data,
            Self::Symbols,
            Self::Comments,
            Self::Properties,
            Self::Functions,
            Self::Registers,
            Self::Equates,
            Self::UserReferences,
            Self::AnalysisReferences,
            Self::ImportReferences,
            Self::DefaultReferences,
            Self::Bookmarks,
        ]
    }
}

// ---------------------------------------------------------------------------
// ClearOptions
// ---------------------------------------------------------------------------

/// A set of clear type toggles.
///
/// Ported from `ghidra.app.plugin.core.clear.ClearOptions`.
#[derive(Debug, Clone)]
pub struct ClearOptions {
    types_to_clear: HashSet<ClearType>,
}

impl ClearOptions {
    /// Create a new ClearOptions that clears everything by default.
    pub fn all() -> Self {
        let types_to_clear = ClearType::all().iter().copied().collect();
        Self { types_to_clear }
    }

    /// Create a new ClearOptions with nothing selected.
    pub fn none() -> Self {
        Self {
            types_to_clear: HashSet::new(),
        }
    }

    /// Create a ClearOptions with just instructions and data enabled
    /// (the default when no options object is provided in Java).
    pub fn instructions_and_data() -> Self {
        let mut opts = Self::none();
        opts.set_should_clear(ClearType::Instructions, true);
        opts.set_should_clear(ClearType::Data, true);
        opts
    }

    /// Set whether a given clear type should be cleared.
    pub fn set_should_clear(&mut self, clear_type: ClearType, should_clear: bool) {
        if should_clear {
            self.types_to_clear.insert(clear_type);
        } else {
            self.types_to_clear.remove(&clear_type);
        }
    }

    /// Check whether a given clear type should be cleared.
    pub fn should_clear(&self, clear_type: ClearType) -> bool {
        self.types_to_clear.contains(&clear_type)
    }

    /// Whether any clear types are enabled.
    pub fn clear_any(&self) -> bool {
        !self.types_to_clear.is_empty()
    }

    /// Get the set of reference source types to clear.
    ///
    /// Maps the four reference-related clear types to source type labels.
    pub fn reference_source_types_to_clear(&self) -> Vec<&'static str> {
        let mut types = Vec::new();
        if self.should_clear(ClearType::UserReferences) {
            types.push("USER_DEFINED");
        }
        if self.should_clear(ClearType::DefaultReferences) {
            types.push("DEFAULT");
        }
        if self.should_clear(ClearType::ImportReferences) {
            types.push("IMPORTED");
        }
        if self.should_clear(ClearType::AnalysisReferences) {
            types.push("ANALYSIS");
        }
        types
    }

    /// The number of enabled clear types.
    pub fn enabled_count(&self) -> usize {
        self.types_to_clear.len()
    }
}

impl Default for ClearOptions {
    fn default() -> Self {
        Self::all()
    }
}

// ---------------------------------------------------------------------------
// ClearOperation -- a clear over an address range
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ClearModel
// ---------------------------------------------------------------------------

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

    /// Compute the total number of addresses that would be affected.
    pub fn total_address_count(&self) -> u64 {
        self.operations.iter().map(|op| op.address_count()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clear_type_all() {
        assert_eq!(ClearType::all().len(), 13);
    }

    #[test]
    fn test_clear_options_all() {
        let opts = ClearOptions::all();
        assert!(opts.clear_any());
        assert!(opts.should_clear(ClearType::Instructions));
        assert!(opts.should_clear(ClearType::Bookmarks));
        assert_eq!(opts.enabled_count(), 13);
    }

    #[test]
    fn test_clear_options_none() {
        let opts = ClearOptions::none();
        assert!(!opts.clear_any());
        assert_eq!(opts.enabled_count(), 0);
    }

    #[test]
    fn test_clear_options_set_toggle() {
        let mut opts = ClearOptions::none();
        opts.set_should_clear(ClearType::Instructions, true);
        assert!(opts.should_clear(ClearType::Instructions));
        assert!(!opts.should_clear(ClearType::Data));
        opts.set_should_clear(ClearType::Instructions, false);
        assert!(!opts.should_clear(ClearType::Instructions));
    }

    #[test]
    fn test_clear_options_instructions_and_data() {
        let opts = ClearOptions::instructions_and_data();
        assert!(opts.should_clear(ClearType::Instructions));
        assert!(opts.should_clear(ClearType::Data));
        assert!(!opts.should_clear(ClearType::Symbols));
    }

    #[test]
    fn test_reference_source_types() {
        let mut opts = ClearOptions::none();
        opts.set_should_clear(ClearType::UserReferences, true);
        opts.set_should_clear(ClearType::AnalysisReferences, true);
        let types = opts.reference_source_types_to_clear();
        assert_eq!(types.len(), 2);
        assert!(types.contains(&"USER_DEFINED"));
        assert!(types.contains(&"ANALYSIS"));
    }

    #[test]
    fn test_clear_operation() {
        let op = ClearOperation::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            ClearType::Instructions,
        );
        assert_eq!(op.address_count(), 0x1000);
    }

    #[test]
    fn test_clear_operation_with_bytes() {
        let op = ClearOperation::new(
            Address::new(0x1000),
            Address::new(0x100F),
            ClearType::Data,
        )
        .with_clear_bytes(true);
        assert!(op.clear_bytes);
    }

    #[test]
    fn test_clear_model() {
        let mut model = ClearModel::new();
        model.add_operation(ClearOperation::new(
            Address::new(0x1000),
            Address::new(0x1FFF),
            ClearType::Instructions,
        ));
        assert_eq!(model.operation_count(), 1);
        model.clear();
        assert_eq!(model.operation_count(), 0);
    }

    #[test]
    fn test_clear_model_total_address_count() {
        let mut model = ClearModel::new();
        model.add_operation(ClearOperation::new(
            Address::new(0x1000),
            Address::new(0x100F),
            ClearType::Instructions,
        ));
        model.add_operation(ClearOperation::new(
            Address::new(0x2000),
            Address::new(0x20FF),
            ClearType::Data,
        ));
        assert_eq!(model.total_address_count(), 16 + 256);
    }

    #[test]
    fn test_clear_options_default_is_all() {
        let opts = ClearOptions::default();
        assert!(opts.should_clear(ClearType::Instructions));
        assert_eq!(opts.enabled_count(), 13);
    }

    #[test]
    fn test_clear_options_no_references() {
        let mut opts = ClearOptions::all();
        opts.set_should_clear(ClearType::UserReferences, false);
        opts.set_should_clear(ClearType::AnalysisReferences, false);
        opts.set_should_clear(ClearType::ImportReferences, false);
        opts.set_should_clear(ClearType::DefaultReferences, false);
        let refs = opts.reference_source_types_to_clear();
        assert!(refs.is_empty());
    }
}
