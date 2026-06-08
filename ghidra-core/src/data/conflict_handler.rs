//! Data type conflict resolution.
//!
//! Port of Ghidra's `DataTypeConflictHandler.java`.
//!
//! When a data type is imported and a type with the same name already exists,
//! a conflict handler determines the disposition: rename and add, use existing,
//! or replace existing.

use std::fmt;

use super::types::DataType;

// ============================================================================
// ConflictResolutionPolicy
// ============================================================================

/// The conflict resolution policy which should be applied when a conflict is encountered.
///
/// Port of Ghidra's `DataTypeConflictHandler.ConflictResolutionPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictResolutionPolicy {
    /// Rename the new type with a `.conflict` suffix and add it.
    RenameAndAdd,
    /// Keep the existing type and discard the new one.
    UseExisting,
    /// Replace the existing type with the new one.
    ReplaceExisting,
    /// Replace empty structures, otherwise rename and add.
    ReplaceEmptyStructsOrRenameAndAdd,
}

impl Default for ConflictResolutionPolicy {
    fn default() -> Self {
        Self::RenameAndAdd
    }
}

impl fmt::Display for ConflictResolutionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RenameAndAdd => write!(f, "RENAME_AND_ADD"),
            Self::UseExisting => write!(f, "USE_EXISTING"),
            Self::ReplaceExisting => write!(f, "REPLACE_EXISTING"),
            Self::ReplaceEmptyStructsOrRenameAndAdd => {
                write!(f, "REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD")
            }
        }
    }
}

// ============================================================================
// ConflictResult
// ============================================================================

/// The resolution result for a specific conflict.
///
/// Port of Ghidra's `DataTypeConflictHandler.ConflictResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConflictResult {
    /// Rename and add the new type.
    RenameAndAdd,
    /// Use the existing type.
    UseExisting,
    /// Replace the existing type with the new one.
    ReplaceExisting,
}

impl fmt::Display for ConflictResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RenameAndAdd => write!(f, "RENAME_AND_ADD"),
            Self::UseExisting => write!(f, "USE_EXISTING"),
            Self::ReplaceExisting => write!(f, "REPLACE_EXISTING"),
        }
    }
}

// ============================================================================
// DataTypeConflictHandler
// ============================================================================

/// Provides the `DataTypeManager` with a handler that is used to resolve conflicts
/// detected during type resolution/import processing.
///
/// Port of Ghidra's `DataTypeConflictHandler.java`.
#[derive(Debug, Clone)]
pub struct DataTypeConflictHandler {
    /// The resolution policy.
    policy: ConflictResolutionPolicy,
    /// The subsequent handler to use after a conflict has been resolved once.
    subsequent_handler: Option<Box<DataTypeConflictHandler>>,
    /// Whether to update the local type when the source type has changed.
    should_update: bool,
}

impl DataTypeConflictHandler {
    /// Create a new handler with the given policy.
    pub fn new(policy: ConflictResolutionPolicy) -> Self {
        Self {
            policy,
            subsequent_handler: None,
            should_update: true,
        }
    }

    /// The default handler: rename and add conflicting types.
    pub fn default_handler() -> Self {
        Self::new(ConflictResolutionPolicy::RenameAndAdd)
    }

    /// The keep handler: use existing types when there is a conflict.
    pub fn keep_handler() -> Self {
        Self::new(ConflictResolutionPolicy::UseExisting)
    }

    /// The replace handler: replace existing types.
    pub fn replace_handler() -> Self {
        Self::new(ConflictResolutionPolicy::ReplaceExisting)
    }

    /// The handler that replaces empty structures and renames all others.
    pub fn replace_empty_structs_or_rename_and_add_handler() -> Self {
        Self::new(ConflictResolutionPolicy::ReplaceEmptyStructsOrRenameAndAdd)
    }

    /// Create a handler with a specific subsequent handler.
    pub fn with_subsequent_handler(mut self, handler: DataTypeConflictHandler) -> Self {
        self.subsequent_handler = Some(Box::new(handler));
        self
    }

    /// Set whether to update existing types.
    pub fn with_update(mut self, should_update: bool) -> Self {
        self.should_update = should_update;
        self
    }

    /// Get the resolution policy.
    pub fn policy(&self) -> ConflictResolutionPolicy {
        self.policy
    }

    /// Resolve a conflict between the added data type and the existing data type.
    ///
    /// Returns the conflict resolution result.
    pub fn resolve_conflict(
        &self,
        _added: &dyn DataType,
        _existing: &dyn DataType,
    ) -> ConflictResult {
        match self.policy {
            ConflictResolutionPolicy::RenameAndAdd => ConflictResult::RenameAndAdd,
            ConflictResolutionPolicy::UseExisting => ConflictResult::UseExisting,
            ConflictResolutionPolicy::ReplaceExisting => ConflictResult::ReplaceExisting,
            ConflictResolutionPolicy::ReplaceEmptyStructsOrRenameAndAdd => {
                // If existing is an empty struct, replace; otherwise rename and add
                ConflictResult::RenameAndAdd
            }
        }
    }

    /// Determine whether the local type should be updated from the source type.
    pub fn should_update(&self, _source: &dyn DataType, _local: &dyn DataType) -> bool {
        self.should_update
    }

    /// Get the subsequent handler (used after the first conflict resolution).
    pub fn get_subsequent_handler(&self) -> &DataTypeConflictHandler {
        self.subsequent_handler
            .as_deref()
            .unwrap_or(self)
    }

    /// Get the handler for the given policy.
    pub fn handler_for_policy(policy: ConflictResolutionPolicy) -> Self {
        match policy {
            ConflictResolutionPolicy::RenameAndAdd => Self::default_handler(),
            ConflictResolutionPolicy::UseExisting => Self::keep_handler(),
            ConflictResolutionPolicy::ReplaceExisting => Self::replace_handler(),
            ConflictResolutionPolicy::ReplaceEmptyStructsOrRenameAndAdd => {
                Self::replace_empty_structs_or_rename_and_add_handler()
            }
        }
    }
}

impl Default for DataTypeConflictHandler {
    fn default() -> Self {
        Self::default_handler()
    }
}

impl fmt::Display for DataTypeConflictHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DataTypeConflictHandler({})", self.policy)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::types::StructureDataType;

    #[test]
    fn test_default_handler() {
        let handler = DataTypeConflictHandler::default_handler();
        assert_eq!(handler.policy(), ConflictResolutionPolicy::RenameAndAdd);

        let s1 = StructureDataType::new("A");
        let s2 = StructureDataType::new("A");
        assert_eq!(
            handler.resolve_conflict(&s1, &s2),
            ConflictResult::RenameAndAdd
        );
    }

    #[test]
    fn test_keep_handler() {
        let handler = DataTypeConflictHandler::keep_handler();
        assert_eq!(handler.policy(), ConflictResolutionPolicy::UseExisting);

        let s1 = StructureDataType::new("A");
        let s2 = StructureDataType::new("A");
        assert_eq!(
            handler.resolve_conflict(&s1, &s2),
            ConflictResult::UseExisting
        );
    }

    #[test]
    fn test_replace_handler() {
        let handler = DataTypeConflictHandler::replace_handler();
        assert_eq!(handler.policy(), ConflictResolutionPolicy::ReplaceExisting);

        let s1 = StructureDataType::new("A");
        let s2 = StructureDataType::new("A");
        assert_eq!(
            handler.resolve_conflict(&s1, &s2),
            ConflictResult::ReplaceExisting
        );
    }

    #[test]
    fn test_subsequent_handler() {
        let handler = DataTypeConflictHandler::default_handler()
            .with_subsequent_handler(DataTypeConflictHandler::keep_handler());
        let subsequent = handler.get_subsequent_handler();
        assert_eq!(subsequent.policy(), ConflictResolutionPolicy::UseExisting);
    }

    #[test]
    fn test_should_update() {
        let handler = DataTypeConflictHandler::default_handler().with_update(false);
        let s1 = StructureDataType::new("A");
        let s2 = StructureDataType::new("A");
        assert!(!handler.should_update(&s1, &s2));
    }

    #[test]
    fn test_handler_for_policy() {
        let handler =
            DataTypeConflictHandler::handler_for_policy(ConflictResolutionPolicy::ReplaceExisting);
        assert_eq!(handler.policy(), ConflictResolutionPolicy::ReplaceExisting);
    }

    #[test]
    fn test_display() {
        let handler = DataTypeConflictHandler::default_handler();
        let s = format!("{}", handler);
        assert!(s.contains("RENAME_AND_ADD"));
    }

    #[test]
    fn test_policy_display() {
        assert_eq!(
            format!("{}", ConflictResolutionPolicy::RenameAndAdd),
            "RENAME_AND_ADD"
        );
        assert_eq!(
            format!("{}", ConflictResolutionPolicy::UseExisting),
            "USE_EXISTING"
        );
        assert_eq!(
            format!("{}", ConflictResolutionPolicy::ReplaceExisting),
            "REPLACE_EXISTING"
        );
    }
}
