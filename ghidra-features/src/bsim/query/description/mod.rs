//! BSim description types.
//!
//! Re-exports the core description types from the parent `bsim` module.
//! Additional query-specific description utilities are provided here.

pub use super::super::description::{
    CategoryRecord, DatabaseInformation, DescriptionManager, ExecutableRecord,
    FunctionDescription, RowKey, SignatureRecord, VectorResult, CallgraphEntry,
};

use serde::{Deserialize, Serialize};

/// Function tag for labeling functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTag {
    /// Tag name.
    pub name: String,
    /// Tag category.
    pub category: String,
}

impl FunctionTag {
    /// Create a new function tag.
    pub fn new(name: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category: category.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_tag() {
        let tag = FunctionTag::new("library", "libc");
        assert_eq!(tag.name, "library");
        assert_eq!(tag.category, "libc");
    }

    #[test]
    fn test_re_exported_types() {
        let func = FunctionDescription::new(0, "main", Some(0x1000));
        assert_eq!(func.function_name, "main");
    }
}
