//! Address label information for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.lang.AddressLabelInfo`.
//!
//! Provides [`AddressLabelInfo`] which pairs an address with label metadata
//! (name, source type, namespace) for display in the listing view.

use crate::addr::Address;
use crate::symbol::SourceType;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Associates an address with label metadata.
///
/// Corresponds to `ghidra.program.model.lang.AddressLabelInfo`.
///
/// This is used when displaying labels in the listing view. It carries the
/// address, the label name, the source of the label, and optionally the
/// namespace path.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::Address;
/// use ghidra_core::addr::label_info::AddressLabelInfo;
/// use ghidra_core::symbol::SourceType;
///
/// let info = AddressLabelInfo::new(
///     Address::new(0x401000),
///     "main",
///     SourceType::UserDefined,
/// );
/// assert_eq!(info.address().offset, 0x401000);
/// assert_eq!(info.name(), "main");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressLabelInfo {
    /// The address of the label.
    address: Address,
    /// The label name.
    name: String,
    /// The source of this label.
    source: SourceType,
    /// Optional namespace path (e.g., ["Global", "MyClass", "myFunc"]).
    namespace_path: Vec<String>,
    /// Whether this label is the primary symbol at its address.
    primary: bool,
    /// Whether this is an entry point.
    entry_point: bool,
    /// Whether this is an external reference.
    external: bool,
}

impl AddressLabelInfo {
    /// Create a new address label info.
    pub fn new(
        address: Address,
        name: impl Into<String>,
        source: SourceType,
    ) -> Self {
        Self {
            address,
            name: name.into(),
            source,
            namespace_path: Vec::new(),
            primary: false,
            entry_point: false,
            external: false,
        }
    }

    /// Create a label info with full configuration.
    pub fn with_options(
        address: Address,
        name: impl Into<String>,
        source: SourceType,
        namespace_path: Vec<String>,
        primary: bool,
        entry_point: bool,
        external: bool,
    ) -> Self {
        Self {
            address,
            name: name.into(),
            source,
            namespace_path,
            primary,
            entry_point,
            external,
        }
    }

    /// Returns the address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the label name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the source type.
    pub fn source(&self) -> SourceType {
        self.source
    }

    /// Returns the namespace path.
    pub fn namespace_path(&self) -> &[String] {
        &self.namespace_path
    }

    /// Returns the fully qualified name (including namespace path).
    pub fn qualified_name(&self) -> String {
        if self.namespace_path.is_empty() {
            self.name.clone()
        } else {
            let mut parts = self.namespace_path.clone();
            parts.push(self.name.clone());
            parts.join("::")
        }
    }

    /// Returns true if this is the primary symbol at its address.
    pub fn is_primary(&self) -> bool {
        self.primary
    }

    /// Returns true if this is an entry point.
    pub fn is_entry_point(&self) -> bool {
        self.entry_point
    }

    /// Returns true if this is an external reference.
    pub fn is_external(&self) -> bool {
        self.external
    }
}

impl fmt::Display for AddressLabelInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.address, self.qualified_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        let info = AddressLabelInfo::new(
            Address::new(0x401000),
            "main",
            SourceType::UserDefined,
        );
        assert_eq!(info.address().offset, 0x401000);
        assert_eq!(info.name(), "main");
        assert_eq!(info.source(), SourceType::UserDefined);
        assert!(info.namespace_path().is_empty());
        assert!(!info.is_primary());
    }

    #[test]
    fn test_with_options() {
        let info = AddressLabelInfo::with_options(
            Address::new(0x401000),
            "myFunc",
            SourceType::Analysis,
            vec!["Global".to_string(), "MyClass".to_string()],
            true,
            true,
            false,
        );
        assert!(info.is_primary());
        assert!(info.is_entry_point());
        assert!(!info.is_external());
        assert_eq!(info.namespace_path().len(), 2);
    }

    #[test]
    fn test_qualified_name_no_namespace() {
        let info = AddressLabelInfo::new(
            Address::new(0x401000),
            "main",
            SourceType::UserDefined,
        );
        assert_eq!(info.qualified_name(), "main");
    }

    #[test]
    fn test_qualified_name_with_namespace() {
        let info = AddressLabelInfo::with_options(
            Address::new(0x401000),
            "myFunc",
            SourceType::UserDefined,
            vec!["Global".to_string(), "MyClass".to_string()],
            false,
            false,
            false,
        );
        assert_eq!(info.qualified_name(), "Global::MyClass::myFunc");
    }

    #[test]
    fn test_display() {
        let info = AddressLabelInfo::new(
            Address::new(0x401000),
            "main",
            SourceType::UserDefined,
        );
        let s = format!("{}", info);
        assert!(s.contains("main"));
        assert!(s.contains("00401000"));
    }

    #[test]
    fn test_clone() {
        let info = AddressLabelInfo::new(
            Address::new(0x401000),
            "main",
            SourceType::UserDefined,
        );
        let cloned = info.clone();
        assert_eq!(info, cloned);
    }

    #[test]
    fn test_eq() {
        let a = AddressLabelInfo::new(
            Address::new(0x401000),
            "main",
            SourceType::UserDefined,
        );
        let b = AddressLabelInfo::new(
            Address::new(0x401000),
            "main",
            SourceType::UserDefined,
        );
        let c = AddressLabelInfo::new(
            Address::new(0x401000),
            "other",
            SourceType::UserDefined,
        );
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
