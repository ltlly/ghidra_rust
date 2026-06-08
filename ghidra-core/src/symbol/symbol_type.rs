//! Symbol type classification.
//!
//! This module provides the [`SymbolType`] enum which classifies symbols in
//! a Ghidra program into distinct categories.
//!
//! # Correspondence to Ghidra
//!
//! This is a direct translation of `ghidra.program.model.symbol.SymbolType`.
//! The Java version is an abstract class with static instances for each type.
//! This Rust version is a plain enum with helper methods for validation,
//! classification, and serialization.

use crate::addr::Address;
use serde::{Deserialize, Serialize};
use std::fmt;

use super::source_type::SourceType;

// ============================================================================
// SymbolType
// ============================================================================

/// The type of a symbol, corresponding to Ghidra's `SymbolType` abstract class
/// and its static instances.
///
/// Each variant has an associated storage ID and namespace flag.
///
/// # Examples
///
/// ```
/// use ghidra_core::symbol::symbol_type::SymbolType;
///
/// assert!(SymbolType::Function.is_namespace());
/// assert!(SymbolType::Label.allows_duplicates());
/// assert!(!SymbolType::Namespace.allows_duplicates());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolType {
    /// A label at a memory or external address. Allows duplicate names.
    Label,
    /// An external library. Must be in the global namespace.
    Library,
    /// A generic namespace. Uses NO_ADDRESS.
    Namespace,
    /// A class namespace. Uses NO_ADDRESS, cannot be inside a function.
    Class,
    /// A function entry point. Allows duplicate names.
    Function,
    /// A function parameter.
    Parameter,
    /// A function local variable.
    LocalVar,
    /// A global register variable.
    GlobalVar,
    /// An imported symbol (external library function).
    Import,
    /// An exported symbol (function or data exported by the binary).
    Export,
    /// An unknown / unclassified symbol type.
    Unknown,
    /// The global namespace root (not persisted in the database).
    Global,
}

impl SymbolType {
    /// The number of persisted symbol types (excluding Global).
    const PERSISTED_COUNT: usize = 8;

    /// All persisted symbol types indexed by storage ID (0..=7).
    const PERSISTED: [Option<SymbolType>; Self::PERSISTED_COUNT] = [
        Some(SymbolType::Label),        // 0
        Some(SymbolType::Library),      // 1
        None,                           // 2 (was deprecated slot)
        Some(SymbolType::Namespace),    // 3
        Some(SymbolType::Class),        // 4
        Some(SymbolType::Function),     // 5
        Some(SymbolType::Parameter),    // 6
        Some(SymbolType::LocalVar),     // 7
    ];

    /// Returns the storage ID used for persistent serialization.
    /// Returns -1 for the Global type.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::symbol::symbol_type::SymbolType;
    ///
    /// assert_eq!(SymbolType::Label.get_id(), 0);
    /// assert_eq!(SymbolType::Function.get_id(), 5);
    /// assert_eq!(SymbolType::Global.get_id(), -1);
    /// ```
    pub fn get_id(self) -> i8 {
        match self {
            SymbolType::Label => 0,
            SymbolType::Library => 1,
            SymbolType::Namespace => 3,
            SymbolType::Class => 4,
            SymbolType::Function => 5,
            SymbolType::Parameter => 6,
            SymbolType::LocalVar => 7,
            SymbolType::GlobalVar => 8,
            SymbolType::Import => 9,
            SymbolType::Export => 10,
            SymbolType::Global => -1,
            SymbolType::Unknown => -2,
        }
    }

    /// Returns the `SymbolType` for the given storage ID, or `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::symbol::symbol_type::SymbolType;
    ///
    /// assert_eq!(SymbolType::from_id(0), Some(SymbolType::Label));
    /// assert_eq!(SymbolType::from_id(5), Some(SymbolType::Function));
    /// assert_eq!(SymbolType::from_id(-1), Some(SymbolType::Global));
    /// assert_eq!(SymbolType::from_id(2), None);
    /// ```
    pub fn from_id(id: i8) -> Option<SymbolType> {
        if id == -1 {
            return Some(SymbolType::Global);
        }
        if id == 8 {
            return Some(SymbolType::GlobalVar);
        }
        if id < 0 || id as usize >= Self::PERSISTED_COUNT {
            return None;
        }
        Self::PERSISTED[id as usize]
    }

    /// Returns `true` if this symbol type represents a namespace-containing
    /// symbol.
    ///
    /// Namespace types can contain other symbols as children in the symbol
    /// tree hierarchy.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::symbol::symbol_type::SymbolType;
    ///
    /// assert!(SymbolType::Library.is_namespace());
    /// assert!(SymbolType::Class.is_namespace());
    /// assert!(SymbolType::Function.is_namespace());
    /// assert!(!SymbolType::Label.is_namespace());
    /// ```
    pub fn is_namespace(self) -> bool {
        matches!(
            self,
            SymbolType::Library
                | SymbolType::Namespace
                | SymbolType::Class
                | SymbolType::Function
                | SymbolType::Global
        )
    }

    /// Returns `true` if this symbol type allows duplicate names within the
    /// same namespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use ghidra_core::symbol::symbol_type::SymbolType;
    ///
    /// assert!(SymbolType::Label.allows_duplicates());
    /// assert!(SymbolType::Function.allows_duplicates());
    /// assert!(!SymbolType::Library.allows_duplicates());
    /// ```
    pub fn allows_duplicates(self) -> bool {
        matches!(self, SymbolType::Label | SymbolType::Function)
    }

    /// Returns `true` if `source` is a valid source for this symbol type,
    /// given an optional address.
    pub fn is_valid_source(self, source: SourceType, addr: Option<&Address>) -> bool {
        match self {
            SymbolType::Label => {
                if source != SourceType::Default {
                    return true;
                }
                addr.map(|a| a.is_external_address()).unwrap_or(false)
            }
            SymbolType::Library
            | SymbolType::Namespace
            | SymbolType::Class
            | SymbolType::GlobalVar
            | SymbolType::Global => source != SourceType::Default,
            SymbolType::Function | SymbolType::Parameter | SymbolType::LocalVar => true,
            SymbolType::Import | SymbolType::Export | SymbolType::Unknown => true,
        }
    }

    /// Returns `true` if `addr` is a valid address for this symbol type.
    pub fn is_valid_address(self, addr: &Address) -> bool {
        match self {
            SymbolType::Label | SymbolType::Function | SymbolType::Import | SymbolType::Export => {
                addr.is_memory_address() || addr.is_external_address()
            }
            SymbolType::Library | SymbolType::Namespace | SymbolType::Class => addr.is_no_address(),
            SymbolType::Parameter | SymbolType::LocalVar | SymbolType::GlobalVar => {
                addr.is_variable_address()
            }
            SymbolType::Unknown => true,
            SymbolType::Global => false,
        }
    }
}

impl fmt::Display for SymbolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SymbolType::Label => write!(f, "Label"),
            SymbolType::Library => write!(f, "Library"),
            SymbolType::Namespace => write!(f, "Namespace"),
            SymbolType::Class => write!(f, "Class"),
            SymbolType::Function => write!(f, "Function"),
            SymbolType::Parameter => write!(f, "Parameter"),
            SymbolType::LocalVar => write!(f, "Local Var"),
            SymbolType::GlobalVar => write!(f, "Global Register Var"),
            SymbolType::Import => write!(f, "Import"),
            SymbolType::Export => write!(f, "Export"),
            SymbolType::Unknown => write!(f, "Unknown"),
            SymbolType::Global => write!(f, "Global"),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_id() {
        assert_eq!(SymbolType::Label.get_id(), 0);
        assert_eq!(SymbolType::Library.get_id(), 1);
        assert_eq!(SymbolType::Namespace.get_id(), 3);
        assert_eq!(SymbolType::Class.get_id(), 4);
        assert_eq!(SymbolType::Function.get_id(), 5);
        assert_eq!(SymbolType::Parameter.get_id(), 6);
        assert_eq!(SymbolType::LocalVar.get_id(), 7);
        assert_eq!(SymbolType::GlobalVar.get_id(), 8);
        assert_eq!(SymbolType::Import.get_id(), 9);
        assert_eq!(SymbolType::Export.get_id(), 10);
        assert_eq!(SymbolType::Global.get_id(), -1);
        assert_eq!(SymbolType::Unknown.get_id(), -2);
    }

    #[test]
    fn test_from_id_roundtrip() {
        let types = [
            SymbolType::Label,
            SymbolType::Library,
            SymbolType::Namespace,
            SymbolType::Class,
            SymbolType::Function,
            SymbolType::Parameter,
            SymbolType::LocalVar,
        ];
        for sym_type in &types {
            let id = sym_type.get_id();
            assert_eq!(SymbolType::from_id(id), Some(*sym_type));
        }
        // Special cases
        assert_eq!(SymbolType::from_id(-1), Some(SymbolType::Global));
        assert_eq!(SymbolType::from_id(8), Some(SymbolType::GlobalVar));
    }

    #[test]
    fn test_from_id_invalid() {
        assert_eq!(SymbolType::from_id(2), None);
        assert_eq!(SymbolType::from_id(11), None);
        assert_eq!(SymbolType::from_id(-3), None);
    }

    #[test]
    fn test_is_namespace() {
        assert!(SymbolType::Library.is_namespace());
        assert!(SymbolType::Namespace.is_namespace());
        assert!(SymbolType::Class.is_namespace());
        assert!(SymbolType::Function.is_namespace());
        assert!(SymbolType::Global.is_namespace());

        assert!(!SymbolType::Label.is_namespace());
        assert!(!SymbolType::Parameter.is_namespace());
        assert!(!SymbolType::LocalVar.is_namespace());
        assert!(!SymbolType::GlobalVar.is_namespace());
        assert!(!SymbolType::Import.is_namespace());
        assert!(!SymbolType::Export.is_namespace());
        assert!(!SymbolType::Unknown.is_namespace());
    }

    #[test]
    fn test_allows_duplicates() {
        assert!(SymbolType::Label.allows_duplicates());
        assert!(SymbolType::Function.allows_duplicates());

        assert!(!SymbolType::Library.allows_duplicates());
        assert!(!SymbolType::Namespace.allows_duplicates());
        assert!(!SymbolType::Class.allows_duplicates());
        assert!(!SymbolType::Global.allows_duplicates());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", SymbolType::Label), "Label");
        assert_eq!(format!("{}", SymbolType::Function), "Function");
        assert_eq!(format!("{}", SymbolType::Library), "Library");
        assert_eq!(format!("{}", SymbolType::Namespace), "Namespace");
        assert_eq!(format!("{}", SymbolType::Class), "Class");
        assert_eq!(format!("{}", SymbolType::Parameter), "Parameter");
        assert_eq!(format!("{}", SymbolType::LocalVar), "Local Var");
        assert_eq!(format!("{}", SymbolType::GlobalVar), "Global Register Var");
        assert_eq!(format!("{}", SymbolType::Import), "Import");
        assert_eq!(format!("{}", SymbolType::Export), "Export");
        assert_eq!(format!("{}", SymbolType::Unknown), "Unknown");
        assert_eq!(format!("{}", SymbolType::Global), "Global");
    }

    #[test]
    fn test_is_valid_source() {
        // Label: Default source is only valid for external addresses
        assert!(SymbolType::Label.is_valid_source(SourceType::Analysis, None));
        // Label with Default source on a regular address is NOT valid
        assert!(!SymbolType::Label.is_valid_source(SourceType::Default, Some(&Address::new(0))));
        // Label with non-Default source is always valid
        assert!(SymbolType::Label.is_valid_source(SourceType::UserDefined, None));
        // Library: Default source is not valid
        assert!(!SymbolType::Library.is_valid_source(SourceType::Default, None));
        assert!(SymbolType::Library.is_valid_source(SourceType::Imported, None));
        // Function: any source is valid
        assert!(SymbolType::Function.is_valid_source(SourceType::Default, None));
        assert!(SymbolType::Function.is_valid_source(SourceType::Analysis, None));
    }

    #[test]
    fn test_is_valid_address() {
        let mem_addr = Address::new(0x1000);
        assert!(SymbolType::Label.is_valid_address(&mem_addr));
        assert!(SymbolType::Function.is_valid_address(&mem_addr));
        // Library must be at NO_ADDRESS
        assert!(!SymbolType::Library.is_valid_address(&mem_addr));
    }

    #[test]
    fn test_serde_roundtrip() {
        let sym_type = SymbolType::Function;
        let json = serde_json::to_string(&sym_type).unwrap();
        let deserialized: SymbolType = serde_json::from_str(&json).unwrap();
        assert_eq!(sym_type, deserialized);
    }
}
