//! Namespace types for hierarchical symbol scoping.
//!
//! This module re-exports the [`Namespace`] trait and related types from the
//! parent `symbol` module, providing a dedicated access path for namespace
//! functionality.
//!
//! # Correspondence to Ghidra
//!
//! The `Namespace` interface in `ghidra.program.model.symbol` defines
//! hierarchical scoping for symbols. In Ghidra, the global namespace (ID=0)
//! is the root. Functions, libraries, classes, and generic namespace types
//! all implement this interface.
//!
//! # Re-exports
//!
//! This file re-exports the following types from `super` (the parent `symbol`
//! module) for convenience:
//!
//! * [`Namespace`] trait
//! * [`GlobalSymbol`] — the root namespace
//! * [`NamespaceSymbol`] — a generic namespace
//! * [`ClassSymbol`] — a class namespace
//! * [`LibrarySymbol`] — an external library namespace

// Re-export the Namespace trait and concrete namespace implementations
// from the parent symbol module.
pub use super::{
    ClassSymbol, GlobalSymbol, GlobalVarSymbol, LibrarySymbol, Namespace, NamespaceSymbol,
};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Address;

    #[test]
    fn test_global_symbol_is_namespace() {
        let global = GlobalSymbol::new();
        assert!(global.is_global());
        assert!(!global.is_external());
        assert_eq!(global.get_id(), 0);
        assert_eq!(global.get_name(), "Global");
    }

    #[test]
    fn test_namespace_symbol_properties() {
        let ns = NamespaceSymbol::new(1, "MyNamespace", 0, crate::symbol::SourceType::UserDefined);
        assert_eq!(ns.get_id(), 1);
        assert_eq!(ns.get_name(), "MyNamespace");
        // parent_namespace_id == 0 means in the global namespace
        assert_eq!(ns.parent_namespace_id(), 0);
        assert!(!ns.is_external());
    }

    #[test]
    fn test_class_symbol_properties() {
        let cls = ClassSymbol::new(2, "MyClass", 0, crate::symbol::SourceType::UserDefined);
        assert_eq!(cls.get_id(), 2);
        assert_eq!(cls.get_name(), "MyClass");
        assert_eq!(cls.parent_namespace_id(), 0);
    }

    #[test]
    fn test_library_symbol_properties() {
        let lib = LibrarySymbol::new(3, "libc.so.6", crate::symbol::SourceType::Imported);
        assert_eq!(lib.get_id(), 3);
        assert_eq!(lib.get_name(), "libc.so.6");
        assert!(lib.is_external());
    }

    #[test]
    fn test_global_namespace_id() {
        assert_eq!(GlobalSymbol::global_namespace_id(), 0u64);
    }

    #[test]
    fn test_namespace_delimiter() {
        assert_eq!(GlobalSymbol::delimiter(), "::");
    }

    #[test]
    fn test_global_path_list() {
        let global = GlobalSymbol::new();
        let path = global.get_path_list(false);
        // Global has an empty path list
        assert!(path.is_empty());
    }
}
