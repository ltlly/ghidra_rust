//! Global symbol implementation.
//!
//! Direct translation of `ghidra.program.model.address.GlobalSymbol`.
//!
//! Provides [`GlobalNamespaceSymbol`] -- the symbol that represents the global
//! namespace root. This is distinct from the [`GlobalSymbol`](crate::symbol::GlobalSymbol)
//! in the symbol module; the address-package version couples the symbol to a
//! specific [`GlobalNamespace`] and returns `NO_ADDRESS` for its address.
//!
//! In the Java codebase, `GlobalSymbol` in the address package implements
//! `Symbol` and wraps the `GlobalNamespace`. The Rust equivalent uses the
//! existing [`SymbolApi`] trait from the symbol module and adds a back-reference
//! to the [`GlobalNamespace`].

use crate::addr::Address;
use crate::addr::global_namespace::{GlobalNamespace, GLOBAL_NAMESPACE_ID};
use crate::symbol::{
    Namespace, SourceType, SymbolApi, SymbolError, SymbolResult, SymbolType,
};
use std::any::Any;
use std::fmt;
use std::sync::{Arc, RwLock};

/// The global namespace symbol.
///
/// Corresponds to `ghidra.program.model.address.GlobalSymbol`.
///
/// This symbol represents the root of the program's namespace hierarchy.
/// It cannot be deleted, renamed, or moved. Its address is always
/// [`Address::NULL`].
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::global_symbol::GlobalNamespaceSymbol;
/// use ghidra_core::addr::Address;
/// use ghidra_core::symbol::SymbolApi;
///
/// let sym = GlobalNamespaceSymbol::new();
/// assert_eq!(sym.get_name(), "global");
/// assert!(sym.is_global());
/// assert!(!sym.is_deleted());
/// assert!(!sym.is_external());
/// ```
#[derive(Debug)]
pub struct GlobalNamespaceSymbol {
    /// Back-reference to the global namespace.
    global_namespace: Arc<RwLock<GlobalNamespace>>,
}

impl GlobalNamespaceSymbol {
    /// Create a new global namespace symbol with a default global namespace.
    pub fn new() -> Self {
        Self {
            global_namespace: Arc::new(RwLock::new(GlobalNamespace::new())),
        }
    }

    /// Create a new global namespace symbol wrapping the given namespace.
    pub fn with_namespace(global_namespace: Arc<RwLock<GlobalNamespace>>) -> Self {
        Self { global_namespace }
    }

    /// Returns a reference to the underlying global namespace.
    pub fn global_namespace(&self) -> &Arc<RwLock<GlobalNamespace>> {
        &self.global_namespace
    }
}

impl Default for GlobalNamespaceSymbol {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolApi for GlobalNamespaceSymbol {
    fn get_address(&self) -> &Address {
        &Address::NULL
    }

    fn get_name(&self) -> String {
        "global".to_string()
    }

    fn get_path(&self) -> Vec<String> {
        Vec::new()
    }

    fn get_name_qualified(&self, _include_namespace: bool) -> String {
        "global".to_string()
    }

    fn get_parent_namespace(&self) -> Option<&dyn Namespace> {
        None
    }

    fn get_parent_symbol(&self) -> Option<&dyn SymbolApi> {
        None
    }

    fn is_descendant(&self, _namespace: &dyn Namespace) -> bool {
        true
    }

    fn is_valid_parent(&self, _parent: &dyn Namespace) -> bool {
        false
    }

    fn get_symbol_type(&self) -> SymbolType {
        SymbolType::Global
    }

    fn get_reference_count(&self) -> usize {
        0
    }

    fn has_references(&self) -> bool {
        false
    }

    fn get_id(&self) -> u64 {
        GLOBAL_NAMESPACE_ID
    }

    fn get_object(&self) -> Option<&dyn Any> {
        Some(&self.global_namespace)
    }

    fn is_global(&self) -> bool {
        true
    }

    fn is_external(&self) -> bool {
        false
    }

    fn is_primary(&self) -> bool {
        true
    }

    fn set_primary(&mut self) -> bool {
        // Global symbol is always primary; no-op.
        false
    }

    fn is_external_entry_point(&self) -> bool {
        false
    }

    fn is_pinned(&self) -> bool {
        false
    }

    fn set_pinned(&mut self, _pinned: bool) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation(
            "Cannot pin the global symbol".to_string(),
        ))
    }

    fn is_dynamic(&self) -> bool {
        false
    }

    fn get_source(&self) -> SourceType {
        SourceType::Default
    }

    fn set_source(&mut self, _source: SourceType) {
        // Global symbol source cannot be changed.
    }

    fn is_deleted(&self) -> bool {
        false
    }

    fn set_name(&mut self, _new_name: &str, _source: SourceType) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation(
            "Setting the name of the Global symbol is not allowed".to_string(),
        ))
    }

    fn set_namespace(&mut self, _new_namespace: &dyn Namespace) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation(
            "Cannot change the Global namespace".to_string(),
        ))
    }

    fn set_name_and_namespace(
        &mut self,
        _new_name: &str,
        _new_namespace: &dyn Namespace,
        _source: SourceType,
    ) -> SymbolResult<()> {
        Err(SymbolError::UnsupportedOperation(
            "Cannot change the Global name and/or namespace".to_string(),
        ))
    }

    fn delete(&mut self) -> bool {
        false
    }
}

impl PartialEq for GlobalNamespaceSymbol {
    fn eq(&self, _other: &Self) -> bool {
        // All global symbols are equal (same as Java: getClass() == obj.getClass()).
        true
    }
}

impl Eq for GlobalNamespaceSymbol {}

impl std::hash::Hash for GlobalNamespaceSymbol {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::any::TypeId::of::<Self>().hash(state);
    }
}

impl fmt::Display for GlobalNamespaceSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "global")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_symbol_name() {
        let sym = GlobalNamespaceSymbol::new();
        assert_eq!(sym.get_name(), "global");
    }

    #[test]
    fn test_global_symbol_address_is_null() {
        let sym = GlobalNamespaceSymbol::new();
        assert!(sym.get_address().is_null());
    }

    #[test]
    fn test_global_symbol_is_global() {
        let sym = GlobalNamespaceSymbol::new();
        assert!(sym.is_global());
    }

    #[test]
    fn test_global_symbol_not_deleted() {
        let sym = GlobalNamespaceSymbol::new();
        assert!(!sym.is_deleted());
    }

    #[test]
    fn test_global_symbol_not_external() {
        let sym = GlobalNamespaceSymbol::new();
        assert!(!sym.is_external());
    }

    #[test]
    fn test_global_symbol_is_primary() {
        let sym = GlobalNamespaceSymbol::new();
        assert!(sym.is_primary());
    }

    #[test]
    fn test_global_symbol_not_dynamic() {
        let sym = GlobalNamespaceSymbol::new();
        assert!(!sym.is_dynamic());
    }

    #[test]
    fn test_global_symbol_not_pinned() {
        let sym = GlobalNamespaceSymbol::new();
        assert!(!sym.is_pinned());
    }

    #[test]
    fn test_global_symbol_cannot_set_pinned() {
        let mut sym = GlobalNamespaceSymbol::new();
        assert!(sym.set_pinned(true).is_err());
    }

    #[test]
    fn test_global_symbol_cannot_rename() {
        let mut sym = GlobalNamespaceSymbol::new();
        assert!(sym.set_name("new_name", SourceType::UserDefined).is_err());
    }

    #[test]
    fn test_global_symbol_cannot_set_namespace() {
        let mut sym = GlobalNamespaceSymbol::new();
        let ns = GlobalNamespace::new();
        assert!(sym.set_namespace(&ns).is_err());
    }

    #[test]
    fn test_global_symbol_cannot_set_name_and_namespace() {
        let mut sym = GlobalNamespaceSymbol::new();
        let ns = GlobalNamespace::new();
        assert!(sym.set_name_and_namespace("x", &ns, SourceType::UserDefined).is_err());
    }

    #[test]
    fn test_global_symbol_cannot_delete() {
        let mut sym = GlobalNamespaceSymbol::new();
        assert!(!sym.delete());
    }

    #[test]
    fn test_global_symbol_cannot_set_source() {
        let mut sym = GlobalNamespaceSymbol::new();
        sym.set_source(SourceType::UserDefined);
        // No-op; source remains default.
    }

    #[test]
    fn test_global_symbol_is_descendant_of_anything() {
        let sym = GlobalNamespaceSymbol::new();
        let ns = GlobalNamespace::new();
        assert!(sym.is_descendant(&ns));
    }

    #[test]
    fn test_global_symbol_no_valid_parent() {
        let sym = GlobalNamespaceSymbol::new();
        let ns = GlobalNamespace::new();
        assert!(!sym.is_valid_parent(&ns));
    }

    #[test]
    fn test_global_symbol_no_parent() {
        let sym = GlobalNamespaceSymbol::new();
        assert!(sym.get_parent_namespace().is_none());
        assert!(sym.get_parent_symbol().is_none());
    }

    #[test]
    fn test_global_symbol_id() {
        let sym = GlobalNamespaceSymbol::new();
        assert_eq!(sym.get_id(), 0);
    }

    #[test]
    fn test_global_symbol_path_empty() {
        let sym = GlobalNamespaceSymbol::new();
        assert!(sym.get_path().is_empty());
    }

    #[test]
    fn test_global_symbol_no_references() {
        let sym = GlobalNamespaceSymbol::new();
        assert_eq!(sym.get_reference_count(), 0);
        assert!(!sym.has_references());
    }

    #[test]
    fn test_global_symbol_symbol_type() {
        let sym = GlobalNamespaceSymbol::new();
        assert_eq!(sym.get_symbol_type(), SymbolType::Global);
    }

    #[test]
    fn test_global_symbol_display() {
        let sym = GlobalNamespaceSymbol::new();
        assert_eq!(format!("{}", sym), "global");
    }

    #[test]
    fn test_global_symbol_equality() {
        let a = GlobalNamespaceSymbol::new();
        let b = GlobalNamespaceSymbol::new();
        assert_eq!(a, b);
    }

    #[test]
    fn test_global_symbol_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(GlobalNamespaceSymbol::new());
        set.insert(GlobalNamespaceSymbol::new());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_global_symbol_with_namespace() {
        let ns = Arc::new(RwLock::new(GlobalNamespace::new()));
        let sym = GlobalNamespaceSymbol::with_namespace(Arc::clone(&ns));
        assert!(sym.global_namespace().read().unwrap().is_global());
    }
}
