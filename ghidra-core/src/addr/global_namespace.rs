//! Global namespace implementation.
//!
//! Direct translation of `ghidra.program.model.address.GlobalNamespace`.
//!
//! Provides [`GlobalNamespace`] -- the root namespace in a program's symbol
//! hierarchy. Every program has exactly one global namespace with ID 0.
//! All top-level symbols live in this namespace.

use crate::addr::{Address, AddressSet};
use crate::symbol::{
    GlobalSymbol as SymbolGlobalSymbol, Namespace, SymbolApi, SymbolError,
    SymbolResult, SymbolType,
};
use std::fmt;

/// The name used for the global namespace.
///
/// This may (incorrectly) appear as the first element within a namespace path
/// (e.g., `Global::Foo::Bar`). It is preferred that the Global namespace be
/// omitted in favor of `Foo::Bar`.
pub const GLOBAL_NAMESPACE_NAME: &str = "Global";

/// The global namespace ID (always 0).
pub const GLOBAL_NAMESPACE_ID: u64 = 0;

/// The global namespace implementation.
///
/// Corresponds to `ghidra.program.model.address.GlobalNamespace`.
///
/// This is the root of the namespace hierarchy in a Ghidra program. All
/// top-level symbols reside in this namespace. It cannot be reparented and
/// its body covers the entire program address space.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::global_namespace::{GlobalNamespace, GLOBAL_NAMESPACE_NAME, GLOBAL_NAMESPACE_ID};
/// use ghidra_core::symbol::Namespace;
///
/// let ns = GlobalNamespace::new();
/// assert_eq!(ns.get_name(), GLOBAL_NAMESPACE_NAME);
/// assert_eq!(ns.get_id(), GLOBAL_NAMESPACE_ID);
/// assert!(ns.is_global());
/// assert!(!ns.is_external());
/// ```
#[derive(Debug)]
pub struct GlobalNamespace {
    /// The global symbol for this namespace.
    global_symbol: SymbolGlobalSymbol,
    /// The address set representing the program body (starts empty).
    body: AddressSet,
}

impl GlobalNamespace {
    /// Create a new global namespace.
    ///
    /// The body starts as an empty address set. Call [`set_body`](Self::set_body)
    /// to populate it with the program's loaded address ranges.
    pub fn new() -> Self {
        Self {
            global_symbol: SymbolGlobalSymbol::new(),
            body: AddressSet::new(),
        }
    }

    /// Create a new global namespace with the given body.
    pub fn with_body(body: AddressSet) -> Self {
        Self {
            global_symbol: SymbolGlobalSymbol::new(),
            body,
        }
    }

    /// Returns a reference to the global symbol.
    pub fn global_symbol(&self) -> &SymbolGlobalSymbol {
        &self.global_symbol
    }

    /// Returns the body address set for this namespace.
    pub fn body(&self) -> &AddressSet {
        &self.body
    }

    /// Updates the body address set for this namespace.
    pub fn set_body(&mut self, body: AddressSet) {
        self.body = body;
    }

    /// Returns `true` if this namespace contains the given address in its body.
    pub fn contains_address(&self, addr: &Address) -> bool {
        self.body.contains(addr)
    }
}

impl Default for GlobalNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl Namespace for GlobalNamespace {
    fn get_symbol(&self) -> &dyn SymbolApi {
        &self.global_symbol
    }

    fn get_type(&self) -> SymbolType {
        SymbolType::Global
    }

    fn is_external(&self) -> bool {
        false
    }

    fn get_name(&self) -> String {
        GLOBAL_NAMESPACE_NAME.to_string()
    }

    fn get_name_full(&self, _include_namespace_path: bool) -> String {
        GLOBAL_NAMESPACE_NAME.to_string()
    }

    fn get_id(&self) -> u64 {
        GLOBAL_NAMESPACE_ID
    }

    fn get_parent_namespace(&self) -> Option<&dyn Namespace> {
        None
    }

    fn get_body(&self) -> Vec<Address> {
        self.body.addresses().collect()
    }

    fn set_parent_namespace(&mut self, _parent: &dyn Namespace) -> SymbolResult<()> {
        Err(SymbolError::InvalidInput(
            "Cannot reparent the global namespace".to_string(),
        ))
    }

    fn is_global(&self) -> bool {
        true
    }
}

impl PartialEq for GlobalNamespace {
    fn eq(&self, _other: &Self) -> bool {
        // All GlobalNamespace instances are equal (like the Java implementation).
        true
    }
}

impl Eq for GlobalNamespace {}

impl std::hash::Hash for GlobalNamespace {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // All GlobalNamespace instances hash the same way.
        std::any::TypeId::of::<Self>().hash(state);
    }
}

impl fmt::Display for GlobalNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", GLOBAL_NAMESPACE_NAME)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Address;

    #[test]
    fn test_global_namespace_name() {
        let ns = GlobalNamespace::new();
        assert_eq!(ns.get_name(), "Global");
    }

    #[test]
    fn test_global_namespace_id() {
        let ns = GlobalNamespace::new();
        assert_eq!(ns.get_id(), 0);
    }

    #[test]
    fn test_is_global() {
        let ns = GlobalNamespace::new();
        assert!(ns.is_global());
    }

    #[test]
    fn test_is_not_external() {
        let ns = GlobalNamespace::new();
        assert!(!ns.is_external());
    }

    #[test]
    fn test_parent_is_none() {
        let ns = GlobalNamespace::new();
        assert!(ns.get_parent_namespace().is_none());
    }

    #[test]
    fn test_cannot_set_parent() {
        let mut ns = GlobalNamespace::new();
        let parent = GlobalNamespace::new();
        assert!(ns.set_parent_namespace(&parent).is_err());
    }

    #[test]
    fn test_display() {
        let ns = GlobalNamespace::new();
        assert_eq!(format!("{}", ns), "Global");
    }

    #[test]
    fn test_equality() {
        let a = GlobalNamespace::new();
        let b = GlobalNamespace::new();
        assert_eq!(a, b);
    }

    #[test]
    fn test_hash_consistency() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(GlobalNamespace::new());
        // Another instance should hash the same and not increase the set size.
        assert_eq!(set.len(), 1);
        set.insert(GlobalNamespace::new());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_get_symbol_type() {
        let ns = GlobalNamespace::new();
        assert_eq!(ns.get_symbol().get_symbol_type(), SymbolType::Global);
    }

    #[test]
    fn test_full_name_same_as_name() {
        let ns = GlobalNamespace::new();
        assert_eq!(ns.get_name_full(true), "Global");
        assert_eq!(ns.get_name_full(false), "Global");
    }

    #[test]
    fn test_empty_body() {
        let ns = GlobalNamespace::new();
        assert!(ns.body().is_empty());
        assert!(ns.get_body().is_empty());
    }

    #[test]
    fn test_with_body() {
        let mut body = AddressSet::new();
        body.add_range(Address::new(0x100), Address::new(0x200));
        let ns = GlobalNamespace::with_body(body);
        assert!(!ns.body().is_empty());
        assert!(ns.contains_address(&Address::new(0x150)));
        assert!(!ns.contains_address(&Address::new(0x300)));
    }

    #[test]
    fn test_set_body() {
        let mut ns = GlobalNamespace::new();
        assert!(ns.body().is_empty());
        let mut body = AddressSet::new();
        body.add_range(Address::new(0x1000), Address::new(0x2000));
        ns.set_body(body);
        assert!(!ns.body().is_empty());
        assert!(ns.contains_address(&Address::new(0x1500)));
    }
}
