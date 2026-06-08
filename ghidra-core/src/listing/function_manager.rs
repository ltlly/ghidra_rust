//! Function manager for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.listing.FunctionManager`.
//!
//! Provides methods to query, create, remove, and iterate over functions,
//! and build call trees.

use crate::addr::Address;
use crate::addr::AddressRange;
use crate::listing::function::Function;
use crate::listing::FunctionTag;
use crate::symbol::SourceType;
use std::collections::{HashMap, HashSet};

/// Manages functions in a program.
///
/// Corresponds to Ghidra's `FunctionManager` interface. Provides methods to
/// query, create, remove, and iterate over functions, and build call trees.
#[derive(Debug, Clone, Default)]
pub struct FunctionManager {
    /// Functions indexed by entry point.
    functions: HashMap<Address, Function>,
    /// Functions indexed by name.
    by_name: HashMap<String, Vec<Address>>,
    /// Known calling convention names.
    calling_convention_names: Vec<String>,
    /// Function tag manager.
    tags: HashMap<String, FunctionTag>,
}

impl FunctionManager {
    /// Create a new empty function manager.
    pub fn new() -> Self {
        Self::default()
    }

    // ---- Function CRUD ----

    /// Create a new function.
    pub fn create_function(
        &mut self,
        name: Option<&str>,
        entry_point: Address,
        body: AddressRange,
        _source: SourceType,
    ) -> Result<&Function, String> {
        let func_name = name.unwrap_or("").to_string();
        if self.functions.contains_key(&entry_point) {
            return Err(format!("Function already exists at {}", entry_point));
        }
        let func = Function::new(func_name.clone(), entry_point, body);
        self.functions.insert(entry_point, func);
        self.by_name
            .entry(func_name)
            .or_default()
            .push(entry_point);
        Ok(self.functions.get(&entry_point).unwrap())
    }

    /// Remove a function by entry point.
    pub fn remove_function(&mut self, entry_point: &Address) -> bool {
        if let Some(func) = self.functions.remove(entry_point) {
            if let Some(addrs) = self.by_name.get_mut(&func.name) {
                addrs.retain(|a| a != entry_point);
                if addrs.is_empty() {
                    self.by_name.remove(&func.name);
                }
            }
            true
        } else {
            false
        }
    }

    /// Get a function by entry point.
    pub fn get_function_at(&self, entry_point: &Address) -> Option<&Function> {
        self.functions.get(entry_point)
    }

    /// Get a mutable reference to a function by entry point.
    pub fn get_function_at_mut(&mut self, entry_point: &Address) -> Option<&mut Function> {
        self.functions.get_mut(entry_point)
    }

    /// Get a function containing an address.
    pub fn get_function_containing(&self, addr: &Address) -> Option<&Function> {
        self.functions
            .values()
            .find(|f| f.contains_address(addr))
    }

    /// Get functions by name.
    pub fn get_functions_by_name(&self, name: &str) -> Vec<&Function> {
        if let Some(addrs) = self.by_name.get(name) {
            addrs
                .iter()
                .filter_map(|a| self.functions.get(a))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all functions.
    pub fn get_functions(&self) -> Vec<&Function> {
        self.functions.values().collect()
    }

    /// Returns true if the manager currently contains no functions.
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Get the first function by entry-point order.
    pub fn get_first_function(&self) -> Option<&Function> {
        self.functions
            .keys()
            .min()
            .and_then(|entry| self.functions.get(entry))
    }

    /// Get the next function after the given entry point.
    pub fn get_function_after(&self, entry_point: &Address) -> Option<&Function> {
        self.functions
            .iter()
            .filter(|(entry, _)| *entry > entry_point)
            .min_by_key(|(entry, _)| *entry)
            .map(|(_, func)| func)
    }

    /// Get all function entry points.
    pub fn get_function_entry_points(&self) -> Vec<Address> {
        self.functions.keys().copied().collect()
    }

    /// Total number of functions.
    pub fn get_function_count(&self) -> usize {
        self.functions.len()
    }

    /// Returns true if a function exists at the entry point.
    pub fn has_function(&self, entry_point: &Address) -> bool {
        self.functions.contains_key(entry_point)
    }

    /// Returns true if the given address is in any function.
    pub fn is_in_function(&self, addr: &Address) -> bool {
        self.functions
            .values()
            .any(|f| f.contains_address(addr))
    }

    // ---- Signature management ----

    /// Get all calling convention names.
    pub fn get_calling_convention_names(&self) -> Vec<&str> {
        self.calling_convention_names
            .iter()
            .map(|s| s.as_str())
            .collect()
    }

    /// Set the calling convention names.
    pub fn set_calling_convention_names(&mut self, names: Vec<String>) {
        self.calling_convention_names = names;
    }

    // ---- Tag management ----

    /// Add a function tag.
    pub fn add_tag(&mut self, tag: FunctionTag) {
        self.tags.insert(tag.get_name().to_string(), tag);
    }

    /// Get a function tag by name.
    pub fn get_tag(&self, name: &str) -> Option<&FunctionTag> {
        self.tags.get(name)
    }

    /// Get all tags.
    pub fn get_all_tags(&self) -> Vec<&FunctionTag> {
        self.tags.values().collect()
    }

    // ---- Call tree ----

    /// Get functions called by the function at entry_point.
    /// (Requires reference/flow data to be populated externally.)
    pub fn get_called_functions(&self, _entry_point: &Address) -> Vec<Address> {
        // In a full implementation this would query references.
        Vec::new()
    }

    /// Get functions that call the function at entry_point.
    pub fn get_calling_functions(&self, _target: &Address) -> Vec<Address> {
        // In a full implementation this would query references.
        Vec::new()
    }

    /// Build the call tree rooted at the given entry point.
    pub fn get_call_tree(&self, root: &Address) -> Vec<(Address, Address)> {
        let mut result = Vec::new();
        let mut visited = HashSet::new();
        self.build_call_tree_recursive(root, &mut result, &mut visited);
        result
    }

    fn build_call_tree_recursive(
        &self,
        current: &Address,
        result: &mut Vec<(Address, Address)>,
        visited: &mut HashSet<Address>,
    ) {
        if !visited.insert(*current) {
            return;
        }
        for callee in self.get_called_functions(current) {
            result.push((*current, callee));
            self.build_call_tree_recursive(&callee, result, visited);
        }
    }
}

/// Alias for backward compatibility. Prefer using `FunctionManager` directly.
pub type InMemoryFunctionManager = FunctionManager;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fm_create_and_remove() {
        let mut mgr = FunctionManager::new();
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        mgr.create_function(Some("main"), Address::new(0x1000), body, SourceType::UserDefined)
            .unwrap();
        assert_eq!(mgr.get_function_count(), 1);
        assert!(mgr.remove_function(&Address::new(0x1000)));
        assert_eq!(mgr.get_function_count(), 0);
    }

    #[test]
    fn test_fm_get_containing() {
        let mut mgr = FunctionManager::new();
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        mgr.create_function(Some("main"), Address::new(0x1000), body, SourceType::UserDefined)
            .unwrap();
        let func = mgr.get_function_containing(&Address::new(0x1010));
        assert!(func.is_some());
        assert_eq!(func.unwrap().name, "main");
    }

    #[test]
    fn test_fm_duplicate_entry() {
        let mut mgr = FunctionManager::new();
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        mgr.create_function(Some("main"), Address::new(0x1000), body, SourceType::UserDefined)
            .unwrap();
        let body2 = AddressRange::new(Address::new(0x1000), Address::new(0x1030));
        assert!(mgr.create_function(Some("other"), Address::new(0x1000), body2, SourceType::UserDefined).is_err());
    }

    #[test]
    fn test_fm_navigation() {
        let mut mgr = FunctionManager::new();
        let body1 = AddressRange::new(Address::new(0x1000), Address::new(0x1005));
        let body2 = AddressRange::new(Address::new(0x2000), Address::new(0x2005));
        assert!(mgr.is_empty());
        mgr.create_function(Some("first"), Address::new(0x1000), body1, SourceType::UserDefined)
            .unwrap();
        mgr.create_function(Some("second"), Address::new(0x2000), body2, SourceType::UserDefined)
            .unwrap();

        assert_eq!(mgr.get_first_function().map(|f| f.name.as_str()), Some("first"));
        assert_eq!(
            mgr.get_function_after(&Address::new(0x1000)).map(|f| f.name.as_str()),
            Some("second")
        );
    }

    #[test]
    fn test_fm_get_by_name() {
        let mut mgr = FunctionManager::new();
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        mgr.create_function(Some("main"), Address::new(0x1000), body, SourceType::UserDefined)
            .unwrap();
        let funcs = mgr.get_functions_by_name("main");
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "main");
    }

    #[test]
    fn test_fm_is_in_function() {
        let mut mgr = FunctionManager::new();
        let body = AddressRange::new(Address::new(0x1000), Address::new(0x1021));
        mgr.create_function(Some("main"), Address::new(0x1000), body, SourceType::UserDefined)
            .unwrap();
        assert!(mgr.is_in_function(&Address::new(0x1010)));
        assert!(!mgr.is_in_function(&Address::new(0x2000)));
    }

    #[test]
    fn test_fm_calling_conventions() {
        let mut mgr = FunctionManager::new();
        mgr.set_calling_convention_names(vec!["__cdecl".to_string(), "__stdcall".to_string()]);
        assert_eq!(mgr.get_calling_convention_names(), vec!["__cdecl", "__stdcall"]);
    }

    #[test]
    fn test_fm_tag_management() {
        let mut mgr = FunctionManager::new();
        mgr.add_tag(FunctionTag::new(0, "inline"));
        mgr.add_tag(FunctionTag::new(1, "noreturn"));
        assert!(mgr.get_tag("inline").is_some());
        assert_eq!(mgr.get_all_tags().len(), 2);
    }
}
