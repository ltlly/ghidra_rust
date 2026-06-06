//! Function manager for trace program views.
//!
//! Ported from Ghidra's `DBTraceProgramViewFunctionManager` in
//! `ghidra.trace.database.program`. Provides function management
//! for a single snapshot of a trace, adapting the trace's code
//! manager to the Ghidra Program FunctionManager interface.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};


/// A function entry in a trace program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewFunction {
    /// Unique key for this function.
    pub key: i64,
    /// The entry point address offset.
    pub entry_point: u64,
    /// The address space name.
    pub space: String,
    /// The function name.
    pub name: String,
    /// The calling convention name.
    pub calling_convention: String,
    /// The return type.
    pub return_type: String,
    /// The size of the function body in bytes.
    pub body_size: u64,
    /// Whether this is a thunk function.
    pub is_thunk: bool,
    /// Whether this is an external function.
    pub is_external: bool,
    /// The snap at which this function was observed.
    pub snap: i64,
    /// The namespace path.
    pub namespace: String,
}

impl ProgramViewFunction {
    /// Create a new function entry.
    pub fn new(
        key: i64,
        entry_point: u64,
        space: impl Into<String>,
        name: impl Into<String>,
        snap: i64,
    ) -> Self {
        Self {
            key,
            entry_point,
            space: space.into(),
            name: name.into(),
            calling_convention: "default".to_string(),
            return_type: "void".to_string(),
            body_size: 0,
            is_thunk: false,
            is_external: false,
            snap,
            namespace: "Global".to_string(),
        }
    }

    /// Set the calling convention.
    pub fn with_calling_convention(mut self, cc: impl Into<String>) -> Self {
        self.calling_convention = cc.into();
        self
    }

    /// Set the return type.
    pub fn with_return_type(mut self, ty: impl Into<String>) -> Self {
        self.return_type = ty.into();
        self
    }

    /// Set the body size.
    pub fn with_body_size(mut self, size: u64) -> Self {
        self.body_size = size;
        self
    }

    /// Mark as thunk.
    pub fn as_thunk(mut self) -> Self {
        self.is_thunk = true;
        self
    }

    /// Mark as external.
    pub fn as_external(mut self) -> Self {
        self.is_external = true;
        self
    }
}

/// Function manager for a trace program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewFunctionManager {
    /// Functions indexed by entry point.
    functions: BTreeMap<u64, ProgramViewFunction>,
    /// The snap this view is for.
    snap: i64,
    /// Next function key.
    next_key: i64,
}

impl ProgramViewFunctionManager {
    /// Create a new function manager.
    pub fn new(snap: i64) -> Self {
        Self {
            functions: BTreeMap::new(),
            snap,
            next_key: 1,
        }
    }

    /// Add a function.
    pub fn add_function(&mut self, mut func: ProgramViewFunction) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        func.key = key;
        func.snap = self.snap;
        let entry = func.entry_point;
        self.functions.insert(entry, func);
        key
    }

    /// Get a function by entry point.
    pub fn get_function_at(&self, entry_point: u64) -> Option<&ProgramViewFunction> {
        self.functions.get(&entry_point)
    }

    /// Get the function containing the given address.
    pub fn get_function_containing(&self, address: u64) -> Option<&ProgramViewFunction> {
        self.functions
            .range(..=address)
            .next_back()
            .map(|(_, f)| f)
            .filter(|f| address >= f.entry_point && address < f.entry_point + f.body_size)
    }

    /// Get all functions.
    pub fn all_functions(&self) -> Vec<&ProgramViewFunction> {
        self.functions.values().collect()
    }

    /// Get the function count.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Remove a function by entry point.
    pub fn remove_function(&mut self, entry_point: u64) -> Option<ProgramViewFunction> {
        self.functions.remove(&entry_point)
    }

    /// Check if an address is a function entry point.
    pub fn is_function_entry(&self, address: u64) -> bool {
        self.functions.contains_key(&address)
    }

    /// Get all external functions.
    pub fn external_functions(&self) -> Vec<&ProgramViewFunction> {
        self.functions.values().filter(|f| f.is_external).collect()
    }

    /// Get all thunk functions.
    pub fn thunk_functions(&self) -> Vec<&ProgramViewFunction> {
        self.functions.values().filter(|f| f.is_thunk).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_new() {
        let f = ProgramViewFunction::new(1, 0x1000, "ram", "main", 0);
        assert_eq!(f.entry_point, 0x1000);
        assert_eq!(f.name, "main");
        assert_eq!(f.calling_convention, "default");
    }

    #[test]
    fn test_function_builder() {
        let f = ProgramViewFunction::new(1, 0x1000, "ram", "foo", 0)
            .with_calling_convention("cdecl")
            .with_return_type("int")
            .with_body_size(64);
        assert_eq!(f.calling_convention, "cdecl");
        assert_eq!(f.return_type, "int");
        assert_eq!(f.body_size, 64);
    }

    #[test]
    fn test_function_manager_add_and_get() {
        let mut mgr = ProgramViewFunctionManager::new(0);
        let key = mgr.add_function(ProgramViewFunction::new(0, 0x1000, "ram", "main", 0));
        assert_eq!(key, 1);
        let f = mgr.get_function_at(0x1000).unwrap();
        assert_eq!(f.name, "main");
    }

    #[test]
    fn test_function_manager_containing() {
        let mut mgr = ProgramViewFunctionManager::new(0);
        let mut f = ProgramViewFunction::new(0, 0x1000, "ram", "main", 0);
        f.body_size = 64;
        mgr.add_function(f);
        assert!(mgr.get_function_containing(0x1020).is_some());
        assert!(mgr.get_function_containing(0x2000).is_none());
    }

    #[test]
    fn test_function_manager_is_entry() {
        let mut mgr = ProgramViewFunctionManager::new(0);
        mgr.add_function(ProgramViewFunction::new(0, 0x1000, "ram", "main", 0));
        assert!(mgr.is_function_entry(0x1000));
        assert!(!mgr.is_function_entry(0x1001));
    }

    #[test]
    fn test_function_manager_count() {
        let mut mgr = ProgramViewFunctionManager::new(0);
        mgr.add_function(ProgramViewFunction::new(0, 0x1000, "ram", "a", 0));
        mgr.add_function(ProgramViewFunction::new(0, 0x2000, "ram", "b", 0));
        assert_eq!(mgr.function_count(), 2);
    }

    #[test]
    fn test_function_manager_external() {
        let mut mgr = ProgramViewFunctionManager::new(0);
        mgr.add_function(ProgramViewFunction::new(0, 0x1000, "ram", "local", 0));
        mgr.add_function(ProgramViewFunction::new(0, 0, "external", "printf", 0).as_external());
        assert_eq!(mgr.external_functions().len(), 1);
    }

    #[test]
    fn test_function_manager_remove() {
        let mut mgr = ProgramViewFunctionManager::new(0);
        mgr.add_function(ProgramViewFunction::new(0, 0x1000, "ram", "a", 0));
        assert!(mgr.remove_function(0x1000).is_some());
        assert_eq!(mgr.function_count(), 0);
    }
}
