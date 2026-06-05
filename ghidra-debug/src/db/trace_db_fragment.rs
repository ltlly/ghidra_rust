//! Database-backed program view fragment and function manager.
//!
//! Ported from Ghidra's `DBTraceProgramViewFragment` and
//! `DBTraceProgramViewFunctionManager`.
//!
//! Provides fragment management (grouping code regions into logical units)
//! and function management for program views on top of trace data.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A unique identifier for a fragment in a program view.
pub type FragmentId = u64;

/// A unique identifier for a function in a program view.
pub type FunctionId = u64;

/// A fragment groups a contiguous region of code into a logical unit.
///
/// In Ghidra, fragments are the primary way to organize code within
/// a program. In a trace context, fragments may span multiple snaps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewFragment {
    /// The unique fragment ID.
    pub id: FragmentId,
    /// The name of this fragment.
    pub name: String,
    /// The address space this fragment lives in.
    pub space_name: String,
    /// The minimum address offset in this fragment.
    pub min_offset: u64,
    /// The maximum address offset in this fragment.
    pub max_offset: u64,
    /// The parent fragment ID (None for root fragments).
    pub parent_id: Option<FragmentId>,
    /// Whether this fragment is currently expanded in the UI.
    pub expanded: bool,
}

impl ProgramViewFragment {
    /// Create a new fragment.
    pub fn new(
        id: FragmentId,
        name: impl Into<String>,
        space_name: impl Into<String>,
        min_offset: u64,
        max_offset: u64,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            space_name: space_name.into(),
            min_offset,
            max_offset,
            parent_id: None,
            expanded: true,
        }
    }

    /// Set the parent fragment.
    pub fn with_parent(mut self, parent_id: FragmentId) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Check if an offset falls within this fragment.
    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.min_offset && offset <= self.max_offset
    }

    /// Get the size of this fragment in bytes.
    pub fn size(&self) -> u64 {
        self.max_offset.saturating_sub(self.min_offset)
    }
}

/// The type of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FunctionType {
    /// A regular function.
    Regular,
    /// A library function.
    Library,
    /// An external function (imported).
    External,
    /// A thunk function (trampoline).
    Thunk,
    /// An inline function.
    Inline,
}

/// Calling convention for a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallingConvention {
    /// Default (unknown) calling convention.
    Default,
    /// cdecl calling convention.
    Cdecl,
    /// stdcall calling convention.
    Stdcall,
    /// fastcall calling convention.
    Fastcall,
    /// System V AMD64 ABI.
    SystemV,
    /// ARM calling convention.
    ArmCall,
    /// Custom / other calling convention.
    Other,
}

/// A function in a program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewFunction {
    /// The unique function ID.
    pub id: FunctionId,
    /// The name of this function.
    pub name: String,
    /// The entry point address.
    pub entry_offset: u64,
    /// The address space this function lives in.
    pub space_name: String,
    /// The type of function.
    pub function_type: FunctionType,
    /// The calling convention.
    pub calling_convention: CallingConvention,
    /// The body ranges (offsets) of this function.
    pub body_ranges: Vec<(u64, u64)>,
    /// The parameter count.
    pub param_count: u32,
    /// Whether this function has a return value.
    pub has_return: bool,
    /// Whether this function is a "thunk" (e.g., PLT entry).
    pub is_thunk: bool,
    /// The lifespan of this function in the trace.
    pub lifespan: Lifespan,
}

impl ProgramViewFunction {
    /// Create a new function.
    pub fn new(
        id: FunctionId,
        name: impl Into<String>,
        entry_offset: u64,
        space_name: impl Into<String>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            entry_offset,
            space_name: space_name.into(),
            function_type: FunctionType::Regular,
            calling_convention: CallingConvention::Default,
            body_ranges: Vec::new(),
            param_count: 0,
            has_return: true,
            is_thunk: false,
            lifespan: Lifespan::ALL,
        }
    }

    /// Set the function type.
    pub fn with_type(mut self, function_type: FunctionType) -> Self {
        self.function_type = function_type;
        self
    }

    /// Set the calling convention.
    pub fn with_calling_convention(mut self, convention: CallingConvention) -> Self {
        self.calling_convention = convention;
        self
    }

    /// Add a body range.
    pub fn add_body_range(&mut self, start: u64, end: u64) {
        self.body_ranges.push((start, end));
    }

    /// Check if an offset is within this function's body.
    pub fn contains_offset(&self, offset: u64) -> bool {
        self.body_ranges
            .iter()
            .any(|&(start, end)| offset >= start && offset <= end)
    }

    /// Get the total size of the function body.
    pub fn body_size(&self) -> u64 {
        self.body_ranges
            .iter()
            .map(|&(start, end)| end.saturating_sub(start))
            .sum()
    }
}

/// The database-backed fragment manager for program views.
#[derive(Debug)]
pub struct DBTraceProgramViewFragmentManager {
    /// Fragments by ID.
    fragments: HashMap<FragmentId, ProgramViewFragment>,
    /// Next fragment ID.
    next_id: FragmentId,
    /// Root fragment ID.
    root_id: FragmentId,
}

impl DBTraceProgramViewFragmentManager {
    /// Create a new fragment manager with a root fragment.
    pub fn new(root_name: impl Into<String>) -> Self {
        let root_id = 1;
        let root = ProgramViewFragment::new(root_id, root_name, "ram", 0, u64::MAX);
        let mut fragments = HashMap::new();
        fragments.insert(root_id, root);
        Self {
            fragments,
            next_id: 2,
            root_id,
        }
    }

    /// Get the root fragment ID.
    pub fn root_id(&self) -> FragmentId {
        self.root_id
    }

    /// Create a new fragment.
    pub fn create_fragment(
        &mut self,
        name: impl Into<String>,
        space_name: impl Into<String>,
        min_offset: u64,
        max_offset: u64,
        parent_id: FragmentId,
    ) -> FragmentId {
        let id = self.next_id;
        self.next_id += 1;
        let fragment = ProgramViewFragment::new(id, name, space_name, min_offset, max_offset)
            .with_parent(parent_id);
        self.fragments.insert(id, fragment);
        id
    }

    /// Get a fragment by ID.
    pub fn get_fragment(&self, id: FragmentId) -> Option<&ProgramViewFragment> {
        self.fragments.get(&id)
    }

    /// Get child fragments of a parent.
    pub fn child_fragments(&self, parent_id: FragmentId) -> Vec<&ProgramViewFragment> {
        self.fragments
            .values()
            .filter(|f| f.parent_id == Some(parent_id))
            .collect()
    }

    /// Get all fragments.
    pub fn all_fragments(&self) -> Vec<&ProgramViewFragment> {
        self.fragments.values().collect()
    }

    /// Get the number of fragments.
    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }

    /// Delete a fragment and all its children.
    pub fn delete_fragment(&mut self, id: FragmentId) -> bool {
        if id == self.root_id {
            return false; // Cannot delete root
        }
        // Collect children first
        let children: Vec<FragmentId> = self
            .fragments
            .values()
            .filter(|f| f.parent_id == Some(id))
            .map(|f| f.id)
            .collect();
        for child_id in children {
            self.delete_fragment(child_id);
        }
        self.fragments.remove(&id).is_some()
    }

    /// Find fragment at a given offset.
    pub fn find_fragment_at(&self, space_name: &str, offset: u64) -> Option<&ProgramViewFragment> {
        self.fragments.values().find(|f| {
            f.space_name == space_name && f.contains_offset(offset) && f.id != self.root_id
        })
    }
}

/// The database-backed function manager for program views.
#[derive(Debug)]
pub struct DBTraceProgramViewFunctionManager {
    /// Functions by ID.
    functions: HashMap<FunctionId, ProgramViewFunction>,
    /// Index of functions by entry point (space, offset).
    by_entry: HashMap<(String, u64), FunctionId>,
    /// Next function ID.
    next_id: FunctionId,
}

impl DBTraceProgramViewFunctionManager {
    /// Create a new function manager.
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
            by_entry: HashMap::new(),
            next_id: 1,
        }
    }

    /// Create a new function.
    pub fn create_function(
        &mut self,
        name: impl Into<String>,
        entry_offset: u64,
        space_name: impl Into<String>,
    ) -> FunctionId {
        let space_name = space_name.into();
        // Check if function already exists at this entry point
        if let Some(&id) = self.by_entry.get(&(space_name.clone(), entry_offset)) {
            return id;
        }
        let id = self.next_id;
        self.next_id += 1;
        let func = ProgramViewFunction::new(id, name, entry_offset, &space_name);
        self.by_entry.insert((space_name, entry_offset), id);
        self.functions.insert(id, func);
        id
    }

    /// Get a function by ID.
    pub fn get_function(&self, id: FunctionId) -> Option<&ProgramViewFunction> {
        self.functions.get(&id)
    }

    /// Get a mutable reference to a function by ID.
    pub fn get_function_mut(&mut self, id: FunctionId) -> Option<&mut ProgramViewFunction> {
        self.functions.get_mut(&id)
    }

    /// Get a function by entry point.
    pub fn get_function_at(&self, space_name: &str, entry_offset: u64) -> Option<&ProgramViewFunction> {
        let id = self.by_entry.get(&(space_name.to_string(), entry_offset))?;
        self.functions.get(id)
    }

    /// Get all functions.
    pub fn all_functions(&self) -> Vec<&ProgramViewFunction> {
        self.functions.values().collect()
    }

    /// Get the number of functions.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Delete a function.
    pub fn delete_function(&mut self, id: FunctionId) -> bool {
        if let Some(func) = self.functions.remove(&id) {
            self.by_entry.remove(&(func.space_name, func.entry_offset));
            true
        } else {
            false
        }
    }

    /// Find functions containing a given address.
    pub fn find_functions_containing(&self, space_name: &str, offset: u64) -> Vec<&ProgramViewFunction> {
        self.functions
            .values()
            .filter(|f| f.space_name == space_name && f.contains_offset(offset))
            .collect()
    }

    /// Get functions in an address range.
    pub fn functions_in_range(
        &self,
        space_name: &str,
        min_offset: u64,
        max_offset: u64,
    ) -> Vec<&ProgramViewFunction> {
        self.functions
            .values()
            .filter(|f| {
                f.space_name == space_name
                    && f.entry_offset >= min_offset
                    && f.entry_offset <= max_offset
            })
            .collect()
    }
}

impl Default for DBTraceProgramViewFunctionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragment_creation() {
        let frag = ProgramViewFragment::new(1, "main", "ram", 0x400000, 0x401000);
        assert_eq!(frag.name, "main");
        assert!(frag.contains_offset(0x400500));
        assert!(!frag.contains_offset(0x300000));
        assert_eq!(frag.size(), 0x1000);
    }

    #[test]
    fn test_fragment_with_parent() {
        let frag = ProgramViewFragment::new(2, "sub", "ram", 0x400000, 0x400500)
            .with_parent(1);
        assert_eq!(frag.parent_id, Some(1));
    }

    #[test]
    fn test_fragment_manager_create() {
        let mut mgr = DBTraceProgramViewFragmentManager::new("My Program");
        assert_eq!(mgr.fragment_count(), 1); // Root fragment
        assert_eq!(mgr.root_id(), 1);

        let id = mgr.create_fragment("text", "ram", 0x400000, 0x401000, 1);
        assert_eq!(mgr.fragment_count(), 2);
        assert!(mgr.get_fragment(id).is_some());
    }

    #[test]
    fn test_fragment_manager_children() {
        let mut mgr = DBTraceProgramViewFragmentManager::new("root");
        let root = mgr.root_id();
        let _child1 = mgr.create_fragment("child1", "ram", 0, 100, root);
        let _child2 = mgr.create_fragment("child2", "ram", 100, 200, root);

        let children = mgr.child_fragments(root);
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_fragment_manager_delete() {
        let mut mgr = DBTraceProgramViewFragmentManager::new("root");
        let id = mgr.create_fragment("temp", "ram", 0, 100, 1);
        assert_eq!(mgr.fragment_count(), 2);
        assert!(mgr.delete_fragment(id));
        assert_eq!(mgr.fragment_count(), 1);
    }

    #[test]
    fn test_fragment_manager_delete_root_fails() {
        let mut mgr = DBTraceProgramViewFragmentManager::new("root");
        assert!(!mgr.delete_fragment(1));
    }

    #[test]
    fn test_function_creation() {
        let func = ProgramViewFunction::new(1, "main", 0x400000, "ram")
            .with_type(FunctionType::Regular)
            .with_calling_convention(CallingConvention::Cdecl);
        assert_eq!(func.name, "main");
        assert_eq!(func.entry_offset, 0x400000);
        assert_eq!(func.function_type, FunctionType::Regular);
        assert_eq!(func.calling_convention, CallingConvention::Cdecl);
    }

    #[test]
    fn test_function_body_ranges() {
        let mut func = ProgramViewFunction::new(1, "func", 0x400000, "ram");
        func.add_body_range(0x400000, 0x400100);
        func.add_body_range(0x400200, 0x400300);

        assert!(func.contains_offset(0x400050));
        assert!(func.contains_offset(0x400250));
        assert!(!func.contains_offset(0x400150));
        assert_eq!(func.body_size(), 0x200);
    }

    #[test]
    fn test_function_manager_create() {
        let mut mgr = DBTraceProgramViewFunctionManager::new();
        let id = mgr.create_function("main", 0x400000, "ram");
        assert_eq!(mgr.function_count(), 1);
        assert!(mgr.get_function(id).is_some());
        assert!(mgr.get_function_at("ram", 0x400000).is_some());
    }

    #[test]
    fn test_function_manager_dedup() {
        let mut mgr = DBTraceProgramViewFunctionManager::new();
        let id1 = mgr.create_function("main", 0x400000, "ram");
        let id2 = mgr.create_function("main", 0x400000, "ram");
        assert_eq!(id1, id2);
        assert_eq!(mgr.function_count(), 1);
    }

    #[test]
    fn test_function_manager_delete() {
        let mut mgr = DBTraceProgramViewFunctionManager::new();
        let id = mgr.create_function("temp", 0x400000, "ram");
        assert!(mgr.delete_function(id));
        assert_eq!(mgr.function_count(), 0);
        assert!(mgr.get_function_at("ram", 0x400000).is_none());
    }

    #[test]
    fn test_function_manager_find_containing() {
        let mut mgr = DBTraceProgramViewFunctionManager::new();
        let id = mgr.create_function("func", 0x400000, "ram");
        mgr.get_function_mut(id).unwrap().add_body_range(0x400000, 0x401000);

        let found = mgr.find_functions_containing("ram", 0x400500);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "func");

        let not_found = mgr.find_functions_containing("ram", 0x500000);
        assert_eq!(not_found.len(), 0);
    }

    #[test]
    fn test_function_manager_range_query() {
        let mut mgr = DBTraceProgramViewFunctionManager::new();
        mgr.create_function("a", 0x400000, "ram");
        mgr.create_function("b", 0x401000, "ram");
        mgr.create_function("c", 0x500000, "ram");

        let funcs = mgr.functions_in_range("ram", 0x400000, 0x401FFF);
        assert_eq!(funcs.len(), 2);
    }

    #[test]
    fn test_function_type_variants() {
        assert_ne!(FunctionType::Regular, FunctionType::Library);
        assert_ne!(FunctionType::External, FunctionType::Thunk);
    }

    #[test]
    fn test_calling_convention_variants() {
        assert_ne!(CallingConvention::Cdecl, CallingConvention::Stdcall);
        assert_eq!(CallingConvention::Default, CallingConvention::Default);
    }
}
