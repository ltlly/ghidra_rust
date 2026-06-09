//! Code comparison view registry and lifecycle management.
//!
//! Ported from Ghidra's `CodeComparisonView` extension point mechanism in
//! `ghidra.features.base.codecompare.panel`.
//!
//! In Ghidra, code comparison views are discovered via `ClassSearcher` as
//! extension points. Each view type (Listing, Decompiler, FunctionGraph)
//! registers itself and can be instantiated on demand. This module provides
//! the Rust equivalent: a registry of view factories that can create
//! comparison view instances.
//!
//! # Key types
//!
//! - [`ViewKind`] -- enumeration of built-in comparison view types
//! - [`ViewFactory`] -- trait for creating comparison view instances
//! - [`ViewRegistry`] -- global registry of available view factories
//! - [`ComparisonViewHandle`] -- a handle to a managed view instance

use super::panel::code_comparison_view::{
    CodeComparisonView, CodeComparisonViewState, ManagedComparisonView, ViewOrientation,
};
use super::panel::{ComparisonData, ComparisonDataPair, ComparisonViewState, ProgramInfo};
use super::model::ComparisonSide;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Built-in comparison view types.
///
/// This enum mirrors the view types that Ghidra discovers via `ClassSearcher`.
/// Each variant corresponds to a specific comparison strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewKind {
    /// Listing (disassembly) comparison view.
    ///
    /// Compares two disassembly listings side by side, highlighting
    /// byte-level, mnemonic-level, and operand-level differences.
    Listing,

    /// Decompiler comparison view.
    ///
    /// Compares two decompiler outputs side by side, using the Pinning
    /// algorithm to match tokens across potentially different architectures.
    Decompiler,

    /// Function graph (CFG) comparison view.
    ///
    /// Compares two control flow graphs, matching basic blocks by
    /// structure and instruction similarity.
    FunctionGraph,
}

impl ViewKind {
    /// A human-readable label for this view kind.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Listing => "Listing View",
            Self::Decompiler => "Decompiler View",
            Self::FunctionGraph => "Function Graph View",
        }
    }

    /// The sort order for this view kind (used for tab ordering).
    pub fn sort_order(&self) -> usize {
        match self {
            Self::Listing => 0,
            Self::Decompiler => 1,
            Self::FunctionGraph => 2,
        }
    }

    /// Whether this view type supports cross-architecture comparison.
    pub fn supports_cross_arch(&self) -> bool {
        match self {
            Self::Listing => false,
            Self::Decompiler => true,
            Self::FunctionGraph => false,
        }
    }

    /// All built-in view kinds.
    pub fn all() -> &'static [ViewKind] {
        &[Self::Listing, Self::Decompiler, Self::FunctionGraph]
    }
}

/// Trait for factories that create comparison view instances.
///
/// In Ghidra, views are created by `ClassSearcher`. In Rust, view
/// factories are registered with a [`ViewRegistry`] and can create
/// new view instances on demand.
pub trait ViewFactory: Send + Sync {
    /// Get the kind of view this factory creates.
    fn kind(&self) -> ViewKind;

    /// Get the display name for this view type.
    fn name(&self) -> &str {
        self.kind().label()
    }

    /// Create a new comparison view state.
    fn create_view(&self, owner: &str) -> ManagedComparisonView;
}

/// A handle to a managed comparison view instance.
///
/// Each handle corresponds to one tab in the comparison panel. The handle
/// tracks the view's lifecycle state and provides access to the underlying
/// view.
pub struct ComparisonViewHandle {
    /// Unique identifier for this handle.
    id: u64,
    /// The kind of view.
    kind: ViewKind,
    /// The view's logical state.
    state: ManagedComparisonView,
    /// Whether this view is currently active (visible tab).
    active: bool,
    /// Whether this view has been disposed.
    disposed: bool,
}

impl std::fmt::Debug for ComparisonViewHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComparisonViewHandle")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("active", &self.active)
            .field("disposed", &self.disposed)
            .finish()
    }
}

impl ComparisonViewHandle {
    /// Create a new view handle.
    pub fn new(id: u64, kind: ViewKind, owner: &str) -> Self {
        Self {
            id,
            kind,
            state: ManagedComparisonView::new(kind.label(), owner),
            active: false,
            disposed: false,
        }
    }

    /// Get the handle ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the view kind.
    pub fn kind(&self) -> ViewKind {
        self.kind
    }

    /// Get the view state.
    pub fn state(&self) -> &ManagedComparisonView {
        &self.state
    }

    /// Get a mutable reference to the view state.
    pub fn state_mut(&mut self) -> &mut ManagedComparisonView {
        &mut self.state
    }

    /// Whether this view is currently active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Set the active state.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
        self.state.state_mut().set_visible(active);
    }

    /// Whether this view has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of this view.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.active = false;
    }

    /// Load comparison data into this view.
    pub fn load_comparisons(
        &mut self,
        left: Box<dyn ComparisonData>,
        right: Box<dyn ComparisonData>,
    ) {
        self.state = ManagedComparisonView::new(self.kind.label(), self.state.state().owner());
        // In a full implementation, this would propagate to the actual view
    }

    /// Clear comparison data.
    pub fn clear_comparisons(&mut self) {
        self.state = ManagedComparisonView::new(self.kind.label(), self.state.state().owner());
    }
}

/// Registry of available view factories.
///
/// View factories are registered once at startup and used to create
/// view instances when the user opens a comparison panel.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::code_comparison_view::*;
///
/// let mut registry = ViewRegistry::new();
/// // In a real application, register factory implementations here.
///
/// // Enumerate available view kinds
/// let kinds: Vec<ViewKind> = ViewKind::all().to_vec();
/// assert_eq!(kinds.len(), 3);
/// ```
pub struct ViewRegistry {
    factories: HashMap<ViewKind, Arc<dyn ViewFactory>>,
    next_handle_id: u64,
}

impl ViewRegistry {
    /// Create a new empty view registry.
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
            next_handle_id: 1,
        }
    }

    /// Register a view factory.
    pub fn register(&mut self, factory: Arc<dyn ViewFactory>) {
        self.factories.insert(factory.kind(), factory);
    }

    /// Check if a view kind is registered.
    pub fn has_view(&self, kind: ViewKind) -> bool {
        self.factories.contains_key(&kind)
    }

    /// Get the list of registered view kinds.
    pub fn available_views(&self) -> Vec<ViewKind> {
        let mut kinds: Vec<ViewKind> = self.factories.keys().copied().collect();
        kinds.sort_by_key(|k| k.sort_order());
        kinds
    }

    /// Create a new view handle for the given kind.
    ///
    /// Returns `None` if no factory is registered for the given kind.
    pub fn create_handle(&mut self, kind: ViewKind, owner: &str) -> Option<ComparisonViewHandle> {
        if self.factories.contains_key(&kind) {
            let id = self.next_handle_id;
            self.next_handle_id += 1;
            Some(ComparisonViewHandle::new(id, kind, owner))
        } else {
            None
        }
    }

    /// Create handles for all registered view kinds.
    pub fn create_all_handles(&mut self, owner: &str) -> Vec<ComparisonViewHandle> {
        let kinds: Vec<ViewKind> = self.available_views();
        kinds
            .into_iter()
            .filter_map(|kind| self.create_handle(kind, owner))
            .collect()
    }

    /// Get the number of registered factories.
    pub fn factory_count(&self) -> usize {
        self.factories.len()
    }
}

impl Default for ViewRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ViewRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewRegistry")
            .field("factory_count", &self.factories.len())
            .field("available", &self.available_views())
            .finish()
    }
}

/// A managed collection of view handles for a comparison session.
///
/// Manages the lifecycle of all comparison views in a single comparison
/// panel. Handles tab switching, data propagation, and cleanup.
#[derive(Debug)]
pub struct ComparisonViewManager {
    /// All view handles, ordered by creation.
    handles: Vec<ComparisonViewHandle>,
    /// Index of the currently active view, if any.
    active_index: Option<usize>,
}

impl ComparisonViewManager {
    /// Create a new empty view manager.
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
            active_index: None,
        }
    }

    /// Create a view manager from a set of handles.
    pub fn from_handles(handles: Vec<ComparisonViewHandle>) -> Self {
        let mut manager = Self {
            handles,
            active_index: None,
        };
        // Activate the first non-disposed handle
        if let Some(idx) = manager.handles.iter().position(|h| !h.is_disposed()) {
            manager.handles[idx].set_active(true);
            manager.active_index = Some(idx);
        }
        manager
    }

    /// Add a view handle.
    pub fn add(&mut self, handle: ComparisonViewHandle) {
        self.handles.push(handle);
    }

    /// Get the number of handles.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Check if the manager has no handles.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Get a reference to the active view handle.
    pub fn active(&self) -> Option<&ComparisonViewHandle> {
        self.active_index.and_then(|idx| self.handles.get(idx))
    }

    /// Get a mutable reference to the active view handle.
    pub fn active_mut(&mut self) -> Option<&mut ComparisonViewHandle> {
        self.active_index.and_then(|idx| self.handles.get_mut(idx))
    }

    /// Set the active view by index.
    ///
    /// Returns true if the view was successfully activated.
    pub fn set_active(&mut self, index: usize) -> bool {
        if index >= self.handles.len() || self.handles[index].is_disposed() {
            return false;
        }

        // Deactivate the current active view
        if let Some(old_idx) = self.active_index {
            if old_idx < self.handles.len() {
                self.handles[old_idx].set_active(false);
            }
        }

        self.handles[index].set_active(true);
        self.active_index = Some(index);
        true
    }

    /// Set the active view by kind.
    ///
    /// Returns true if a view of the given kind was found and activated.
    pub fn set_active_by_kind(&mut self, kind: ViewKind) -> bool {
        if let Some(idx) = self.handles.iter().position(|h| h.kind() == kind && !h.is_disposed()) {
            self.set_active(idx)
        } else {
            false
        }
    }

    /// Get a reference to a handle by index.
    pub fn get(&self, index: usize) -> Option<&ComparisonViewHandle> {
        self.handles.get(index)
    }

    /// Get a mutable reference to a handle by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut ComparisonViewHandle> {
        self.handles.get_mut(index)
    }

    /// Get a handle by kind.
    pub fn get_by_kind(&self, kind: ViewKind) -> Option<&ComparisonViewHandle> {
        self.handles.iter().find(|h| h.kind() == kind && !h.is_disposed())
    }

    /// Get a mutable handle by kind.
    pub fn get_by_kind_mut(&mut self, kind: ViewKind) -> Option<&mut ComparisonViewHandle> {
        self.handles.iter_mut().find(|h| h.kind() == kind && !h.is_disposed())
    }

    /// Iterate over all handles.
    pub fn iter(&self) -> impl Iterator<Item = &ComparisonViewHandle> {
        self.handles.iter().filter(|h| !h.is_disposed())
    }

    /// Dispose of all handles.
    pub fn dispose_all(&mut self) {
        for handle in &mut self.handles {
            handle.dispose();
        }
        self.active_index = None;
    }
}

impl Default for ComparisonViewManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::panel::{AddressSet, EmptyComparisonData, FunctionComparisonData, FunctionComparisonInfo, ProgramInfo};

    fn make_program(id: u64, path: &str, name: &str) -> ProgramInfo {
        ProgramInfo::new(id, path, name)
    }

    fn make_func_data(name: &str, entry: u64, prog: ProgramInfo) -> FunctionComparisonData {
        let info = FunctionComparisonInfo::new(name, entry, entry, entry + 0x100, prog);
        FunctionComparisonData::new(info)
    }

    // --- ViewKind tests ---

    #[test]
    fn test_view_kind_label() {
        assert_eq!(ViewKind::Listing.label(), "Listing View");
        assert_eq!(ViewKind::Decompiler.label(), "Decompiler View");
        assert_eq!(ViewKind::FunctionGraph.label(), "Function Graph View");
    }

    #[test]
    fn test_view_kind_sort_order() {
        assert!(ViewKind::Listing.sort_order() < ViewKind::Decompiler.sort_order());
        assert!(ViewKind::Decompiler.sort_order() < ViewKind::FunctionGraph.sort_order());
    }

    #[test]
    fn test_view_kind_cross_arch() {
        assert!(!ViewKind::Listing.supports_cross_arch());
        assert!(ViewKind::Decompiler.supports_cross_arch());
        assert!(!ViewKind::FunctionGraph.supports_cross_arch());
    }

    #[test]
    fn test_view_kind_all() {
        assert_eq!(ViewKind::all().len(), 3);
    }

    // --- ComparisonViewHandle tests ---

    #[test]
    fn test_handle_new() {
        let handle = ComparisonViewHandle::new(1, ViewKind::Listing, "TestPlugin");
        assert_eq!(handle.id(), 1);
        assert_eq!(handle.kind(), ViewKind::Listing);
        assert!(!handle.is_active());
        assert!(!handle.is_disposed());
    }

    #[test]
    fn test_handle_active() {
        let mut handle = ComparisonViewHandle::new(1, ViewKind::Listing, "Test");
        handle.set_active(true);
        assert!(handle.is_active());

        handle.set_active(false);
        assert!(!handle.is_active());
    }

    #[test]
    fn test_handle_dispose() {
        let mut handle = ComparisonViewHandle::new(1, ViewKind::Listing, "Test");
        handle.set_active(true);
        handle.dispose();

        assert!(handle.is_disposed());
        assert!(!handle.is_active());
    }

    // --- ViewRegistry tests ---

    #[test]
    fn test_registry_new() {
        let registry = ViewRegistry::new();
        assert_eq!(registry.factory_count(), 0);
        assert!(registry.available_views().is_empty());
    }

    #[test]
    fn test_registry_create_handle_unregistered() {
        let mut registry = ViewRegistry::new();
        assert!(registry.create_handle(ViewKind::Listing, "Test").is_none());
    }

    #[test]
    fn test_registry_available_views_sorted() {
        let registry = ViewRegistry::new();
        // Without factories, available_views is empty, but the ViewKind::all() is sorted
        let kinds = ViewKind::all();
        assert_eq!(kinds[0], ViewKind::Listing);
        assert_eq!(kinds[1], ViewKind::Decompiler);
        assert_eq!(kinds[2], ViewKind::FunctionGraph);
    }

    // --- ComparisonViewManager tests ---

    #[test]
    fn test_manager_new() {
        let manager = ComparisonViewManager::new();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
        assert!(manager.active().is_none());
    }

    #[test]
    fn test_manager_from_handles() {
        let handles = vec![
            ComparisonViewHandle::new(1, ViewKind::Listing, "Test"),
            ComparisonViewHandle::new(2, ViewKind::Decompiler, "Test"),
        ];
        let manager = ComparisonViewManager::from_handles(handles);
        assert_eq!(manager.len(), 2);
        assert!(manager.active().is_some());
        assert_eq!(manager.active().unwrap().kind(), ViewKind::Listing);
    }

    #[test]
    fn test_manager_set_active() {
        let handles = vec![
            ComparisonViewHandle::new(1, ViewKind::Listing, "Test"),
            ComparisonViewHandle::new(2, ViewKind::Decompiler, "Test"),
        ];
        let mut manager = ComparisonViewManager::from_handles(handles);
        assert_eq!(manager.active().unwrap().kind(), ViewKind::Listing);

        assert!(manager.set_active(1));
        assert_eq!(manager.active().unwrap().kind(), ViewKind::Decompiler);
    }

    #[test]
    fn test_manager_set_active_by_kind() {
        let handles = vec![
            ComparisonViewHandle::new(1, ViewKind::Listing, "Test"),
            ComparisonViewHandle::new(2, ViewKind::Decompiler, "Test"),
        ];
        let mut manager = ComparisonViewManager::from_handles(handles);

        assert!(manager.set_active_by_kind(ViewKind::Decompiler));
        assert_eq!(manager.active().unwrap().kind(), ViewKind::Decompiler);
    }

    #[test]
    fn test_manager_set_active_invalid_index() {
        let handles = vec![ComparisonViewHandle::new(1, ViewKind::Listing, "Test")];
        let mut manager = ComparisonViewManager::from_handles(handles);

        assert!(!manager.set_active(5));
    }

    #[test]
    fn test_manager_get_by_kind() {
        let handles = vec![
            ComparisonViewHandle::new(1, ViewKind::Listing, "Test"),
            ComparisonViewHandle::new(2, ViewKind::Decompiler, "Test"),
        ];
        let manager = ComparisonViewManager::from_handles(handles);

        assert!(manager.get_by_kind(ViewKind::Listing).is_some());
        assert!(manager.get_by_kind(ViewKind::FunctionGraph).is_none());
    }

    #[test]
    fn test_manager_dispose_all() {
        let handles = vec![
            ComparisonViewHandle::new(1, ViewKind::Listing, "Test"),
            ComparisonViewHandle::new(2, ViewKind::Decompiler, "Test"),
        ];
        let mut manager = ComparisonViewManager::from_handles(handles);

        manager.dispose_all();
        assert!(manager.active().is_none());
        for handle in manager.iter() {
            // iter() filters disposed, so this should produce nothing
            panic!("Should not reach here");
        }
    }

    #[test]
    fn test_manager_add() {
        let mut manager = ComparisonViewManager::new();
        manager.add(ComparisonViewHandle::new(1, ViewKind::Listing, "Test"));
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_manager_iter() {
        let handles = vec![
            ComparisonViewHandle::new(1, ViewKind::Listing, "Test"),
            ComparisonViewHandle::new(2, ViewKind::Decompiler, "Test"),
        ];
        let manager = ComparisonViewManager::from_handles(handles);

        let kinds: Vec<ViewKind> = manager.iter().map(|h| h.kind()).collect();
        assert_eq!(kinds.len(), 2);
    }
}
