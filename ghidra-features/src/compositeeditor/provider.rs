//! Composite editor provider types.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.EditorProvider`,
//! `StructureEditorProvider`, `UnionEditorProvider`, and `CompositeEditorProvider`.

use serde::{Deserialize, Serialize};

use super::{CompositeEditorModel, StructureEditorModel, UnionEditorModel};

// ---------------------------------------------------------------------------
// EditorProvider trait
// ---------------------------------------------------------------------------

/// Interface implemented by data type editors.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.EditorProvider`.
pub trait EditorProvider {
    /// Get the name of this editor.
    fn name(&self) -> &str;

    /// Get the data type path being edited (category + name).
    fn dt_path(&self) -> &DataTypePath;

    /// Get the data type manager ID for the edited type.
    fn data_type_manager_id(&self) -> i64;

    /// Whether this editor is editing the data type with the given path.
    fn is_editing(&self, dt_path: &DataTypePath) -> bool {
        self.dt_path() == dt_path
    }

    /// Show the editor.
    fn show(&mut self);

    /// Whether changes need to be saved.
    fn needs_save(&self) -> bool;

    /// Prompt the user if this editor has changes that need saving.
    ///
    /// Returns true if the user doesn't cancel.
    fn check_for_save(&self, allow_cancel: bool) -> bool;

    /// Dispose of resources.
    fn dispose(&mut self);
}

// ---------------------------------------------------------------------------
// DataTypePath
// ---------------------------------------------------------------------------

/// The category path + name identifying a data type.
///
/// Ported from `ghidra.program.model.data.DataTypePath`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DataTypePath {
    /// The category path (e.g., "/MyCategory/SubCategory").
    pub category_path: String,
    /// The data type name.
    pub data_type_name: String,
}

impl DataTypePath {
    /// Create a new data type path.
    pub fn new(category_path: impl Into<String>, data_type_name: impl Into<String>) -> Self {
        Self {
            category_path: category_path.into(),
            data_type_name: data_type_name.into(),
        }
    }

    /// Create a path in the root category.
    pub fn root(data_type_name: impl Into<String>) -> Self {
        Self {
            category_path: "/".into(),
            data_type_name: data_type_name.into(),
        }
    }

    /// Full path string (category + name).
    pub fn full_path(&self) -> String {
        if self.category_path.ends_with('/') {
            format!("{}{}", self.category_path, self.data_type_name)
        } else {
            format!("{}/{}", self.category_path, self.data_type_name)
        }
    }
}

impl std::fmt::Display for DataTypePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full_path())
    }
}

// ---------------------------------------------------------------------------
// EditorListener
// ---------------------------------------------------------------------------

/// Listener for editor lifecycle events.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.EditorListener`.
pub trait EditorListener: Send + Sync {
    /// Called when the editor window is closed.
    fn editor_closed(&self, editor_name: &str);

    /// Called when the editor is about to be disposed.
    fn editor_disposed(&self, editor_name: &str);
}

// ---------------------------------------------------------------------------
// StructureEditorProvider
// ---------------------------------------------------------------------------

/// Provider for the structure data type editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.StructureEditorProvider`.
pub struct StructureEditorProvider {
    /// The editor name.
    name: String,
    /// The data type path.
    dt_path: DataTypePath,
    /// The data type manager ID.
    dt_manager_id: i64,
    /// The structure editor model.
    pub model: StructureEditorModel,
    /// Editor listeners.
    listeners: Vec<Box<dyn EditorListener>>,
    /// Whether the provider is visible.
    visible: bool,
    /// Whether disposed.
    disposed: bool,
}

impl std::fmt::Debug for StructureEditorProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StructureEditorProvider")
            .field("name", &self.name)
            .field("dt_path", &self.dt_path)
            .field("dt_manager_id", &self.dt_manager_id)
            .field("model", &self.model)
            .field("visible", &self.visible)
            .field("disposed", &self.disposed)
            .finish()
    }
}

impl StructureEditorProvider {
    /// Create a new structure editor provider.
    pub fn new(
        dt_path: DataTypePath,
        dt_manager_id: i64,
    ) -> Self {
        let name = format!("Structure Editor: {}", dt_path.data_type_name);
        let model = StructureEditorModel::new(&dt_path.data_type_name);
        Self {
            name,
            dt_path,
            dt_manager_id,
            model,
            listeners: Vec::new(),
            visible: false,
            disposed: false,
        }
    }

    /// Add a listener.
    pub fn add_listener(&mut self, listener: Box<dyn EditorListener>) {
        self.listeners.push(listener);
    }

    /// Whether the editor is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }
}

impl EditorProvider for StructureEditorProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn dt_path(&self) -> &DataTypePath {
        &self.dt_path
    }

    fn data_type_manager_id(&self) -> i64 {
        self.dt_manager_id
    }

    fn show(&mut self) {
        self.visible = true;
    }

    fn needs_save(&self) -> bool {
        self.model.base.is_dirty()
    }

    fn check_for_save(&self, _allow_cancel: bool) -> bool {
        // In the real implementation, this would show a dialog.
        // Here we just return true (don't cancel).
        true
    }

    fn dispose(&mut self) {
        for listener in &self.listeners {
            listener.editor_disposed(&self.name);
        }
        self.listeners.clear();
        self.disposed = true;
        self.visible = false;
    }
}

// ---------------------------------------------------------------------------
// UnionEditorProvider
// ---------------------------------------------------------------------------

/// Provider for the union data type editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.UnionEditorProvider`.
pub struct UnionEditorProvider {
    /// The editor name.
    name: String,
    /// The data type path.
    dt_path: DataTypePath,
    /// The data type manager ID.
    dt_manager_id: i64,
    /// The union editor model.
    pub model: UnionEditorModel,
    /// Editor listeners.
    listeners: Vec<Box<dyn EditorListener>>,
    /// Whether visible.
    visible: bool,
    /// Whether disposed.
    disposed: bool,
}

impl std::fmt::Debug for UnionEditorProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnionEditorProvider")
            .field("name", &self.name)
            .field("dt_path", &self.dt_path)
            .field("dt_manager_id", &self.dt_manager_id)
            .field("model", &self.model)
            .field("visible", &self.visible)
            .field("disposed", &self.disposed)
            .finish()
    }
}

impl UnionEditorProvider {
    /// Create a new union editor provider.
    pub fn new(
        dt_path: DataTypePath,
        dt_manager_id: i64,
    ) -> Self {
        let name = format!("Union Editor: {}", dt_path.data_type_name);
        let model = UnionEditorModel::new(&dt_path.data_type_name);
        Self {
            name,
            dt_path,
            dt_manager_id,
            model,
            listeners: Vec::new(),
            visible: false,
            disposed: false,
        }
    }

    /// Add a listener.
    pub fn add_listener(&mut self, listener: Box<dyn EditorListener>) {
        self.listeners.push(listener);
    }

    /// Whether visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }
}

impl EditorProvider for UnionEditorProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn dt_path(&self) -> &DataTypePath {
        &self.dt_path
    }

    fn data_type_manager_id(&self) -> i64 {
        self.dt_manager_id
    }

    fn show(&mut self) {
        self.visible = true;
    }

    fn needs_save(&self) -> bool {
        self.model.base.is_dirty()
    }

    fn check_for_save(&self, _allow_cancel: bool) -> bool {
        true
    }

    fn dispose(&mut self) {
        for listener in &self.listeners {
            listener.editor_disposed(&self.name);
        }
        self.listeners.clear();
        self.disposed = true;
        self.visible = false;
    }
}

// ---------------------------------------------------------------------------
// CompositeEditorProvider (generic)
// ---------------------------------------------------------------------------

/// A generic editor provider that can hold either a structure or union model.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorProvider`.
#[derive(Debug)]
pub struct CompositeEditorProvider {
    /// The editor name.
    name: String,
    /// The data type path.
    dt_path: DataTypePath,
    /// The data type manager ID.
    dt_manager_id: i64,
    /// Whether editing a structure (true) or union (false).
    is_struct: bool,
    /// The generic model.
    pub model: CompositeEditorModel,
    /// Whether visible.
    visible: bool,
    /// Whether disposed.
    disposed: bool,
}

impl CompositeEditorProvider {
    /// Create a new composite editor provider.
    pub fn new(
        dt_path: DataTypePath,
        dt_manager_id: i64,
        is_struct: bool,
    ) -> Self {
        let kind = if is_struct { "Structure" } else { "Union" };
        let name = format!("{} Editor: {}", kind, dt_path.data_type_name);
        let model = CompositeEditorModel::new(&dt_path.data_type_name, is_struct);
        Self {
            name,
            dt_path,
            dt_manager_id,
            is_struct,
            model,
            visible: false,
            disposed: false,
        }
    }

    /// Whether this is a structure editor.
    pub fn is_struct(&self) -> bool {
        self.is_struct
    }

    /// The type kind name.
    pub fn type_kind(&self) -> &'static str {
        if self.is_struct { "Structure" } else { "Union" }
    }

    /// Whether visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Dispose.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.visible = false;
    }

    /// Whether disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

impl EditorProvider for CompositeEditorProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn dt_path(&self) -> &DataTypePath {
        &self.dt_path
    }

    fn data_type_manager_id(&self) -> i64 {
        self.dt_manager_id
    }

    fn show(&mut self) {
        self.visible = true;
    }

    fn needs_save(&self) -> bool {
        self.model.is_dirty()
    }

    fn check_for_save(&self, _allow_cancel: bool) -> bool {
        true
    }

    fn dispose(&mut self) {
        self.disposed = true;
        self.visible = false;
    }
}

// ---------------------------------------------------------------------------
// ViewerDataTypeManager
// ---------------------------------------------------------------------------

/// A read-only data type manager view used by the composite viewer.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeViewerDataTypeManager`.
#[derive(Debug)]
pub struct CompositeViewerDataTypeManager {
    /// The data type manager ID.
    pub manager_id: i64,
    /// The source data type name.
    pub source_name: String,
    /// Whether the viewer data type is synchronized with the source.
    pub synchronized: bool,
}

impl CompositeViewerDataTypeManager {
    /// Create a new viewer data type manager.
    pub fn new(manager_id: i64, source_name: impl Into<String>) -> Self {
        Self {
            manager_id,
            source_name: source_name.into(),
            synchronized: true,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_path() {
        let path = DataTypePath::new("/MyCategory", "MyStruct");
        assert_eq!(path.full_path(), "/MyCategory/MyStruct");
        assert_eq!(format!("{}", path), "/MyCategory/MyStruct");
    }

    #[test]
    fn test_data_type_path_root() {
        let path = DataTypePath::root("int");
        assert_eq!(path.full_path(), "/int");
    }

    #[test]
    fn test_data_type_path_trailing_slash() {
        let path = DataTypePath::new("/", "int");
        assert_eq!(path.full_path(), "/int");
    }

    #[test]
    fn test_structure_editor_provider() {
        let dt_path = DataTypePath::root("MyStruct");
        let mut provider = StructureEditorProvider::new(dt_path.clone(), 1);
        assert_eq!(provider.name(), "Structure Editor: MyStruct");
        assert_eq!(provider.dt_path(), &dt_path);
        assert_eq!(provider.data_type_manager_id(), 1);
        assert!(!provider.is_visible());
        assert!(!provider.needs_save());

        provider.show();
        assert!(provider.is_visible());
    }

    #[test]
    fn test_structure_editor_provider_editing_check() {
        let dt_path = DataTypePath::root("MyStruct");
        let provider = StructureEditorProvider::new(dt_path.clone(), 1);

        let other_path = DataTypePath::root("OtherStruct");
        assert!(provider.is_editing(&dt_path));
        assert!(!provider.is_editing(&other_path));
    }

    #[test]
    fn test_union_editor_provider() {
        let dt_path = DataTypePath::root("MyUnion");
        let mut provider = UnionEditorProvider::new(dt_path.clone(), 2);
        assert_eq!(provider.name(), "Union Editor: MyUnion");
        assert!(!provider.is_visible());

        provider.show();
        assert!(provider.is_visible());
    }

    #[test]
    fn test_composite_editor_provider_struct() {
        let dt_path = DataTypePath::root("S");
        let mut provider = CompositeEditorProvider::new(dt_path, 1, true);
        assert_eq!(provider.type_kind(), "Structure");
        assert!(provider.is_struct());
        assert!(!provider.is_disposed());

        provider.dispose();
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_composite_editor_provider_union() {
        let dt_path = DataTypePath::root("U");
        let provider = CompositeEditorProvider::new(dt_path, 1, false);
        assert_eq!(provider.type_kind(), "Union");
        assert!(!provider.is_struct());
    }

    #[test]
    fn test_composite_editor_provider_needs_save() {
        let dt_path = DataTypePath::root("S");
        let mut provider = CompositeEditorProvider::new(dt_path, 1, true);
        assert!(!provider.needs_save());

        provider.model.add_component(0, "int");
        assert!(provider.needs_save());
    }

    #[test]
    fn test_composite_editor_provider_check_for_save() {
        let dt_path = DataTypePath::root("S");
        let provider = CompositeEditorProvider::new(dt_path, 1, true);
        assert!(provider.check_for_save(true));
        assert!(provider.check_for_save(false));
    }

    #[test]
    fn test_composite_viewer_data_type_manager() {
        let mgr = CompositeViewerDataTypeManager::new(42, "MyStruct");
        assert_eq!(mgr.manager_id, 42);
        assert_eq!(mgr.source_name, "MyStruct");
        assert!(mgr.synchronized);
    }

    #[test]
    fn test_data_type_path_eq() {
        let p1 = DataTypePath::new("/cat", "name");
        let p2 = DataTypePath::new("/cat", "name");
        let p3 = DataTypePath::new("/cat", "other");
        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_data_type_path_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(DataTypePath::root("int"));
        assert!(set.contains(&DataTypePath::root("int")));
        assert!(!set.contains(&DataTypePath::root("char")));
    }
}
