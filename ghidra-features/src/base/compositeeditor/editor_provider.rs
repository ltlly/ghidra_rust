//! Editor provider types for composite data type editors.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.EditorProvider`,
//! `StructureEditorProvider`, `UnionEditorProvider`, and
//! `CompositeEditorProvider`.
//!
//! Provides the Base-integrated editor provider implementations that manage
//! editor lifecycle, data type manager integration, save-check dialogs,
//! and docking window visibility for composite (struct/union) editors.

use super::{
    DataTypePath, EditorListener,
    composite_editor_panel::CompositeEditorPanel,
};

// ---------------------------------------------------------------------------
// Editor provider trait
// ---------------------------------------------------------------------------

/// Trait for composite editor providers in the Base plugin framework.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.EditorProvider`.
pub trait EditorProvider: Send {
    /// The name of this editor (e.g., "Structure Editor: MyStruct").
    fn name(&self) -> &str;

    /// The data type path being edited.
    fn dt_path(&self) -> &DataTypePath;

    /// The data type manager ID for the edited type.
    fn data_type_manager_id(&self) -> i64;

    /// Whether this editor is for the given data type path.
    fn is_editing(&self, dt_path: &DataTypePath) -> bool {
        self.dt_path() == dt_path
    }

    /// Show the editor window.
    fn show(&mut self);

    /// Whether the editor has unsaved changes.
    fn needs_save(&self) -> bool;

    /// Prompt for save if needed. Returns true if the user doesn't cancel.
    fn check_for_save(&self, allow_cancel: bool) -> bool;

    /// Dispose of the editor and release resources.
    fn dispose(&mut self);
}

// ---------------------------------------------------------------------------
// Structure editor provider
// ---------------------------------------------------------------------------

/// Editor provider for structure data types.
///
/// Integrates the composite editor panel with the Base plugin framework,
/// managing docking window visibility, data type manager interaction,
/// and editor lifecycle events.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.StructureEditorProvider`.
pub struct StructureEditorProvider {
    name: String,
    dt_path: DataTypePath,
    dt_manager_id: i64,
    /// The editor panel.
    pub panel: CompositeEditorPanel,
    listeners: Vec<Box<dyn EditorListener>>,
    visible: bool,
    disposed: bool,
}

impl std::fmt::Debug for StructureEditorProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StructureEditorProvider")
            .field("name", &self.name)
            .field("dt_path", &self.dt_path)
            .field("dt_manager_id", &self.dt_manager_id)
            .field("visible", &self.visible)
            .field("disposed", &self.disposed)
            .finish()
    }
}

impl StructureEditorProvider {
    /// Create a new structure editor provider.
    pub fn new(dt_path: DataTypePath, dt_manager_id: i64) -> Self {
        let name = format!("Structure Editor: {}", dt_path.data_type_name);
        let panel = CompositeEditorPanel::new(dt_path.clone(), true);
        Self {
            name,
            dt_path,
            dt_manager_id,
            panel,
            listeners: Vec::new(),
            visible: false,
            disposed: false,
        }
    }

    /// Add an editor listener.
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
        self.panel.is_dirty()
    }

    fn check_for_save(&self, _allow_cancel: bool) -> bool {
        // In a full implementation, this would show a dialog.
        true
    }

    fn dispose(&mut self) {
        for listener in &self.listeners {
            listener.editor_closing(&self.dt_path);
        }
        self.listeners.clear();
        self.disposed = true;
        self.visible = false;
    }
}

// ---------------------------------------------------------------------------
// Union editor provider
// ---------------------------------------------------------------------------

/// Editor provider for union data types.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.UnionEditorProvider`.
pub struct UnionEditorProvider {
    name: String,
    dt_path: DataTypePath,
    dt_manager_id: i64,
    /// The editor panel.
    pub panel: CompositeEditorPanel,
    listeners: Vec<Box<dyn EditorListener>>,
    visible: bool,
    disposed: bool,
}

impl std::fmt::Debug for UnionEditorProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnionEditorProvider")
            .field("name", &self.name)
            .field("dt_path", &self.dt_path)
            .field("dt_manager_id", &self.dt_manager_id)
            .field("visible", &self.visible)
            .field("disposed", &self.disposed)
            .finish()
    }
}

impl UnionEditorProvider {
    /// Create a new union editor provider.
    pub fn new(dt_path: DataTypePath, dt_manager_id: i64) -> Self {
        let name = format!("Union Editor: {}", dt_path.data_type_name);
        let panel = CompositeEditorPanel::new(dt_path.clone(), false);
        Self {
            name,
            dt_path,
            dt_manager_id,
            panel,
            listeners: Vec::new(),
            visible: false,
            disposed: false,
        }
    }

    /// Add an editor listener.
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
        self.panel.is_dirty()
    }

    fn check_for_save(&self, _allow_cancel: bool) -> bool {
        true
    }

    fn dispose(&mut self) {
        for listener in &self.listeners {
            listener.editor_closing(&self.dt_path);
        }
        self.listeners.clear();
        self.disposed = true;
        self.visible = false;
    }
}

// ---------------------------------------------------------------------------
// Generic composite editor provider
// ---------------------------------------------------------------------------

/// A generic editor provider that can hold either a structure or union editor.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeEditorProvider`.
#[derive(Debug)]
pub struct CompositeEditorProvider {
    name: String,
    dt_path: DataTypePath,
    dt_manager_id: i64,
    is_struct: bool,
    /// The editor panel.
    pub panel: CompositeEditorPanel,
    visible: bool,
    disposed: bool,
}

impl CompositeEditorProvider {
    /// Create a new composite editor provider.
    pub fn new(dt_path: DataTypePath, dt_manager_id: i64, is_struct: bool) -> Self {
        let kind = if is_struct { "Structure" } else { "Union" };
        let name = format!("{} Editor: {}", kind, dt_path.data_type_name);
        let panel = CompositeEditorPanel::new(dt_path.clone(), is_struct);
        Self {
            name,
            dt_path,
            dt_manager_id,
            is_struct,
            panel,
            visible: false,
            disposed: false,
        }
    }

    /// Whether this is a structure editor.
    pub fn is_struct(&self) -> bool {
        self.is_struct
    }

    /// The type kind name ("Structure" or "Union").
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
        self.panel.is_dirty()
    }

    fn check_for_save(&self, _allow_cancel: bool) -> bool {
        true
    }

    fn dispose(&mut self) {
        self.disposed = true;
        self.visible = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_path(name: &str) -> DataTypePath {
        DataTypePath::new("/", name)
    }

    #[test]
    fn test_structure_editor_provider() {
        let dt_path = root_path("MyStruct");
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
        let dt_path = root_path("MyStruct");
        let provider = StructureEditorProvider::new(dt_path.clone(), 1);
        assert!(provider.is_editing(&dt_path));
        assert!(!provider.is_editing(&root_path("Other")));
    }

    #[test]
    fn test_structure_editor_provider_dispose() {
        let dt_path = root_path("S");
        let mut provider = StructureEditorProvider::new(dt_path, 1);
        provider.show();
        provider.dispose();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_union_editor_provider() {
        let dt_path = root_path("MyUnion");
        let mut provider = UnionEditorProvider::new(dt_path.clone(), 2);
        assert_eq!(provider.name(), "Union Editor: MyUnion");
        assert!(!provider.is_visible());

        provider.show();
        assert!(provider.is_visible());
    }

    #[test]
    fn test_union_editor_provider_dispose() {
        let dt_path = root_path("U");
        let mut provider = UnionEditorProvider::new(dt_path, 1);
        provider.dispose();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_composite_editor_provider_struct() {
        let dt_path = root_path("S");
        let mut provider = CompositeEditorProvider::new(dt_path, 1, true);
        assert_eq!(provider.type_kind(), "Structure");
        assert!(provider.is_struct());
        assert!(!provider.is_disposed());

        provider.dispose();
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_composite_editor_provider_union() {
        let dt_path = root_path("U");
        let provider = CompositeEditorProvider::new(dt_path, 1, false);
        assert_eq!(provider.type_kind(), "Union");
        assert!(!provider.is_struct());
    }

    #[test]
    fn test_composite_editor_provider_needs_save() {
        let dt_path = root_path("S");
        let provider = CompositeEditorProvider::new(dt_path, 1, true);
        assert!(!provider.needs_save());
        // Note: can't easily test dirty state without adding components
        // through the panel, which requires mutable access to the provider
        // and then the panel.
    }

    #[test]
    fn test_composite_editor_provider_check_for_save() {
        let dt_path = root_path("S");
        let provider = CompositeEditorProvider::new(dt_path, 1, true);
        assert!(provider.check_for_save(true));
        assert!(provider.check_for_save(false));
    }
}
