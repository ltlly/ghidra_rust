//! Composite viewer model for read-only display of data type structures.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.compositeeditor` Java package:
//! - `CompositeViewerModel` -- read-only model for viewing composite types
//! - `CompositeViewerDataTypeManager` -- read-only DTM for the viewer
//! - `CompositeViewerModelListener` -- listener for viewer model changes
//!
//! The viewer model is the read-only counterpart to the editor model.
//! It provides a simplified view of a composite data type (structure or
//! union) that can be used in preview windows, hover popups, and other
//! read-only contexts.

use serde::{Deserialize, Serialize};

/// A component entry in the composite viewer model.
///
/// Represents a single field/member in a structure or union.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewerComponent {
    /// The ordinal (index) of this component within the composite.
    pub ordinal: usize,
    /// The field name.
    pub field_name: String,
    /// The data type name of this component.
    pub data_type_name: String,
    /// The size in bytes.
    pub size: usize,
    /// The offset within the composite (0 for unions).
    pub offset: usize,
    /// The comment on this component, if any.
    pub comment: Option<String>,
    /// Whether this component is a bitfield.
    pub is_bitfield: bool,
    /// The bitfield details, if applicable.
    pub bitfield_info: Option<BitfieldInfo>,
}

/// Bitfield-specific information for a component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitfieldInfo {
    /// The bit offset within the containing storage unit.
    pub bit_offset: usize,
    /// The number of bits in this bitfield.
    pub bit_size: usize,
    /// The size of the containing storage unit in bytes.
    pub storage_size: usize,
}

/// The read-only viewer model for a composite data type.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeViewerModel`.
#[derive(Debug, Clone)]
pub struct CompositeViewerModel {
    /// The name of the composite data type being viewed.
    pub composite_name: String,
    /// Whether this is a structure (true) or union (false).
    pub is_structure: bool,
    /// The components (fields) of the composite type.
    pub components: Vec<ViewerComponent>,
    /// The total size of the composite in bytes.
    pub total_size: usize,
    /// The selected component ordinal, if any.
    pub selected_ordinal: Option<usize>,
    /// Whether to show hex numbers.
    pub show_hex: bool,
    /// Whether the model has unsaved changes (always false for viewer).
    pub has_changes: bool,
}

impl CompositeViewerModel {
    /// Create a new viewer model.
    pub fn new(
        composite_name: impl Into<String>,
        is_structure: bool,
    ) -> Self {
        Self {
            composite_name: composite_name.into(),
            is_structure,
            components: Vec::new(),
            total_size: 0,
            selected_ordinal: None,
            show_hex: true,
            has_changes: false,
        }
    }

    /// Add a component to the model.
    pub fn add_component(&mut self, component: ViewerComponent) {
        self.components.push(component);
        self.recalculate_size();
    }

    /// Get the number of components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Get a component by ordinal.
    pub fn get_component(&self, ordinal: usize) -> Option<&ViewerComponent> {
        self.components.get(ordinal)
    }

    /// Get the selected component.
    pub fn selected_component(&self) -> Option<&ViewerComponent> {
        self.selected_ordinal.and_then(|o| self.get_component(o))
    }

    /// Set the selected component.
    pub fn set_selected(&mut self, ordinal: Option<usize>) {
        self.selected_ordinal = ordinal;
    }

    /// Toggle hex display mode.
    pub fn toggle_hex(&mut self) {
        self.show_hex = !self.show_hex;
    }

    /// Recalculate the total size from components.
    fn recalculate_size(&mut self) {
        if self.is_structure {
            self.total_size = self.components.iter().map(|c| c.size).sum();
        } else {
            self.total_size = self.components.iter().map(|c| c.size).max().unwrap_or(0);
        }
    }

    /// Get the composite type kind string.
    pub fn type_kind(&self) -> &'static str {
        if self.is_structure {
            "structure"
        } else {
            "union"
        }
    }

    /// Find components by field name.
    pub fn find_by_name(&self, name: &str) -> Vec<&ViewerComponent> {
        self.components
            .iter()
            .filter(|c| c.field_name == name)
            .collect()
    }

    /// Find components at a given offset (structures only).
    pub fn find_at_offset(&self, offset: usize) -> Vec<&ViewerComponent> {
        self.components
            .iter()
            .filter(|c| c.offset == offset)
            .collect()
    }

    /// Get a summary of the composite type.
    pub fn summary(&self) -> String {
        format!(
            "{} {} ({} fields, {} bytes)",
            self.type_kind(),
            self.composite_name,
            self.components.len(),
            self.total_size,
        )
    }
}

// ---------------------------------------------------------------------------
// CompositeViewerDataTypeManager -- read-only DTM for the viewer
// ---------------------------------------------------------------------------

/// A read-only data type manager for the composite viewer.
///
/// This is a simplified DTM that only provides enough functionality to
/// display composite types in a viewer context.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.CompositeViewerDataTypeManager`.
#[derive(Debug, Clone)]
pub struct CompositeViewerDataTypeManager {
    /// Name of this DTM.
    pub name: String,
    /// Cached data type definitions (name -> size).
    pub types: Vec<(String, usize)>,
}

impl CompositeViewerDataTypeManager {
    /// Create a new viewer DTM.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            types: Vec::new(),
        }
    }

    /// Add a data type definition.
    pub fn add_type(&mut self, name: impl Into<String>, size: usize) {
        self.types.push((name.into(), size));
    }

    /// Look up the size of a data type by name.
    pub fn get_type_size(&self, name: &str) -> Option<usize> {
        self.types.iter().find(|(n, _)| n == name).map(|(_, s)| *s)
    }

    /// Get all registered type names.
    pub fn type_names(&self) -> Vec<&str> {
        self.types.iter().map(|(n, _)| n.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// CompositeViewerModelListener
// ---------------------------------------------------------------------------

/// Events emitted by the composite viewer model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewerModelEvent {
    /// A component was added.
    ComponentAdded(usize),
    /// A component was removed.
    ComponentRemoved(usize),
    /// The selection changed.
    SelectionChanged(Option<usize>),
    /// The hex display mode changed.
    HexModeChanged(bool),
    /// The entire model was reloaded.
    ModelReloaded,
}

/// Trait for listeners that receive viewer model events.
pub trait CompositeViewerModelListener: Send + Sync {
    /// Called when the model emits an event.
    fn on_event(&self, event: &ViewerModelEvent);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_component(ordinal: usize, name: &str, dtype: &str, size: usize, offset: usize) -> ViewerComponent {
        ViewerComponent {
            ordinal,
            field_name: name.to_string(),
            data_type_name: dtype.to_string(),
            size,
            offset,
            comment: None,
            is_bitfield: false,
            bitfield_info: None,
        }
    }

    #[test]
    fn test_viewer_model_structure() {
        let mut model = CompositeViewerModel::new("my_struct", true);
        model.add_component(make_test_component(0, "x", "int", 4, 0));
        model.add_component(make_test_component(1, "y", "int", 4, 4));
        model.add_component(make_test_component(2, "z", "float", 4, 8));

        assert_eq!(model.component_count(), 3);
        assert_eq!(model.total_size, 12);
        assert_eq!(model.type_kind(), "structure");
    }

    #[test]
    fn test_viewer_model_union() {
        let mut model = CompositeViewerModel::new("my_union", false);
        model.add_component(make_test_component(0, "i", "int", 4, 0));
        model.add_component(make_test_component(1, "f", "float", 4, 0));

        assert_eq!(model.total_size, 4); // max of components for union
        assert_eq!(model.type_kind(), "union");
    }

    #[test]
    fn test_viewer_model_selection() {
        let mut model = CompositeViewerModel::new("test", true);
        model.add_component(make_test_component(0, "a", "int", 4, 0));

        assert!(model.selected_component().is_none());
        model.set_selected(Some(0));
        let selected = model.selected_component().unwrap();
        assert_eq!(selected.field_name, "a");

        model.set_selected(None);
        assert!(model.selected_component().is_none());
    }

    #[test]
    fn test_viewer_model_find_by_name() {
        let mut model = CompositeViewerModel::new("test", true);
        model.add_component(make_test_component(0, "x", "int", 4, 0));
        model.add_component(make_test_component(1, "y", "int", 4, 4));
        model.add_component(make_test_component(2, "x", "float", 4, 8));

        let xs = model.find_by_name("x");
        assert_eq!(xs.len(), 2);
        let ys = model.find_by_name("y");
        assert_eq!(ys.len(), 1);
        let zs = model.find_by_name("z");
        assert_eq!(zs.len(), 0);
    }

    #[test]
    fn test_viewer_model_find_at_offset() {
        let mut model = CompositeViewerModel::new("test", true);
        model.add_component(make_test_component(0, "a", "int", 4, 0));
        model.add_component(make_test_component(1, "b", "int", 4, 4));
        model.add_component(make_test_component(2, "c", "char", 1, 0));

        let at_0 = model.find_at_offset(0);
        assert_eq!(at_0.len(), 2); // a and c
        let at_4 = model.find_at_offset(4);
        assert_eq!(at_4.len(), 1); // b
    }

    #[test]
    fn test_viewer_model_summary() {
        let mut model = CompositeViewerModel::new("Point", true);
        model.add_component(make_test_component(0, "x", "int", 4, 0));
        model.add_component(make_test_component(1, "y", "int", 4, 4));

        let summary = model.summary();
        assert!(summary.contains("structure"));
        assert!(summary.contains("Point"));
        assert!(summary.contains("2 fields"));
        assert!(summary.contains("8 bytes"));
    }

    #[test]
    fn test_viewer_model_hex_toggle() {
        let mut model = CompositeViewerModel::new("test", true);
        assert!(model.show_hex);
        model.toggle_hex();
        assert!(!model.show_hex);
        model.toggle_hex();
        assert!(model.show_hex);
    }

    #[test]
    fn test_bitfield_info() {
        let component = ViewerComponent {
            ordinal: 0,
            field_name: "flags".into(),
            data_type_name: "uint".into(),
            size: 4,
            offset: 0,
            comment: None,
            is_bitfield: true,
            bitfield_info: Some(BitfieldInfo {
                bit_offset: 3,
                bit_size: 5,
                storage_size: 4,
            }),
        };

        let bf = component.bitfield_info.as_ref().unwrap();
        assert_eq!(bf.bit_offset, 3);
        assert_eq!(bf.bit_size, 5);
        assert_eq!(bf.storage_size, 4);
    }

    #[test]
    fn test_viewer_dtm() {
        let mut dtm = CompositeViewerDataTypeManager::new("TestDTM");
        dtm.add_type("int", 4);
        dtm.add_type("long", 8);
        dtm.add_type("char", 1);

        assert_eq!(dtm.get_type_size("int"), Some(4));
        assert_eq!(dtm.get_type_size("long"), Some(8));
        assert_eq!(dtm.get_type_size("nonexistent"), None);

        let names = dtm.type_names();
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn test_viewer_model_event_types() {
        let events = vec![
            ViewerModelEvent::ComponentAdded(0),
            ViewerModelEvent::ComponentRemoved(1),
            ViewerModelEvent::SelectionChanged(Some(2)),
            ViewerModelEvent::HexModeChanged(true),
            ViewerModelEvent::ModelReloaded,
        ];
        assert_eq!(events.len(), 5);
    }
}
