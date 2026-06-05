//! Symbol renderer and transient table model.
//!
//! Ported from `ghidra.app.plugin.core.symtable.SymbolRenderer`,
//! `TransientSymbolTableModel`, and the row-object mapper classes.

use super::model::{SymbolRowObject, SymbolTableKind};
use super::filter::SymbolFilter;

// ---------------------------------------------------------------------------
// SymbolRenderer
// ---------------------------------------------------------------------------

/// Render mode for a symbol cell in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolRenderMode {
    /// Normal rendering.
    Normal,
    /// Bold rendering (for primary symbols or functions).
    Bold,
    /// Strikethrough (for deleted symbols).
    Strikethrough,
    /// Italic (for external symbols).
    Italic,
}

/// Color scheme for symbol rendering.
#[derive(Debug, Clone)]
pub struct SymbolColorScheme {
    /// Color for function symbols.
    pub function_color: String,
    /// Color for label symbols.
    pub label_color: String,
    /// Color for class/namespace symbols.
    pub class_color: String,
    /// Color for library symbols.
    pub library_color: String,
    /// Color for external symbols.
    pub external_color: String,
    /// Color for parameter symbols.
    pub parameter_color: String,
    /// Color for local variable symbols.
    pub local_color: String,
    /// Default color for unknown types.
    pub default_color: String,
}

impl Default for SymbolColorScheme {
    fn default() -> Self {
        Self {
            function_color: "#0000FF".into(),
            label_color: "#000000".into(),
            class_color: "#800080".into(),
            library_color: "#008000".into(),
            external_color: "#A52A2A".into(),
            parameter_color: "#0000FF".into(),
            local_color: "#808080".into(),
            default_color: "#000000".into(),
        }
    }
}

/// Symbol renderer that determines visual properties for symbol cells.
///
/// Ported from `ghidra.app.plugin.core.symtable.SymbolRenderer`.
///
/// # Example
///
/// ```
/// use ghidra_features::symtable::renderer::*;
/// use ghidra_features::symtable::model::*;
///
/// let renderer = SymbolRenderer::new();
/// let symbol = SymbolRowObject::new("main", 0x401000, SymbolTableKind::Function, "Global");
///
/// let render = renderer.render(&symbol);
/// assert_eq!(render.mode, SymbolRenderMode::Bold);
/// ```
#[derive(Debug)]
pub struct SymbolRenderer {
    /// The color scheme.
    colors: SymbolColorScheme,
}

impl SymbolRenderer {
    /// Create a new symbol renderer with default colors.
    pub fn new() -> Self {
        Self {
            colors: SymbolColorScheme::default(),
        }
    }

    /// Create a new renderer with a custom color scheme.
    pub fn with_colors(colors: SymbolColorScheme) -> Self {
        Self { colors }
    }

    /// Get the color scheme.
    pub fn colors(&self) -> &SymbolColorScheme {
        &self.colors
    }

    /// Set the color scheme.
    pub fn set_colors(&mut self, colors: SymbolColorScheme) {
        self.colors = colors;
    }

    /// Compute rendering properties for a symbol row object.
    pub fn render(&self, symbol: &SymbolRowObject) -> SymbolRenderState {
        let (mode, color) = match symbol.kind() {
            SymbolTableKind::Function => (SymbolRenderMode::Bold, &self.colors.function_color),
            SymbolTableKind::Label => (SymbolRenderMode::Normal, &self.colors.label_color),
            SymbolTableKind::Class => (SymbolRenderMode::Bold, &self.colors.class_color),
            SymbolTableKind::Library => (SymbolRenderMode::Normal, &self.colors.library_color),
            SymbolTableKind::External => (SymbolRenderMode::Italic, &self.colors.external_color),
            SymbolTableKind::Parameter => (SymbolRenderMode::Normal, &self.colors.parameter_color),
            SymbolTableKind::Local => (SymbolRenderMode::Normal, &self.colors.local_color),
            SymbolTableKind::Unknown => (SymbolRenderMode::Normal, &self.colors.default_color),
        };

        SymbolRenderState {
            text: symbol.name().to_string(),
            mode,
            color: color.clone(),
            background_color: None,
        }
    }

    /// Render a deleted symbol placeholder.
    pub fn render_deleted(&self) -> SymbolRenderState {
        SymbolRenderState {
            text: "<< REMOVED >>".to_string(),
            mode: SymbolRenderMode::Strikethrough,
            color: "#808080".into(),
            background_color: None,
        }
    }
}

impl Default for SymbolRenderer {
    fn default() -> Self {
        Self::new()
    }
}

/// Rendering state for a single symbol cell.
#[derive(Debug, Clone)]
pub struct SymbolRenderState {
    /// The text to display.
    pub text: String,
    /// The render mode.
    pub mode: SymbolRenderMode,
    /// Foreground color.
    pub color: String,
    /// Optional background color.
    pub background_color: Option<String>,
}

// ---------------------------------------------------------------------------
// TransientSymbolTableModel
// ---------------------------------------------------------------------------

/// A symbol table model for a temporary/transient set of symbols.
///
/// Ported from `ghidra.app.plugin.core.symtable.TransientSymbolTableModel`.
///
/// Unlike the main symbol table model which reflects the program's symbol
/// table, this model holds a user-supplied set of symbols (e.g., search
/// results, reference targets) that can be individually removed.
///
/// # Example
///
/// ```
/// use ghidra_features::symtable::renderer::*;
/// use ghidra_features::symtable::model::*;
///
/// let mut model = TransientSymbolTableModel::new("Search Results");
/// model.add_symbol(SymbolRowObject::new("printf", 0x1000, SymbolTableKind::External, "libc"));
/// model.add_symbol(SymbolRowObject::new("malloc", 0x1004, SymbolTableKind::External, "libc"));
/// assert_eq!(model.row_count(), 2);
///
/// model.remove_symbol(0);
/// assert_eq!(model.row_count(), 1);
/// assert_eq!(model.get(0).unwrap().name(), "malloc");
/// ```
#[derive(Debug)]
pub struct TransientSymbolTableModel {
    /// The title for this model (used for provider naming).
    title: String,
    /// The symbol rows.
    rows: Vec<SymbolRowObject>,
    /// Whether removed symbols are kept (hidden) vs. truly deleted.
    soft_delete: bool,
    /// Indices of soft-deleted rows.
    deleted_indices: Vec<usize>,
}

impl TransientSymbolTableModel {
    /// Create a new transient model with the given title.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            rows: Vec::new(),
            soft_delete: false,
            deleted_indices: Vec::new(),
        }
    }

    /// Get the model title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Add a symbol to the model.
    pub fn add_symbol(&mut self, symbol: SymbolRowObject) {
        self.rows.push(symbol);
    }

    /// Remove a symbol by index.
    pub fn remove_symbol(&mut self, index: usize) -> Option<SymbolRowObject> {
        if index >= self.rows.len() {
            return None;
        }
        if self.soft_delete {
            self.deleted_indices.push(index);
            None // soft-deleted, not returned
        } else {
            Some(self.rows.remove(index))
        }
    }

    /// Get a symbol by index (skipping soft-deleted entries).
    pub fn get(&self, index: usize) -> Option<&SymbolRowObject> {
        if self.soft_delete {
            let mut visible_index = 0;
            for (i, row) in self.rows.iter().enumerate() {
                if self.deleted_indices.contains(&i) {
                    continue;
                }
                if visible_index == index {
                    return Some(row);
                }
                visible_index += 1;
            }
            None
        } else {
            self.rows.get(index)
        }
    }

    /// Number of visible rows.
    pub fn row_count(&self) -> usize {
        if self.soft_delete {
            self.rows.len() - self.deleted_indices.len()
        } else {
            self.rows.len()
        }
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.row_count() == 0
    }

    /// Get all symbols (including soft-deleted ones).
    pub fn all_symbols(&self) -> &[SymbolRowObject] {
        &self.rows
    }

    /// Clear all symbols.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.deleted_indices.clear();
    }

    /// Set soft-delete mode.
    pub fn set_soft_delete(&mut self, soft_delete: bool) {
        self.soft_delete = soft_delete;
    }

    /// Whether soft-delete is enabled.
    pub fn is_soft_delete(&self) -> bool {
        self.soft_delete
    }

    /// Restore a soft-deleted symbol by index.
    pub fn restore(&mut self, index: usize) -> bool {
        if index < self.deleted_indices.len() {
            self.deleted_indices.remove(index);
            true
        } else {
            false
        }
    }

    /// Apply a filter and return matching symbol indices.
    pub fn filtered_indices(&self, filter: &SymbolFilter) -> Vec<usize> {
        self.rows
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.soft_delete || !self.deleted_indices.contains(i))
            .filter(|(_, row)| {
                // Check type filter for the symbol kind
                let tf = filter.type_filter();
                match row.kind() {
                    SymbolTableKind::Function => tf.functions,
                    SymbolTableKind::Label => tf.labels,
                    SymbolTableKind::Class => tf.classes,
                    SymbolTableKind::Library => tf.libraries,
                    SymbolTableKind::External => tf.external,
                    SymbolTableKind::Parameter => tf.parameters,
                    SymbolTableKind::Local => tf.locals,
                    SymbolTableKind::Unknown => tf.labels, // unknowns shown with labels
                }
            })
            .map(|(i, _)| i)
            .collect()
    }
}

impl Default for TransientSymbolTableModel {
    fn default() -> Self {
        Self::new("Transient Symbols")
    }
}

// ---------------------------------------------------------------------------
// SymbolRowObjectToAddressTableRowMapper
// ---------------------------------------------------------------------------

/// Maps a `SymbolRowObject` to its address.
///
/// Ported from `SymbolRowObjectToAddressTableRowMapper.java`.
#[derive(Debug)]
pub struct SymbolRowObjectToAddressTableRowMapper;

impl SymbolRowObjectToAddressTableRowMapper {
    /// Map a symbol row object to its address.
    ///
    /// Returns `None` for deleted symbols (address 0 with no name).
    pub fn map(row: &SymbolRowObject) -> Option<u64> {
        if row.name().is_empty() && row.address() == 0 {
            None
        } else {
            Some(row.address())
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolRowObjectToProgramLocationTableRowMapper
// ---------------------------------------------------------------------------

/// A program location derived from a symbol row object.
#[derive(Debug, Clone)]
pub struct SymbolProgramLocation {
    /// The symbol's address.
    pub address: u64,
    /// The symbol name.
    pub symbol_name: String,
    /// The symbol namespace.
    pub namespace: String,
    /// The program name.
    pub program_name: String,
}

/// Maps a `SymbolRowObject` to a `ProgramLocation`.
///
/// Ported from `SymbolRowObjectToProgramLocationTableRowMapper.java`.
#[derive(Debug)]
pub struct SymbolRowObjectToProgramLocationTableRowMapper;

impl SymbolRowObjectToProgramLocationTableRowMapper {
    /// Map a symbol row object to a program location.
    ///
    /// Returns `None` for deleted symbols (address 0 with no name).
    pub fn map(row: &SymbolRowObject, program_name: &str) -> Option<SymbolProgramLocation> {
        if row.name().is_empty() && row.address() == 0 {
            None
        } else {
            Some(SymbolProgramLocation {
                address: row.address(),
                symbol_name: row.name().to_string(),
                namespace: row.namespace().to_string(),
                program_name: program_name.to_string(),
            })
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_symbol(name: &str, addr: u64) -> SymbolRowObject {
        SymbolRowObject::new(name, addr, SymbolTableKind::Function, "Global")
    }

    #[test]
    fn test_symbol_renderer_default() {
        let renderer = SymbolRenderer::new();
        let symbol = make_test_symbol("main", 0x401000);
        let render = renderer.render(&symbol);
        assert_eq!(render.mode, SymbolRenderMode::Bold);
        assert_eq!(render.text, "main");
    }

    #[test]
    fn test_symbol_renderer_label() {
        let renderer = SymbolRenderer::new();
        let symbol = SymbolRowObject::new("LAB_001", 0x100, SymbolTableKind::Label, "Global");
        let render = renderer.render(&symbol);
        assert_eq!(render.mode, SymbolRenderMode::Normal);
    }

    #[test]
    fn test_symbol_renderer_external() {
        let renderer = SymbolRenderer::new();
        let symbol =
            SymbolRowObject::new("printf", 0x0, SymbolTableKind::External, "libc");
        let render = renderer.render(&symbol);
        assert_eq!(render.mode, SymbolRenderMode::Italic);
    }

    #[test]
    fn test_symbol_renderer_deleted() {
        let renderer = SymbolRenderer::new();
        let render = renderer.render_deleted();
        assert_eq!(render.text, "<< REMOVED >>");
        assert_eq!(render.mode, SymbolRenderMode::Strikethrough);
    }

    #[test]
    fn test_transient_model_basic() {
        let mut model = TransientSymbolTableModel::new("Test");
        assert!(model.is_empty());

        model.add_symbol(make_test_symbol("a", 0x100));
        model.add_symbol(make_test_symbol("b", 0x200));
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_transient_model_remove() {
        let mut model = TransientSymbolTableModel::new("Test");
        model.add_symbol(make_test_symbol("a", 0x100));
        model.add_symbol(make_test_symbol("b", 0x200));

        let removed = model.remove_symbol(0);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name(), "a");
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.get(0).unwrap().name(), "b");
    }

    #[test]
    fn test_transient_model_soft_delete() {
        let mut model = TransientSymbolTableModel::new("Test");
        model.set_soft_delete(true);

        model.add_symbol(make_test_symbol("a", 0x100));
        model.add_symbol(make_test_symbol("b", 0x200));
        model.add_symbol(make_test_symbol("c", 0x300));

        model.remove_symbol(1); // soft-delete "b"
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.get(0).unwrap().name(), "a");
        assert_eq!(model.get(1).unwrap().name(), "c"); // "b" skipped
    }

    #[test]
    fn test_transient_model_clear() {
        let mut model = TransientSymbolTableModel::new("Test");
        model.add_symbol(make_test_symbol("a", 0x100));
        model.clear();
        assert!(model.is_empty());
    }

    #[test]
    fn test_address_mapper() {
        let symbol = make_test_symbol("test", 0x400000);
        let addr = SymbolRowObjectToAddressTableRowMapper::map(&symbol);
        assert_eq!(addr, Some(0x400000));
    }

    #[test]
    fn test_address_mapper_empty() {
        // Simulate a "deleted" symbol with empty name and zero address
        let symbol = SymbolRowObject::new("", 0, SymbolTableKind::Label, "");
        let addr = SymbolRowObjectToAddressTableRowMapper::map(&symbol);
        assert!(addr.is_none());
    }

    #[test]
    fn test_location_mapper() {
        let symbol = make_test_symbol("main", 0x401000);
        let loc =
            SymbolRowObjectToProgramLocationTableRowMapper::map(&symbol, "test_program");
        assert!(loc.is_some());
        let loc = loc.unwrap();
        assert_eq!(loc.address, 0x401000);
        assert_eq!(loc.symbol_name, "main");
        assert_eq!(loc.program_name, "test_program");
    }

    #[test]
    fn test_location_mapper_deleted() {
        // Simulate a "deleted" symbol with empty name and zero address
        let symbol = SymbolRowObject::new("", 0, SymbolTableKind::Label, "");
        let loc =
            SymbolRowObjectToProgramLocationTableRowMapper::map(&symbol, "prog");
        assert!(loc.is_none());
    }

    #[test]
    fn test_transient_model_filtered() {
        let mut model = TransientSymbolTableModel::new("Test");
        model.add_symbol(SymbolRowObject::new(
            "func",
            0x100,
            SymbolTableKind::Function,
            "Global",
        ));
        model.add_symbol(SymbolRowObject::new(
            "label",
            0x200,
            SymbolTableKind::Label,
            "Global",
        ));
        model.add_symbol(SymbolRowObject::new(
            "func2",
            0x300,
            SymbolTableKind::Function,
            "Global",
        ));

        let mut filter = SymbolFilter::new();
        filter.type_filter_mut().functions = true;
        filter.type_filter_mut().labels = false;

        let indices = model.filtered_indices(&filter);
        assert_eq!(indices.len(), 2);
        assert_eq!(model.get(indices[0]).unwrap().name(), "func");
        assert_eq!(model.get(indices[1]).unwrap().name(), "func2");
    }

    #[test]
    fn test_symbol_render_state_clone() {
        let renderer = SymbolRenderer::new();
        let symbol = make_test_symbol("test", 0x100);
        let render = renderer.render(&symbol);
        let cloned = render.clone();
        assert_eq!(render.text, cloned.text);
        assert_eq!(render.mode, cloned.mode);
    }

    #[test]
    fn test_custom_color_scheme() {
        let colors = SymbolColorScheme {
            function_color: "#FF0000".into(),
            ..Default::default()
        };
        let renderer = SymbolRenderer::with_colors(colors);
        let symbol = make_test_symbol("func", 0x100);
        let render = renderer.render(&symbol);
        assert_eq!(render.color, "#FF0000");
    }

    #[test]
    fn test_transient_model_all_symbols() {
        let mut model = TransientSymbolTableModel::new("Test");
        model.set_soft_delete(true);
        model.add_symbol(make_test_symbol("a", 0x100));
        model.add_symbol(make_test_symbol("b", 0x200));

        model.remove_symbol(0);
        // all_symbols still includes soft-deleted
        assert_eq!(model.all_symbols().len(), 2);
        // but row_count doesn't
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_transient_model_restore() {
        let mut model = TransientSymbolTableModel::new("Test");
        model.set_soft_delete(true);
        model.add_symbol(make_test_symbol("a", 0x100));
        model.add_symbol(make_test_symbol("b", 0x200));

        model.remove_symbol(0);
        assert_eq!(model.row_count(), 1);

        assert!(model.restore(0));
        assert_eq!(model.row_count(), 2);
    }
}
