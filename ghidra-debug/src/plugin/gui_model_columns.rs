//! Table column definitions for the object model viewer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.model.columns` package.
//! Each column type defines how a particular aspect of a trace object value
//! row should be extracted and displayed.

use serde::{Deserialize, Serialize};

use super::gui_model::ObjectModelRow;

// ---------------------------------------------------------------------------
// Column types
// ---------------------------------------------------------------------------

/// The kind of value a column displays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ColumnKind {
    /// The entry key (name or index).
    Key,
    /// The value of the entry.
    Value,
    /// The lifespan.
    Life,
    /// A lifespan plot (visual bar).
    LifePlot,
    /// An attribute value.
    Attribute,
    /// A property of the entry object.
    Property,
    /// The entry's length (for containers).
    Length,
    /// An address value.
    Address,
    /// A string representation of the path.
    PathString,
    /// The value of a path entry.
    PathValue,
    /// The last key of a path.
    PathLastKey,
    /// The lifespan of the last path entry.
    PathLastLife,
    /// A lifespan plot for the last path entry.
    PathLastLifePlot,
    /// Whether the value is editable.
    Editable,
}

/// A column descriptor for the object model table.
///
/// Ported from Ghidra's `DynamicTableColumn` specializations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelColumn {
    /// The column kind.
    pub kind: ColumnKind,
    /// The column header name.
    pub header_name: String,
    /// The attribute name (for attribute columns).
    pub attribute_name: Option<String>,
    /// Whether the column is visible by default.
    pub visible_by_default: bool,
    /// The column index in the table.
    pub column_index: usize,
    /// Whether this column is editable.
    pub editable: bool,
    /// The preferred width in pixels.
    pub preferred_width: Option<usize>,
}

impl ModelColumn {
    /// Create a key column.
    pub fn key() -> Self {
        Self {
            kind: ColumnKind::Key,
            header_name: "Key".into(),
            attribute_name: None,
            visible_by_default: true,
            column_index: 0,
            editable: false,
            preferred_width: Some(120),
        }
    }

    /// Create a value column.
    pub fn value() -> Self {
        Self {
            kind: ColumnKind::Value,
            header_name: "Value".into(),
            attribute_name: None,
            visible_by_default: true,
            column_index: 1,
            editable: false,
            preferred_width: Some(200),
        }
    }

    /// Create a lifespan column.
    pub fn life() -> Self {
        Self {
            kind: ColumnKind::Life,
            header_name: "Life".into(),
            attribute_name: None,
            visible_by_default: true,
            column_index: 2,
            editable: false,
            preferred_width: Some(100),
        }
    }

    /// Create a lifespan plot column.
    pub fn life_plot() -> Self {
        Self {
            kind: ColumnKind::LifePlot,
            header_name: "Life Plot".into(),
            attribute_name: None,
            visible_by_default: false,
            column_index: 3,
            editable: false,
            preferred_width: Some(200),
        }
    }

    /// Create an attribute column.
    pub fn attribute(name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            kind: ColumnKind::Attribute,
            header_name: name.clone(),
            attribute_name: Some(name),
            visible_by_default: true,
            column_index: 0,
            editable: false,
            preferred_width: Some(150),
        }
    }

    /// Create an editable attribute column.
    pub fn editable_attribute(name: impl Into<String>) -> Self {
        let mut col = Self::attribute(name);
        col.editable = true;
        col
    }

    /// Extract the display value from a row for this column.
    pub fn get_display(&self, row: &ObjectModelRow) -> String {
        match self.kind {
            ColumnKind::Key => row.key.clone(),
            ColumnKind::Value => row.display.clone(),
            ColumnKind::Life => format!("{}", row.lifespan),
            ColumnKind::LifePlot => {
                // Life plot display is handled by the rendering layer
                format!("{}", row.lifespan)
            }
            ColumnKind::Attribute => {
                if let Some(attr_name) = &self.attribute_name {
                    row.get_attribute(attr_name)
                        .map(|a| a.display.clone())
                        .unwrap_or_default()
                } else {
                    String::new()
                }
            }
            ColumnKind::Property => row.entry.key.clone(),
            ColumnKind::Length => {
                // Length is a derived property
                row.attributes.len().to_string()
            }
            ColumnKind::Address => {
                // Address columns need program context
                row.display.clone()
            }
            ColumnKind::PathString => row.entry.full_path().to_string(),
            ColumnKind::PathValue => row.entry.display(),
            ColumnKind::PathLastKey => row.entry.key.clone(),
            ColumnKind::PathLastLife => format!("{}", row.entry.lifespan),
            ColumnKind::PathLastLifePlot => format!("{}", row.entry.lifespan),
            ColumnKind::Editable => row.display.clone(),
        }
    }

    /// Extract the HTML display from a row for this column.
    pub fn get_html_display(&self, row: &ObjectModelRow) -> String {
        match self.kind {
            ColumnKind::Attribute => {
                if let Some(attr_name) = &self.attribute_name {
                    row.get_attribute(attr_name)
                        .map(|a| a.html_display.clone())
                        .unwrap_or_default()
                } else {
                    String::new()
                }
            }
            _ => format!("<html>{}</html>", self.get_display(row)),
        }
    }

    /// Extract the tooltip from a row for this column.
    pub fn get_tooltip(&self, row: &ObjectModelRow) -> String {
        match self.kind {
            ColumnKind::Attribute => {
                if let Some(attr_name) = &self.attribute_name {
                    row.get_attribute(attr_name)
                        .map(|a| a.tooltip.clone())
                        .unwrap_or_default()
                } else {
                    String::new()
                }
            }
            _ => self.get_display(row),
        }
    }

    /// Check if the value in this column is modified.
    pub fn is_modified(&self, row: &ObjectModelRow) -> bool {
        match self.kind {
            ColumnKind::Attribute => {
                if let Some(attr_name) = &self.attribute_name {
                    row.get_attribute(attr_name)
                        .map(|a| a.modified)
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            _ => row.modified,
        }
    }

    /// Whether this column is visible by default for the given schema.
    pub fn is_hidden_by_schema(&self) -> bool {
        !self.visible_by_default
    }
}

// ---------------------------------------------------------------------------
// Column descriptor (collection)
// ---------------------------------------------------------------------------

/// A collection of columns for the object model table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ColumnDescriptor {
    /// The columns in order.
    columns: Vec<ModelColumn>,
    /// The sorted column index.
    sorted_column: Option<usize>,
}

impl ColumnDescriptor {
    /// Create a new empty descriptor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a default descriptor with key, value, and life columns.
    pub fn default_columns() -> Self {
        Self {
            columns: vec![
                ModelColumn::key(),
                ModelColumn::value(),
                ModelColumn::life(),
                ModelColumn::life_plot(),
            ],
            sorted_column: None,
        }
    }

    /// Add a column.
    pub fn add_column(&mut self, mut column: ModelColumn) {
        column.column_index = self.columns.len();
        self.columns.push(column);
    }

    /// Add a visible column.
    pub fn add_visible_column(&mut self, mut column: ModelColumn) {
        column.visible_by_default = true;
        column.column_index = self.columns.len();
        self.columns.push(column);
    }

    /// Add a hidden column.
    pub fn add_hidden_column(&mut self, mut column: ModelColumn) {
        column.visible_by_default = false;
        column.column_index = self.columns.len();
        self.columns.push(column);
    }

    /// Get all columns.
    pub fn columns(&self) -> &[ModelColumn] {
        &self.columns
    }

    /// Get a column by index.
    pub fn column(&self, index: usize) -> Option<&ModelColumn> {
        self.columns.get(index)
    }

    /// The number of columns.
    pub fn len(&self) -> usize {
        self.columns.len()
    }

    /// Whether there are no columns.
    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    /// Get the sorted column index.
    pub fn sorted_column(&self) -> Option<usize> {
        self.sorted_column
    }

    /// Set the sorted column.
    pub fn set_sorted_column(&mut self, index: Option<usize>) {
        self.sorted_column = index;
    }

    /// Compute attributes for a trace and add attribute columns.
    pub fn add_attribute_columns(&mut self, attribute_names: &[String]) {
        for name in attribute_names {
            self.add_visible_column(ModelColumn::attribute(name));
        }
    }
}

// ---------------------------------------------------------------------------
// Editable column trait
// ---------------------------------------------------------------------------

/// A column that supports editing values.
///
/// Ported from Ghidra's `EditableColumn` interface.
pub trait EditableColumn {
    /// Check if a cell is editable.
    fn is_editable(&self, row: &ObjectModelRow) -> bool;

    /// Set a value in a cell.
    fn set_value(&self, row: &mut ObjectModelRow, value: &str) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Column renderer
// ---------------------------------------------------------------------------

/// Configuration for how column values should be rendered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnRenderConfig {
    /// Whether to use monospace font.
    pub monospace: bool,
    /// The foreground color override.
    pub foreground: Option<[u8; 4]>,
    /// The background color override.
    pub background: Option<[u8; 4]>,
    /// Whether to render as HTML.
    pub html: bool,
}

impl Default for ColumnRenderConfig {
    fn default() -> Self {
        Self {
            monospace: false,
            foreground: None,
            background: None,
            html: true,
        }
    }
}

impl ColumnRenderConfig {
    /// Create a monospace config.
    pub fn monospace() -> Self {
        Self {
            monospace: true,
            html: false,
            ..Default::default()
        }
    }

    /// Create an HTML config.
    pub fn html() -> Self {
        Self {
            html: true,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::gui_model::AttributeValue;
    use crate::model::Lifespan;
    use crate::target::key_path::KeyPath;

    fn make_test_row() -> ObjectModelRow {
        let entry = super::super::gui_model::ModelValueEntry::new(
            "name",
            Some(super::super::gui_model::ModelValue::String("init".into())),
            Lifespan::now_on(0),
            KeyPath::of(&["Processes", "[5]"]),
        );
        let mut row = ObjectModelRow::new(entry);
        row.set_attribute(
            "pid",
            AttributeValue::new("1234").with_modified(true),
        );
        row
    }

    #[test]
    fn test_key_column() {
        let col = ModelColumn::key();
        let row = make_test_row();
        assert_eq!(col.get_display(&row), "name");
        assert_eq!(col.kind, ColumnKind::Key);
        assert!(col.visible_by_default);
    }

    #[test]
    fn test_value_column() {
        let col = ModelColumn::value();
        let row = make_test_row();
        assert_eq!(col.get_display(&row), "init");
    }

    #[test]
    fn test_life_column() {
        let col = ModelColumn::life();
        let row = make_test_row();
        let display = col.get_display(&row);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_attribute_column() {
        let col = ModelColumn::attribute("pid");
        let row = make_test_row();
        assert_eq!(col.get_display(&row), "1234");
        assert!(col.is_modified(&row));
    }

    #[test]
    fn test_attribute_column_missing() {
        let col = ModelColumn::attribute("missing");
        let row = make_test_row();
        assert_eq!(col.get_display(&row), "");
        assert!(!col.is_modified(&row));
    }

    #[test]
    fn test_path_string_column() {
        let col = ModelColumn {
            kind: ColumnKind::PathString,
            header_name: "Path".into(),
            attribute_name: None,
            visible_by_default: true,
            column_index: 0,
            editable: false,
            preferred_width: None,
        };
        let row = make_test_row();
        assert_eq!(col.get_display(&row), "Processes.[5].name");
    }

    #[test]
    fn test_column_descriptor() {
        let mut desc = ColumnDescriptor::new();
        assert!(desc.is_empty());

        desc.add_visible_column(ModelColumn::key());
        desc.add_visible_column(ModelColumn::value());
        desc.add_hidden_column(ModelColumn::life_plot());
        assert_eq!(desc.len(), 3);
        assert!(desc.column(0).unwrap().visible_by_default);
        assert!(!desc.column(2).unwrap().visible_by_default);
    }

    #[test]
    fn test_column_descriptor_default() {
        let desc = ColumnDescriptor::default_columns();
        assert_eq!(desc.len(), 4);
        assert_eq!(desc.column(0).unwrap().kind, ColumnKind::Key);
        assert_eq!(desc.column(1).unwrap().kind, ColumnKind::Value);
    }

    #[test]
    fn test_add_attribute_columns() {
        let mut desc = ColumnDescriptor::default_columns();
        desc.add_attribute_columns(&["pid".into(), "name".into()]);
        assert_eq!(desc.len(), 6);
        assert_eq!(desc.column(4).unwrap().header_name, "pid");
        assert_eq!(desc.column(5).unwrap().header_name, "name");
    }

    #[test]
    fn test_column_html_display() {
        let col = ModelColumn::key();
        let row = make_test_row();
        assert_eq!(col.get_html_display(&row), "<html>name</html>");
    }

    #[test]
    fn test_column_tooltip() {
        let col = ModelColumn::value();
        let row = make_test_row();
        assert_eq!(col.get_tooltip(&row), "init");
    }

    #[test]
    fn test_editable_attribute_column() {
        let col = ModelColumn::editable_attribute("pid");
        assert!(col.editable);
    }

    #[test]
    fn test_column_render_config() {
        let config = ColumnRenderConfig::monospace();
        assert!(config.monospace);
        assert!(!config.html);

        let config = ColumnRenderConfig::html();
        assert!(config.html);
    }

    #[test]
    fn test_sorted_column() {
        let mut desc = ColumnDescriptor::default_columns();
        assert!(desc.sorted_column().is_none());
        desc.set_sorted_column(Some(1));
        assert_eq!(desc.sorted_column(), Some(1));
    }
}
