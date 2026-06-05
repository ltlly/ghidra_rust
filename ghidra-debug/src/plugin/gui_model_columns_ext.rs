//! Extended model column types for the debugger model plugin.
//!
//! Ported from `ghidra/app/plugin/core/debug/gui/model/columns/` package.
//! Provides column descriptors for the object model table, including:
//! - Path columns
//! - Value columns
//! - Life (lifespan) columns
//! - Attribute/property columns
//! - Column renderers

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The kind of a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ColumnKind {
    /// Path segment (key).
    Path,
    /// Key string.
    Key,
    /// Value display.
    Value,
    /// Life span display.
    Life,
    /// Numeric value.
    Numeric,
    /// Boolean property.
    Boolean,
    /// String attribute.
    StringAttribute,
    /// Object attribute.
    ObjectAttribute,
    /// Editable attribute.
    EditableAttribute,
    /// Property map.
    Property,
    /// Length.
    Length,
    /// Address.
    Address,
    /// Lifespan plot (visual).
    LifePlot,
}

/// A column descriptor for the model table.
///
/// Ported from `TraceValueKeyColumn.java`, `TraceValueValColumn.java`, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDescriptor {
    /// Column name/header.
    pub name: String,
    /// The kind of column.
    pub kind: ColumnKind,
    /// Column width in pixels.
    pub width: u32,
    /// Whether this column is editable.
    pub editable: bool,
    /// Whether this column is visible.
    pub visible: bool,
    /// Column index.
    pub index: u32,
}

impl ColumnDescriptor {
    /// Create a new column descriptor.
    pub fn new(name: String, kind: ColumnKind) -> Self {
        Self {
            name,
            kind,
            width: 100,
            editable: false,
            visible: true,
            index: 0,
        }
    }

    /// Set the width.
    pub fn with_width(mut self, width: u32) -> Self {
        self.width = width;
        self
    }

    /// Set editable.
    pub fn with_editable(mut self, editable: bool) -> Self {
        self.editable = editable;
        self
    }

    /// Set visibility.
    pub fn with_visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }
}

/// Render configuration for a column.
///
/// Ported from `TraceValueColumnRenderer.java` and `TracePathColumnRenderer.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnRenderConfig {
    /// Whether to render as hex.
    pub hex: bool,
    /// Whether to render as monospace.
    pub monospace: bool,
    /// Prefix text.
    pub prefix: Option<String>,
    /// Suffix text.
    pub suffix: Option<String>,
    /// Maximum display length.
    pub max_length: Option<usize>,
}

impl Default for ColumnRenderConfig {
    fn default() -> Self {
        Self {
            hex: false,
            monospace: true,
            prefix: None,
            suffix: None,
            max_length: None,
        }
    }
}

/// A path column showing the key path.
///
/// Ported from `TracePathColumn.java`.
#[derive(Debug, Clone)]
pub struct TracePathColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
    /// Render configuration.
    pub render: ColumnRenderConfig,
}

impl TracePathColumn {
    /// Create a new path column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Path".into(), ColumnKind::Path)
                .with_width(200),
            render: ColumnRenderConfig::default(),
        }
    }
}

/// A path string column showing the full path as a string.
///
/// Ported from `TracePathStringColumn.java`.
#[derive(Debug, Clone)]
pub struct TracePathStringColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
}

impl TracePathStringColumn {
    /// Create a new path string column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Path".into(), ColumnKind::Path)
                .with_width(250),
        }
    }
}

/// A key column showing the last key in a path.
///
/// Ported from `TracePathLastKeyColumn.java`.
#[derive(Debug, Clone)]
pub struct TracePathLastKeyColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
}

impl TracePathLastKeyColumn {
    /// Create a new last-key column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Key".into(), ColumnKind::Key)
                .with_width(100),
        }
    }
}

/// A value column for displaying object values.
///
/// Ported from `TraceValueValColumn.java`.
#[derive(Debug, Clone)]
pub struct TraceValueValColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
    /// Render configuration.
    pub render: ColumnRenderConfig,
}

impl TraceValueValColumn {
    /// Create a new value column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Value".into(), ColumnKind::Value)
                .with_width(150),
            render: ColumnRenderConfig {
                hex: true,
                ..Default::default()
            },
        }
    }
}

/// A life column showing the lifespan of an object.
///
/// Ported from `TraceValueLifeColumn.java`.
#[derive(Debug, Clone)]
pub struct TraceValueLifeColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
}

impl TraceValueLifeColumn {
    /// Create a new life column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Life".into(), ColumnKind::Life)
                .with_width(80),
        }
    }
}

/// A key column for trace values.
///
/// Ported from `TraceValueKeyColumn.java`.
#[derive(Debug, Clone)]
pub struct TraceValueKeyColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
}

impl TraceValueKeyColumn {
    /// Create a new key column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Key".into(), ColumnKind::Key)
                .with_width(100),
        }
    }
}

/// An attribute column for object attributes.
///
/// Ported from `TraceValueObjectAttributeColumn.java`.
#[derive(Debug, Clone)]
pub struct TraceValueObjectAttributeColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
    /// The attribute name.
    pub attribute_name: String,
}

impl TraceValueObjectAttributeColumn {
    /// Create a new attribute column.
    pub fn new(attribute_name: String) -> Self {
        Self {
            descriptor: ColumnDescriptor::new(attribute_name.clone(), ColumnKind::ObjectAttribute)
                .with_width(120),
            attribute_name,
        }
    }
}

/// An editable attribute column.
///
/// Ported from `TraceValueObjectEditableAttributeColumn.java`.
#[derive(Debug, Clone)]
pub struct TraceValueObjectEditableAttributeColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
    /// The attribute name.
    pub attribute_name: String,
}

impl TraceValueObjectEditableAttributeColumn {
    /// Create a new editable attribute column.
    pub fn new(attribute_name: String) -> Self {
        Self {
            descriptor: ColumnDescriptor::new(attribute_name.clone(), ColumnKind::EditableAttribute)
                .with_width(120)
                .with_editable(true),
            attribute_name,
        }
    }
}

/// A property column for object properties.
///
/// Ported from `TraceValueObjectPropertyColumn.java`.
#[derive(Debug, Clone)]
pub struct TraceValueObjectPropertyColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
    /// The property name.
    pub property_name: String,
}

impl TraceValueObjectPropertyColumn {
    /// Create a new property column.
    pub fn new(property_name: String) -> Self {
        Self {
            descriptor: ColumnDescriptor::new(property_name.clone(), ColumnKind::Property)
                .with_width(100),
            property_name,
        }
    }
}

/// A length column for displaying object sizes.
///
/// Ported from `AbstractTraceValueObjectLengthColumn.java`.
#[derive(Debug, Clone)]
pub struct TraceValueLengthColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
}

impl TraceValueLengthColumn {
    /// Create a new length column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Length".into(), ColumnKind::Length)
                .with_width(60),
        }
    }
}

/// An address column for displaying object addresses.
///
/// Ported from `AbstractTraceValueObjectAddressColumn.java`.
#[derive(Debug, Clone)]
pub struct TraceValueAddressColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
    /// Whether to display in hex.
    pub hex: bool,
}

impl TraceValueAddressColumn {
    /// Create a new address column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Address".into(), ColumnKind::Address)
                .with_width(120),
            hex: true,
        }
    }
}

/// A lifespan plot column showing a visual representation of the lifespan.
///
/// Ported from `TraceValueLifePlotColumn.java`.
#[derive(Debug, Clone)]
pub struct TraceValueLifePlotColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
}

impl TraceValueLifePlotColumn {
    /// Create a new lifespan plot column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Life".into(), ColumnKind::LifePlot)
                .with_width(200),
        }
    }
}

/// A path lifespan column showing the last lifespan.
///
/// Ported from `TracePathLastLifespanColumn.java`.
#[derive(Debug, Clone)]
pub struct TracePathLastLifespanColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
}

impl TracePathLastLifespanColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Life".into(), ColumnKind::Life)
                .with_width(80),
        }
    }
}

/// A path value column.
///
/// Ported from `TracePathValueColumn.java`.
#[derive(Debug, Clone)]
pub struct TracePathValueColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
}

impl TracePathValueColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Value".into(), ColumnKind::Value)
                .with_width(150),
        }
    }
}

/// A lifespan plot column for the path view.
///
/// Ported from `TracePathLastLifespanPlotColumn.java`.
#[derive(Debug, Clone)]
pub struct TracePathLastLifespanPlotColumn {
    /// Column descriptor.
    pub descriptor: ColumnDescriptor,
}

impl TracePathLastLifespanPlotColumn {
    /// Create a new column.
    pub fn new() -> Self {
        Self {
            descriptor: ColumnDescriptor::new("Life".into(), ColumnKind::LifePlot)
                .with_width(200),
        }
    }
}

/// A collection of columns for the model table.
#[derive(Debug, Clone)]
pub struct ModelColumnSet {
    /// All columns.
    pub columns: Vec<ColumnDescriptor>,
}

impl ModelColumnSet {
    /// Create the default set of columns for the object model.
    pub fn object_model() -> Self {
        Self {
            columns: vec![
                ColumnDescriptor::new("Key".into(), ColumnKind::Key).with_width(100),
                ColumnDescriptor::new("Value".into(), ColumnKind::Value).with_width(150),
                ColumnDescriptor::new("Life".into(), ColumnKind::Life).with_width(80),
                ColumnDescriptor::new("Length".into(), ColumnKind::Length).with_width(60),
            ],
        }
    }

    /// Create the default set of columns for the path model.
    pub fn path_model() -> Self {
        Self {
            columns: vec![
                ColumnDescriptor::new("Path".into(), ColumnKind::Path).with_width(250),
                ColumnDescriptor::new("Value".into(), ColumnKind::Value).with_width(150),
                ColumnDescriptor::new("Life".into(), ColumnKind::Life).with_width(80),
            ],
        }
    }

    /// Get visible columns.
    pub fn visible_columns(&self) -> Vec<&ColumnDescriptor> {
        self.columns.iter().filter(|c| c.visible).collect()
    }

    /// Get a column by name.
    pub fn get_column(&self, name: &str) -> Option<&ColumnDescriptor> {
        self.columns.iter().find(|c| c.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_column_descriptor() {
        let col = ColumnDescriptor::new("Test".into(), ColumnKind::Value)
            .with_width(200)
            .with_editable(true);
        assert_eq!(col.name, "Test");
        assert_eq!(col.width, 200);
        assert!(col.editable);
        assert!(col.visible);
    }

    #[test]
    fn test_column_render_config() {
        let config = ColumnRenderConfig::default();
        assert!(!config.hex);
        assert!(config.monospace);
    }

    #[test]
    fn test_model_column_set() {
        let set = ModelColumnSet::object_model();
        assert_eq!(set.columns.len(), 4);
        let visible = set.visible_columns();
        assert_eq!(visible.len(), 4);
    }

    #[test]
    fn test_path_column() {
        let col = TracePathColumn::new();
        assert_eq!(col.descriptor.name, "Path");
        assert_eq!(col.descriptor.kind, ColumnKind::Path);
    }

    #[test]
    fn test_value_column() {
        let col = TraceValueValColumn::new();
        assert!(col.render.hex);
    }

    #[test]
    fn test_attribute_column() {
        let col = TraceValueObjectAttributeColumn::new("name".into());
        assert_eq!(col.attribute_name, "name");
        assert_eq!(col.descriptor.kind, ColumnKind::ObjectAttribute);
    }

    #[test]
    fn test_editable_attribute_column() {
        let col = TraceValueObjectEditableAttributeColumn::new("value".into());
        assert!(col.descriptor.editable);
    }
}
