//! Table column definitions for the object model viewer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.model.columns` package
//! (17 Java files).
//!
//! Each column type defines how a particular aspect of a trace object value
//! row should be extracted, formatted, and rendered. The Java originals are
//! Swing `DynamicTableColumn` specializations; the Rust port focuses on the
//! data-model layer (value extraction and formatting).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Value column types -- extract data from ObjectModelRow / ValueRow
// ---------------------------------------------------------------------------

/// Extracts the key (name or index) of a value entry.
///
/// Ported from `TraceValueKeyColumn`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceValueKeyColumn {
    /// Whether to show the fully-qualified path.
    pub show_full_path: bool,
}

impl TraceValueKeyColumn {
    /// Get the display key for a value entry.
    pub fn get_value(&self, row: &ValueRow) -> String {
        if self.show_full_path {
            row.path_string()
        } else {
            row.key.clone()
        }
    }
}

/// Extracts the value string of a value entry.
///
/// Ported from `TraceValueValColumn`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceValueValColumn {
    /// Optional diff highlight color (ARGB).
    pub diff_color: Option<u32>,
}

impl TraceValueValColumn {
    /// Get the display value for a value entry.
    pub fn get_value(&self, row: &ValueRow) -> String {
        row.value_display.clone()
    }

    /// Set the diff highlight color.
    pub fn set_diff_color(&mut self, color: Option<u32>) {
        self.diff_color = color;
    }
}

/// Extracts the lifespan of a value entry.
///
/// Ported from `TraceValueLifeColumn`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceValueLifeColumn {
    /// The radix for snap display (10 or 16).
    pub snap_radix: u32,
}

impl TraceValueLifeColumn {
    /// Get the lifespan display string.
    pub fn get_value(&self, row: &ValueRow) -> String {
        match (&row.lifespan_min, &row.lifespan_max) {
            (Some(min), Some(max)) => {
                let (fmt_min, fmt_max) = match self.snap_radix {
                    16 => (format!("0x{:x}", min), format!("0x{:x}", max)),
                    _ => (format!("{}", min), format!("{}", max)),
                };
                format!("[{}, {})", fmt_min, fmt_max)
            }
            (Some(min), None) => {
                let fmt_min = match self.snap_radix {
                    16 => format!("0x{:x}", min),
                    _ => format!("{}", min),
                };
                format!("[{}, ...)", fmt_min)
            }
            _ => String::from("[none]"),
        }
    }
}

/// A lifespan plot column that visualises a value's lifespan as a bar
/// within the full trace time range.
///
/// Ported from `TraceValueLifePlotColumn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceValueLifePlotColumn {
    /// The minimum snap of the full range.
    pub full_range_min: i64,
    /// The maximum snap of the full range.
    pub full_range_max: i64,
    /// The currently selected snap.
    pub current_snap: Option<i64>,
}

impl Default for TraceValueLifePlotColumn {
    fn default() -> Self {
        Self {
            full_range_min: 0,
            full_range_max: 0,
            current_snap: None,
        }
    }
}

impl TraceValueLifePlotColumn {
    /// Set the full time range.
    pub fn set_full_range(&mut self, min: i64, max: i64) {
        self.full_range_min = min;
        self.full_range_max = max;
    }

    /// Set the current snap position.
    pub fn set_snap(&mut self, snap: i64) {
        self.current_snap = Some(snap);
    }

    /// Compute the normalized bar boundaries for a given lifespan.
    /// Returns (start_pct, end_pct) each in [0.0, 1.0].
    pub fn compute_bar(&self, row: &ValueRow) -> (f64, f64) {
        let range = (self.full_range_max - self.full_range_min) as f64;
        if range <= 0.0 {
            return (0.0, 0.0);
        }
        let start = row
            .lifespan_min
            .map(|v| ((v - self.full_range_min) as f64 / range).clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let end = row
            .lifespan_max
            .map(|v| ((v - self.full_range_min) as f64 / range).clamp(0.0, 1.0))
            .unwrap_or(1.0);
        (start, end)
    }
}

// ---------------------------------------------------------------------------
// Object-attribute column types
// ---------------------------------------------------------------------------

/// Extracts an object attribute for display.
///
/// Ported from `TraceValueObjectAttributeColumn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceValueObjectAttributeColumn {
    /// The attribute name in the schema.
    pub attribute_name: String,
    /// The schema index that owns this attribute.
    pub schema_id: u64,
    /// Optional diff highlight color (ARGB).
    pub diff_color: Option<u32>,
    /// Whether this column is hidden by default.
    pub hidden: bool,
}

impl TraceValueObjectAttributeColumn {
    /// Extract the attribute value from a row.
    pub fn get_value(&self, row: &ValueRow) -> Option<String> {
        row.attributes
            .iter()
            .find(|a| a.name == self.attribute_name)
            .map(|a| a.display_value.clone())
    }
}

/// An editable version of the object-attribute column.
///
/// Ported from `TraceValueObjectEditableAttributeColumn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceValueObjectEditableAttributeColumn {
    /// The inner attribute column.
    pub inner: TraceValueObjectAttributeColumn,
}

impl TraceValueObjectEditableAttributeColumn {
    /// Check whether the cell for a given row is editable.
    pub fn is_editable(&self, row: &ValueRow) -> bool {
        // Only primitive (non-container) attributes are editable.
        row.attributes
            .iter()
            .find(|a| a.name == self.inner.attribute_name)
            .map(|a| !a.is_container)
            .unwrap_or(false)
    }

    /// Format the new value for display after editing.
    pub fn format_set_value(&self, _row: &ValueRow, new_value: &str) -> String {
        new_value.to_string()
    }
}

/// Extracts an object property value.
///
/// Ported from `TraceValueObjectPropertyColumn`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceValueObjectPropertyColumn {
    /// The property key.
    pub property_name: String,
}

impl TraceValueObjectPropertyColumn {
    /// Extract the property value from a row.
    pub fn get_value(&self, row: &ValueRow) -> Option<String> {
        row.properties
            .iter()
            .find(|p| p.name == self.property_name)
            .map(|p| p.value.clone())
    }
}

// ---------------------------------------------------------------------------
// Path column types -- operate on the path side of the two-table model
// ---------------------------------------------------------------------------

/// Displays the full path string of a trace object.
///
/// Ported from `TracePathStringColumn`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracePathStringColumn;

impl TracePathStringColumn {
    /// Get the path string.
    pub fn get_value(&self, row: &PathRow) -> String {
        row.path_string()
    }
}

/// Displays the value at the end of a path.
///
/// Ported from `TracePathValueColumn`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracePathValueColumn;

impl TracePathValueColumn {
    /// Get the value of the last entry.
    pub fn get_value(&self, row: &PathRow) -> String {
        row.value.clone()
    }
}

/// Displays the last key of a path.
///
/// Ported from `TracePathLastKeyColumn`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracePathLastKeyColumn;

impl TracePathLastKeyColumn {
    /// Get the last key.
    pub fn get_value(&self, row: &PathRow) -> String {
        row.last_key()
    }
}

/// Displays the lifespan of the last path entry.
///
/// Ported from `TracePathLastLifespanColumn`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracePathLastLifespanColumn {
    /// Radix for snap display.
    pub snap_radix: u32,
}

impl TracePathLastLifespanColumn {
    /// Get the lifespan display string.
    pub fn get_value(&self, row: &PathRow) -> String {
        match (&row.lifespan_min, &row.lifespan_max) {
            (Some(min), Some(max)) => {
                let (fmt_min, fmt_max) = match self.snap_radix {
                    16 => (format!("0x{:x}", min), format!("0x{:x}", max)),
                    _ => (format!("{}", min), format!("{}", max)),
                };
                format!("[{}, {})", fmt_min, fmt_max)
            }
            _ => String::from("[none]"),
        }
    }
}

/// A plot column for the last entry of a path.
///
/// Ported from `TracePathLastLifespanPlotColumn`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracePathLastLifespanPlotColumn {
    /// The full range for the plot.
    pub full_range_min: i64,
    /// The full range max.
    pub full_range_max: i64,
}

impl TracePathLastLifespanPlotColumn {
    /// Set the full time range.
    pub fn set_full_range(&mut self, min: i64, max: i64) {
        self.full_range_min = min;
        self.full_range_max = max;
    }

    /// Compute the normalised bar for a path row.
    pub fn compute_bar(&self, row: &PathRow) -> (f64, f64) {
        let range = (self.full_range_max - self.full_range_min) as f64;
        if range <= 0.0 {
            return (0.0, 0.0);
        }
        let start = row
            .lifespan_min
            .map(|v| ((v - self.full_range_min) as f64 / range).clamp(0.0, 1.0))
            .unwrap_or(0.0);
        let end = row
            .lifespan_max
            .map(|v| ((v - self.full_range_min) as f64 / range).clamp(0.0, 1.0))
            .unwrap_or(1.0);
        (start, end)
    }
}

// ---------------------------------------------------------------------------
// Abstract base column types
// ---------------------------------------------------------------------------

/// Abstract column for displaying the length of a container object.
///
/// Ported from `AbstractTraceValueObjectLengthColumn`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AbstractTraceValueObjectLengthColumn;

impl AbstractTraceValueObjectLengthColumn {
    /// Get the length display for a value row.
    pub fn get_value(&self, row: &ValueRow) -> String {
        row.container_length
            .map(|l| format!("{}", l))
            .unwrap_or_default()
    }
}

/// Abstract column for displaying an address value.
///
/// Ported from `AbstractTraceValueObjectAddressColumn`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AbstractTraceValueObjectAddressColumn {
    /// Whether to show the address space name prefix.
    pub show_space_prefix: bool,
}

impl AbstractTraceValueObjectAddressColumn {
    /// Get the address display for a value row.
    pub fn get_value(&self, row: &ValueRow) -> String {
        row.address_value
            .map(|addr| {
                if self.show_space_prefix {
                    if let Some(ref space) = row.address_space {
                        format!("{}:{:x}", space, addr)
                    } else {
                        format!("0x{:x}", addr)
                    }
                } else {
                    format!("0x{:x}", addr)
                }
            })
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Renderer types
// ---------------------------------------------------------------------------

/// Renderer configuration for value columns.
///
/// Ported from `TraceValueColumnRenderer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceValueColumnRenderer {
    /// Background color for stale / unknown values (ARGB).
    pub stale_color: Option<u32>,
    /// Background color for changed values (ARGB).
    pub diff_color: Option<u32>,
    /// Background color for selected changed values (ARGB).
    pub diff_color_selected: Option<u32>,
}

impl Default for TraceValueColumnRenderer {
    fn default() -> Self {
        Self {
            stale_color: Some(0xFF_80_80_80), // grey
            diff_color: None,
            diff_color_selected: None,
        }
    }
}

/// Renderer configuration for path columns.
///
/// Ported from `TracePathColumnRenderer`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TracePathColumnRenderer {
    /// Background color for the currently focused path (ARGB).
    pub focus_color: Option<u32>,
}

// ---------------------------------------------------------------------------
// Editable column trait
// ---------------------------------------------------------------------------

/// Trait for columns that support in-place editing.
///
/// Ported from the `EditableColumn` marker interface.
pub trait EditableColumn {
    /// Check if a given cell is editable.
    fn is_editable(&self, row_index: usize) -> bool;

    /// Set the value for a cell.
    fn set_value(&mut self, row_index: usize, new_value: &str) -> Result<(), String>;

    /// Validate a proposed value before committing.
    fn validate_value(&self, new_value: &str) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Data model types used by columns
// ---------------------------------------------------------------------------

/// A row in the value (right) side of the model table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValueRow {
    /// The entry key (name or index).
    pub key: String,
    /// The full key path segments.
    pub key_path: Vec<String>,
    /// The display-formatted value.
    pub value_display: String,
    /// The raw value as bytes.
    pub raw_value: Vec<u8>,
    /// Minimum snap of the lifespan.
    pub lifespan_min: Option<i64>,
    /// Maximum snap of the lifespan.
    pub lifespan_max: Option<i64>,
    /// Length if the object is a container.
    pub container_length: Option<usize>,
    /// The address value, if the object represents an address.
    pub address_value: Option<u64>,
    /// The address space name.
    pub address_space: Option<String>,
    /// Whether this value is hidden by the schema.
    pub hidden: bool,
    /// Object attributes.
    pub attributes: Vec<AttributeEntry>,
    /// Object properties.
    pub properties: Vec<PropertyEntry>,
}

impl ValueRow {
    /// Get the full path as a dot-separated string.
    pub fn path_string(&self) -> String {
        self.key_path.join(".")
    }
}

/// A row in the path (left) side of the model table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathRow {
    /// The key path segments.
    pub key_path: Vec<String>,
    /// The display value of the entry.
    pub value: String,
    /// Minimum snap of the lifespan.
    pub lifespan_min: Option<i64>,
    /// Maximum snap of the lifespan.
    pub lifespan_max: Option<i64>,
}

impl PathRow {
    /// Get the full path as a dot-separated string.
    pub fn path_string(&self) -> String {
        self.key_path.join(".")
    }

    /// Get the last segment of the path.
    pub fn last_key(&self) -> String {
        self.key_path
            .last()
            .cloned()
            .unwrap_or_default()
    }
}

/// An attribute entry on a value row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeEntry {
    /// The attribute name.
    pub name: String,
    /// The display-formatted value.
    pub display_value: String,
    /// Whether this attribute is a container type.
    pub is_container: bool,
    /// The schema ID that owns this attribute.
    pub schema_id: u64,
}

/// A property entry on a value row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PropertyEntry {
    /// The property name.
    pub name: String,
    /// The property value.
    pub value: String,
}

// ---------------------------------------------------------------------------
// Column descriptor helper
// ---------------------------------------------------------------------------

/// Describes a complete set of columns for a model table.
///
/// Ported from `TableColumnDescriptor`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ColumnDescriptor {
    /// Key column (always visible, always first).
    pub key: TraceValueKeyColumn,
    /// Value column.
    pub value: TraceValueValColumn,
    /// Lifespan column.
    pub life: TraceValueLifeColumn,
    /// Plot column (typically hidden).
    pub plot: TraceValueLifePlotColumn,
    /// Dynamic attribute columns (populated from schema).
    pub attributes: Vec<TraceValueObjectAttributeColumn>,
    /// Path-side columns.
    pub path_columns: PathColumnSet,
}

/// The set of path-side columns.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PathColumnSet {
    /// Path string column.
    pub path_string: TracePathStringColumn,
    /// Path value column.
    pub path_value: TracePathValueColumn,
    /// Last key column.
    pub last_key: TracePathLastKeyColumn,
    /// Last lifespan column.
    pub last_lifespan: TracePathLastLifespanColumn,
    /// Last lifespan plot column.
    pub last_life_plot: TracePathLastLifespanPlotColumn,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_key_column() {
        let col = TraceValueKeyColumn { show_full_path: false };
        let row = ValueRow {
            key: "Threads".into(),
            key_path: vec!["Processes".into(), "1234".into(), "Threads".into()],
            ..Default::default()
        };
        assert_eq!(col.get_value(&row), "Threads");

        let col_path = TraceValueKeyColumn { show_full_path: true };
        assert_eq!(col_path.get_value(&row), "Processes.1234.Threads");
    }

    #[test]
    fn test_value_val_column() {
        let col = TraceValueValColumn::default();
        let row = ValueRow {
            value_display: "0x400000".into(),
            ..Default::default()
        };
        assert_eq!(col.get_value(&row), "0x400000");
    }

    #[test]
    fn test_value_life_column_dec() {
        let col = TraceValueLifeColumn { snap_radix: 10 };
        let row = ValueRow {
            lifespan_min: Some(0),
            lifespan_max: Some(10),
            ..Default::default()
        };
        assert_eq!(col.get_value(&row), "[0, 10)");
    }

    #[test]
    fn test_value_life_column_hex() {
        let col = TraceValueLifeColumn { snap_radix: 16 };
        let row = ValueRow {
            lifespan_min: Some(0x10),
            lifespan_max: Some(0xff),
            ..Default::default()
        };
        assert_eq!(col.get_value(&row), "[0x10, 0xff)");
    }

    #[test]
    fn test_value_life_column_none() {
        let col = TraceValueLifeColumn { snap_radix: 10 };
        let row = ValueRow::default();
        assert_eq!(col.get_value(&row), "[none]");
    }

    #[test]
    fn test_life_plot_column_bar() {
        let mut col = TraceValueLifePlotColumn::default();
        col.set_full_range(0, 100);
        let row = ValueRow {
            lifespan_min: Some(25),
            lifespan_max: Some(75),
            ..Default::default()
        };
        let (start, end) = col.compute_bar(&row);
        assert!((start - 0.25).abs() < 1e-9);
        assert!((end - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_life_plot_column_zero_range() {
        let col = TraceValueLifePlotColumn {
            full_range_min: 5,
            full_range_max: 5,
            current_snap: None,
        };
        let row = ValueRow::default();
        let (s, e) = col.compute_bar(&row);
        assert_eq!(s, 0.0);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_object_attribute_column() {
        let col = TraceValueObjectAttributeColumn {
            attribute_name: "pid".into(),
            schema_id: 1,
            diff_color: None,
            hidden: false,
        };
        let row = ValueRow {
            attributes: vec![AttributeEntry {
                name: "pid".into(),
                display_value: "1234".into(),
                is_container: false,
                schema_id: 1,
            }],
            ..Default::default()
        };
        assert_eq!(col.get_value(&row).unwrap(), "1234");
        assert!(col.get_value(&ValueRow::default()).is_none());
    }

    #[test]
    fn test_editable_attribute_column() {
        let col = TraceValueObjectEditableAttributeColumn {
            inner: TraceValueObjectAttributeColumn {
                attribute_name: "name".into(),
                schema_id: 1,
                diff_color: None,
                hidden: false,
            },
        };
        let row = ValueRow {
            attributes: vec![AttributeEntry {
                name: "name".into(),
                display_value: "test".into(),
                is_container: false,
                schema_id: 1,
            }],
            ..Default::default()
        };
        assert!(col.is_editable(&row));

        let container_row = ValueRow {
            attributes: vec![AttributeEntry {
                name: "name".into(),
                display_value: "[]".into(),
                is_container: true,
                schema_id: 1,
            }],
            ..Default::default()
        };
        assert!(!col.is_editable(&container_row));
    }

    #[test]
    fn test_object_length_column() {
        let col = AbstractTraceValueObjectLengthColumn;
        let row = ValueRow {
            container_length: Some(42),
            ..Default::default()
        };
        assert_eq!(col.get_value(&row), "42");
        assert_eq!(col.get_value(&ValueRow::default()), "");
    }

    #[test]
    fn test_address_column() {
        let col = AbstractTraceValueObjectAddressColumn { show_space_prefix: true };
        let row = ValueRow {
            address_value: Some(0x400000),
            address_space: Some("ram".into()),
            ..Default::default()
        };
        assert_eq!(col.get_value(&row), "ram:400000");

        let col_no_prefix = AbstractTraceValueObjectAddressColumn { show_space_prefix: false };
        assert_eq!(col_no_prefix.get_value(&row), "0x400000");
    }

    #[test]
    fn test_property_column() {
        let col = TraceValueObjectPropertyColumn {
            property_name: "color".into(),
        };
        let row = ValueRow {
            properties: vec![PropertyEntry {
                name: "color".into(),
                value: "red".into(),
            }],
            ..Default::default()
        };
        assert_eq!(col.get_value(&row).unwrap(), "red");
    }

    #[test]
    fn test_path_columns() {
        let row = PathRow {
            key_path: vec!["Processes".into(), "1".into(), "Threads".into()],
            value: "running".into(),
            lifespan_min: Some(0),
            lifespan_max: Some(50),
        };

        let str_col = TracePathStringColumn;
        assert_eq!(str_col.get_value(&row), "Processes.1.Threads");

        let val_col = TracePathValueColumn;
        assert_eq!(val_col.get_value(&row), "running");

        let key_col = TracePathLastKeyColumn;
        assert_eq!(key_col.get_value(&row), "Threads");

        let life_col = TracePathLastLifespanColumn { snap_radix: 10 };
        assert_eq!(life_col.get_value(&row), "[0, 50)");
    }

    #[test]
    fn test_path_last_life_plot() {
        let mut col = TracePathLastLifespanPlotColumn {
            full_range_min: 0,
            full_range_max: 100,
        };
        let row = PathRow {
            key_path: vec!["p".into()],
            value: "v".into(),
            lifespan_min: Some(0),
            lifespan_max: Some(50),
        };
        let (s, e) = col.compute_bar(&row);
        assert!((s - 0.0).abs() < 1e-9);
        assert!((e - 0.5).abs() < 1e-9);

        col.set_full_range(10, 20);
        let (s2, e2) = col.compute_bar(&row);
        assert!((s2 - 0.0).abs() < 1e-9); // clamped
        assert!((e2 - 1.0).abs() < 1e-9); // clamped
    }

    #[test]
    fn test_column_renderer_defaults() {
        let r = TraceValueColumnRenderer::default();
        assert!(r.stale_color.is_some());
        assert!(r.diff_color.is_none());
    }

    #[test]
    fn test_column_descriptor_default() {
        let desc = ColumnDescriptor::default();
        assert!(desc.attributes.is_empty());
        assert!(!desc.key.show_full_path);
    }

    #[test]
    fn test_value_row_path_string() {
        let row = ValueRow {
            key_path: vec!["a".into(), "b".into(), "c".into()],
            ..Default::default()
        };
        assert_eq!(row.path_string(), "a.b.c");
    }

    #[test]
    fn test_path_row_last_key() {
        let row = PathRow {
            key_path: vec!["x".into(), "y".into()],
            ..Default::default()
        };
        assert_eq!(row.last_key(), "y");
    }

    #[test]
    fn test_path_row_empty() {
        let row = PathRow::default();
        assert_eq!(row.last_key(), "");
        assert_eq!(row.path_string(), "");
    }
}
