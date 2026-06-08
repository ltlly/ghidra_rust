//! TableColumnInitializer -- trait for initializing table column properties.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.gui.TableColumnInitializer`.
//!
//! In the Java version this is an interface that `DynamicTableColumn`
//! implementations can optionally implement to control their column's
//! width, font metrics, and padding.  In Rust we express this as a trait
//! that table column descriptors can implement.
//!
//! The static helper `initialize_table_columns` is provided as a free
//! function that iterates over all columns in a model and calls their
//! initializer if they implement [`TableColumnInitializer`].

/// Metrics derived from a table header's font, used to compute
/// column widths in a UI-framework-agnostic way.
#[derive(Debug, Clone)]
pub struct FontMetrics {
    /// Average character width in pixels.
    pub avg_char_width: f64,
    /// Height of the font in pixels.
    pub font_height: f64,
}

impl FontMetrics {
    /// Creates a new `FontMetrics` with the given values.
    pub fn new(avg_char_width: f64, font_height: f64) -> Self {
        Self {
            avg_char_width,
            font_height,
        }
    }

    /// Estimates the pixel width of `s` using the average character width.
    pub fn string_width(&self, s: &str) -> f64 {
        s.len() as f64 * self.avg_char_width
    }
}

/// Represents a table column's display properties that can be adjusted
/// by a [`TableColumnInitializer`].
#[derive(Debug, Clone)]
pub struct TableColumnProperties {
    /// The preferred width of the column in pixels.
    preferred_width: f64,
    /// The minimum width of the column in pixels.
    min_width: f64,
    /// The maximum width of the column in pixels (0 = unlimited).
    max_width: f64,
    /// Whether the column is resizable.
    resizable: bool,
}

impl TableColumnProperties {
    /// Creates a new `TableColumnProperties` with default values.
    pub fn new() -> Self {
        Self {
            preferred_width: 75.0,
            min_width: 10.0,
            max_width: 0.0,
            resizable: true,
        }
    }

    /// Returns the preferred width.
    pub fn preferred_width(&self) -> f64 {
        self.preferred_width
    }

    /// Sets the preferred width.
    pub fn set_preferred_width(&mut self, width: f64) {
        self.preferred_width = width;
    }

    /// Returns the minimum width.
    pub fn min_width(&self) -> f64 {
        self.min_width
    }

    /// Sets the minimum width.
    pub fn set_min_width(&mut self, width: f64) {
        self.min_width = width;
    }

    /// Returns the maximum width (0 = unlimited).
    pub fn max_width(&self) -> f64 {
        self.max_width
    }

    /// Sets the maximum width.
    pub fn set_max_width(&mut self, width: f64) {
        self.max_width = width;
    }

    /// Returns whether the column is resizable.
    pub fn is_resizable(&self) -> bool {
        self.resizable
    }

    /// Sets whether the column is resizable.
    pub fn set_resizable(&mut self, resizable: bool) {
        self.resizable = resizable;
    }
}

impl Default for TableColumnProperties {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for table column descriptors that can initialize their own
/// display properties.
///
/// In the Java version this was a marker interface on
/// `DynamicTableColumn` with a `initializeTableColumn` method.
/// Column implementations that need custom widths or rendering
/// should implement this trait.
pub trait TableColumnInitializer {
    /// Called to allow the column to adjust its display properties.
    ///
    /// # Arguments
    ///
    /// * `properties` -- mutable reference to the column's display
    ///   properties.
    /// * `font_metrics` -- font metrics from the table header.
    /// * `padding` -- additional horizontal padding (typically the
    ///   width of "WW" in the header font).
    fn initialize_table_column(
        &self,
        properties: &mut TableColumnProperties,
        font_metrics: &FontMetrics,
        padding: f64,
    );
}

/// Iterates over all columns in a model and calls their
/// [`TableColumnInitializer::initialize_table_column`] method if
/// they implement the trait.
///
/// This is the Rust equivalent of the Java static helper
/// `TableColumnInitializer.initializeTableColumns(GTable, GDynamicColumnTableModel)`.
///
/// # Arguments
///
/// * `columns` -- slice of optional column initializers (one per column).
/// * `properties` -- mutable slice of column properties (one per column).
/// * `font_metrics` -- font metrics from the table header.
pub fn initialize_table_columns(
    columns: &[Option<&dyn TableColumnInitializer>],
    properties: &mut [TableColumnProperties],
    font_metrics: &FontMetrics,
) {
    let padding = font_metrics.string_width("WW");

    for (col_init, col_props) in columns.iter().zip(properties.iter_mut()) {
        if let Some(initializer) = col_init {
            initializer.initialize_table_column(col_props, font_metrics, padding);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockColumn {
        desired_width: f64,
    }

    impl TableColumnInitializer for MockColumn {
        fn initialize_table_column(
            &self,
            properties: &mut TableColumnProperties,
            _font_metrics: &FontMetrics,
            _padding: f64,
        ) {
            properties.set_preferred_width(self.desired_width);
        }
    }

    #[test]
    fn test_table_column_properties_default() {
        let props = TableColumnProperties::new();
        assert_eq!(props.preferred_width(), 75.0);
        assert_eq!(props.min_width(), 10.0);
        assert_eq!(props.max_width(), 0.0);
        assert!(props.is_resizable());
    }

    #[test]
    fn test_table_column_properties_setters() {
        let mut props = TableColumnProperties::new();
        props.set_preferred_width(200.0);
        props.set_min_width(50.0);
        props.set_max_width(500.0);
        props.set_resizable(false);

        assert_eq!(props.preferred_width(), 200.0);
        assert_eq!(props.min_width(), 50.0);
        assert_eq!(props.max_width(), 500.0);
        assert!(!props.is_resizable());
    }

    #[test]
    fn test_font_metrics_string_width() {
        let fm = FontMetrics::new(8.0, 16.0);
        assert_eq!(fm.string_width("WW"), 16.0);
        assert_eq!(fm.string_width(""), 0.0);
        assert_eq!(fm.string_width("test"), 32.0);
    }

    #[test]
    fn test_initialize_table_columns() {
        let col1 = MockColumn { desired_width: 100.0 };
        let col2 = MockColumn { desired_width: 200.0 };

        let columns: Vec<Option<&dyn TableColumnInitializer>> =
            vec![Some(&col1), Some(&col2)];
        let mut properties = vec![
            TableColumnProperties::new(),
            TableColumnProperties::new(),
        ];

        let fm = FontMetrics::new(8.0, 16.0);
        initialize_table_columns(&columns, &mut properties, &fm);

        assert_eq!(properties[0].preferred_width(), 100.0);
        assert_eq!(properties[1].preferred_width(), 200.0);
    }

    #[test]
    fn test_initialize_table_columns_with_none() {
        let col1 = MockColumn { desired_width: 100.0 };

        let columns: Vec<Option<&dyn TableColumnInitializer>> =
            vec![Some(&col1), None];
        let mut properties = vec![
            TableColumnProperties::new(),
            TableColumnProperties::new(),
        ];

        let fm = FontMetrics::new(8.0, 16.0);
        initialize_table_columns(&columns, &mut properties, &fm);

        assert_eq!(properties[0].preferred_width(), 100.0);
        // None column keeps default
        assert_eq!(properties[1].preferred_width(), 75.0);
    }

    #[test]
    fn test_initialize_table_columns_empty() {
        let columns: Vec<Option<&dyn TableColumnInitializer>> = vec![];
        let mut properties: Vec<TableColumnProperties> = vec![];

        let fm = FontMetrics::new(8.0, 16.0);
        initialize_table_columns(&columns, &mut properties, &fm);
        // No panic, empty is fine
    }

    #[test]
    fn test_table_column_properties_default_trait() {
        let props = TableColumnProperties::default();
        assert_eq!(props.preferred_width(), 75.0);
    }
}
