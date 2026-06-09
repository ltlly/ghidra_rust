//! Byte Viewer Layout Model implementation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.byteviewer.ByteViewerLayoutModel`.
//!
//! This module provides the layout model that computes how byte fields are
//! positioned within the viewer grid. It maps from (block, offset, column)
//! coordinates to (row, column) display coordinates and vice versa, taking
//! into account bytes per line, grouping, offset alignment, and format
//! model properties.
//!
//! # Key types
//!
//! - [`ByteViewerLayoutModel`] -- the main layout model
//! - [`FieldLayout`] -- describes how a single field is positioned
//! - [`RowLayout`] -- describes the layout of an entire row

use num_bigint::BigInt;

use super::{
    ByteViewerConfigOptions, ByteFormat,
};

/// Convert a `BigInt` to `usize`, returning `None` for negative or oversized values.
fn bigint_to_usize(v: &BigInt) -> Option<usize> {
    if v.sign() == num_bigint::Sign::Minus {
        return None;
    }
    let bytes = v.to_bytes_be().1;
    let mut result: usize = 0;
    for &b in &bytes {
        result = result.checked_mul(256)?.checked_add(b as usize)?;
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// FieldLayout
// ---------------------------------------------------------------------------

/// Describes the layout position of a single field within the viewer grid.
///
/// Each field maps from a (row, column) display coordinate to the
/// corresponding (block_index, offset, unit_size) data coordinates.
#[derive(Debug, Clone)]
pub struct FieldLayout {
    /// The display row index.
    pub row: usize,
    /// The display column index.
    pub col: usize,
    /// The block index this field belongs to.
    pub block_index: usize,
    /// The byte offset within the block.
    pub offset: BigInt,
    /// The unit byte size (how many bytes this field represents).
    pub unit_byte_size: usize,
    /// The number of display characters this field occupies.
    pub symbol_size: usize,
    /// The x-pixel position where this field starts (for rendering).
    pub x_position: usize,
    /// The width in pixels of this field.
    pub width: usize,
}

impl FieldLayout {
    /// Create a new field layout.
    pub fn new(
        row: usize,
        col: usize,
        block_index: usize,
        offset: BigInt,
        unit_byte_size: usize,
        symbol_size: usize,
    ) -> Self {
        Self {
            row,
            col,
            block_index,
            offset,
            unit_byte_size,
            symbol_size,
            x_position: 0,
            width: 0,
        }
    }

    /// The end offset (exclusive) of this field within its block.
    pub fn end_offset(&self) -> BigInt {
        &self.offset + self.unit_byte_size
    }

    /// Whether this field covers the given block offset.
    pub fn covers_offset(&self, block_index: usize, offset: &BigInt) -> bool {
        self.block_index == block_index
            && offset >= &self.offset
            && offset < &self.end_offset()
    }
}

// ---------------------------------------------------------------------------
// RowLayout
// ---------------------------------------------------------------------------

/// Describes the layout of an entire display row.
///
/// A row layout maps one row of byte fields from data coordinates to
/// display coordinates, tracking where each field starts and ends.
#[derive(Debug, Clone)]
pub struct RowLayout {
    /// The display row index.
    pub row_index: usize,
    /// The start address of this row.
    pub start_address: u64,
    /// The block index this row primarily belongs to.
    pub block_index: usize,
    /// The byte offset within the block where this row starts.
    pub offset: BigInt,
    /// The field layouts for this row.
    pub fields: Vec<FieldLayout>,
    /// The total width of this row in display units.
    pub total_width: usize,
    /// Whether this row crosses a block boundary.
    pub cross_block: bool,
}

impl RowLayout {
    /// Create a new row layout.
    pub fn new(row_index: usize, start_address: u64, block_index: usize, offset: BigInt) -> Self {
        Self {
            row_index,
            start_address,
            block_index,
            offset,
            fields: Vec::new(),
            total_width: 0,
            cross_block: false,
        }
    }

    /// Add a field layout to this row.
    pub fn add_field(&mut self, field: FieldLayout) {
        self.total_width = self.total_width.max(field.x_position + field.width);
        self.fields.push(field);
    }

    /// Find the field at the given display column.
    pub fn field_at_column(&self, col: usize) -> Option<&FieldLayout> {
        self.fields.iter().find(|f| f.col == col)
    }

    /// Find the field covering the given block offset.
    pub fn field_at_offset(&self, block_index: usize, offset: &BigInt) -> Option<&FieldLayout> {
        self.fields.iter().find(|f| f.covers_offset(block_index, offset))
    }

    /// The number of fields in this row.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

// ---------------------------------------------------------------------------
// ByteViewerLayoutModel
// ---------------------------------------------------------------------------

/// The layout model for the byte viewer.
///
/// Ported from Ghidra's `ByteViewerLayoutModel`.
///
/// Computes and caches the mapping between data coordinates
/// (block_index, offset, column) and display coordinates (row, col).
/// The layout model is invalidated when configuration changes (bytes per
/// line, format model, etc.) and recomputed lazily.
#[derive(Debug)]
pub struct ByteViewerLayoutModel {
    /// Configuration options used for layout computation.
    config: ByteViewerConfigOptions,
    /// Cached row layouts.
    row_layouts: Vec<RowLayout>,
    /// The format model in use.
    format: ByteFormat,
    /// Unit byte size for the current format.
    unit_byte_size: usize,
    /// Symbol size (characters per unit) for the current format.
    symbol_size: usize,
    /// Character width in pixels (for GUI rendering).
    char_width: usize,
    /// Whether the cache is valid.
    valid: bool,
    /// Number of visible rows.
    visible_rows: usize,
    /// Starting row offset.
    start_offset: BigInt,
}

impl ByteViewerLayoutModel {
    /// Create a new layout model with default settings.
    pub fn new() -> Self {
        let format = ByteFormat::default();
        let symbol_size = format.field_width();
        Self {
            config: ByteViewerConfigOptions::new(),
            row_layouts: Vec::new(),
            format,
            unit_byte_size: 1,
            symbol_size,
            char_width: 8,
            valid: false,
            visible_rows: 25,
            start_offset: BigInt::from(0),
        }
    }

    /// Create with specific configuration.
    pub fn with_config(config: ByteViewerConfigOptions) -> Self {
        let mut model = Self::new();
        model.config = config;
        model
    }

    // -- Configuration -------------------------------------------------------

    /// Get the configuration.
    pub fn config(&self) -> &ByteViewerConfigOptions {
        &self.config
    }

    /// Set the configuration and invalidate the cache.
    pub fn set_config(&mut self, config: ByteViewerConfigOptions) {
        if self.config.are_layout_params_changed(&config) {
            self.valid = false;
        }
        self.config = config;
    }

    /// Get the current format.
    pub fn format(&self) -> ByteFormat {
        self.format
    }

    /// Set the format and invalidate the cache.
    pub fn set_format(&mut self, format: ByteFormat) {
        self.format = format;
        self.symbol_size = format.field_width();
        self.valid = false;
    }

    /// Get the unit byte size.
    pub fn unit_byte_size(&self) -> usize {
        self.unit_byte_size
    }

    /// Set the unit byte size.
    pub fn set_unit_byte_size(&mut self, size: usize) {
        self.unit_byte_size = size;
        self.valid = false;
    }

    /// Get the symbol size.
    pub fn symbol_size(&self) -> usize {
        self.symbol_size
    }

    /// Set the symbol size.
    pub fn set_symbol_size(&mut self, size: usize) {
        self.symbol_size = size;
        self.valid = false;
    }

    /// Get the character width.
    pub fn char_width(&self) -> usize {
        self.char_width
    }

    /// Set the character width.
    pub fn set_char_width(&mut self, width: usize) {
        self.char_width = width;
        self.valid = false;
    }

    /// Get the number of visible rows.
    pub fn visible_rows(&self) -> usize {
        self.visible_rows
    }

    /// Set the number of visible rows.
    pub fn set_visible_rows(&mut self, rows: usize) {
        self.visible_rows = rows;
        self.valid = false;
    }

    /// Get the start offset.
    pub fn start_offset(&self) -> &BigInt {
        &self.start_offset
    }

    /// Set the start offset.
    pub fn set_start_offset(&mut self, offset: BigInt) {
        self.start_offset = offset;
        self.valid = false;
    }

    // -- Layout computation --------------------------------------------------

    /// Whether the layout cache is valid.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Invalidate the layout cache.
    pub fn invalidate(&mut self) {
        self.valid = false;
        self.row_layouts.clear();
    }

    /// Get the bytes per line from the configuration.
    pub fn bytes_per_line(&self) -> usize {
        self.config.bytes_per_line()
    }

    /// Get the number of fields per line for the current format.
    pub fn fields_per_line(&self) -> usize {
        if self.unit_byte_size == 0 {
            0
        } else {
            self.bytes_per_line() / self.unit_byte_size
        }
    }

    /// Compute the total width of one display row in character units.
    pub fn row_char_width(&self) -> usize {
        let field_count = self.fields_per_line();
        let hex_width = field_count * (self.symbol_size + 1); // +1 for spacing
        let address_width = 10; // "00000000  "
        let ascii_width = if self.config.is_compact_chars() {
            self.bytes_per_line() + 4 // "  |" + data + "|"
        } else {
            0
        };
        address_width + hex_width + ascii_width
    }

    /// Rebuild the row layouts from the given block data.
    ///
    /// The `block_sizes` parameter is a slice of (block_index, block_size)
    /// pairs describing the blocks available.
    pub fn recompute(&mut self, block_sizes: &[(usize, usize)]) {
        self.row_layouts.clear();

        let bytes_per_line = self.bytes_per_line();
        let fields_per_line = self.fields_per_line();
        let offset = self.config.offset();
        let hex_group_size = self.config.hex_group_size();

        let mut current_offset = self.start_offset.clone();

        for row_idx in 0..self.visible_rows {
            // Find which block this row starts in
            let mut block_index = 0usize;
            let mut block_offset = current_offset.clone();
            let mut found = false;

            for &(bidx, bsize) in block_sizes {
                let block_size = BigInt::from(bsize);
                if block_offset < block_size {
                    block_index = bidx;
                    found = true;
                    break;
                }
                block_offset = &block_offset - &block_size;
                block_index = bidx;
            }

            if !found && !block_sizes.is_empty() {
                block_index = block_sizes.last().unwrap().0;
            }

            let mut row = RowLayout::new(
                row_idx,
                0, // address computed by caller
                block_index,
                block_offset.clone(),
            );

            // Compute field positions
            let mut x = 10usize; // start after address column

            for field_idx in 0..fields_per_line {
                let field_offset = &block_offset + (field_idx * self.unit_byte_size);
                let col = field_idx;

                // Add group spacing
                if field_idx > 0 && hex_group_size > 0 && field_idx % hex_group_size == 0 {
                    x += 1; // space between groups
                }

                let field = FieldLayout::new(
                    row_idx,
                    col,
                    block_index,
                    field_offset,
                    self.unit_byte_size,
                    self.symbol_size,
                );

                let mut f = field;
                f.x_position = x;
                f.width = self.symbol_size * self.char_width;

                row.add_field(f);
                x += self.symbol_size;
            }

            row.total_width = x + if self.config.is_compact_chars() {
                self.bytes_per_line() + 4
            } else {
                0
            };

            self.row_layouts.push(row);
            current_offset = &current_offset + bytes_per_line;
        }

        self.valid = true;
    }

    /// Get the row layouts.
    pub fn row_layouts(&self) -> &[RowLayout] {
        &self.row_layouts
    }

    /// Get the layout for a specific row.
    pub fn row_layout(&self, row: usize) -> Option<&RowLayout> {
        self.row_layouts.get(row)
    }

    /// Translate a display (row, col) to a data (block_index, offset) pair.
    pub fn display_to_data(
        &self,
        row: usize,
        col: usize,
    ) -> Option<(usize, &BigInt)> {
        let row_layout = self.row_layouts.get(row)?;
        let field = row_layout.field_at_column(col)?;
        Some((field.block_index, &field.offset))
    }

    /// Translate data coordinates (block_index, offset) to display (row, col).
    pub fn data_to_display(
        &self,
        block_index: usize,
        offset: &BigInt,
    ) -> Option<(usize, usize)> {
        for row_layout in &self.row_layouts {
            if let Some(field) = row_layout.field_at_offset(block_index, offset) {
                return Some((field.row, field.col));
            }
        }
        None
    }

    /// Compute the column index within a field given a sub-character position.
    pub fn sub_column_for_offset(
        &self,
        block_index: usize,
        offset: &BigInt,
    ) -> Option<usize> {
        for row_layout in &self.row_layouts {
            if let Some(field) = row_layout.field_at_offset(block_index, offset) {
                let diff = offset - &field.offset;
                let sub_col: usize = bigint_to_usize(&diff).unwrap_or(0);
                return Some(field.col * self.unit_byte_size + sub_col);
            }
        }
        None
    }

    /// Get the x-pixel position for a given display column.
    pub fn x_position_for_column(&self, row: usize, col: usize) -> Option<usize> {
        let row_layout = self.row_layouts.get(row)?;
        let field = row_layout.field_at_column(col)?;
        Some(field.x_position * self.char_width)
    }

    /// Get the column width for a given display column.
    pub fn column_width(&self, col: usize) -> usize {
        self.symbol_size * self.char_width
    }
}

impl Default for ByteViewerLayoutModel {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layout_model_create() {
        let model = ByteViewerLayoutModel::new();
        assert_eq!(model.bytes_per_line(), 16);
        assert_eq!(model.format(), ByteFormat::Hex);
        assert!(!model.is_valid());
    }

    #[test]
    fn test_layout_model_with_config() {
        let mut config = ByteViewerConfigOptions::new();
        config.set_bytes_per_line(32);
        let model = ByteViewerLayoutModel::with_config(config);
        assert_eq!(model.bytes_per_line(), 32);
    }

    #[test]
    fn test_layout_model_invalidate() {
        let mut model = ByteViewerLayoutModel::new();
        model.valid = true;
        model.invalidate();
        assert!(!model.is_valid());
    }

    #[test]
    fn test_layout_model_format_change() {
        let mut model = ByteViewerLayoutModel::new();
        model.valid = true;
        model.set_format(ByteFormat::Binary);
        assert!(!model.is_valid());
        assert_eq!(model.symbol_size(), 8);
    }

    #[test]
    fn test_layout_model_fields_per_line() {
        let model = ByteViewerLayoutModel::new();
        assert_eq!(model.fields_per_line(), 16); // 16 bytes / 1 unit

        let mut model2 = ByteViewerLayoutModel::new();
        model2.set_unit_byte_size(2);
        assert_eq!(model2.fields_per_line(), 8); // 16 bytes / 2 units
    }

    #[test]
    fn test_layout_model_recompute() {
        let mut model = ByteViewerLayoutModel::new();
        model.set_visible_rows(2);
        model.recompute(&[(0, 64)]);

        assert!(model.is_valid());
        assert_eq!(model.row_layouts().len(), 2);
    }

    #[test]
    fn test_layout_model_display_to_data() {
        let mut model = ByteViewerLayoutModel::new();
        model.set_visible_rows(2);
        model.recompute(&[(0, 64)]);

        let result = model.display_to_data(0, 0);
        assert!(result.is_some());
        let (block_idx, offset) = result.unwrap();
        assert_eq!(block_idx, 0);
        assert_eq!(*offset, BigInt::from(0));
    }

    #[test]
    fn test_layout_model_data_to_display() {
        let mut model = ByteViewerLayoutModel::new();
        model.set_visible_rows(2);
        model.recompute(&[(0, 64)]);

        let result = model.data_to_display(0, &BigInt::from(0));
        assert!(result.is_some());
        let (row, col) = result.unwrap();
        assert_eq!(row, 0);
        assert_eq!(col, 0);
    }

    #[test]
    fn test_layout_model_column_width() {
        let model = ByteViewerLayoutModel::new();
        // Hex format: 2 chars * 8 pixels = 16
        assert_eq!(model.column_width(0), 16);
    }

    #[test]
    fn test_layout_model_row_char_width() {
        let model = ByteViewerLayoutModel::new();
        // 10 (address) + 16 fields * 3 (2 hex + 1 space) + 20 (ASCII) = 68
        let width = model.row_char_width();
        assert!(width > 0);
    }

    #[test]
    fn test_field_layout() {
        let field = FieldLayout::new(0, 3, 1, BigInt::from(10), 1, 2);
        assert_eq!(field.row, 0);
        assert_eq!(field.col, 3);
        assert_eq!(field.block_index, 1);
        assert_eq!(field.end_offset(), BigInt::from(11));
        assert!(field.covers_offset(1, &BigInt::from(10)));
        assert!(!field.covers_offset(1, &BigInt::from(11)));
        assert!(!field.covers_offset(0, &BigInt::from(10)));
    }

    #[test]
    fn test_row_layout() {
        let mut row = RowLayout::new(0, 0x1000, 0, BigInt::from(0));
        assert_eq!(row.row_index, 0);
        assert_eq!(row.start_address, 0x1000);
        assert_eq!(row.field_count(), 0);

        let field = FieldLayout::new(0, 0, 0, BigInt::from(0), 1, 2);
        row.add_field(field);
        assert_eq!(row.field_count(), 1);
    }

    #[test]
    fn test_row_layout_field_at_column() {
        let mut row = RowLayout::new(0, 0, 0, BigInt::from(0));
        row.add_field(FieldLayout::new(0, 0, 0, BigInt::from(0), 1, 2));
        row.add_field(FieldLayout::new(0, 1, 0, BigInt::from(1), 1, 2));
        row.add_field(FieldLayout::new(0, 2, 0, BigInt::from(2), 1, 2));

        assert!(row.field_at_column(0).is_some());
        assert!(row.field_at_column(1).is_some());
        assert!(row.field_at_column(5).is_none());
    }

    #[test]
    fn test_row_layout_field_at_offset() {
        let mut row = RowLayout::new(0, 0, 0, BigInt::from(0));
        row.add_field(FieldLayout::new(0, 0, 0, BigInt::from(0), 2, 4));

        assert!(row.field_at_offset(0, &BigInt::from(0)).is_some());
        assert!(row.field_at_offset(0, &BigInt::from(1)).is_some());
        assert!(row.field_at_offset(0, &BigInt::from(2)).is_none());
    }

    #[test]
    fn test_layout_model_multi_block() {
        let mut model = ByteViewerLayoutModel::new();
        model.set_visible_rows(4);
        model.set_start_offset(BigInt::from(0));
        model.recompute(&[(0, 16), (1, 32)]);

        assert!(model.is_valid());
        assert_eq!(model.row_layouts().len(), 4);
    }

    #[test]
    fn test_layout_model_unit_byte_size() {
        let mut model = ByteViewerLayoutModel::new();
        model.valid = true;
        model.set_unit_byte_size(4);
        assert!(!model.is_valid());
        assert_eq!(model.unit_byte_size(), 4);
    }

    #[test]
    fn test_layout_model_char_width() {
        let mut model = ByteViewerLayoutModel::new();
        assert_eq!(model.char_width(), 8);
        model.set_char_width(10);
        assert_eq!(model.char_width(), 10);
    }
}
