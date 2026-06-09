//! Byte Viewer Component implementation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.byteviewer.ByteViewerComponent`.
//!
//! This component manages the core viewing logic: it holds the byte block
//! set, tracks the current cursor position and selection, manages the
//! configured format model, and renders rows of formatted bytes for display.
//!
//! # Key types
//!
//! - [`ByteViewerComponent`] -- the main component that drives byte display
//! - [`CursorPosition`] -- the current cursor within the byte viewer
//! - [`ViewerRow`] -- a single rendered row of formatted bytes

use num_bigint::BigInt;

use super::{
    ByteBlockSet, ByteBlockSelection, ByteViewerConfigOptions,
    ByteFormat, AddressFormat, ByteField,
};
use super::byte_viewer_layout_model::ByteViewerLayoutModel;

/// Convert a `BigInt` to `u64`, returning 0 for values that don't fit.
fn bigint_to_u64(v: &BigInt) -> u64 {
    if v.sign() == num_bigint::Sign::Minus {
        return 0;
    }
    let bytes = v.to_bytes_be().1;
    let mut result: u64 = 0;
    for &b in &bytes {
        result = result.wrapping_mul(256).wrapping_add(b as u64);
    }
    result
}

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
// CursorPosition
// ---------------------------------------------------------------------------

/// The current cursor position within the byte viewer.
///
/// Tracks which byte the user is currently pointing at, along with the
/// sub-column offset for multi-column format models.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorPosition {
    /// The block index within the block set.
    pub block_index: usize,
    /// The byte offset within the block.
    pub offset: BigInt,
    /// The sub-column index (for formats that split a byte into multiple
    /// character columns, e.g. hex showing nibbles).
    pub sub_column: usize,
}

impl CursorPosition {
    /// Create a new cursor position.
    pub fn new(block_index: usize, offset: BigInt, sub_column: usize) -> Self {
        Self {
            block_index,
            offset,
            sub_column,
        }
    }

    /// Create at the start of a block.
    pub fn at_start(block_index: usize) -> Self {
        Self {
            block_index,
            offset: BigInt::from(0),
            sub_column: 0,
        }
    }

    /// The absolute address from a block set.
    pub fn address(&self, block_set: &ByteBlockSet) -> Option<u64> {
        block_set
            .blocks()
            .get(self.block_index)
            .map(|block| {
                let offset_u64: u64 = bigint_to_u64(&self.offset);
                block.start_address() + offset_u64
            })
    }
}

impl Default for CursorPosition {
    fn default() -> Self {
        Self::at_start(0)
    }
}

// ---------------------------------------------------------------------------
// ViewerRow
// ---------------------------------------------------------------------------

/// A single rendered row in the byte viewer display.
///
/// Contains the address, the byte fields for each column, and an optional
/// ASCII representation.
#[derive(Debug, Clone)]
pub struct ViewerRow {
    /// The start address of this row.
    pub address: u64,
    /// The block index this row belongs to.
    pub block_index: usize,
    /// The byte offset within the block where this row starts.
    pub offset: BigInt,
    /// The formatted byte fields for this row.
    pub fields: Vec<ByteField>,
    /// The ASCII representation of the bytes (if enabled).
    pub ascii: Option<String>,
    /// Whether the row spans multiple blocks.
    pub cross_block: bool,
}

impl ViewerRow {
    /// Create a new viewer row.
    pub fn new(
        address: u64,
        block_index: usize,
        offset: BigInt,
        fields: Vec<ByteField>,
    ) -> Self {
        Self {
            address,
            block_index,
            offset,
            fields,
            ascii: None,
            cross_block: false,
        }
    }

    /// Generate the ASCII representation for this row's bytes.
    pub fn generate_ascii(&mut self) {
        let ascii: String = self
            .fields
            .iter()
            .map(|f| {
                if f.value.is_ascii_graphic() || f.value == b' ' {
                    f.value as char
                } else {
                    '.'
                }
            })
            .collect();
        self.ascii = Some(ascii);
    }

    /// The number of fields (bytes) in this row.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether the row has no fields.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ByteViewerComponent
// ---------------------------------------------------------------------------

/// The core byte viewer component.
///
/// Ported from Ghidra's `ByteViewerComponent`.
///
/// Manages:
/// - The byte block set (the data being viewed)
/// - Cursor position and selection tracking
/// - Format model configuration
/// - Row rendering for display
/// - Navigation (go-to-address)
/// - Layout model integration
#[derive(Debug)]
pub struct ByteViewerComponent {
    /// The byte block set being displayed.
    block_set: Option<ByteBlockSet>,
    /// Current cursor position.
    cursor: CursorPosition,
    /// Current selection (if any).
    selection: ByteBlockSelection,
    /// The layout model for this component.
    layout: ByteViewerLayoutModel,
    /// Configuration options.
    config: ByteViewerConfigOptions,
    /// The address format for displaying addresses.
    address_format: AddressFormat,
    /// Number of visible rows.
    visible_rows: usize,
    /// The starting row index (for scrolling).
    start_row: BigInt,
    /// Whether the component has been disposed.
    disposed: bool,
    /// Cached rendered rows.
    rendered_rows: Vec<ViewerRow>,
    /// Whether the rendered rows cache is dirty.
    needs_refresh: bool,
}

impl ByteViewerComponent {
    /// Create a new byte viewer component with default settings.
    pub fn new() -> Self {
        Self {
            block_set: None,
            cursor: CursorPosition::default(),
            selection: ByteBlockSelection::new(),
            layout: ByteViewerLayoutModel::new(),
            config: ByteViewerConfigOptions::new(),
            address_format: AddressFormat::default(),
            visible_rows: 25,
            start_row: BigInt::from(0),
            disposed: false,
            rendered_rows: Vec::new(),
            needs_refresh: true,
        }
    }

    /// Create with specific configuration.
    pub fn with_config(config: ByteViewerConfigOptions) -> Self {
        let mut component = Self::new();
        component.config = config;
        component
    }

    // -- Configuration -------------------------------------------------------

    /// Get the configuration options.
    pub fn config(&self) -> &ByteViewerConfigOptions {
        &self.config
    }

    /// Set configuration options.
    pub fn set_config(&mut self, config: ByteViewerConfigOptions) {
        let changed = self.config.are_layout_params_changed(&config);
        self.config = config;
        if changed {
            self.layout.invalidate();
            self.needs_refresh = true;
        }
    }

    /// Get the address format.
    pub fn address_format(&self) -> AddressFormat {
        self.address_format
    }

    /// Set the address format.
    pub fn set_address_format(&mut self, format: AddressFormat) {
        self.address_format = format;
        self.needs_refresh = true;
    }

    // -- Block set -----------------------------------------------------------

    /// Get the current block set.
    pub fn block_set(&self) -> Option<&ByteBlockSet> {
        self.block_set.as_ref()
    }

    /// Set the byte block set.
    pub fn set_block_set(&mut self, block_set: ByteBlockSet) {
        self.block_set = Some(block_set);
        self.cursor = CursorPosition::default();
        self.selection = ByteBlockSelection::new();
        self.layout.invalidate();
        self.needs_refresh = true;
    }

    /// Clear the block set.
    pub fn clear(&mut self) {
        self.block_set = None;
        self.cursor = CursorPosition::default();
        self.selection = ByteBlockSelection::new();
        self.rendered_rows.clear();
        self.needs_refresh = true;
    }

    // -- Cursor and navigation -----------------------------------------------

    /// Get the current cursor position.
    pub fn cursor(&self) -> &CursorPosition {
        &self.cursor
    }

    /// Set the cursor position.
    pub fn set_cursor(&mut self, cursor: CursorPosition) {
        self.cursor = cursor;
    }

    /// Get the current address (if a block set is loaded).
    pub fn current_address(&self) -> Option<u64> {
        let block_set = self.block_set.as_ref()?;
        self.cursor.address(block_set)
    }

    /// Navigate to the given address.
    ///
    /// Finds the block containing the address and updates the cursor.
    pub fn go_to_address(&mut self, address: u64) -> bool {
        let block_set = match &self.block_set {
            Some(bs) => bs,
            None => return false,
        };

        for (i, block) in block_set.blocks().iter().enumerate() {
            if block.contains(address) {
                let offset = address - block.start_address();
                self.cursor = CursorPosition::new(i, BigInt::from(offset), 0);
                self.needs_refresh = true;
                return true;
            }
        }
        false
    }

    /// Navigate to the start of the first block.
    pub fn go_to_start(&mut self) {
        self.cursor = CursorPosition::at_start(0);
        self.start_row = BigInt::from(0);
        self.needs_refresh = true;
    }

    /// Navigate to the end of the last block.
    pub fn go_to_end(&mut self) {
        if let Some(block_set) = &self.block_set {
            let last_idx = block_set.block_count().saturating_sub(1);
            if let Some(block) = block_set.blocks().get(last_idx) {
                self.cursor = CursorPosition::new(
                    last_idx,
                    BigInt::from(block.size().saturating_sub(1)),
                    0,
                );
            }
        }
        self.needs_refresh = true;
    }

    // -- Selection -----------------------------------------------------------

    /// Get the current selection.
    pub fn selection(&self) -> &ByteBlockSelection {
        &self.selection
    }

    /// Set the selection.
    pub fn set_selection(&mut self, selection: ByteBlockSelection) {
        self.selection = selection;
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selection = ByteBlockSelection::new();
    }

    // -- Display / Rendering -------------------------------------------------

    /// Get the number of visible rows.
    pub fn visible_rows(&self) -> usize {
        self.visible_rows
    }

    /// Set the number of visible rows.
    pub fn set_visible_rows(&mut self, rows: usize) {
        self.visible_rows = rows;
        self.needs_refresh = true;
    }

    /// Get the starting row index.
    pub fn start_row(&self) -> &BigInt {
        &self.start_row
    }

    /// Set the starting row index.
    pub fn set_start_row(&mut self, row: BigInt) {
        self.start_row = row;
        self.needs_refresh = true;
    }

    /// Get the layout model.
    pub fn layout(&self) -> &ByteViewerLayoutModel {
        &self.layout
    }

    /// Get a mutable reference to the layout model.
    pub fn layout_mut(&mut self) -> &mut ByteViewerLayoutModel {
        &mut self.layout
    }

    /// Whether the component needs a refresh.
    pub fn needs_refresh(&self) -> bool {
        self.needs_refresh
    }

    /// Render visible rows based on the current state.
    ///
    /// Returns the rendered rows. This regenerates the cache if dirty.
    pub fn render(&mut self) -> &[ViewerRow] {
        if self.needs_refresh {
            self.refresh_rows();
            self.needs_refresh = false;
        }
        &self.rendered_rows
    }

    /// Force a full refresh of the rendered rows.
    fn refresh_rows(&mut self) {
        self.rendered_rows.clear();

        let block_set = match &self.block_set {
            Some(bs) => bs,
            None => return,
        };

        let bytes_per_line = self.config.bytes_per_line();
        let format = ByteFormat::default();

        for row_idx in 0..self.visible_rows {
            let row_offset = &self.start_row + (row_idx * bytes_per_line);

            // Find which block this row belongs to
            let mut block_index = 0usize;
            let mut block_offset = row_offset.clone();
            for (i, block) in block_set.blocks().iter().enumerate() {
                let block_size = BigInt::from(block.size());
                if row_offset < block_size {
                    block_index = i;
                    block_offset = row_offset.clone();
                    break;
                }
            }

            let block = match block_set.blocks().get(block_index) {
                Some(b) => b,
                None => continue,
            };

            let offset_u64: u64 = bigint_to_u64(&block_offset);
            let address = block.start_address() + offset_u64;

            let mut fields = Vec::new();
            for col in 0..bytes_per_line {
                let byte_offset = offset_u64 + col as u64;
                let value = block.byte_at(byte_offset as usize).unwrap_or(0);
                let field = ByteField::new(address + col as u64, value, format, col);
                fields.push(field);
            }

            let mut row = ViewerRow::new(address, block_index, block_offset, fields);
            if self.config.is_compact_chars() {
                row.generate_ascii();
            }
            self.rendered_rows.push(row);
        }
    }

    /// Get the byte value at the given address.
    pub fn byte_at(&self, address: u64) -> Option<u8> {
        self.block_set.as_ref()?.byte_at(address)
    }

    /// Whether the component has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of the component.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.block_set = None;
        self.rendered_rows.clear();
    }
}

impl Default for ByteViewerComponent {
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
    use super::super::ByteBlock;

    fn make_test_block_set() -> ByteBlockSet {
        let mut bs = ByteBlockSet::new("test");
        bs.add_block(ByteBlock::new(".text", 0x1000, vec![0x90, 0xC3, 0xCC, 0x00]));
        bs.add_block(ByteBlock::new(".data", 0x2000, vec![0xCA, 0xFE, 0xBA, 0xBE]));
        bs
    }

    #[test]
    fn test_component_create() {
        let component = ByteViewerComponent::new();
        assert!(component.block_set().is_none());
        assert!(!component.is_disposed());
        assert_eq!(component.visible_rows(), 25);
    }

    #[test]
    fn test_component_set_block_set() {
        let mut component = ByteViewerComponent::new();
        let bs = make_test_block_set();
        component.set_block_set(bs);
        assert!(component.block_set().is_some());
        assert_eq!(component.block_set().unwrap().block_count(), 2);
    }

    #[test]
    fn test_component_go_to_address() {
        let mut component = ByteViewerComponent::new();
        component.set_block_set(make_test_block_set());

        assert!(component.go_to_address(0x2001));
        let cursor = component.cursor();
        assert_eq!(cursor.block_index, 1);
        assert_eq!(cursor.offset, BigInt::from(1));

        assert!(!component.go_to_address(0x5000));
    }

    #[test]
    fn test_component_current_address() {
        let mut component = ByteViewerComponent::new();
        assert!(component.current_address().is_none());

        component.set_block_set(make_test_block_set());
        component.go_to_address(0x1002);
        assert_eq!(component.current_address(), Some(0x1002));
    }

    #[test]
    fn test_component_byte_at() {
        let mut component = ByteViewerComponent::new();
        component.set_block_set(make_test_block_set());

        assert_eq!(component.byte_at(0x1000), Some(0x90));
        assert_eq!(component.byte_at(0x2000), Some(0xCA));
        assert_eq!(component.byte_at(0x3000), None);
    }

    #[test]
    fn test_component_selection() {
        let mut component = ByteViewerComponent::new();
        let sel = ByteBlockSelection::from_ranges(vec![
            super::super::ByteBlockRange::new(0, BigInt::from(0), BigInt::from(9)),
        ]);
        component.set_selection(sel);
        assert_eq!(component.selection().number_of_ranges(), 1);

        component.clear_selection();
        assert!(component.selection().is_empty());
    }

    #[test]
    fn test_component_clear() {
        let mut component = ByteViewerComponent::new();
        component.set_block_set(make_test_block_set());
        component.go_to_address(0x1000);

        component.clear();
        assert!(component.block_set().is_none());
        assert!(component.current_address().is_none());
    }

    #[test]
    fn test_component_dispose() {
        let mut component = ByteViewerComponent::new();
        component.set_block_set(make_test_block_set());
        component.dispose();

        assert!(component.is_disposed());
        assert!(component.block_set().is_none());
    }

    #[test]
    fn test_component_config() {
        let mut config = ByteViewerConfigOptions::new();
        config.set_bytes_per_line(32);
        let component = ByteViewerComponent::with_config(config);
        assert_eq!(component.config().bytes_per_line(), 32);
    }

    #[test]
    fn test_component_render() {
        let mut component = ByteViewerComponent::new();
        component.set_visible_rows(2);
        component.set_block_set(make_test_block_set());

        let rows = component.render();
        assert!(!rows.is_empty());
        assert_eq!(rows[0].address, 0x1000);
    }

    #[test]
    fn test_cursor_position_default() {
        let cursor = CursorPosition::default();
        assert_eq!(cursor.block_index, 0);
        assert_eq!(cursor.offset, BigInt::from(0));
        assert_eq!(cursor.sub_column, 0);
    }

    #[test]
    fn test_cursor_position_at_start() {
        let cursor = CursorPosition::at_start(3);
        assert_eq!(cursor.block_index, 3);
        assert_eq!(cursor.offset, BigInt::from(0));
    }

    #[test]
    fn test_viewer_row_ascii() {
        let fields = vec![
            ByteField::new(0x1000, 0x48, ByteFormat::Hex, 0), // 'H'
            ByteField::new(0x1001, 0x69, ByteFormat::Hex, 1), // 'i'
            ByteField::new(0x1002, 0x00, ByteFormat::Hex, 2), // NUL
        ];
        let mut row = ViewerRow::new(0x1000, 0, BigInt::from(0), fields);
        assert!(row.ascii.is_none());
        row.generate_ascii();
        assert_eq!(row.ascii.as_deref(), Some("Hi."));
    }

    #[test]
    fn test_component_go_to_start_end() {
        let mut component = ByteViewerComponent::new();
        component.set_block_set(make_test_block_set());

        component.go_to_end();
        let cursor = component.cursor();
        assert_eq!(cursor.block_index, 1);
        assert_eq!(cursor.offset, BigInt::from(3));

        component.go_to_start();
        let cursor = component.cursor();
        assert_eq!(cursor.block_index, 0);
        assert_eq!(cursor.offset, BigInt::from(0));
    }

    #[test]
    fn test_component_address_format() {
        let mut component = ByteViewerComponent::new();
        assert_eq!(component.address_format(), AddressFormat::Hex64);
        component.set_address_format(AddressFormat::Hex32);
        assert_eq!(component.address_format(), AddressFormat::Hex32);
    }
}
