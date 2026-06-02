//! Disassembly listing renderer.
//!
//! Renders the disassembly listing view with address, bytes, label, mnemonic,
//! operand, and comment columns.  Supports multi-line instruction display,
//! column sizing and truncation, single/multi-line selection, drag-scroll
//! with address tracking, and configurable syntax highlighting.
//!
//! ## Usage
//!
//! ```ignore
//! let mut renderer = DisassemblyRenderer::default();
//! let listing: &dyn Listing = ...;
//! let range = AddressRange::new(start, end);
//! renderer.render(ui, listing, range);
//! ```

use super::field_formatter::FieldFormatter;
use egui::{
    pos2, vec2, Align, Align2, Color32, CursorIcon, Frame, Id, Key, Layout, Modifiers, Pos2, Rect,
    Response, RichText, ScrollArea, Sense, Stroke, Ui, Vec2,
};
use ghidra_core::addr::{Address, AddressRange};
use ghidra_core::program::listing::{FlowType, Instruction, Listing, Operand};
use std::collections::HashSet;

// ============================================================================
// Constants
// ============================================================================

/// Default row height in pixels.
const DEFAULT_LINE_HEIGHT: f32 = 18.0;

/// Minimum row height.
const MIN_LINE_HEIGHT: f32 = 12.0;

/// Maximum row height.
const MAX_LINE_HEIGHT: f32 = 36.0;

/// Default header height.
const HEADER_HEIGHT: f32 = 24.0;

/// Padding inside columns (horizontal).
const COLUMN_PADDING_X: f32 = 3.0;

/// Padding inside columns (vertical).
const COLUMN_PADDING_Y: f32 = 1.0;

/// Gap between columns.
const COLUMN_GAP: f32 = 4.0;

/// Separator width between columns (for resize handles).
const SEPARATOR_WIDTH: f32 = 4.0;

/// Default column widths in pixels.
const DEFAULT_ADDRESS_WIDTH: f32 = 80.0;
const DEFAULT_BYTES_WIDTH: f32 = 120.0;
const DEFAULT_LABEL_WIDTH: f32 = 120.0;
const DEFAULT_MNEMONIC_WIDTH: f32 = 70.0;
const DEFAULT_OPERAND_WIDTH: f32 = 220.0;
const DEFAULT_COMMENT_WIDTH: f32 = 180.0;

/// Column minimum widths.
const MIN_ADDRESS_WIDTH: f32 = 50.0;
const MIN_BYTES_WIDTH: f32 = 40.0;
const MIN_LABEL_WIDTH: f32 = 30.0;
const MIN_MNEMONIC_WIDTH: f32 = 30.0;
const MIN_OPERAND_WIDTH: f32 = 60.0;
const MIN_COMMENT_WIDTH: f32 = 40.0;

/// Column maximum widths.
const MAX_ADDRESS_WIDTH: f32 = 180.0;
const MAX_BYTES_WIDTH: f32 = 300.0;
const MAX_LABEL_WIDTH: f32 = 400.0;
const MAX_MNEMONIC_WIDTH: f32 = 150.0;
const MAX_OPERAND_WIDTH: f32 = 600.0;
const MAX_COMMENT_WIDTH: f32 = 500.0;

// ============================================================================
// DisassemblyRenderer
// ============================================================================

/// The disassembly listing renderer.
///
/// Manages column widths, row rendering, selection, and navigation within
/// a disassembly listing view.  Delegates text formatting to [`FieldFormatter`].
#[derive(Debug, Clone)]
pub struct DisassemblyRenderer {
    // Font settings
    /// Font to use for all listing text.
    pub font: egui::FontId,
    /// Height of each line in pixels.
    pub line_height: f32,

    // Color settings
    /// Color for the address column text.
    pub address_color: Color32,
    /// Color for instruction mnemonics.
    pub mnemonic_color: Color32,
    /// Color for register names in operands.
    pub register_color: Color32,
    /// Color for immediate (scalar) values.
    pub immediate_color: Color32,
    /// Color for address references in operands.
    pub address_ref_color: Color32,
    /// Color for comments.
    pub comment_color: Color32,
    /// Color for labels and symbol names.
    pub label_color: Color32,
    /// Color for the raw bytes column.
    pub bytes_color: Color32,
    /// Color for cross-reference markers.
    pub xref_color: Color32,
    /// Background color for selected rows.
    pub selection_color: Color32,
    /// Color for the cursor line highlight.
    pub cursor_color: Color32,
    /// Background color for the listing area.
    pub background_color: Color32,
    /// Background color for alternating (odd) rows.
    pub alternating_row: Color32,

    // Column widths
    /// Width of the address column.
    address_width: f32,
    /// Width of the bytes column.
    bytes_width: f32,
    /// Width of the label column.
    label_width: f32,
    /// Width of the mnemonic column.
    mnemonic_width: f32,
    /// Width of the operand column.
    operand_width: f32,
    /// Width of the comment column.
    comment_width: f32,

    /// Which columns are visible.
    show_address: bool,
    show_bytes: bool,
    show_label: bool,
    show_mnemonic: bool,
    show_operands: bool,
    show_comment: bool,

    // Interaction state
    /// Currently hovered address (for navigation).
    hovered_address: Option<Address>,
    /// Currently selected addresses (multi-select, ctrl+click).
    selected_addresses: HashSet<Address>,
    /// Range selection start (shift+click).
    selection_anchor: Option<Address>,
    /// Range selection end.
    selection_end: Option<Address>,
    /// The cursor (focus) address.
    cursor_address: Address,
    /// Top visible address (for scroll position tracking).
    top_visible_address: Option<Address>,
    /// Column being resized (index of the column, None if not resizing).
    resizing_column: Option<usize>,
    /// Whether the user is currently dragging to scroll.
    is_dragging: bool,
    /// Drag start position in UI coordinates.
    drag_start: Option<Pos2>,
    /// Drag start address (for address tracking during scroll).
    drag_start_address: Option<Address>,
    /// Last click position (for double-click detection).
    last_click_pos: Option<Pos2>,
    /// Address that was last clicked.
    last_clicked_address: Option<Address>,

    // Formatter
    /// The field formatter for text formatting.
    pub formatter: FieldFormatter,
}

impl Default for DisassemblyRenderer {
    fn default() -> Self {
        Self {
            font: egui::FontId::monospace(12.0),
            line_height: DEFAULT_LINE_HEIGHT,

            address_color: Color32::from_rgb(150, 150, 160),
            mnemonic_color: Color32::from_rgb(130, 190, 255),
            register_color: Color32::from_rgb(180, 210, 255),
            immediate_color: Color32::from_rgb(100, 255, 130),
            address_ref_color: Color32::from_rgb(255, 220, 120),
            comment_color: Color32::from_rgb(100, 200, 100),
            label_color: Color32::from_rgb(255, 200, 100),
            bytes_color: Color32::from_rgb(140, 140, 150),
            xref_color: Color32::from_rgb(100, 170, 170),
            selection_color: Color32::from_rgba_premultiplied(80, 140, 255, 45),
            cursor_color: Color32::from_rgba_premultiplied(255, 255, 100, 30),
            background_color: Color32::from_rgb(30, 30, 35),
            alternating_row: Color32::from_rgba_premultiplied(255, 255, 255, 8),

            address_width: DEFAULT_ADDRESS_WIDTH,
            bytes_width: DEFAULT_BYTES_WIDTH,
            label_width: DEFAULT_LABEL_WIDTH,
            mnemonic_width: DEFAULT_MNEMONIC_WIDTH,
            operand_width: DEFAULT_OPERAND_WIDTH,
            comment_width: DEFAULT_COMMENT_WIDTH,

            show_address: true,
            show_bytes: true,
            show_label: true,
            show_mnemonic: true,
            show_operands: true,
            show_comment: true,

            hovered_address: None,
            selected_addresses: HashSet::new(),
            selection_anchor: None,
            selection_end: None,
            cursor_address: Address::new(0x1000),
            top_visible_address: None,
            resizing_column: None,
            is_dragging: false,
            drag_start: None,
            drag_start_address: None,
            last_click_pos: None,
            last_clicked_address: None,

            formatter: FieldFormatter::default(),
        }
    }
}

impl DisassemblyRenderer {
    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    /// Create a new renderer with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set the line height.
    pub fn with_line_height(mut self, height: f32) -> Self {
        self.line_height = height.clamp(MIN_LINE_HEIGHT, MAX_LINE_HEIGHT);
        self
    }

    /// Builder: set all column visibility at once.
    pub fn with_columns(
        mut self,
        address: bool,
        bytes: bool,
        label: bool,
        mnemonic: bool,
        operands: bool,
        comment: bool,
    ) -> Self {
        self.show_address = address;
        self.show_bytes = bytes;
        self.show_label = label;
        self.show_mnemonic = mnemonic;
        self.show_operands = operands;
        self.show_comment = comment;
        self
    }

    // ------------------------------------------------------------------
    // Column management
    // ------------------------------------------------------------------

    /// Recalculate column widths based on available space.
    ///
    /// Distributes available width proportionally among visible columns,
    /// clamped to their min/max widths.
    pub fn calculate_columns(&mut self, ui: &egui::Ui) {
        let available = ui.available_width();
        let visible_count = self.visible_column_count();

        if visible_count == 0 {
            return;
        }

        let gap_space = COLUMN_GAP * (visible_count.saturating_sub(1)) as f32;

        // Collect current widths of visible columns
        let widths = self.visible_widths();
        let total: f32 = widths.iter().sum();

        // If we have more space available, distribute proportionally
        if available > total + gap_space {
            let extra = (available - total - gap_space) / visible_count as f32;
            self.distribute_width_extra(extra);
        }
    }

    /// Count how many columns are visible.
    fn visible_column_count(&self) -> usize {
        let mut count = 0;
        if self.show_address {
            count += 1;
        }
        if self.show_bytes {
            count += 1;
        }
        if self.show_label {
            count += 1;
        }
        if self.show_mnemonic {
            count += 1;
        }
        if self.show_operands {
            count += 1;
        }
        if self.show_comment {
            count += 1;
        }
        count
    }

    /// Get widths of visible columns in display order.
    fn visible_widths(&self) -> Vec<f32> {
        let mut widths = Vec::new();
        if self.show_address {
            widths.push(self.address_width);
        }
        if self.show_bytes {
            widths.push(self.bytes_width);
        }
        if self.show_label {
            widths.push(self.label_width);
        }
        if self.show_mnemonic {
            widths.push(self.mnemonic_width);
        }
        if self.show_operands {
            widths.push(self.operand_width);
        }
        if self.show_comment {
            widths.push(self.comment_width);
        }
        widths
    }

    /// Distribute extra width proportionally.
    fn distribute_width_extra(&mut self, extra: f32) {
        if extra <= 0.0 {
            return;
        }
        if self.show_address {
            self.address_width =
                (self.address_width + extra).clamp(MIN_ADDRESS_WIDTH, MAX_ADDRESS_WIDTH);
        }
        if self.show_bytes {
            self.bytes_width = (self.bytes_width + extra).clamp(MIN_BYTES_WIDTH, MAX_BYTES_WIDTH);
        }
        if self.show_label {
            self.label_width = (self.label_width + extra).clamp(MIN_LABEL_WIDTH, MAX_LABEL_WIDTH);
        }
        if self.show_mnemonic {
            self.mnemonic_width =
                (self.mnemonic_width + extra).clamp(MIN_MNEMONIC_WIDTH, MAX_MNEMONIC_WIDTH);
        }
        if self.show_operands {
            self.operand_width =
                (self.operand_width + extra).clamp(MIN_OPERAND_WIDTH, MAX_OPERAND_WIDTH);
        }
        if self.show_comment {
            self.comment_width =
                (self.comment_width + extra).clamp(MIN_COMMENT_WIDTH, MAX_COMMENT_WIDTH);
        }
    }

    /// Set the width of a specific column.
    pub fn set_column_width(&mut self, index: usize, width: f32) {
        let clamped = width.clamp(0.0, 1000.0);
        match index {
            0 => self.address_width = clamped.clamp(MIN_ADDRESS_WIDTH, MAX_ADDRESS_WIDTH),
            1 => self.bytes_width = clamped.clamp(MIN_BYTES_WIDTH, MAX_BYTES_WIDTH),
            2 => self.label_width = clamped.clamp(MIN_LABEL_WIDTH, MAX_LABEL_WIDTH),
            3 => self.mnemonic_width = clamped.clamp(MIN_MNEMONIC_WIDTH, MAX_MNEMONIC_WIDTH),
            4 => self.operand_width = clamped.clamp(MIN_OPERAND_WIDTH, MAX_OPERAND_WIDTH),
            5 => self.comment_width = clamped.clamp(MIN_COMMENT_WIDTH, MAX_COMMENT_WIDTH),
            _ => {}
        }
    }

    /// Get the width of a specific column.
    pub fn column_width(&self, index: usize) -> f32 {
        match index {
            0 => self.address_width,
            1 => self.bytes_width,
            2 => self.label_width,
            3 => self.mnemonic_width,
            4 => self.operand_width,
            5 => self.comment_width,
            _ => 0.0,
        }
    }

    /// Compute total width needed for all visible columns + gaps.
    pub fn total_content_width(&self) -> f32 {
        let widths = self.visible_widths();
        if widths.is_empty() {
            return 0.0;
        }
        widths.iter().sum::<f32>() + COLUMN_GAP * (widths.len().saturating_sub(1)) as f32
    }

    // ------------------------------------------------------------------
    // Navigation
    // ------------------------------------------------------------------

    /// Navigate to a specific address, clearing selection.
    pub fn navigate_to(&mut self, addr: Address) {
        self.cursor_address = addr;
        self.selected_addresses.clear();
        self.selection_anchor = None;
        self.selection_end = None;
    }

    /// Set the cursor to an address (single click — no navigation).
    pub fn set_cursor(&mut self, addr: Address) {
        self.cursor_address = addr;
    }

    /// Get the cursor address.
    pub fn cursor_address(&self) -> Address {
        self.cursor_address
    }

    /// Get the address at a specific UI position (relative to the listing body).
    ///
    /// Returns `None` if the position is outside the listing area.
    pub fn get_clicked_address(&self, ui: &egui::Ui, pos: Pos2) -> Option<Address> {
        // The position is relative to the scroll area content.
        // Each row is `line_height` tall; the top row corresponds to
        // the first visible instruction.
        let available = ui.available_rect_before_wrap();
        if !available.contains(pos) {
            return None;
        }

        let relative_y = pos.y - available.top();
        let row_index = (relative_y / self.line_height) as usize;

        // We need the listing data to resolve.  This method is called from
        // the `render` method which populates `top_visible_address`.
        if let Some(top_addr) = self.top_visible_address {
            let target_addr = Address::new(top_addr.offset + row_index as u64);
            if target_addr.offset != u64::MAX {
                return Some(target_addr);
            }
        }

        None
    }

    /// Map a pixel offset within the listing body to a row index.
    fn y_to_row_index(&self, y: f32) -> usize {
        if y < 0.0 || self.line_height <= 0.0 {
            return 0;
        }
        (y / self.line_height) as usize
    }

    /// Map an address to a y-position within the listing body relative to
    /// the top visible address.
    fn addr_to_y_offset(&self, addr: &Address, top_addr: &Address) -> f32 {
        if addr.offset < top_addr.offset {
            return 0.0;
        }
        let delta = addr.offset - top_addr.offset;
        delta as f32 * self.line_height
    }

    // ------------------------------------------------------------------
    // Selection
    // ------------------------------------------------------------------

    /// Select a single address (clears previous selection).
    pub fn select(&mut self, addr: Address) {
        self.cursor_address = addr;
        self.selected_addresses.clear();
        self.selected_addresses.insert(addr);
        self.selection_anchor = Some(addr);
        self.selection_end = None;
    }

    /// Toggle selection of an address (ctrl+click).
    pub fn toggle_select(&mut self, addr: Address) {
        if self.selected_addresses.contains(&addr) {
            self.selected_addresses.remove(&addr);
        } else {
            self.selected_addresses.insert(addr);
        }
        self.cursor_address = addr;
        self.selection_anchor = None;
        self.selection_end = None;
    }

    /// Extend selection to an address (shift+click).
    pub fn extend_selection(&mut self, addr: Address) {
        let anchor = self.selection_anchor.unwrap_or(self.cursor_address);
        let start = if anchor.offset <= addr.offset {
            anchor
        } else {
            addr
        };
        let end = if anchor.offset > addr.offset {
            anchor
        } else {
            addr
        };

        for a in AddressRange::new(start, end).iter() {
            self.selected_addresses.insert(a);
        }
        self.selection_end = Some(addr);
        self.cursor_address = addr;
    }

    /// Clear all selection.
    pub fn clear_selection(&mut self) {
        self.selected_addresses.clear();
        self.selection_anchor = None;
        self.selection_end = None;
    }

    /// Check if an address is selected.
    pub fn is_selected(&self, addr: &Address) -> bool {
        self.selected_addresses.contains(addr)
    }

    /// Get all selected addresses, sorted.
    pub fn selected_addresses_sorted(&self) -> Vec<Address> {
        let mut addrs: Vec<Address> = self.selected_addresses.iter().copied().collect();
        addrs.sort_by_key(|a| a.offset);
        addrs
    }

    /// Check if an address is within the range selection.
    fn is_in_range_selection(&self, addr: &Address) -> bool {
        if let (Some(anchor), Some(end)) = (self.selection_anchor, self.selection_end) {
            let start = if anchor.offset <= end.offset {
                anchor
            } else {
                end
            };
            let stop = if anchor.offset > end.offset {
                anchor
            } else {
                end
            };
            return addr.offset >= start.offset && addr.offset <= stop.offset;
        }
        false
    }

    // ------------------------------------------------------------------
    // Render
    // ------------------------------------------------------------------

    /// Render the disassembly listing into the given egui Ui.
    ///
    /// `listing` is the data source providing instructions and data.
    /// `range` defines the address range to display.
    pub fn render(&mut self, ui: &mut egui::Ui, listing: &dyn Listing, range: AddressRange) {
        // Recalculate column widths
        self.calculate_columns(ui);

        let available_rect = ui.available_rect_before_wrap();
        let content_width = self.total_content_width();

        // --- Header ---
        let header_rect = Rect::from_min_size(
            available_rect.min,
            vec2(available_rect.width(), HEADER_HEIGHT),
        );
        self.render_header(ui, header_rect);

        // --- Body ---
        let body_top = available_rect.min.y + HEADER_HEIGHT;
        let body_rect = Rect::from_min_size(
            pos2(available_rect.min.x, body_top),
            vec2(
                available_rect.width(),
                available_rect.height() - HEADER_HEIGHT,
            ),
        );

        // Calculate how many rows are visible
        let visible_rows = ((body_rect.height() / self.line_height) as usize).max(1);
        let total_rows = range.len().min(u64::MAX) as usize;

        if total_rows == 0 {
            ui.allocate_rect(body_rect, Sense::hover());
            ui.painter()
                .rect_filled(body_rect, 0.0, self.background_color);
            ui.put(
                body_rect,
                egui::Label::new(
                    RichText::new("No disassembly data")
                        .color(self.comment_color)
                        .monospace(),
                ),
            );
            return;
        }

        // Build the list of instructions and data in the range
        let instructions = listing.get_instructions(&range);
        let data_items = listing.get_data_items(&range);

        // Collect all addresses in order
        let mut addresses: Vec<Address> = range.iter().collect();
        addresses.truncate(10000); // Safety limit

        let total_height = addresses.len() as f32 * self.line_height;

        // Wrap in a scroll area
        let scroll_id = ui.make_persistent_id("disassembly_scroll");

        // We render inside a frame
        Frame::none().fill(self.background_color).show(ui, |ui| {
            let inner_rect = ui.available_rect_before_wrap();

            // Draw background
            ui.painter()
                .rect_filled(inner_rect, 0.0, self.background_color);

            // Compute scroll offset from current scroll position
            let scroll = ui.clip_rect();
            let scroll_top = scroll.top().max(inner_rect.top());
            let first_visible_row = if self.line_height > 0.0 {
                ((scroll_top - inner_rect.top()) / self.line_height) as usize
            } else {
                0
            };
            let last_visible_row = (first_visible_row + visible_rows + 2).min(addresses.len());

            if first_visible_row < addresses.len() {
                self.top_visible_address = Some(addresses[first_visible_row]);
            }

            // Allocate space for the scrollable content
            let content_size = vec2(content_width.max(inner_rect.width()), total_height);
            let (rect, _response) = ui.allocate_exact_size(content_size, Sense::click_and_drag());

            // Handle scroll drag in the body
            let input = ui.input(|i| i.clone());

            // Handle keyboard navigation
            self.handle_keyboard(&input, &addresses);

            // Render visible rows
            for row_idx in first_visible_row..last_visible_row {
                if row_idx >= addresses.len() {
                    break;
                }
                let addr = addresses[row_idx];
                let y_pos = inner_rect.top() + row_idx as f32 * self.line_height;

                // Clamp to visible area
                if y_pos + self.line_height < scroll_top || y_pos > scroll.bottom() {
                    continue;
                }

                let row_rect = Rect::from_min_size(
                    pos2(inner_rect.left(), y_pos),
                    vec2(content_width.max(inner_rect.width()), self.line_height),
                );

                // Determine if this row is the cursor or selected
                let is_cursor = addr == self.cursor_address;
                let is_selected = self.is_selected(&addr) || self.is_in_range_selection(&addr);
                let is_odd = row_idx % 2 == 1;

                // Paint row background
                self.paint_row_bg(ui, &row_rect, is_cursor, is_selected, is_odd);

                // Find instruction or data for this row
                let ins = instructions.iter().find(|i| i.address == addr);
                let data = data_items.iter().find(|d| d.address == addr);

                // Render row content
                let mut x_offset = inner_rect.left();
                let col_count = self.visible_column_count();

                let mut col_idx: usize = 0;

                // Address column
                if self.show_address {
                    let w = self.address_width;
                    let col_rect =
                        Rect::from_min_size(pos2(x_offset, y_pos), vec2(w, self.line_height));
                    self.render_address_col(ui, &col_rect, &addr);
                    x_offset += w;
                    if col_idx < col_count - 1 {
                        self.render_col_separator(ui, x_offset, y_pos, col_idx);
                        x_offset += COLUMN_GAP;
                    }
                    col_idx += 1;
                }

                // Bytes column
                if self.show_bytes {
                    let w = self.bytes_width;
                    let col_rect =
                        Rect::from_min_size(pos2(x_offset, y_pos), vec2(w, self.line_height));
                    if let Some(ins) = ins {
                        self.render_bytes_col(ui, &col_rect, &ins.bytes);
                    } else if let Some(d) = data {
                        // Data has no bytes field; use raw lookup
                        let raw = listing.get_bytes(addr, d.size);
                        self.render_bytes_col(ui, &col_rect, &raw);
                    } else {
                        // Render empty
                        self.render_text_col(ui, &col_rect, "", self.bytes_color, Align::Min);
                    }
                    x_offset += w;
                    if col_idx < col_count - 1 {
                        self.render_col_separator(ui, x_offset, y_pos, col_idx);
                        x_offset += COLUMN_GAP;
                    }
                    col_idx += 1;
                }

                // Label column
                if self.show_label {
                    let w = self.label_width;
                    let col_rect =
                        Rect::from_min_size(pos2(x_offset, y_pos), vec2(w, self.line_height));
                    if let Some(ins) = ins {
                        if let Some(ref label) = ins.label {
                            self.render_text_col(
                                ui,
                                &col_rect,
                                label,
                                self.label_color,
                                Align::Min,
                            );
                        } else {
                            self.render_text_col(ui, &col_rect, "", self.label_color, Align::Min);
                        }
                    } else if let Some(d) = data {
                        if let Some(ref label) = d.label {
                            self.render_text_col(
                                ui,
                                &col_rect,
                                label,
                                self.label_color,
                                Align::Min,
                            );
                        } else {
                            self.render_text_col(ui, &col_rect, "", self.label_color, Align::Min);
                        }
                    }
                    x_offset += w;
                    if col_idx < col_count - 1 {
                        self.render_col_separator(ui, x_offset, y_pos, col_idx);
                        x_offset += COLUMN_GAP;
                    }
                    col_idx += 1;
                }

                // Mnemonic column
                if self.show_mnemonic {
                    let w = self.mnemonic_width;
                    let col_rect =
                        Rect::from_min_size(pos2(x_offset, y_pos), vec2(w, self.line_height));
                    if let Some(ins) = ins {
                        let color = self.mnemonic_color_for_flow(&ins.flow_type);
                        self.render_text_col(ui, &col_rect, &ins.mnemonic, color, Align::Min);
                    } else if let Some(d) = data {
                        let label = if d.is_defined {
                            d.data_type_name.clone()
                        } else {
                            "db".to_string()
                        };
                        self.render_text_col(
                            ui,
                            &col_rect,
                            &label,
                            self.mnemonic_color,
                            Align::Min,
                        );
                    }
                    x_offset += w;
                    if col_idx < col_count - 1 {
                        self.render_col_separator(ui, x_offset, y_pos, col_idx);
                        x_offset += COLUMN_GAP;
                    }
                    col_idx += 1;
                }

                // Operand column
                if self.show_operands {
                    let w = self.operand_width;
                    let col_rect =
                        Rect::from_min_size(pos2(x_offset, y_pos), vec2(w, self.line_height));
                    if let Some(ins) = ins {
                        self.render_operand_col(ui, &col_rect, ins);
                    } else if let Some(d) = data {
                        if let Some(ref value) = d.value {
                            self.render_text_col(
                                ui,
                                &col_rect,
                                value,
                                self.immediate_color,
                                Align::Min,
                            );
                        }
                    }
                    x_offset += w;
                    if col_idx < col_count - 1 {
                        self.render_col_separator(ui, x_offset, y_pos, col_idx);
                        x_offset += COLUMN_GAP;
                    }
                    col_idx += 1;
                }

                // Comment column
                if self.show_comment {
                    let w = self.comment_width;
                    let col_rect =
                        Rect::from_min_size(pos2(x_offset, y_pos), vec2(w, self.line_height));
                    let comment_text = if let Some(ins) = ins {
                        ins.comment.as_deref().unwrap_or("")
                    } else if let Some(d) = data {
                        d.comment.as_deref().unwrap_or("")
                    } else {
                        ""
                    };
                    if !comment_text.is_empty() {
                        let formatted = self.formatter.format_eol_comment(comment_text);
                        self.render_text_col(
                            ui,
                            &col_rect,
                            &formatted,
                            self.comment_color,
                            Align::Min,
                        );
                    }
                    // x_offset += w; // last column
                }

                // Handle click/drag interaction on the row
                let row_response = ui.interact(
                    row_rect,
                    Id::new(("listing_line", addr.offset)),
                    Sense::click_and_drag(),
                );
                self.handle_row_interaction(&row_response, addr, &input);
            }
        });
    }

    // ------------------------------------------------------------------
    // Row background
    // ------------------------------------------------------------------

    /// Paint the background for a single row.
    fn paint_row_bg(&self, ui: &Ui, rect: &Rect, is_cursor: bool, is_selected: bool, is_odd: bool) {
        if is_cursor {
            ui.painter().rect_filled(*rect, 0.0, self.cursor_color);
        } else if is_selected {
            ui.painter().rect_filled(*rect, 0.0, self.selection_color);
        } else if is_odd {
            ui.painter().rect_filled(*rect, 0.0, self.alternating_row);
        }
    }

    // ------------------------------------------------------------------
    // Header
    // ------------------------------------------------------------------

    /// Render the column header bar.
    fn render_header(&mut self, ui: &mut Ui, rect: Rect) {
        let header_bg = Color32::from_rgb(45, 45, 55);
        let header_text_color = Color32::from_rgb(180, 200, 220);

        ui.painter().rect_filled(rect, 0.0, header_bg);
        ui.painter().line_segment(
            [rect.left_bottom(), rect.right_bottom()],
            Stroke::new(1.0, Color32::from_rgb(80, 80, 90)),
        );

        let mut x_offset = rect.left();
        let col_count = self.visible_column_count();
        let mut col_idx: usize = 0;

        let columns: &[(&str, f32, bool)] = &[
            ("Address", self.address_width, self.show_address),
            ("Bytes", self.bytes_width, self.show_bytes),
            ("Label", self.label_width, self.show_label),
            ("Mnemonic", self.mnemonic_width, self.show_mnemonic),
            ("Operands", self.operand_width, self.show_operands),
            ("Comment", self.comment_width, self.show_comment),
        ];

        for (label, width, visible) in columns {
            if !visible {
                continue;
            }
            let w = *width;
            let col_rect = Rect::from_min_size(
                pos2(x_offset + COLUMN_PADDING_X, rect.top() + 2.0),
                vec2(w - COLUMN_PADDING_X * 2.0, rect.height() - 4.0),
            );
            ui.painter().text(
                col_rect.left_top(),
                Align2::LEFT_TOP,
                label,
                egui::FontId::monospace(11.0),
                header_text_color,
            );
            x_offset += w;
            if col_idx < col_count - 1 {
                // Separator
                let sep_x = x_offset;
                let sep_rect = Rect::from_min_size(
                    pos2(sep_x, rect.top()),
                    vec2(SEPARATOR_WIDTH, rect.height()),
                );
                // Detect hover on separator for resize
                let sep_id = Id::new(("col_resize", col_idx));
                let sep_resp = ui.interact(sep_rect, sep_id, Sense::drag());
                if sep_resp.hovered() || self.resizing_column == Some(col_idx) {
                    ui.ctx().set_cursor_icon(CursorIcon::ResizeColumn);
                    ui.painter()
                        .rect_filled(sep_rect, 0.0, Color32::from_rgb(120, 160, 220));
                } else {
                    ui.painter()
                        .rect_filled(sep_rect, 0.0, Color32::from_rgb(60, 60, 70));
                }

                // Handle resize drag
                if sep_resp.dragged() {
                    let delta = sep_resp.drag_delta().x;
                    if delta.abs() > 0.5 {
                        let new_width = (*width + delta).clamp(0.0, 1000.0);
                        self.set_column_width(col_idx, new_width);
                        self.resizing_column = Some(col_idx);
                    }
                } else if self.resizing_column == Some(col_idx) {
                    self.resizing_column = None;
                }
                x_offset += COLUMN_GAP;
            }
            col_idx += 1;
        }
    }

    /// Render a column separator (vertical gap between columns).
    fn render_col_separator(&self, ui: &Ui, x: f32, y: f32, col_idx: usize) {
        let sep_rect = Rect::from_min_size(pos2(x, y), vec2(COLUMN_GAP, self.line_height));
        // Subtle vertical line
        let mid_x = x + COLUMN_GAP * 0.5;
        ui.painter().line_segment(
            [
                pos2(mid_x, y + 2.0),
                pos2(mid_x, y + self.line_height - 2.0),
            ],
            Stroke::new(0.5, Color32::from_rgba_premultiplied(128, 128, 128, 60)),
        );
    }

    // ------------------------------------------------------------------
    // Column cell renderers
    // ------------------------------------------------------------------

    /// Render the address column.
    fn render_address_col(&self, ui: &Ui, rect: &Rect, addr: &Address) {
        let text = self.formatter.format_address_raw(addr);
        self.render_text_rect(ui, rect, &text, self.address_color, Align::Min);
    }

    /// Render the bytes column.
    fn render_bytes_col(&self, ui: &Ui, rect: &Rect, bytes: &[u8]) {
        let text = self.formatter.format_bytes(bytes);
        self.render_text_rect(ui, rect, &text, self.bytes_color, Align::Min);
    }

    /// Render the operand column with syntax-colored tokens.
    fn render_operand_col(&self, ui: &Ui, rect: &Rect, ins: &Instruction) {
        if ins.operands.is_empty() {
            return;
        }

        let mut x = rect.left() + COLUMN_PADDING_X;
        let y_center = rect.center().y;

        for (i, op) in ins.operands.iter().enumerate() {
            let (text, color) = self.operand_display(op);

            let galley = ui
                .painter()
                .layout_no_wrap(text.clone(), self.font.clone(), color);
            let text_pos = pos2(x, y_center - galley.size().y * 0.5);
            ui.painter().galley(text_pos, galley, color);
            x += ui
                .painter()
                .layout_no_wrap(text, self.font.clone(), color)
                .size()
                .x;

            // Comma separator between operands
            if i + 1 < ins.operands.len() {
                let comma_galley = ui.painter().layout_no_wrap(
                    ", ".to_string(),
                    self.font.clone(),
                    self.immediate_color,
                );
                ui.painter().galley(
                    pos2(x, y_center - comma_galley.size().y * 0.5),
                    comma_galley,
                    self.immediate_color,
                );
                x += ui
                    .painter()
                    .layout_no_wrap(", ".to_string(), self.font.clone(), Color32::WHITE)
                    .size()
                    .x;
            }
        }
    }

    /// Get display text and color for an operand.
    fn operand_display(&self, op: &Operand) -> (String, Color32) {
        match op {
            Operand::Register(name) => (name.clone(), self.register_color),
            Operand::Scalar(v) => {
                let text = self.formatter.number_format.format_scalar(*v);
                (text, self.immediate_color)
            }
            Operand::Address(addr) => {
                let text = self.formatter.format_address_raw(addr);
                (text, self.address_ref_color)
            }
            Operand::Expression(e) => (e.clone(), self.address_ref_color),
            Operand::Float(v) => {
                let text = format!("{:.6}", v);
                (text, self.immediate_color)
            }
            Operand::None => (String::new(), self.immediate_color),
        }
    }

    /// Render a text string in a column rectangle.
    fn render_text_rect(&self, ui: &Ui, rect: &Rect, text: &str, color: Color32, align: Align) {
        if text.is_empty() {
            return;
        }
        // Truncate if needed
        let max_chars = ((rect.width().max(20.0) - COLUMN_PADDING_X * 2.0) / 8.0) as usize;
        let display = if text.len() > max_chars.saturating_sub(1) && max_chars > 3 {
            let truncated: String = text.chars().take(max_chars.saturating_sub(1)).collect();
            format!("{}>", truncated)
        } else {
            text.to_string()
        };

        let galley = ui
            .painter()
            .layout_no_wrap(display.clone(), self.font.clone(), color);

        let text_pos = match align {
            Align::Min => pos2(
                rect.left() + COLUMN_PADDING_X,
                rect.center().y - galley.size().y * 0.5,
            ),
            Align::Center => pos2(
                rect.center().x - galley.size().x * 0.5,
                rect.center().y - galley.size().y * 0.5,
            ),
            Align::Max => pos2(
                rect.right() - COLUMN_PADDING_X - galley.size().x,
                rect.center().y - galley.size().y * 0.5,
            ),
        };
        ui.painter().galley(text_pos, galley, color);
    }

    /// Render a text string with a given alignment (simpler version calling paint_text_rect).
    fn render_text_col(&self, ui: &Ui, rect: &Rect, text: &str, color: Color32, align: Align) {
        self.render_text_rect(ui, rect, text, color, align);
    }

    // ------------------------------------------------------------------
    // Interaction handling
    // ------------------------------------------------------------------

    /// Handle click and drag interactions on a listing row.
    fn handle_row_interaction(
        &mut self,
        response: &Response,
        addr: Address,
        input: &egui::InputState,
    ) {
        let modifiers = input.modifiers;

        if response.clicked() {
            if modifiers.ctrl {
                self.toggle_select(addr);
            } else if modifiers.shift {
                self.extend_selection(addr);
            } else {
                self.select(addr);
            }
            self.last_clicked_address = Some(addr);
        }

        if response.double_clicked() {
            // Double-click: navigate (handled by caller via get_clicked_address)
        }

        if response.hovered() {
            self.hovered_address = Some(addr);
        }

        // Drag-scroll
        if response.dragged() && self.selected_addresses.is_empty() {
            if self.drag_start.is_none() {
                self.drag_start = response.interact_pointer_pos();
                self.drag_start_address = Some(addr);
            }
            self.is_dragging = true;

            // Compute how many rows we've dragged and adjust scroll
            if let Some(start_pos) = self.drag_start {
                if let Some(current_pos) = response.interact_pointer_pos() {
                    let delta_y = current_pos.y - start_pos.y;
                    let rows_moved = (delta_y / self.line_height) as i64;
                    // The caller (application) should handle actual scroll
                    // based on this information.
                }
            }
        } else if self.is_dragging {
            // Drag ended
            self.is_dragging = false;
            self.drag_start = None;
            self.drag_start_address = None;
        }
    }

    /// Handle keyboard input for navigation and editing.
    fn handle_keyboard(&mut self, input: &egui::InputState, addresses: &[Address]) {
        let current_idx = addresses
            .binary_search_by_key(&self.cursor_address.offset, |a| a.offset)
            .unwrap_or(0);

        // Arrow down
        if input.key_pressed(Key::ArrowDown) {
            let next = (current_idx + 1).min(addresses.len().saturating_sub(1));
            if next < addresses.len() {
                let next_addr = addresses[next];
                if input.modifiers.shift {
                    self.extend_selection(next_addr);
                } else {
                    self.select(next_addr);
                }
            }
        }

        // Arrow up
        if input.key_pressed(Key::ArrowUp) {
            let prev = current_idx.saturating_sub(1);
            if prev < addresses.len() {
                let prev_addr = addresses[prev];
                if input.modifiers.shift {
                    self.extend_selection(prev_addr);
                } else {
                    self.select(prev_addr);
                }
            }
        }

        // Page down
        if input.key_pressed(Key::PageDown) {
            let rows_to_skip = 20usize;
            let next = (current_idx + rows_to_skip).min(addresses.len().saturating_sub(1));
            if next < addresses.len() {
                self.select(addresses[next]);
            }
        }

        // Page up
        if input.key_pressed(Key::PageUp) {
            let prev = current_idx.saturating_sub(20);
            if prev < addresses.len() {
                self.select(addresses[prev]);
            }
        }

        // Home
        if input.key_pressed(Key::Home) {
            if let Some(first) = addresses.first() {
                self.select(*first);
            }
        }

        // End
        if input.key_pressed(Key::End) {
            if let Some(last) = addresses.last() {
                self.select(*last);
            }
        }

        // Escape: clear selection
        if input.key_pressed(Key::Escape) {
            self.clear_selection();
        }
    }

    // ------------------------------------------------------------------
    // Color helpers
    // ------------------------------------------------------------------

    /// Get a mnemonic color based on the flow type.
    fn mnemonic_color_for_flow(&self, flow: &FlowType) -> Color32 {
        match flow {
            FlowType::Call | FlowType::ConditionalCall => Color32::from_rgb(255, 180, 100),
            FlowType::Return => Color32::from_rgb(255, 150, 130),
            FlowType::Jump => Color32::from_rgb(255, 130, 180),
            FlowType::ConditionalJump => Color32::from_rgb(200, 150, 255),
            FlowType::Terminator => Color32::from_rgb(255, 100, 100),
            FlowType::SystemCall => Color32::from_rgb(255, 90, 90),
            FlowType::Normal => self.mnemonic_color,
        }
    }

    // ------------------------------------------------------------------
    // Visibility toggles
    // ------------------------------------------------------------------

    /// Toggle visibility of a column.
    pub fn toggle_column(&mut self, col: &str) {
        match col {
            "address" => self.show_address = !self.show_address,
            "bytes" => self.show_bytes = !self.show_bytes,
            "label" => self.show_label = !self.show_label,
            "mnemonic" => self.show_mnemonic = !self.show_mnemonic,
            "operands" => self.show_operands = !self.show_operands,
            "comment" => self.show_comment = !self.show_comment,
            _ => {}
        }
    }

    /// Set the formatter.
    pub fn with_formatter(mut self, formatter: FieldFormatter) -> Self {
        self.formatter = formatter;
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::program::listing::{InMemoryListing, Instruction};

    fn make_test_renderer() -> DisassemblyRenderer {
        DisassemblyRenderer::default()
    }

    fn make_test_listing() -> InMemoryListing {
        let mut listing = InMemoryListing::new();
        // Add some code units
        for i in 0..10u64 {
            let addr = Address::new(0x1000 + i);
            listing
                .create_code_unit(addr, 1, vec![(i & 0xFF) as u8])
                .unwrap();
        }
        listing
    }

    #[test]
    fn test_new_renderer() {
        let r = make_test_renderer();
        assert_eq!(r.cursor_address(), Address::new(0x1000));
        assert!(r.selected_addresses_sorted().is_empty());
    }

    #[test]
    fn test_select() {
        let mut r = make_test_renderer();
        let addr = Address::new(0x401000);
        r.select(addr);
        assert_eq!(r.cursor_address(), addr);
        assert!(r.is_selected(&addr));
        assert_eq!(r.selected_addresses_sorted(), vec![addr]);
    }

    #[test]
    fn test_toggle_select() {
        let mut r = make_test_renderer();
        let addr = Address::new(0x401000);
        r.toggle_select(addr);
        assert!(r.is_selected(&addr));
        r.toggle_select(addr);
        assert!(!r.is_selected(&addr));
    }

    #[test]
    fn test_extend_selection() {
        let mut r = make_test_renderer();
        r.select(Address::new(0x1000));
        r.extend_selection(Address::new(0x1005));
        assert!(r.is_selected(&Address::new(0x1000)));
        assert!(r.is_selected(&Address::new(0x1003)));
        assert!(r.is_selected(&Address::new(0x1005)));
        assert!(!r.is_selected(&Address::new(0x1006)));
    }

    #[test]
    fn test_clear_selection() {
        let mut r = make_test_renderer();
        r.select(Address::new(0x1000));
        r.toggle_select(Address::new(0x2000));
        assert_eq!(r.selected_addresses_sorted().len(), 2);
        r.clear_selection();
        assert!(r.selected_addresses_sorted().is_empty());
    }

    #[test]
    fn test_navigate_to() {
        let mut r = make_test_renderer();
        r.select(Address::new(0x1000));
        r.toggle_select(Address::new(0x2000));
        r.navigate_to(Address::new(0x5000));
        assert_eq!(r.cursor_address(), Address::new(0x5000));
        assert!(r.selected_addresses_sorted().is_empty());
    }

    #[test]
    fn test_column_visibility() {
        let mut r = make_test_renderer();
        assert_eq!(r.visible_column_count(), 6);
        r.toggle_column("bytes");
        assert_eq!(r.visible_column_count(), 5);
        r.toggle_column("bytes");
        assert_eq!(r.visible_column_count(), 6);
    }

    #[test]
    fn test_column_widths() {
        let mut r = make_test_renderer();
        r.set_column_width(0, 100.0);
        assert_eq!(r.address_width, 100.0);

        // Clamped to min
        r.set_column_width(0, 10.0);
        assert_eq!(r.address_width, MIN_ADDRESS_WIDTH);

        // Clamped to max
        r.set_column_width(3, 1000.0);
        assert_eq!(r.mnemonic_width, MAX_MNEMONIC_WIDTH);
    }

    #[test]
    fn test_mnemonic_color_for_flow() {
        let r = make_test_renderer();
        let call_color = r.mnemonic_color_for_flow(&FlowType::Call);
        let ret_color = r.mnemonic_color_for_flow(&FlowType::Return);
        let jmp_color = r.mnemonic_color_for_flow(&FlowType::Jump);
        let normal_color = r.mnemonic_color_for_flow(&FlowType::Normal);

        // Each flow type should have a different color
        assert_ne!(call_color, ret_color);
        assert_ne!(call_color, jmp_color);
        assert_eq!(normal_color, r.mnemonic_color);
    }

    #[test]
    fn test_operand_display_register() {
        let r = make_test_renderer();
        let op = Operand::Register("rax".to_string());
        let (text, color) = r.operand_display(&op);
        assert_eq!(text, "rax");
        assert_eq!(color, r.register_color);
    }

    #[test]
    fn test_operand_display_scalar() {
        let r = make_test_renderer();
        let op = Operand::Scalar(0x42);
        let (text, color) = r.operand_display(&op);
        // With default hex formatter
        assert!(text.contains("42"));
        assert_eq!(color, r.immediate_color);
    }

    #[test]
    fn test_operand_display_address() {
        let r = make_test_renderer();
        let op = Operand::Address(Address::new(0x401000));
        let (text, color) = r.operand_display(&op);
        assert!(text.contains("401000"));
        assert_eq!(color, r.address_ref_color);
    }

    #[test]
    fn test_total_content_width() {
        let r = make_test_renderer();
        let total = r.total_content_width();
        assert!(total > 0.0);
        // 6 columns + 5 gaps
        let expected = DEFAULT_ADDRESS_WIDTH
            + DEFAULT_BYTES_WIDTH
            + DEFAULT_LABEL_WIDTH
            + DEFAULT_MNEMONIC_WIDTH
            + DEFAULT_OPERAND_WIDTH
            + DEFAULT_COMMENT_WIDTH
            + COLUMN_GAP * 5.0;
        assert!((total - expected).abs() < 0.1);
    }
}
