//! Bytes/Hex view for the Ghidra GUI.
//!
//! Displays raw bytes in hex dump format with address labels,
//! hex byte columns (grouped), and ASCII representation. Supports
//! range selection, inline hex editing, keyboard navigation,
//! search with highlighting, and clipboard export.

mod render;

pub use render::render_bytes_view;

use ghidra_core::addr::Address;
use std::collections::{HashMap, HashSet};

/// Maximum number of bytes storable in the view.
const _MAX_BYTES: usize = 1_048_576; // 1 MiB

// =============================================================================
// BytesView
// =============================================================================

/// The bytes/hex view state — model for a classic hex-dump editor.
///
/// Layout:
/// ```text
/// 00001000  48 65 6C 6C 6F 20 57 6F  72 6C 64 21 00 00 00 00  |Hello World!....|
/// ```
pub struct BytesView {
    // -- data -----------------------------------------------------------------
    /// The base address of the first byte in the buffer.
    pub start_address: Address,
    /// Raw byte buffer (index `i` maps to address `start_address + i`).
    pub bytes: Vec<u8>,
    /// Snapshot of the original bytes (before edits); missing entries
    /// denote unchanged bytes.
    pub original_bytes: HashMap<u64, u8>,
    /// Whether we have loaded any data at all.
    pub has_data: bool,

    // -- display layout -------------------------------------------------------
    /// Number of bytes displayed per row.
    pub bytes_per_row: usize,
    /// Visual grouping size for hex column (2, 4, or 8). Group separators
    /// are rendered as an extra space between groups.
    pub group_size: usize,
    /// Show the address column.
    pub show_address: bool,
    /// Show the ASCII representation column.
    pub show_ascii: bool,
    /// Monospace font id used for rendering.
    pub font: egui::FontId,
    /// Column widths in points: (address, hex, ascii).  Negative or zero
    /// values mean "auto-size".
    pub column_widths: (f32, f32, f32),

    // -- selection & cursor ---------------------------------------------------
    /// The cursor position as an absolute offset (independent of start_address).
    pub cursor_offset: u64,
    /// A range selection expressed as `(start, end)` absolute offsets.
    /// When `start == end` the selection is a single byte.
    pub selection: Option<(u64, u64)>,
    /// Whether the user is currently dragging a selection.
    pub dragging: bool,

    // -- edit mode ------------------------------------------------------------
    /// When `true` the currently focused byte is being edited inline.
    pub edit_mode: bool,
    /// The text buffer for the edit (hex string).
    pub edit_buffer: String,
    /// Previous cursor offset before entering edit mode (for cancel).
    prev_cursor: u64,

    // -- search ---------------------------------------------------------------
    /// Current search pattern as a hex string (e.g. "48 65 6C" or "48656C").
    pub search_pattern: String,
    /// Offsets where the search pattern was found.
    pub search_results: Vec<u64>,
    /// Index into `search_results` for the "current" highlighted hit.
    pub search_current: usize,
    /// Whether the search bar is visible.
    pub show_search: bool,

    // -- scroll & visible rows ------------------------------------------------
    /// Scroll offset in rows from the start of data.
    pub scroll_offset: usize,
    /// Number of rows visible in the viewport (auto-computed).
    pub visible_rows: usize,
    /// The line height (set at render time).
    line_height: f32,

    // -- clipboard ------------------------------------------------------------
    /// Last copy action result (for status display).
    pub last_copy: String,

    // -- goto dialog ----------------------------------------------------------
    /// Text buffer for the Ctrl+G "go to address" dialog.
    pub goto_buffer: String,
    /// Whether the goto dialog is visible.
    pub show_goto: bool,
}

impl BytesView {
    // -- construction ---------------------------------------------------------

    /// Create a new empty bytes view.
    pub fn new() -> Self {
        Self {
            start_address: Address::new(0x1000),
            bytes: Vec::new(),
            original_bytes: HashMap::new(),
            has_data: false,
            bytes_per_row: 16,
            group_size: 2,
            show_address: true,
            show_ascii: true,
            font: egui::FontId::monospace(13.0),
            column_widths: (0.0, 0.0, 0.0), // auto
            cursor_offset: 0x1000,
            selection: None,
            dragging: false,
            edit_mode: false,
            edit_buffer: String::new(),
            prev_cursor: 0x1000,
            search_pattern: String::new(),
            search_results: Vec::new(),
            search_current: 0,
            show_search: false,
            scroll_offset: 0,
            visible_rows: 32,
            line_height: 18.0,
            last_copy: String::new(),
            goto_buffer: String::new(),
            show_goto: false,
        }
    }

    // -- data loading ---------------------------------------------------------

    /// Load bytes from a slice and set the base address.
    pub fn load_bytes(&mut self, data: &[u8], start_address: Address) {
        self.start_address = start_address;
        self.bytes = Vec::from(data);
        self.original_bytes.clear();
        self.has_data = !self.bytes.is_empty();
        self.cursor_offset = start_address.offset;
        self.selection = None;
        self.scroll_offset = 0;
    }

    /// Get the byte at an absolute offset.
    pub fn get_byte(&self, offset: u64) -> Option<u8> {
        let start = self.start_address.offset;
        if offset < start {
            return None;
        }
        let idx = (offset - start) as usize;
        self.bytes.get(idx).copied()
    }

    /// Get the byte at an address (convenience wrapper).
    pub fn get_byte_at_addr(&self, addr: &Address) -> Option<u8> {
        self.get_byte(addr.offset)
    }

    /// Returns `true` when the byte at `offset` was modified.
    pub fn is_changed(&self, offset: u64) -> bool {
        self.original_bytes.contains_key(&offset)
    }

    /// Get the total number of bytes stored.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` when there is no data.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The end offset (exclusive).
    pub fn end_offset(&self) -> u64 {
        self.start_address.offset + self.bytes.len() as u64
    }

    // -- row helpers ----------------------------------------------------------

    /// Return the bytes for one display row as `(offset, byte)` pairs.
    pub fn get_row(&self, row_index: usize) -> Vec<(u64, u8)> {
        let row_start = self.start_address.offset + (row_index * self.bytes_per_row) as u64;
        let mut out = Vec::with_capacity(self.bytes_per_row);
        for col in 0..self.bytes_per_row {
            let off = row_start + col as u64;
            if let Some(b) = self.get_byte(off) {
                out.push((off, b));
            }
        }
        out
    }

    /// Get the ASCII representation for a row.
    pub fn row_ascii(&self, row_index: usize) -> Vec<(u64, char)> {
        self.get_row(row_index)
            .into_iter()
            .map(|(off, b)| {
                let ch = if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                };
                (off, ch)
            })
            .collect()
    }

    /// Total number of rows in the current data.
    pub fn total_rows(&self) -> usize {
        if self.bytes.is_empty() {
            return 0;
        }
        (self.bytes.len() + self.bytes_per_row - 1) / self.bytes_per_row
    }

    /// Offset of the first byte in a row.
    pub fn row_start_offset(&self, row_index: usize) -> u64 {
        self.start_address.offset + (row_index * self.bytes_per_row) as u64
    }

    // -- cursor & selection ---------------------------------------------------

    /// Move the cursor to an absolute offset and clear any range selection.
    pub fn set_cursor(&mut self, offset: u64) {
        self.cursor_offset = offset;
        self.selection = Some((offset, offset));
    }

    /// Extend the current selection to `offset` (shift-click behavior).
    pub fn extend_selection_to(&mut self, offset: u64) {
        let anchor = self
            .selection
            .map(|(s, _e)| s)
            .unwrap_or(self.cursor_offset);
        let (start, end) = if offset < anchor {
            (offset, anchor)
        } else {
            (anchor, offset)
        };
        self.selection = Some((start, end));
        self.cursor_offset = offset;
    }

    /// Start a drag selection at `offset`.
    pub fn start_drag(&mut self, offset: u64) {
        self.dragging = true;
        self.set_cursor(offset);
    }

    /// Continue a drag selection to `offset`.
    pub fn continue_drag(&mut self, offset: u64) {
        if self.dragging {
            self.extend_selection_to(offset);
        }
    }

    /// End a drag selection.
    pub fn end_drag(&mut self) {
        self.dragging = false;
    }

    /// The selected offset range as `(start, end)` inclusive, or `None`.
    pub fn selected_range(&self) -> Option<(u64, u64)> {
        self.selection
    }

    /// Returns `true` when `offset` is within the current selection.
    pub fn is_selected(&self, offset: u64) -> bool {
        if let Some((s, e)) = self.selection {
            offset >= s && offset <= e
        } else {
            false
        }
    }

    /// Returns `true` when `offset` is the cursor position.
    pub fn is_cursor(&self, offset: u64) -> bool {
        self.cursor_offset == offset
    }

    /// The minimum selected offset, or the cursor position.
    pub fn anchor_offset(&self) -> u64 {
        self.selection
            .map(|(s, _e)| s)
            .unwrap_or(self.cursor_offset)
    }

    // -- edit mode ------------------------------------------------------------

    /// Enter hex-edit mode at the current cursor position.
    pub fn enter_edit_mode(&mut self) {
        if let Some(byte) = self.get_byte(self.cursor_offset) {
            self.edit_buffer = format!("{:02X}", byte);
            self.prev_cursor = self.cursor_offset;
            self.edit_mode = true;
        }
    }

    /// Commit the edit buffer, writing the parsed byte to the buffer.
    /// Returns the offset that was modified, or `None` on failure.
    pub fn commit_edit(&mut self) -> Option<u64> {
        let off = self.cursor_offset;
        let start = self.start_address.offset;
        if off < start {
            self.edit_mode = false;
            self.edit_buffer.clear();
            return None;
        }
        let idx = (off - start) as usize;
        if idx >= self.bytes.len() {
            self.edit_mode = false;
            self.edit_buffer.clear();
            return None;
        }

        if let Ok(byte) = u8::from_str_radix(&self.edit_buffer, 16) {
            // Save original before mutation
            if !self.original_bytes.contains_key(&off) {
                self.original_bytes.insert(off, self.bytes[idx]);
            }
            self.bytes[idx] = byte;
            self.edit_mode = false;
            self.edit_buffer.clear();
            return Some(off);
        }
        // Invalid hex — stay in edit mode
        None
    }

    /// Cancel edit mode, reverting any in-progress edit.
    pub fn cancel_edit(&mut self) {
        self.edit_mode = false;
        self.edit_buffer.clear();
        self.cursor_offset = self.prev_cursor;
    }

    /// Revert the byte at `offset` to its original value.
    pub fn revert_byte(&mut self, offset: u64) {
        if let Some(orig) = self.original_bytes.remove(&offset) {
            let start = self.start_address.offset;
            let idx = (offset - start) as usize;
            if idx < self.bytes.len() {
                self.bytes[idx] = orig;
            }
        }
    }

    /// Revert all changed bytes.
    pub fn revert_all(&mut self) {
        for (&off, &orig) in &self.original_bytes.clone() {
            let start = self.start_address.offset;
            let idx = (off - start) as usize;
            if idx < self.bytes.len() {
                self.bytes[idx] = orig;
            }
        }
        self.original_bytes.clear();
    }

    // -- navigation -----------------------------------------------------------

    /// Scroll up by one row.
    pub fn scroll_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(1);
    }

    /// Scroll down by one row (clamped to available rows).
    pub fn scroll_down(&mut self) {
        let max = self.total_rows().saturating_sub(self.visible_rows);
        if self.scroll_offset < max {
            self.scroll_offset += 1;
        }
    }

    /// Scroll up by one page (visible_rows rows).
    pub fn page_up(&mut self) {
        self.scroll_offset = self.scroll_offset.saturating_sub(self.visible_rows);
    }

    /// Scroll down by one page.
    pub fn page_down(&mut self) {
        let max = self.total_rows().saturating_sub(self.visible_rows);
        self.scroll_offset = (self.scroll_offset + self.visible_rows).min(max);
    }

    /// Move cursor up one row.
    pub fn cursor_up(&mut self) {
        self.cursor_offset = self.cursor_offset.saturating_sub(self.bytes_per_row as u64);
        let lo = self.start_address.offset;
        if self.cursor_offset < lo {
            self.cursor_offset = lo;
        }
        self.set_cursor(self.cursor_offset);
        self.scroll_into_view();
    }

    /// Move cursor down one row.
    pub fn cursor_down(&mut self) {
        let next = self.cursor_offset + self.bytes_per_row as u64;
        let hi = self.end_offset();
        if next < hi {
            self.cursor_offset = next;
        }
        self.set_cursor(self.cursor_offset);
        self.scroll_into_view();
    }

    /// Move cursor left one byte.
    pub fn cursor_left(&mut self) {
        let lo = self.start_address.offset;
        if self.cursor_offset > lo {
            self.cursor_offset -= 1;
        }
        self.set_cursor(self.cursor_offset);
        self.scroll_into_view();
    }

    /// Move cursor right one byte.
    pub fn cursor_right(&mut self) {
        let hi = self.end_offset();
        if self.cursor_offset + 1 < hi {
            self.cursor_offset += 1;
        }
        self.set_cursor(self.cursor_offset);
        self.scroll_into_view();
    }

    /// Ensure the cursor row is visible.
    fn scroll_into_view(&mut self) {
        let row = self.cursor_row_index();
        if row < self.scroll_offset {
            self.scroll_offset = row;
        } else if row >= self.scroll_offset + self.visible_rows {
            self.scroll_offset = row.saturating_sub(self.visible_rows.saturating_sub(1));
        }
    }

    /// The row index containing the cursor offset.
    fn cursor_row_index(&self) -> usize {
        let start = self.start_address.offset;
        if self.cursor_offset < start {
            return 0;
        }
        ((self.cursor_offset - start) / self.bytes_per_row as u64) as usize
    }

    /// Navigate to a specific address, making it the new cursor and scrolling
    /// to the row.
    pub fn goto(&mut self, addr: Address) {
        let offset = addr.offset;
        let start = self.start_address.offset;
        let end = start + self.bytes.len() as u64;
        let target = if offset < start {
            start
        } else if offset >= end {
            end.saturating_sub(1)
        } else {
            offset
        };
        self.cursor_offset = target;
        self.set_cursor(target);
        self.scroll_into_view();
    }

    /// Handle the Ctrl+G "go to address" dialog.
    pub fn submit_goto(&mut self) -> Option<Address> {
        let s = self.goto_buffer.trim();
        let addr = u64::from_str_radix(s, 16).ok()?;
        self.goto_buffer.clear();
        self.show_goto = false;
        self.goto(Address::new(addr));
        Some(Address::new(addr))
    }

    // -- search ---------------------------------------------------------------

    /// Parse a hex pattern string (spaces optional) to bytes.
    fn parse_hex_pattern(pattern: &str) -> Vec<u8> {
        let cleaned: String = pattern.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i + 1 < cleaned.len() {
            if let Ok(b) = u8::from_str_radix(&cleaned[i..i + 2], 16) {
                out.push(b);
            }
            i += 2;
        }
        out
    }

    /// Execute a search for the current pattern.
    pub fn search(&mut self) {
        self.search_results.clear();
        self.search_current = 0;

        let pattern = Self::parse_hex_pattern(&self.search_pattern);
        if pattern.is_empty() || pattern.len() > self.bytes.len() {
            return;
        }

        // Boyer-Moore-Horspool-ish naive scan
        for i in 0..=self.bytes.len() - pattern.len() {
            if self.bytes[i..i + pattern.len()] == pattern[..] {
                self.search_results
                    .push(self.start_address.offset + i as u64);
            }
        }
    }

    /// Jump to the next search result.
    pub fn search_next(&mut self) {
        if self.search_results.is_empty() {
            return;
        }
        if self.search_current + 1 < self.search_results.len() {
            self.search_current += 1;
        } else {
            // Wrap
            self.search_current = 0;
        }
        let off = self.search_results[self.search_current];
        self.cursor_offset = off;
        self.set_cursor(off);
        self.scroll_into_view();
    }

    /// Jump to the previous search result.
    pub fn search_prev(&mut self) {
        if self.search_results.is_empty() {
            return;
        }
        if self.search_current > 0 {
            self.search_current -= 1;
        } else {
            // Wrap
            self.search_current = self.search_results.len().saturating_sub(1);
        }
        let off = self.search_results[self.search_current];
        self.cursor_offset = off;
        self.set_cursor(off);
        self.scroll_into_view();
    }

    /// Offsets where a hit starts (read by the renderer for highlighting).
    pub fn search_hit_offsets(&self) -> HashSet<u64> {
        let pattern = Self::parse_hex_pattern(&self.search_pattern);
        if pattern.is_empty() || self.search_results.is_empty() {
            return HashSet::new();
        }
        // For each hit, mark all offsets in the pattern span
        let len = pattern.len() as u64;
        let mut set = HashSet::new();
        for base in &self.search_results {
            for i in 0..len {
                set.insert(base + i);
            }
        }
        set
    }

    /// The current search hit start offset — rendered with a distinct color.
    pub fn current_search_hit_offset(&self) -> Option<u64> {
        self.search_results.get(self.search_current).copied()
    }

    // -- copy -----------------------------------------------------------------

    /// Copy selected bytes as a hex string.
    pub fn copy_as_hex(&self) -> String {
        let bytes = self.selected_bytes();
        bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Copy selected bytes as a C array literal.
    pub fn copy_as_c_array(&self) -> String {
        let bytes = self.selected_bytes();
        let mut s = String::from("{ ");
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            s.push_str(&format!("0x{:02X}", b));
        }
        s.push_str(" }");
        s
    }

    /// Copy selected bytes as a Python bytes literal.
    pub fn copy_as_python_bytes(&self) -> String {
        let bytes = self.selected_bytes();
        let hex = bytes
            .iter()
            .map(|b| format!("\\x{:02X}", b))
            .collect::<Vec<_>>()
            .join("");
        format!("b\"{}\"", hex)
    }

    /// Copy the selected bytes as a Python bytearray.
    pub fn copy_as_python_bytearray(&self) -> String {
        let bytes = self.selected_bytes();
        let inner = bytes
            .iter()
            .map(|b| format!("0x{:02X}", b))
            .collect::<Vec<_>>()
            .join(", ");
        format!("bytearray([{}])", inner)
    }

    /// The bytes currently selected, or the single byte at the cursor.
    fn selected_bytes(&self) -> Vec<u8> {
        if let Some((s, e)) = self.selection {
            if s != e {
                let start = self.start_address.offset;
                let lo = if s > start { (s - start) as usize } else { 0 };
                let hi = ((e - start) as usize + 1).min(self.bytes.len());
                if lo < hi {
                    return self.bytes[lo..hi].to_vec();
                }
            }
        }
        // Fallback: cursor byte
        if let Some(b) = self.get_byte(self.cursor_offset) {
            return vec![b];
        }
        Vec::new()
    }

    // -- highlight helpers ----------------------------------------------------

    /// Returns true when `offset` is a search hit (not the current one).
    pub fn is_search_hit(&self, _offset: u64) -> bool {
        // Handled via set lookup in render — kept for API compatibility.
        false
    }

    /// Returns true when `offset` is the current highlighted search hit.
    pub fn is_current_search_hit(&self, _offset: u64) -> bool {
        // Handled via set lookup in render.
        false
    }

    // -- demo data ------------------------------------------------------------

    /// Load demo bytes for testing / UI development.
    pub fn load_demo(&mut self) {
        let base = 0x0001000u64;
        let mut data = Vec::with_capacity(256);

        for i in 0u8..=255 {
            if i < 0x40 {
                // Looks like an incrementing pattern
                data.push(i.wrapping_mul(4));
            } else if i < 0x80 {
                // Descending
                data.push((255u8.wrapping_sub(i)).wrapping_mul(2));
            } else if i < 0xC0 {
                // Mixed / pseudo-random
                data.push(i.wrapping_mul(3).wrapping_add(7));
            } else {
                // More structured: some printable ASCII
                if i >= 0xE0 {
                    data.push(b'.'); // filler
                } else {
                    data.push((i - 0xC0) + 0x20); // ' ' .. '?'
                }
            }
        }

        self.load_bytes(&data, Address::new(base));
    }
}

impl Default for BytesView {
    fn default() -> Self {
        let mut view = Self::new();
        view.load_demo();
        view
    }
}
