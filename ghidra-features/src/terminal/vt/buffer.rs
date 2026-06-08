//! VT100 terminal display buffer with scrollback.
//!
//! Ported from `ghidra.app.plugin.core.terminal.vt.VtBuffer`.
//!
//! Implements all buffer, line, and character manipulations available in the
//! terminal. While the VT parser determines what commands to execute, this
//! buffer provides the actual implementation of those commands.

use std::collections::VecDeque;

use super::attributes::VtAttributes;
use super::line::VtLine;

/// Default number of rows in the terminal.
pub const DEFAULT_ROWS: usize = 25;
/// Default number of columns in the terminal.
pub const DEFAULT_COLS: usize = 80;
/// Tab stop width.
const TAB_WIDTH: usize = 8;

/// The type of erasure to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erasure {
    /// Erase from cursor to end of display/line.
    ToEnd,
    /// Erase from start of display/line to cursor.
    ToStart,
    /// Erase entire display/line.
    All,
    /// Erase entire display including scrollback.
    AllPlusScrollback,
}

/// A buffer for a terminal display and scroll-back.
///
/// Manages the screen grid, cursor position, scrollback history,
/// scroll viewport, and all character/line manipulation operations.
#[derive(Debug)]
pub struct VtBuffer {
    rows: usize,
    cols: usize,
    cur_x: usize,
    cur_y: usize,
    saved_x: usize,
    saved_y: usize,
    bottom_y: usize,
    origin_mode: bool,
    auto_wrap: bool,
    scroll_start: usize,
    scroll_end: usize, // exclusive
    max_scroll_back: usize,
    cur_attrs: VtAttributes,
    scroll_back: VecDeque<VtLine>,
    lines: Vec<VtLine>,
}

impl VtBuffer {
    /// Create a new buffer with default dimensions (25 rows x 80 cols).
    pub fn new() -> Self {
        Self::with_size(DEFAULT_ROWS, DEFAULT_COLS)
    }

    /// Create a new buffer with the given dimensions.
    pub fn with_size(rows: usize, cols: usize) -> Self {
        let rows = rows.max(1);
        let cols = cols.max(1);
        let lines = (0..rows).map(|_| VtLine::new(cols)).collect();
        Self {
            rows,
            cols,
            cur_x: 0,
            cur_y: 0,
            saved_x: 0,
            saved_y: 0,
            bottom_y: 0,
            origin_mode: false,
            auto_wrap: true,
            scroll_start: 0,
            scroll_end: rows,
            max_scroll_back: 10_000,
            cur_attrs: VtAttributes::DEFAULTS,
            scroll_back: VecDeque::new(),
            lines,
        }
    }

    /// Clear the buffer and all state, as if just created.
    pub fn reset(&mut self) {
        self.lines = (0..self.rows).map(|_| VtLine::new(self.cols)).collect();
        self.cur_x = 0;
        self.cur_y = 0;
        self.scroll_back.clear();
    }

    /// Get the number of rows.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Get the number of columns.
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// Get the cursor X position.
    pub fn cursor_x(&self) -> usize {
        self.cur_x
    }

    /// Get the cursor Y position.
    pub fn cursor_y(&self) -> usize {
        self.cur_y
    }

    /// Get the current attributes.
    pub fn attributes(&self) -> &VtAttributes {
        &self.cur_attrs
    }

    /// Set the current attributes.
    pub fn set_attributes(&mut self, attrs: VtAttributes) {
        self.cur_attrs = attrs;
    }

    /// Get the scrollback buffer.
    pub fn scroll_back(&self) -> &VecDeque<VtLine> {
        &self.scroll_back
    }

    /// Get a reference to the display lines.
    pub fn lines(&self) -> &[VtLine] {
        &self.lines
    }

    /// Get a mutable reference to the display lines.
    pub fn lines_mut(&mut self) -> &mut Vec<VtLine> {
        &mut self.lines
    }

    /// Get a specific line.
    pub fn line(&self, row: usize) -> Option<&VtLine> {
        self.lines.get(row)
    }

    /// Get the auto-wrap mode.
    pub fn auto_wrap(&self) -> bool {
        self.auto_wrap
    }

    /// Set the auto-wrap mode.
    pub fn set_auto_wrap(&mut self, wrap: bool) {
        self.auto_wrap = wrap;
    }

    /// Get the origin mode.
    pub fn origin_mode(&self) -> bool {
        self.origin_mode
    }

    /// Set the origin mode.
    pub fn set_origin_mode(&mut self, origin: bool) {
        self.origin_mode = origin;
    }

    /// Save the current cursor position.
    pub fn save_cursor(&mut self) {
        self.saved_x = self.cur_x;
        self.saved_y = self.cur_y;
    }

    /// Restore the previously saved cursor position.
    pub fn restore_cursor(&mut self) {
        self.cur_x = self.saved_x.min(self.cols.saturating_sub(1));
        self.cur_y = self.saved_y.min(self.rows.saturating_sub(1));
    }

    /// Put a character at the cursor and advance the cursor.
    pub fn put_char(&mut self, ch: char) {
        if ch == '\0' {
            return;
        }
        // Scroll if cursor is completely off-screen.
        while self.cur_y >= self.rows {
            self.scroll_viewport_down(true);
        }
        if self.cur_y < self.lines.len() && self.cur_x < self.cols {
            let attrs = self.cur_attrs.clone();
            self.lines[self.cur_y].put_char(self.cur_x, ch, &attrs);
        }
        self.cur_x += 1;
        if self.cur_x >= self.cols && self.auto_wrap {
            self.cur_x = 0;
            self.lines[self.cur_y].wrapped = true;
            self.cur_y += 1;
        }
    }

    /// Handle a line-feed / newline.
    pub fn line_feed(&mut self) {
        self.cur_y += 1;
        self.check_vertical_scroll();
    }

    /// Handle a carriage return.
    pub fn carriage_return(&mut self) {
        self.cur_x = 0;
    }

    /// Handle a backspace.
    pub fn backspace(&mut self) {
        if self.cur_x > 0 {
            self.cur_x -= 1;
        }
    }

    /// Handle a tab.
    pub fn tab(&mut self) {
        self.cur_x = ((self.cur_x / TAB_WIDTH) + 1) * TAB_WIDTH;
        if self.cur_x >= self.cols {
            self.cur_x = self.cols - 1;
        }
    }

    /// Move the cursor up `n` rows (cannot go above scroll region top).
    pub fn move_cursor_up(&mut self, n: usize) {
        let limit = self.scroll_start;
        self.cur_y = self.cur_y.saturating_sub(n).max(limit);
    }

    /// Move the cursor down `n` rows.
    pub fn move_cursor_down(&mut self, n: usize) {
        let limit = self.scroll_end.saturating_sub(1);
        self.cur_y = (self.cur_y + n).min(limit);
        self.check_vertical_scroll();
    }

    /// Move the cursor forward (right) `n` columns.
    pub fn move_cursor_forward(&mut self, n: usize) {
        self.cur_x = (self.cur_x + n).min(self.cols.saturating_sub(1));
    }

    /// Move the cursor backward (left) `n` columns.
    pub fn move_cursor_backward(&mut self, n: usize) {
        self.cur_x = self.cur_x.saturating_sub(n);
    }

    /// Set the cursor position (1-based row, col).
    pub fn set_cursor_position(&mut self, row: u16, col: u16) {
        self.cur_x = ((col as usize).saturating_sub(1)).min(self.cols.saturating_sub(1));
        self.cur_y = ((row as usize).saturating_sub(1)).min(self.rows.saturating_sub(1));
        self.bottom_y = self.bottom_y.max(self.cur_y);
    }

    /// Set an absolute cursor position (0-based).
    pub fn set_cursor_abs(&mut self, x: usize, y: usize) {
        self.cur_x = x.min(self.cols.saturating_sub(1));
        self.cur_y = y.min(self.rows.saturating_sub(1));
        self.bottom_y = self.bottom_y.max(self.cur_y);
    }

    /// Scroll the viewport down by one line.
    ///
    /// If `into_scroll_back` is true and the scroll region starts at the top,
    /// the removed line is pushed into the scrollback buffer.
    pub fn scroll_viewport_down(&mut self, into_scroll_back: bool) {
        if self.scroll_start >= self.scroll_end {
            return;
        }
        let removed = self.lines.remove(self.scroll_start);

        if into_scroll_back && self.scroll_start == 0 && self.max_scroll_back > 0 {
            // Evict oldest scrollback line if at capacity.
            if self.scroll_back.len() >= self.max_scroll_back {
                self.scroll_back.pop_front();
            }
            self.scroll_back.push_back(removed);
        }
        // Insert a blank line at the bottom of the scroll region.
        self.lines.insert(self.scroll_end - 1, VtLine::new(self.cols));
    }

    /// Scroll the viewport up by one line.
    pub fn scroll_viewport_up(&mut self) {
        if self.scroll_start >= self.scroll_end {
            return;
        }
        let mut temp = self.lines.remove(self.scroll_end - 1);
        temp.reset(self.cols);
        self.lines.insert(self.scroll_start, temp);
    }

    /// If the cursor is beyond the scroll region bottom, scroll down.
    fn check_vertical_scroll(&mut self) {
        while self.cur_y >= self.scroll_end {
            self.scroll_viewport_down(true);
            self.cur_y = self.cur_y.saturating_sub(1);
        }
    }

    /// Insert `n` blank lines at the cursor.
    pub fn insert_lines(&mut self, n: usize) {
        for _ in 0..n {
            if self.scroll_end > 0 && self.scroll_end - 1 < self.lines.len() {
                let mut temp = self.lines.remove(self.scroll_end - 1);
                temp.reset(self.cols);
                let insert_at = self.cur_y.min(self.lines.len());
                self.lines.insert(insert_at, temp);
            }
        }
    }

    /// Delete `n` lines at the cursor.
    pub fn delete_lines(&mut self, n: usize) {
        for _ in 0..n {
            if self.cur_y < self.lines.len() {
                self.lines.remove(self.cur_y);
                let insert_at = (self.scroll_end - 1).min(self.lines.len());
                let mut blank = VtLine::new(self.cols);
                blank.reset(self.cols);
                self.lines.insert(insert_at, blank);
            }
        }
    }

    /// Insert `n` blank characters at the cursor.
    pub fn insert_chars(&mut self, n: usize) {
        if self.cur_y < self.lines.len() {
            self.lines[self.cur_y].insert(self.cur_x, n);
        }
    }

    /// Delete `n` characters at the cursor.
    pub fn delete_chars(&mut self, n: usize) {
        if self.cur_y < self.lines.len() {
            self.lines[self.cur_y].delete(self.cur_x, n);
        }
    }

    /// Erase `n` characters at the cursor.
    pub fn erase_chars(&mut self, n: usize) {
        if self.cur_y < self.lines.len() {
            let attrs = self.cur_attrs.clone();
            self.lines[self.cur_y].erase(self.cur_x, self.cur_x + n, &attrs);
        }
    }

    /// Set the scroll region (0-based start, exclusive end).
    pub fn set_scroll_region(&mut self, start: Option<u16>, end: Option<u16>) {
        self.scroll_start = start.map(|s| s as usize).unwrap_or(0).min(self.rows);
        self.scroll_end = end.map(|e| e as usize + 1).unwrap_or(self.rows).min(self.rows);
        if self.scroll_end <= self.scroll_start {
            self.scroll_end = self.scroll_start + 1;
        }
        self.cur_x = 0;
        self.cur_y = 0;
    }

    /// Erase a portion of the display.
    pub fn erase_display(&mut self, erasure: Erasure) {
        match erasure {
            Erasure::ToEnd => {
                let attrs = self.cur_attrs.clone();
                if self.cur_y < self.lines.len() {
                    self.lines[self.cur_y].erase(self.cur_x, self.cols, &attrs);
                }
                for row in (self.cur_y + 1)..self.rows {
                    if row < self.lines.len() {
                        self.lines[row].reset(self.cols);
                    }
                }
            }
            Erasure::ToStart => {
                let attrs = self.cur_attrs.clone();
                for row in 0..self.cur_y {
                    if row < self.lines.len() {
                        self.lines[row].reset(self.cols);
                    }
                }
                if self.cur_y < self.lines.len() {
                    self.lines[self.cur_y].erase(0, self.cur_x + 1, &attrs);
                }
            }
            Erasure::All => {
                for line in self.lines.iter_mut() {
                    line.reset(self.cols);
                }
                self.cur_x = 0;
                self.cur_y = 0;
            }
            Erasure::AllPlusScrollback => {
                for line in self.lines.iter_mut() {
                    line.reset(self.cols);
                }
                self.scroll_back.clear();
                self.cur_x = 0;
                self.cur_y = 0;
            }
        }
    }

    /// Erase a portion of the current line.
    pub fn erase_line(&mut self, erasure: Erasure) {
        if self.cur_y >= self.lines.len() {
            return;
        }
        let attrs = self.cur_attrs.clone();
        match erasure {
            Erasure::ToEnd => {
                self.lines[self.cur_y].erase(self.cur_x, self.cols, &attrs);
            }
            Erasure::ToStart => {
                self.lines[self.cur_y].erase(0, self.cur_x + 1, &attrs);
            }
            Erasure::All | Erasure::AllPlusScrollback => {
                self.lines[self.cur_y].reset(self.cols);
            }
        }
    }

    /// Resize the buffer to new dimensions.
    pub fn resize(&mut self, new_rows: usize, new_cols: usize) {
        let new_rows = new_rows.max(1);
        let new_cols = new_cols.max(1);
        // Resize existing lines.
        for line in self.lines.iter_mut() {
            line.resize(new_cols);
        }
        // Add/remove rows.
        while self.lines.len() < new_rows {
            self.lines.push(VtLine::new(new_cols));
        }
        self.lines.truncate(new_rows);
        self.rows = new_rows;
        self.cols = new_cols;
        self.scroll_end = new_rows;
        self.cur_x = self.cur_x.min(new_cols.saturating_sub(1));
        self.cur_y = self.cur_y.min(new_rows.saturating_sub(1));
    }

    /// Index (scroll up) -- move cursor down, scrolling if needed.
    pub fn index(&mut self) {
        self.cur_y += 1;
        if self.cur_y >= self.scroll_end {
            self.cur_y = self.scroll_end.saturating_sub(1);
            self.scroll_viewport_down(true);
        }
    }

    /// Reverse index (scroll down) -- move cursor up, scrolling if needed.
    pub fn reverse_index(&mut self) {
        if self.cur_y <= self.scroll_start {
            self.scroll_viewport_up();
        } else {
            self.cur_y = self.cur_y.saturating_sub(1);
        }
    }

    /// Get the number of lines in the scrollback buffer.
    pub fn scroll_back_len(&self) -> usize {
        self.scroll_back.len()
    }
}

impl Default for VtBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_new() {
        let buf = VtBuffer::new();
        assert_eq!(buf.rows(), DEFAULT_ROWS);
        assert_eq!(buf.cols(), DEFAULT_COLS);
        assert_eq!(buf.cursor_x(), 0);
        assert_eq!(buf.cursor_y(), 0);
    }

    #[test]
    fn test_put_char() {
        let mut buf = VtBuffer::with_size(5, 10);
        buf.put_char('A');
        assert_eq!(buf.line(0).unwrap().cell(0).unwrap().ch, 'A');
        assert_eq!(buf.cursor_x(), 1);
    }

    #[test]
    fn test_auto_wrap() {
        let mut buf = VtBuffer::with_size(5, 3);
        buf.put_char('A');
        buf.put_char('B');
        buf.put_char('C');
        // Cursor should have wrapped to next line.
        assert_eq!(buf.cursor_y(), 1);
        assert_eq!(buf.cursor_x(), 0);
    }

    #[test]
    fn test_line_feed() {
        let mut buf = VtBuffer::with_size(5, 10);
        buf.line_feed();
        assert_eq!(buf.cursor_y(), 1);
    }

    #[test]
    fn test_carriage_return() {
        let mut buf = VtBuffer::with_size(5, 10);
        buf.cur_x = 5;
        buf.carriage_return();
        assert_eq!(buf.cursor_x(), 0);
    }

    #[test]
    fn test_cursor_movement() {
        let mut buf = VtBuffer::with_size(10, 20);
        buf.move_cursor_down(3);
        assert_eq!(buf.cursor_y(), 3);
        buf.move_cursor_forward(5);
        assert_eq!(buf.cursor_x(), 5);
        buf.move_cursor_up(2);
        assert_eq!(buf.cursor_y(), 1);
        buf.move_cursor_backward(3);
        assert_eq!(buf.cursor_x(), 2);
    }

    #[test]
    fn test_set_cursor_position() {
        let mut buf = VtBuffer::with_size(10, 20);
        buf.set_cursor_position(5, 10);
        assert_eq!(buf.cursor_x(), 9); // 1-based to 0-based
        assert_eq!(buf.cursor_y(), 4);
    }

    #[test]
    fn test_erase_display_all() {
        let mut buf = VtBuffer::with_size(5, 10);
        buf.put_char('X');
        buf.erase_display(Erasure::All);
        assert_eq!(buf.line(0).unwrap().cell(0).unwrap().ch, ' ');
        assert_eq!(buf.cursor_x(), 0);
        assert_eq!(buf.cursor_y(), 0);
    }

    #[test]
    fn test_erase_display_to_end() {
        let mut buf = VtBuffer::with_size(3, 5);
        for c in "HelloWorldMore".chars() {
            buf.put_char(c);
        }
        // Lines: "Hello", "World", "More "
        buf.set_cursor_position(1, 1); // row 1, col 1 (0-based: row 0, col 0)
        buf.erase_display(Erasure::ToEnd);
        // All lines cleared from row 0 onwards.
        assert_eq!(buf.line(0).unwrap().text(), "     ");
        assert_eq!(buf.line(1).unwrap().text(), "     ");
        assert_eq!(buf.line(2).unwrap().text(), "     ");
    }

    #[test]
    fn test_erase_line() {
        let mut buf = VtBuffer::with_size(5, 10);
        for c in "Hello".chars() {
            buf.put_char(c);
        }
        // After "Hello", cursor is at col 5 (wrapped from 4 to 5 triggers wrap to next line,
        // cursor ends at col 0, row 1). Move to row 0, col 0.
        buf.set_cursor_position(1, 1); // row 0, col 0
        buf.erase_line(Erasure::ToEnd);
        // Entire line erased.
        assert_eq!(buf.line(0).unwrap().text(), "          ");
    }

    #[test]
    fn test_insert_delete_lines() {
        let mut buf = VtBuffer::with_size(5, 10);
        for row in 0..5 {
            buf.set_cursor_position(row + 1, 1);
            for c in format!("L{}", row).chars() {
                buf.put_char(c);
            }
        }
        // Lines: ["L0...", "L1...", "L2...", "L3...", "L4..."]
        buf.set_cursor_position(2, 1); // cursor at row 1
        buf.insert_lines(1);
        // A blank line inserted at row 1 pushes L1, L2, L3 down; L4 is recycled.
        // Lines: ["L0...", blank, "L1...", "L2...", "L3..."]
        assert_eq!(buf.line(1).unwrap().text(), "          "); // blank
        assert_eq!(buf.line(2).unwrap().text(), "L1        "); // L1 + 8 spaces = 10 cols
    }

    #[test]
    fn test_insert_delete_chars() {
        let mut buf = VtBuffer::with_size(5, 10);
        for c in "ABCDE".chars() {
            buf.put_char(c);
        }
        buf.set_cursor_position(1, 3);
        buf.insert_chars(2);
        assert_eq!(buf.line(0).unwrap().cell(0).unwrap().ch, 'A');
        assert_eq!(buf.line(0).unwrap().cell(1).unwrap().ch, 'B');
        assert_eq!(buf.line(0).unwrap().cell(2).unwrap().ch, ' ');
        assert_eq!(buf.line(0).unwrap().cell(4).unwrap().ch, 'C');
    }

    #[test]
    fn test_resize() {
        let mut buf = VtBuffer::with_size(5, 10);
        buf.resize(8, 20);
        assert_eq!(buf.rows(), 8);
        assert_eq!(buf.cols(), 20);
    }

    #[test]
    fn test_save_restore_cursor() {
        let mut buf = VtBuffer::with_size(10, 20);
        buf.set_cursor_position(3, 7);
        buf.save_cursor();
        buf.set_cursor_position(1, 1);
        buf.restore_cursor();
        assert_eq!(buf.cursor_x(), 6);
        assert_eq!(buf.cursor_y(), 2);
    }

    #[test]
    fn test_scroll_region() {
        let mut buf = VtBuffer::with_size(5, 10);
        buf.set_scroll_region(Some(1), Some(3));
        assert_eq!(buf.scroll_start, 1);
        assert_eq!(buf.scroll_end, 4); // end is exclusive (3+1)
    }

    #[test]
    fn test_tab() {
        let mut buf = VtBuffer::with_size(5, 40);
        buf.tab();
        assert_eq!(buf.cursor_x(), 8);
        buf.tab();
        assert_eq!(buf.cursor_x(), 16);
    }

    #[test]
    fn test_backspace() {
        let mut buf = VtBuffer::with_size(5, 10);
        buf.cur_x = 5;
        buf.backspace();
        assert_eq!(buf.cursor_x(), 4);
        buf.backspace();
        assert_eq!(buf.cursor_x(), 3);
    }

    #[test]
    fn test_index_reverse_index() {
        let mut buf = VtBuffer::with_size(5, 10);
        // Scroll region rows 0..=2 (exclusive end = 3).
        buf.set_scroll_region(Some(0), Some(2));
        buf.cur_y = 2;
        buf.index(); // cur_y becomes 3, which >= scroll_end (3), so scroll + clamp
        assert_eq!(buf.cursor_y(), 2);
        buf.reverse_index(); // cur_y is at scroll_start, so scroll down
        assert_eq!(buf.cursor_y(), 1);
    }
}
