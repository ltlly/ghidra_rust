//! A single line of cells in the VT100 terminal display.
//!
//! Ported from `ghidra.app.plugin.core.terminal.vt.VtLine`.

use super::attributes::{AnsiColor, VtAttributes};

/// A character cell in a terminal line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtCell {
    /// The character displayed in this cell.
    pub ch: char,
    /// The attributes applied to this cell.
    pub attrs: VtAttributes,
}

impl VtCell {
    /// Create a blank cell with default attributes.
    pub fn blank(attrs: &VtAttributes) -> Self {
        Self {
            ch: ' ',
            attrs: attrs.clone(),
        }
    }
}

/// A single line in the terminal buffer.
///
/// Ported from `ghidra.app.plugin.core.terminal.vt.VtLine`.
/// Each line has a fixed column width and tracks whether it has been
/// wrapped (soft-wrapped from a long output).
#[derive(Debug, Clone)]
pub struct VtLine {
    /// The cells in this line.
    cells: Vec<VtCell>,
    /// Whether this line is soft-wrapped (continued from the previous line).
    pub wrapped: bool,
}

impl VtLine {
    /// Create a new blank line with the given column count.
    pub fn new(cols: usize) -> Self {
        let default_attrs = VtAttributes::DEFAULTS;
        Self {
            cells: (0..cols).map(|_| VtCell::blank(&default_attrs)).collect(),
            wrapped: false,
        }
    }

    /// Reset this line to blanks with the given column count.
    pub fn reset(&mut self, cols: usize) {
        let default_attrs = VtAttributes::DEFAULTS;
        self.cells = (0..cols).map(|_| VtCell::blank(&default_attrs)).collect();
        self.wrapped = false;
    }

    /// Get the number of columns.
    pub fn cols(&self) -> usize {
        self.cells.len()
    }

    /// Get a reference to the cell at column `col`.
    pub fn cell(&self, col: usize) -> Option<&VtCell> {
        self.cells.get(col)
    }

    /// Get a mutable reference to the cell at column `col`.
    pub fn cell_mut(&mut self, col: usize) -> Option<&mut VtCell> {
        self.cells.get_mut(col)
    }

    /// Put a character at column `col` with the given attributes.
    pub fn put_char(&mut self, col: usize, ch: char, attrs: &VtAttributes) {
        if let Some(cell) = self.cells.get_mut(col) {
            cell.ch = ch;
            cell.attrs = attrs.clone();
        }
    }

    /// Erase cells from `start_col` (inclusive) to `end_col` (exclusive),
    /// replacing them with blanks using the given attributes.
    pub fn erase(&mut self, start_col: usize, end_col: usize, attrs: &VtAttributes) {
        let end = end_col.min(self.cells.len());
        for cell in self.cells[start_col..end].iter_mut() {
            cell.ch = ' ';
            cell.attrs = attrs.clone();
        }
    }

    /// Insert `n` blank cells at column `col`, shifting existing cells right.
    /// Cells that fall off the right edge are discarded.
    pub fn insert(&mut self, col: usize, n: usize) {
        let attrs = VtAttributes::DEFAULTS;
        for _ in 0..n {
            if col < self.cells.len() {
                self.cells.pop();
                self.cells.insert(col, VtCell::blank(&attrs));
            }
        }
    }

    /// Delete `n` cells starting at column `col`, shifting remaining cells left.
    /// Blank cells are appended at the right end.
    pub fn delete(&mut self, col: usize, n: usize) {
        let attrs = VtAttributes::DEFAULTS;
        for _ in 0..n {
            if col < self.cells.len() {
                self.cells.remove(col);
                self.cells.push(VtCell::blank(&attrs));
            }
        }
    }

    /// Resize the line to the given column count.
    pub fn resize(&mut self, new_cols: usize) {
        let attrs = VtAttributes::DEFAULTS;
        if new_cols > self.cells.len() {
            while self.cells.len() < new_cols {
                self.cells.push(VtCell::blank(&attrs));
            }
        } else {
            self.cells.truncate(new_cols);
        }
    }

    /// Extract the text content of this line as a string.
    pub fn text(&self) -> String {
        self.cells.iter().map(|c| c.ch).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_line_new() {
        let line = VtLine::new(80);
        assert_eq!(line.cols(), 80);
        assert!(!line.wrapped);
        assert_eq!(line.cell(0).unwrap().ch, ' ');
    }

    #[test]
    fn test_put_char() {
        let mut line = VtLine::new(10);
        let attrs = VtAttributes::DEFAULTS;
        line.put_char(3, 'X', &attrs);
        assert_eq!(line.cell(3).unwrap().ch, 'X');
    }

    #[test]
    fn test_erase() {
        let mut line = VtLine::new(10);
        let attrs = VtAttributes::DEFAULTS;
        line.put_char(2, 'A', &attrs);
        line.put_char(3, 'B', &attrs);
        line.erase(2, 4, &attrs);
        assert_eq!(line.cell(2).unwrap().ch, ' ');
        assert_eq!(line.cell(3).unwrap().ch, ' ');
    }

    #[test]
    fn test_insert() {
        let mut line = VtLine::new(5);
        let attrs = VtAttributes::DEFAULTS;
        line.put_char(0, 'A', &attrs);
        line.put_char(1, 'B', &attrs);
        line.insert(1, 1);
        assert_eq!(line.cell(0).unwrap().ch, 'A');
        assert_eq!(line.cell(1).unwrap().ch, ' ');
        assert_eq!(line.cell(2).unwrap().ch, 'B');
    }

    #[test]
    fn test_delete() {
        let mut line = VtLine::new(5);
        let attrs = VtAttributes::DEFAULTS;
        line.put_char(0, 'A', &attrs);
        line.put_char(1, 'B', &attrs);
        line.put_char(2, 'C', &attrs);
        line.delete(1, 1);
        assert_eq!(line.cell(0).unwrap().ch, 'A');
        assert_eq!(line.cell(1).unwrap().ch, 'C');
        assert_eq!(line.cell(4).unwrap().ch, ' ');
    }

    #[test]
    fn test_resize() {
        let mut line = VtLine::new(5);
        line.resize(3);
        assert_eq!(line.cols(), 3);
        line.resize(8);
        assert_eq!(line.cols(), 8);
    }

    #[test]
    fn test_text() {
        let mut line = VtLine::new(5);
        let attrs = VtAttributes::DEFAULTS;
        line.put_char(0, 'H', &attrs);
        line.put_char(1, 'i', &attrs);
        assert_eq!(line.text(), "Hi   ");
    }

    #[test]
    fn test_reset() {
        let mut line = VtLine::new(5);
        let attrs = VtAttributes::DEFAULTS;
        line.put_char(0, 'X', &attrs);
        line.wrapped = true;
        line.reset(10);
        assert_eq!(line.cols(), 10);
        assert!(!line.wrapped);
        assert_eq!(line.cell(0).unwrap().ch, ' ');
    }
}
