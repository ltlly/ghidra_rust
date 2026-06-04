//! reStructuredText table builder.
//!
//! Port of `ghidra.doclets.typestubs.RstTableBuilder`.
//!
//! Converts HTML table data into reStructuredText grid table format.

use std::fmt::Write;

/// Column alignment for RST tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    Left,
    Center,
    Right,
}

impl Alignment {
    /// Parse alignment from an HTML `align` attribute value.
    pub fn from_html(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "LEFT" => Alignment::Left,
            "CENTER" => Alignment::Center,
            "RIGHT" => Alignment::Right,
            _ => Alignment::Left,
        }
    }
}

/// Padding added to each column.
const COLUMN_PADDING: usize = 2;

/// Builder for reStructuredText grid tables.
#[derive(Debug)]
pub struct RstTableBuilder {
    columns: Vec<Cell>,
    rows: Vec<Vec<Cell>>,
    column_widths: Vec<usize>,
    caption: Option<String>,
}

/// A cell in the table (may span multiple lines).
#[derive(Debug, Clone)]
struct Cell {
    lines: Vec<String>,
    alignment: Alignment,
}

impl Cell {
    fn new(value: &str, alignment: Alignment) -> Self {
        let lines: Vec<String> = value.lines().map(|l| l.trim_start().to_string()).collect();
        Self { lines, alignment }
    }

    fn line_count(&self) -> usize {
        self.lines.len().max(1)
    }
}

impl RstTableBuilder {
    /// Create a new empty table builder.
    pub fn new() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
            column_widths: Vec::new(),
            caption: None,
        }
    }

    /// Set a caption for the table.
    pub fn set_caption(&mut self, caption: &str) {
        if !caption.is_empty() {
            self.caption = Some(caption.to_string());
        }
    }

    /// Add a column header.
    pub fn add_column(&mut self, value: &str, align: Alignment) {
        let col = self.columns.len();
        self.columns.push(Cell::new(value, align));
        self.grow_column(value, col);
    }

    /// Add a row with cells.
    pub fn add_row(&mut self, cells: Vec<(&str, Alignment)>) {
        let mut row = Vec::new();
        for (i, (value, align)) in cells.iter().enumerate() {
            let col = i;
            let cell = Cell::new(value, *align);
            self.grow_column(value, col);
            row.push(cell);
        }
        self.rows.push(row);
    }

    /// Grow the column width for the given column to accommodate the value.
    fn grow_column(&mut self, value: &str, col: usize) {
        let width = value
            .lines()
            .map(|l| l.trim_start().len())
            .max()
            .unwrap_or(0)
            + COLUMN_PADDING;
        if col >= self.column_widths.len() {
            self.column_widths.resize(col + 1, 0);
        }
        if self.column_widths[col] < width {
            self.column_widths[col] = width;
        }
    }

    /// Build the RST grid table string.
    pub fn build(&self) -> String {
        let mut output = String::new();
        output.push('\n');

        // Caption
        if let Some(ref caption) = self.caption {
            let len = caption.len();
            let _ = writeln!(output, "{}", "^".repeat(len));
            let _ = writeln!(output, "{caption}");
            let _ = writeln!(output, "{}", "^".repeat(len));
        }

        // Column header row
        self.build_row_border(&mut output, '-');
        self.build_row(&mut output, &self.columns);
        self.build_row_border(&mut output, '=');

        // Data rows
        for row in &self.rows {
            self.build_row(&mut output, row);
            self.build_row_border(&mut output, '-');
        }

        output
    }

    /// Build a row border.
    fn build_row_border(&self, output: &mut String, c: char) {
        output.push('+');
        for &width in &self.column_widths {
            for _ in 0..width {
                output.push(c);
            }
            output.push('+');
        }
        output.push('\n');
    }

    /// Build a row of cells.
    fn build_row(&self, output: &mut String, cells: &[Cell]) {
        let max_lines = cells.iter().map(|c| c.line_count()).max().unwrap_or(1);

        for line_idx in 0..max_lines {
            output.push('|');
            for (col_idx, cell) in cells.iter().enumerate() {
                let col_width = self.column_widths.get(col_idx).copied().unwrap_or(0);
                if line_idx < cell.lines.len() {
                    let line = &cell.lines[line_idx];
                    let aligned = align_line(line, col_width, cell.alignment);
                    let _ = write!(output, "{aligned}");
                } else {
                    let _ = write!(output, "{}", " ".repeat(col_width));
                }
                output.push('|');
            }
            output.push('\n');
        }
    }
}

impl Default for RstTableBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Align a single line within the given column width.
fn align_line(value: &str, col_width: usize, align: Alignment) -> String {
    let len = value.len();
    match align {
        Alignment::Left => {
            format!("{value}{}", " ".repeat(col_width - len))
        }
        Alignment::Center => {
            let total_pad = col_width - len;
            let left = total_pad / 2;
            let right = total_pad - left;
            format!("{}{value}{}", " ".repeat(left), " ".repeat(right))
        }
        Alignment::Right => {
            format!("{}{value}", " ".repeat(col_width - len))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_table() {
        let mut builder = RstTableBuilder::new();
        builder.add_column("Name", Alignment::Center);
        builder.add_column("Value", Alignment::Center);
        builder.add_row(vec![
            ("foo", Alignment::Left),
            ("42", Alignment::Right),
        ]);

        let result = builder.build();
        assert!(result.contains("Name"));
        assert!(result.contains("Value"));
        assert!(result.contains("foo"));
        assert!(result.contains("42"));
        assert!(result.contains('+'));
        assert!(result.contains('|'));
        assert!(result.contains("==="));
        assert!(result.contains("---"));
    }

    #[test]
    fn test_table_with_caption() {
        let mut builder = RstTableBuilder::new();
        builder.set_caption("My Table");
        builder.add_column("A", Alignment::Left);
        builder.add_row(vec![("1", Alignment::Left)]);

        let result = builder.build();
        assert!(result.contains("My Table"));
        assert!(result.contains("^^^^^^^^"));
    }

    #[test]
    fn test_multi_line_cell() {
        let mut builder = RstTableBuilder::new();
        builder.add_column("Col", Alignment::Left);
        builder.add_row(vec![("line1\nline2", Alignment::Left)]);

        let result = builder.build();
        assert!(result.contains("line1"));
        assert!(result.contains("line2"));
    }

    #[test]
    fn test_alignment() {
        assert_eq!(
            align_line("x", 5, Alignment::Left),
            "x    "
        );
        assert_eq!(
            align_line("x", 5, Alignment::Center),
            "  x  "
        );
        assert_eq!(
            align_line("x", 5, Alignment::Right),
            "    x"
        );
    }

    #[test]
    fn test_alignment_from_html() {
        assert_eq!(Alignment::from_html("left"), Alignment::Left);
        assert_eq!(Alignment::from_html("CENTER"), Alignment::Center);
        assert_eq!(Alignment::from_html("Right"), Alignment::Right);
        assert_eq!(Alignment::from_html("unknown"), Alignment::Left);
    }

    #[test]
    fn test_empty_table() {
        let builder = RstTableBuilder::new();
        let result = builder.build();
        assert!(result.starts_with('\n'));
    }
}
