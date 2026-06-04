//! Printing Plugin -- print listing contents.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.printing` Java package.
//!
//! Provides model-level logic for preparing listing content for printing.

use ghidra_core::Address;

/// The page orientation for printing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageOrientation {
    /// Portrait orientation.
    Portrait,
    /// Landscape orientation.
    Landscape,
}

/// Print settings.
#[derive(Debug, Clone)]
pub struct PrintSettings {
    /// The page orientation.
    pub orientation: PageOrientation,
    /// Whether to print headers.
    pub print_header: bool,
    /// Whether to print line numbers.
    pub print_line_numbers: bool,
    /// The header text.
    pub header_text: String,
    /// Start address.
    pub start_address: Option<Address>,
    /// End address.
    pub end_address: Option<Address>,
    /// Font size in points.
    pub font_size: f64,
}

impl PrintSettings {
    /// Create default print settings.
    pub fn new() -> Self {
        Self {
            orientation: PageOrientation::Portrait,
            print_header: true,
            print_line_numbers: true,
            header_text: String::new(),
            start_address: None,
            end_address: None,
            font_size: 10.0,
        }
    }
}

impl Default for PrintSettings {
    fn default() -> Self {
        Self::new()
    }
}

/// A formatted print line.
#[derive(Debug, Clone)]
pub struct PrintLine {
    /// The address this line corresponds to.
    pub address: Address,
    /// The formatted text of this line.
    pub text: String,
    /// The line number.
    pub line_number: u32,
}

/// Model for preparing content for printing.
#[derive(Debug, Default)]
pub struct PrintModel {
    settings: PrintSettings,
    lines: Vec<PrintLine>,
}

impl PrintModel {
    /// Create a new print model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or set the print settings.
    pub fn settings(&self) -> &PrintSettings {
        &self.settings
    }

    /// Get mutable access to print settings.
    pub fn settings_mut(&mut self) -> &mut PrintSettings {
        &mut self.settings
    }

    /// Add a print line.
    pub fn add_line(&mut self, line: PrintLine) {
        self.lines.push(line);
    }

    /// Get all print lines.
    pub fn get_lines(&self) -> &[PrintLine] {
        &self.lines
    }

    /// The number of lines.
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_settings() {
        let settings = PrintSettings::default();
        assert_eq!(settings.orientation, PageOrientation::Portrait);
        assert!(settings.print_header);
    }

    #[test]
    fn test_print_model() {
        let mut model = PrintModel::new();
        model.add_line(PrintLine {
            address: Address::new(0x1000),
            text: "mov rax, rbx".into(),
            line_number: 1,
        });
        assert_eq!(model.line_count(), 1);
    }
}
