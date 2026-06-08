//! Printing plugin and printable (listing rendering for print).
//!
//! Ported from `ghidra.app.plugin.core.printing.PrintingPlugin`,
//! `CodeUnitPrintable`, and `PrintOptionsDialog`.

use super::PrintSettings;
use ghidra_core::Address;

// ---------------------------------------------------------------------------
// CodeUnitPrintable -- renders code units for printing
// ---------------------------------------------------------------------------

/// Renders code units for printing.
///
/// Ported from `ghidra.app.plugin.core.printing.CodeUnitPrintable`.
#[derive(Debug)]
pub struct CodeUnitPrintable {
    /// The start address.
    start_address: Address,
    /// The end address.
    end_address: Address,
    /// The page number.
    current_page: usize,
    /// Total pages to print.
    total_pages: usize,
    /// The lines per page.
    lines_per_page: usize,
    /// Whether there are more pages.
    has_more: bool,
    /// The rendered lines for the current page.
    rendered_lines: Vec<String>,
}

impl CodeUnitPrintable {
    /// Create a new code unit printable.
    pub fn new(start: Address, end: Address) -> Self {
        Self {
            start_address: start,
            end_address: end,
            current_page: 0,
            total_pages: 0,
            lines_per_page: 60,
            has_more: true,
            rendered_lines: Vec::new(),
        }
    }

    /// Set the lines per page.
    pub fn set_lines_per_page(&mut self, lines: usize) {
        self.lines_per_page = lines;
    }

    /// Get the lines per page.
    pub fn lines_per_page(&self) -> usize {
        self.lines_per_page
    }

    /// Get the start address.
    pub fn start_address(&self) -> Address {
        self.start_address
    }

    /// Get the end address.
    pub fn end_address(&self) -> Address {
        self.end_address
    }

    /// Get the current page number (0-based, incremented after prepare).
    pub fn current_page(&self) -> usize {
        self.current_page
    }

    /// Whether there are more pages.
    pub fn has_more_pages(&self) -> bool {
        self.has_more
    }

    /// Prepare the next page of output.
    ///
    /// Returns true if a page was prepared, false if no more pages.
    pub fn prepare_next_page(&mut self) -> bool {
        if !self.has_more {
            return false;
        }

        self.current_page += 1;
        self.rendered_lines.clear();

        // Simulate rendering: produce placeholder lines
        let addr_range = self.end_address.offset.saturating_sub(self.start_address.offset) + 1;
        let lines_this_page = self.lines_per_page.min(addr_range as usize);

        for i in 0..lines_this_page {
            let addr = self.start_address.offset + (self.current_page - 1) as u64 * self.lines_per_page as u64 + i as u64;
            self.rendered_lines.push(format!(
                "0x{:08X}  ...",
                addr
            ));
        }

        // Check if we've passed the end address
        let next_start = self.start_address.offset + self.current_page as u64 * self.lines_per_page as u64;
        self.has_more = next_start <= self.end_address.offset;

        true
    }

    /// Get the rendered lines for the current page.
    pub fn rendered_lines(&self) -> &[String] {
        &self.rendered_lines
    }

    /// Estimate total pages.
    pub fn estimate_total_pages(&self) -> usize {
        let addr_range = self.end_address.offset.saturating_sub(self.start_address.offset) + 1;
        ((addr_range as usize + self.lines_per_page - 1) / self.lines_per_page).max(1)
    }

    /// Reset to the beginning.
    pub fn reset(&mut self) {
        self.current_page = 0;
        self.has_more = true;
        self.rendered_lines.clear();
    }
}

// ---------------------------------------------------------------------------
// PrintingPlugin
// ---------------------------------------------------------------------------

/// Plugin providing the print listing action.
///
/// Ported from `ghidra.app.plugin.core.printing.PrintingPlugin`.
#[derive(Debug)]
pub struct PrintingPlugin {
    /// Print settings.
    settings: PrintSettings,
    /// The currently loaded printable.
    printable: Option<CodeUnitPrintable>,
    /// Whether the print dialog is open.
    dialog_open: bool,
}

impl PrintingPlugin {
    /// Create a new printing plugin.
    pub fn new() -> Self {
        Self {
            settings: PrintSettings::default(),
            printable: None,
            dialog_open: false,
        }
    }

    /// Get the print settings.
    pub fn settings(&self) -> &PrintSettings {
        &self.settings
    }

    /// Get mutable print settings.
    pub fn settings_mut(&mut self) -> &mut PrintSettings {
        &mut self.settings
    }

    /// Load a printable for the given address range.
    pub fn load_printable(&mut self, start: Address, end: Address) {
        self.printable = Some(CodeUnitPrintable::new(start, end));
    }

    /// Get the current printable.
    pub fn printable(&self) -> Option<&CodeUnitPrintable> {
        self.printable.as_ref()
    }

    /// Get mutable printable.
    pub fn printable_mut(&mut self) -> Option<&mut CodeUnitPrintable> {
        self.printable.as_mut()
    }

    /// Open the print dialog (model only).
    pub fn open_dialog(&mut self) {
        self.dialog_open = true;
    }

    /// Close the print dialog.
    pub fn close_dialog(&mut self) {
        self.dialog_open = false;
    }

    /// Whether the dialog is open.
    pub fn is_dialog_open(&self) -> bool {
        self.dialog_open
    }
}

impl Default for PrintingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PrintOptionsDialog
// ---------------------------------------------------------------------------

/// Model for the print options dialog.
///
/// Ported from `ghidra.app.plugin.core.printing.PrintOptionsDialog`.
#[derive(Debug, Clone)]
pub struct PrintOptionsDialog {
    /// The current settings.
    settings: PrintSettings,
    /// Whether the dialog was confirmed.
    confirmed: bool,
}

impl PrintOptionsDialog {
    /// Create a new print options dialog.
    pub fn new() -> Self {
        Self {
            settings: PrintSettings::default(),
            confirmed: false,
        }
    }

    /// Get the settings.
    pub fn settings(&self) -> &PrintSettings {
        &self.settings
    }

    /// Get mutable settings.
    pub fn settings_mut(&mut self) -> &mut PrintSettings {
        &mut self.settings
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Whether the dialog was confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

impl Default for PrintOptionsDialog {
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
    use crate::printing::PageOrientation;
    use crate::printing::PaperSize;

    #[test]
    fn test_code_unit_printable_basic() {
        let mut printable = CodeUnitPrintable::new(Address::new(0x1000), Address::new(0x1100));
        assert!(printable.has_more_pages());
        // current_page is 0 initially (before first prepare)
        assert_eq!(printable.current_page(), 0);

        assert!(printable.prepare_next_page());
        assert_eq!(printable.current_page(), 1);
        assert!(!printable.rendered_lines().is_empty());

        printable.reset();
        assert_eq!(printable.current_page(), 0);
    }

    #[test]
    fn test_code_unit_printable_estimate() {
        let printable = CodeUnitPrintable::new(Address::new(0x1000), Address::new(0x10FF));
        let pages = printable.estimate_total_pages();
        assert!(pages >= 1);
        // 256 addresses / 60 lines per page = ~5 pages
        assert!(pages >= 4);
    }

    #[test]
    fn test_code_unit_printable_lines_per_page() {
        let mut printable = CodeUnitPrintable::new(Address::new(0x1000), Address::new(0x10FF));
        assert_eq!(printable.lines_per_page(), 60);

        printable.set_lines_per_page(30);
        assert_eq!(printable.lines_per_page(), 30);
    }

    #[test]
    fn test_printing_plugin() {
        let mut plugin = PrintingPlugin::new();
        assert!(!plugin.is_dialog_open());
        assert!(plugin.printable().is_none());

        plugin.open_dialog();
        assert!(plugin.is_dialog_open());

        plugin.load_printable(Address::new(0x1000), Address::new(0x1FFF));
        assert!(plugin.printable().is_some());

        plugin.close_dialog();
        assert!(!plugin.is_dialog_open());
    }

    #[test]
    fn test_print_options_dialog() {
        let mut dialog = PrintOptionsDialog::new();
        assert!(!dialog.is_confirmed());

        dialog.settings_mut().font_size = 10.0;
        assert_eq!(dialog.settings().font_size, 10.0);

        dialog.confirm();
        assert!(dialog.is_confirmed());
    }

    #[test]
    fn test_page_orientation() {
        assert_ne!(PageOrientation::Portrait, PageOrientation::Landscape);
    }

    #[test]
    fn test_paper_size_dimensions() {
        let (w, h) = PaperSize::Letter.dimensions_inches();
        assert!((w - 8.5).abs() < 0.01);
        assert!((h - 11.0).abs() < 0.01);

        let (w, h) = PaperSize::A4.dimensions_inches();
        assert!((w - 8.27).abs() < 0.01);
    }
}
