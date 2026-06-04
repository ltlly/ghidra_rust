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

/// Paper size presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaperSize {
    /// US Letter (8.5 x 11 inches).
    Letter,
    /// A4 (210 x 297 mm).
    A4,
    /// Legal (8.5 x 14 inches).
    Legal,
    /// Custom size.
    Custom,
}

impl PaperSize {
    /// Return (width, height) in inches.
    pub fn dimensions_inches(&self) -> (f64, f64) {
        match self {
            Self::Letter => (8.5, 11.0),
            Self::A4 => (8.27, 11.69),
            Self::Legal => (8.5, 14.0),
            Self::Custom => (8.5, 11.0),
        }
    }
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
    /// Paper size.
    pub paper_size: PaperSize,
    /// Top margin in inches.
    pub margin_top: f64,
    /// Bottom margin in inches.
    pub margin_bottom: f64,
    /// Left margin in inches.
    pub margin_left: f64,
    /// Right margin in inches.
    pub margin_right: f64,
    /// Whether to print page numbers.
    pub print_page_numbers: bool,
    /// Number of copies.
    pub copies: u32,
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
            paper_size: PaperSize::Letter,
            margin_top: 0.75,
            margin_bottom: 0.75,
            margin_left: 0.75,
            margin_right: 0.75,
            print_page_numbers: true,
            copies: 1,
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

    /// Paginate lines into pages.
    pub fn paginate(&self, lines_per_page: usize) -> Vec<PrintPage> {
        let mut pages = Vec::new();
        for (i, chunk) in self.lines.chunks(lines_per_page).enumerate() {
            pages.push(PrintPage {
                page_number: (i + 1) as u32,
                lines: chunk.to_vec(),
                header: if self.settings.print_header {
                    Some(self.settings.header_text.clone())
                } else {
                    None
                },
            });
        }
        pages
    }

    /// Total number of pages for the given lines-per-page.
    pub fn page_count(&self, lines_per_page: usize) -> usize {
        if lines_per_page == 0 { return 0; }
        (self.lines.len() + lines_per_page - 1) / lines_per_page
    }
}

/// A single page of print output.
#[derive(Debug, Clone)]
pub struct PrintPage {
    /// Page number (1-based).
    pub page_number: u32,
    /// Lines on this page.
    pub lines: Vec<PrintLine>,
    /// Optional header text.
    pub header: Option<String>,
}

impl PrintPage {
    /// Line count on this page.
    pub fn line_count(&self) -> usize { self.lines.len() }

    /// First address on this page.
    pub fn first_address(&self) -> Option<Address> { self.lines.first().map(|l| l.address) }

    /// Last address on this page.
    pub fn last_address(&self) -> Option<Address> { self.lines.last().map(|l| l.address) }
}

/// Computes page layout dimensions.
#[derive(Debug, Clone)]
pub struct PageLayout {
    /// Printable width in points.
    pub printable_width: f64,
    /// Printable height in points.
    pub printable_height: f64,
    /// Lines per page.
    pub lines_per_page: usize,
    /// Characters per line.
    pub chars_per_line: usize,
}

impl PageLayout {
    /// Create a page layout from print settings and a character size.
    pub fn from_settings(settings: &PrintSettings, char_width: f64, line_height: f64) -> Self {
        let dpi = 72.0;
        let (paper_w, paper_h) = settings.paper_size.dimensions_inches();
        let (page_w, page_h) = match settings.orientation {
            PageOrientation::Portrait => (paper_w, paper_h),
            PageOrientation::Landscape => (paper_h, paper_w),
        };
        let printable_w = (page_w - settings.margin_left - settings.margin_right) * dpi;
        let printable_h = (page_h - settings.margin_top - settings.margin_bottom) * dpi;
        let lpp = if line_height > 0.0 { (printable_h / line_height) as usize } else { 60 };
        let cpl = if char_width > 0.0 { (printable_w / char_width) as usize } else { 80 };
        Self { printable_width: printable_w, printable_height: printable_h, lines_per_page: lpp, chars_per_line: cpl }
    }
}

/// A complete print job.
#[derive(Debug)]
pub struct PrintJob {
    /// Print settings.
    pub settings: PrintSettings,
    /// All pages.
    pub pages: Vec<PrintPage>,
    /// Job name.
    pub job_name: String,
}

impl PrintJob {
    /// Create a new print job.
    pub fn new(settings: PrintSettings, lines: Vec<PrintLine>, lines_per_page: usize) -> Self {
        let mut model = PrintModel::new();
        model.settings = settings.clone();
        for line in lines { model.add_line(line); }
        let pages = model.paginate(lines_per_page);
        let name = settings.header_text.clone();
        Self { settings, pages, job_name: if name.is_empty() { "Ghidra Print Job".to_string() } else { name } }
    }

    /// Total pages.
    pub fn total_pages(&self) -> usize { self.pages.len() }

    /// Get a specific page (1-based).
    pub fn get_page(&self, page_number: u32) -> Option<&PrintPage> {
        self.pages.iter().find(|p| p.page_number == page_number)
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
        assert_eq!(settings.paper_size, PaperSize::Letter);
        assert_eq!(settings.copies, 1);
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

    #[test]
    fn test_paginate() {
        let mut model = PrintModel::new();
        for i in 0..25u32 {
            model.add_line(PrintLine {
                address: Address::new(0x1000 + i as u64 * 4),
                text: format!("line {}", i),
                line_number: i + 1,
            });
        }
        let pages = model.paginate(10);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[0].line_count(), 10);
        assert_eq!(pages[2].line_count(), 5);
        assert_eq!(model.page_count(10), 3);
    }

    #[test]
    fn test_print_page_addresses() {
        let lines: Vec<PrintLine> = (0..5u32).map(|i| PrintLine {
            address: Address::new(0x1000 + i as u64 * 0x100),
            text: format!("line {}", i),
            line_number: i + 1,
        }).collect();
        let page = PrintPage { page_number: 1, lines, header: Some("Test".into()) };
        assert_eq!(page.first_address().unwrap().offset, 0x1000);
        assert_eq!(page.last_address().unwrap().offset, 0x1400);
    }

    #[test]
    fn test_print_job() {
        let settings = PrintSettings::new();
        let lines: Vec<PrintLine> = (0..20u32).map(|i| PrintLine {
            address: Address::new(0x1000 + i as u64 * 4),
            text: format!("instr {}", i),
            line_number: i + 1,
        }).collect();
        let job = PrintJob::new(settings, lines, 10);
        assert_eq!(job.total_pages(), 2);
        assert!(job.get_page(3).is_none());
    }

    #[test]
    fn test_paper_size() {
        let (w, h) = PaperSize::Letter.dimensions_inches();
        assert!((w - 8.5).abs() < 0.01);
        let (w, h) = PaperSize::A4.dimensions_inches();
        assert!((w - 8.27).abs() < 0.01);
    }

    #[test]
    fn test_page_layout() {
        let settings = PrintSettings::new();
        let layout = PageLayout::from_settings(&settings, 6.0, 12.0);
        assert!(layout.lines_per_page > 0);
        assert!((layout.printable_width - 504.0).abs() < 1.0);
    }
}
