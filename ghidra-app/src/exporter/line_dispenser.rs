//! Line dispensers — helper types for multi-line text formatting.
//!
//! Ported from Ghidra's `AbstractLineDispenser`, `CommentLineDispenser`, and
//! `ReferenceLineDispenser`. These types break long text (comments, cross-references)
//! into fixed-width lines for the listing export.

use super::options::ProgramTextOptions;
use ghidra_core::program::Program;

// ---------------------------------------------------------------------------
// Utility functions (static methods from AbstractLineDispenser)
// ---------------------------------------------------------------------------

/// Generate a fill string of `n` spaces.
pub fn get_fill(n: usize) -> String {
    " ".repeat(n)
}

/// Clip a string to a fixed width, with optional padding and justification.
///
/// If the string is longer than `width`, it is truncated with "..." appended.
/// If shorter, it is padded with spaces on the left or right.
pub fn clip(s: &str, width: usize, pad_if_shorter: bool, left_justify: bool) -> String {
    if width == 0 {
        return String::new();
    }

    let char_count = s.chars().count();

    if char_count <= width {
        if pad_if_shorter {
            let fill = get_fill(width - char_count);
            if left_justify {
                format!("{}{}", s, fill)
            } else {
                format!("{}{}", fill, s)
            }
        } else {
            s.to_string()
        }
    } else {
        // Truncate with "..."
        let visible = width.saturating_sub(3);
        let truncated: String = s.chars().take(visible).collect();
        format!("{}...", truncated)
    }
}

/// Clip a string to a fixed width (default: pad + left-justify).
pub fn clip_default(s: &str, width: usize) -> String {
    clip(s, width, true, true)
}

/// Generate an address anchor string (for HTML mode).
pub fn get_address_anchor(addr: u64) -> String {
    format!("{:x}", addr)
}

// ---------------------------------------------------------------------------
// CommentLineDispenser
// ---------------------------------------------------------------------------

/// Breaks a comment string into multiple fixed-width lines.
///
/// Ported from Ghidra's `CommentLineDispenser`.
pub struct CommentLineDispenser {
    lines: Vec<String>,
    index: usize,
    /// Total fill width for continuation lines.
    pub fill_amount: usize,
    /// Width of each comment line.
    pub width: usize,
}

impl CommentLineDispenser {
    /// Create a new dispenser that breaks the comment into lines.
    ///
    /// * `comment` — the comment text (may contain newlines)
    /// * `width` — maximum width of each line
    /// * `fill_amount` — indentation for continuation lines
    pub fn new(comment: &str, width: usize, fill_amount: usize) -> Self {
        let lines: Vec<String> = comment
            .lines()
            .map(|line| clip_default(line, width))
            .collect();

        Self {
            lines,
            index: 0,
            fill_amount,
            width,
        }
    }

    /// Returns true if there are more lines to dispense.
    pub fn has_more_lines(&self) -> bool {
        self.index < self.lines.len()
    }

    /// Get the next line, advancing the cursor.
    pub fn get_next_line(&mut self) -> Option<&str> {
        if self.has_more_lines() {
            let line = &self.lines[self.index];
            self.index += 1;
            Some(line)
        } else {
            None
        }
    }

    /// Get the fill (indentation) string for the current position.
    pub fn get_fill(&self) -> String {
        let extra = if self.has_more_lines() { 0 } else { self.width };
        get_fill(self.fill_amount + extra)
    }

    /// Dispose of the dispenser (no-op in Rust, but mirrors Java's API).
    pub fn dispose(&mut self) {
        self.lines.clear();
        self.index = 0;
    }
}

// ---------------------------------------------------------------------------
// ReferenceLineDispenser
// ---------------------------------------------------------------------------

/// Represents a single cross-reference to display.
#[derive(Debug, Clone)]
pub struct XrefItem {
    /// The address (from or to, depending on direction).
    pub address: u64,
    /// Human-readable display string.
    pub display: String,
}

impl XrefItem {
    fn new(address: u64, ref_type: &str) -> Self {
        let display = if ref_type.is_empty() {
            format!("0x{:x}", address)
        } else {
            format!("0x{:x}{}", address, ref_type)
        };
        Self { address, display }
    }

    fn displayable_width(&self) -> usize {
        self.display.len()
    }
}

/// Breaks cross-references into multiple fixed-width lines for display.
///
/// Ported from Ghidra's `ReferenceLineDispenser`.
pub struct ReferenceLineDispenser {
    lines: Vec<String>,
    index: usize,
    /// Total fill amount for this dispenser.
    pub fill_amount: usize,
    /// Width of each reference line.
    pub width: usize,
}

impl ReferenceLineDispenser {
    /// Create an empty dispenser (no references to display).
    pub fn empty() -> Self {
        Self {
            lines: Vec::new(),
            index: 0,
            fill_amount: 0,
            width: 0,
        }
    }

    /// Create a dispenser that formats forward or back references.
    ///
    /// * `program` — the program (for xref lookups)
    /// * `addr` — the address whose references to display
    /// * `forward` — true for forward references, false for back references
    /// * `options` — the text options controlling widths
    pub fn for_code_unit(
        program: &Program,
        addr: u64,
        forward: bool,
        options: &ProgramTextOptions,
    ) -> Self {
        let width = options.ref_width;
        let fill_amount =
            options.addr_width + options.bytes_width + options.label_width;
        let header_width = options.ref_header_width;
        let header = if forward { " FWD" } else { "XREF" };
        let prefix = &options.comment_prefix;

        // Collect xrefs from the program's xref table.
        // program.xrefs is HashMap<Address, Vec<Address>>: to_addr -> [from_addrs]
        let addr_key = ghidra_core::addr::Address::new(addr);
        let mut refs: Vec<XrefItem> = Vec::new();
        if forward {
            // Forward refs: find all entries where `addr` is in the from_addrs list
            for (to_addr, from_addrs) in &program.xrefs {
                if from_addrs.iter().any(|a| a.offset == addr) {
                    refs.push(XrefItem::new(to_addr.offset, ""));
                }
            }
        } else {
            // Back refs: look up `addr` as a key in the xref map
            if let Some(from_addrs) = program.xrefs.get(&addr_key) {
                for from_addr in from_addrs {
                    refs.push(XrefItem::new(from_addr.offset, ""));
                }
            }
        }

        if refs.is_empty() || width < 1 {
            return Self::empty();
        }

        let mut lines = Vec::new();
        let mut buf = String::new();

        // Write header
        if options.show_reference_headers {
            let text = format!("{}[{}]: ", header, refs.len());
            buf.push_str(&clip_default(&text, header_width));
        } else {
            buf.push_str(&get_fill(header_width));
            buf.push_str(prefix);
        }

        let mut current_width = 0;
        let refs_len = refs.len();
        for (i, xref) in refs.iter().enumerate() {
            let next_width = current_width + xref.displayable_width();
            if next_width > width {
                lines.push(format!("{}{}", prefix, buf));
                buf = get_fill(header_width);
                current_width = 0;
            }
            current_width += xref.displayable_width();
            buf.push_str(&xref.display);
            if i < refs_len - 1 {
                buf.push(',');
            }
        }
        if !buf.is_empty() {
            lines.push(format!("{}{}", prefix, buf));
        }

        Self {
            lines,
            index: 0,
            fill_amount,
            width,
        }
    }

    /// Returns true if there are more lines.
    pub fn has_more_lines(&self) -> bool {
        self.index < self.lines.len()
    }

    /// Get the next line.
    pub fn get_next_line(&mut self) -> Option<&str> {
        if self.has_more_lines() {
            let line = &self.lines[self.index];
            self.index += 1;
            Some(line)
        } else {
            None
        }
    }

    /// Get the fill string for continuation lines.
    pub fn get_fill(&self) -> String {
        let extra = if self.has_more_lines() { 0 } else { self.width };
        get_fill(self.fill_amount + extra)
    }

    /// Dispose of the dispenser.
    pub fn dispose(&mut self) {
        self.lines.clear();
        self.index = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clip_short_string_left_justified() {
        assert_eq!(clip("hi", 5, true, true), "hi   ");
    }

    #[test]
    fn test_clip_short_string_right_justified() {
        assert_eq!(clip("hi", 5, true, false), "   hi");
    }

    #[test]
    fn test_clip_no_pad() {
        assert_eq!(clip("hi", 5, false, true), "hi");
    }

    #[test]
    fn test_clip_long_string() {
        assert_eq!(clip("hello world!", 8, true, true), "hello...");
    }

    #[test]
    fn test_clip_width_zero() {
        assert_eq!(clip("anything", 0, true, true), "");
    }

    #[test]
    fn test_clip_width_three() {
        assert_eq!(clip("abcdef", 3, true, true), "...");
    }

    #[test]
    fn test_clip_exact_width() {
        assert_eq!(clip("abc", 3, true, true), "abc");
    }

    #[test]
    fn test_get_fill() {
        assert_eq!(get_fill(0), "");
        assert_eq!(get_fill(3), "   ");
    }

    #[test]
    fn test_comment_dispenser_single_line() {
        let mut disp = CommentLineDispenser::new("hello world", 20, 4);
        assert!(disp.has_more_lines());
        assert_eq!(disp.get_next_line(), Some("hello world         "));
        assert!(!disp.has_more_lines());
        assert_eq!(disp.get_next_line(), None);
    }

    #[test]
    fn test_comment_dispenser_multi_line() {
        let mut disp = CommentLineDispenser::new("line1\nline2\nline3", 10, 4);
        assert_eq!(disp.get_next_line(), Some("line1     "));
        assert_eq!(disp.get_next_line(), Some("line2     "));
        assert_eq!(disp.get_next_line(), Some("line3     "));
        assert!(!disp.has_more_lines());
    }

    #[test]
    fn test_comment_dispenser_get_fill() {
        let mut disp = CommentLineDispenser::new("a\nb", 10, 4);
        // Before consuming any lines, fill = fill_amount (4)
        assert_eq!(disp.get_fill().len(), 4);
        disp.get_next_line(); // consume "a"
        // Still one line left, fill = fill_amount (4)
        assert_eq!(disp.get_fill().len(), 4);
        disp.get_next_line(); // consume "b"
        // No lines left, fill = fill_amount + width (4 + 10 = 14)
        assert_eq!(disp.get_fill().len(), 14);
    }

    #[test]
    fn test_empty_reference_dispenser() {
        let disp = ReferenceLineDispenser::empty();
        assert!(!disp.has_more_lines());
    }
}
