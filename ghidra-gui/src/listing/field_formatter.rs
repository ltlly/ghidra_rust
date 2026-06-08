//! Field formatter for the disassembly listing view.
//!
//! Formats instruction operands, references, data types, numbers in multiple
//! radices (hex, dec, oct, bin, char, float), and addresses with symbol
//! labels.  Used by the disassembly renderer to produce consistently formatted
//! text for each column of the listing.

use ghidra_core::addr::Address;
use ghidra_core::program::listing::{Instruction, Operand};
use ghidra_core::program::Program;
use ghidra_core::symbol::Symbol;
use std::fmt::Write;

// ============================================================================
// AddressFormat
// ============================================================================

/// Controls how addresses are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFormat {
    /// `00001000` — compact hex with leading zeros.
    CompactHex,
    /// `0x1000` — hex with `0x` prefix.
    PrefixedHex,
    /// `4096` — decimal.
    Decimal,
    /// `0x00001000` — full-width prefixed hex.
    FullWidthHex,
    /// `ram:00001000` — space-prefixed.
    SpacePrefixed,
}

impl Default for AddressFormat {
    fn default() -> Self {
        Self::CompactHex
    }
}

impl AddressFormat {
    /// Format an address according to this style.
    pub fn format(&self, addr: &Address) -> String {
        match self {
            AddressFormat::CompactHex => format!("{:08X}", addr.offset),
            AddressFormat::PrefixedHex => format!("0x{:X}", addr.offset),
            AddressFormat::Decimal => format!("{}", addr.offset),
            AddressFormat::FullWidthHex => format!("0x{:016X}", addr.offset),
            AddressFormat::SpacePrefixed => format!("ram:{:08X}", addr.offset),
        }
    }

    /// Format an address for a given pointer size (4 or 8 bytes).
    pub fn format_sized(&self, addr: &Address, pointer_size: usize) -> String {
        match self {
            AddressFormat::CompactHex => match pointer_size {
                4 => format!("{:08X}", addr.offset),
                8 => format!("{:016X}", addr.offset),
                _ => format!("{:08X}", addr.offset),
            },
            _ => self.format(addr),
        }
    }
}

// ============================================================================
// NumberFormat
// ============================================================================

/// Controls how numeric values are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberFormat {
    /// Hexadecimal (the default for disassembly).
    Hex,
    /// Signed decimal.
    Decimal,
    /// Unsigned decimal.
    UnsignedDecimal,
    /// Octal.
    Octal,
    /// Binary.
    Binary,
    /// Character literal (ASCII-printable bytes).
    Char,
    /// Floating-point (f32).
    Float,
    /// Double-precision floating-point (f64).
    Double,
    /// Auto-detect best representation.
    Auto,
}

impl Default for NumberFormat {
    fn default() -> Self {
        Self::Hex
    }
}

impl NumberFormat {
    /// Format a scalar value (`i64`) according to this style.
    pub fn format_scalar(&self, value: i64) -> String {
        match self {
            NumberFormat::Hex => format!("0x{:X}", value),
            NumberFormat::Decimal => format!("{}", value),
            NumberFormat::UnsignedDecimal => format!("{}", value as u64),
            NumberFormat::Octal => format!("0o{:o}", value),
            NumberFormat::Binary => format!("0b{:b}", value),
            NumberFormat::Char => {
                let u = value as u32;
                if let Some(c) = char::from_u32(u) {
                    if c.is_ascii_graphic() || c == ' ' {
                        format!("'{}'", c)
                    } else {
                        format!("'\\x{:02X}'", u & 0xFF)
                    }
                } else {
                    format!("0x{:X}", value)
                }
            }
            NumberFormat::Float => {
                let f = f32::from_bits(value as u32);
                format!("{:.6}", f)
            }
            NumberFormat::Double => {
                let f = f64::from_bits(value as u64);
                format!("{:.12}", f)
            }
            NumberFormat::Auto => {
                // Heuristic: small values in decimal, larger in hex
                if (-128..=255).contains(&value) {
                    format!("{}", value)
                } else if value >= 32 && value <= 126 {
                    format!("'{}'", value as u8 as char)
                } else {
                    format!("0x{:X}", value)
                }
            }
        }
    }

    /// Format a raw byte slice as a number.
    pub fn format_bytes(&self, bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return String::new();
        }
        match self {
            NumberFormat::Hex => {
                let mut s = String::with_capacity(bytes.len() * 3);
                for (i, b) in bytes.iter().enumerate() {
                    if i > 0 {
                        s.push(' ');
                    }
                    let _ = write!(s, "{:02X}", b);
                }
                s
            }
            NumberFormat::Char => {
                // Try to interpret as ASCII
                if bytes.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
                    let s: String = bytes.iter().map(|&b| b as char).collect();
                    format!("\"{}\"", s.escape_default())
                } else {
                    Self::Hex.format_bytes(bytes)
                }
            }
            _ => {
                // For other formats, try to interpret as a little-endian integer
                let value = bytes_to_u64_le(bytes);
                self.format_scalar(value as i64)
            }
        }
    }
}

/// Convert a little-endian byte slice to u64.
fn bytes_to_u64_le(bytes: &[u8]) -> u64 {
    let len = bytes.len().min(8);
    let mut value: u64 = 0;
    for (i, &b) in bytes.iter().take(len).enumerate() {
        value |= (b as u64) << (i * 8);
    }
    value
}

// ============================================================================
// FieldFormatter
// ============================================================================

/// Formats listing fields for display: addresses, operands, bytes, labels,
/// comments, and cross-references.
///
/// The formatter uses the current [`AddressFormat`] and [`NumberFormat`]
/// settings together with optional label/comment override logic.
#[derive(Debug, Clone)]
pub struct FieldFormatter {
    /// How addresses are rendered.
    pub address_format: AddressFormat,

    /// How numeric values (scalars, immediates) are rendered.
    pub number_format: NumberFormat,

    /// Whether to show block names in address formatting.
    pub show_block_names: bool,

    /// Maximum number of display lines for a multi-line instruction.
    pub max_display_lines: usize,

    /// Maximum depth for expanding nested data-type references.
    pub max_reference_depth: usize,
}

impl Default for FieldFormatter {
    fn default() -> Self {
        Self {
            address_format: AddressFormat::default(),
            number_format: NumberFormat::default(),
            show_block_names: false,
            max_display_lines: 4,
            max_reference_depth: 3,
        }
    }
}

impl FieldFormatter {
    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    /// Create a new formatter with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set the address format.
    pub fn with_address_format(mut self, fmt: AddressFormat) -> Self {
        self.address_format = fmt;
        self
    }

    /// Builder: set the number format.
    pub fn with_number_format(mut self, fmt: NumberFormat) -> Self {
        self.number_format = fmt;
        self
    }

    // ------------------------------------------------------------------
    // Address formatting
    // ------------------------------------------------------------------

    /// Format an address for display, optionally substituting known symbols.
    ///
    /// When `program` is provided, looks up the symbol table to see if a
    /// label exists at this address.  If one does, the label is used
    /// instead of (or in addition to) the raw address.
    pub fn format_address(&self, addr: &Address, program: Option<&Program>) -> String {
        if let Some(prog) = program {
            if let Some(sym) = prog.get_symbol_at(addr) {
                let sym_name = sym.name();
                if sym_name != format!("DAT_{:08X}", addr.offset)
                    && sym_name != format!("FUN_{:08X}", addr.offset)
                    && sym_name != format!("LAB_{:08X}", addr.offset)
                {
                    if self.show_block_names {
                        return format!("{} ({})", sym_name, self.address_format.format(addr));
                    }
                    return sym_name;
                }
            }
        }
        self.address_format.format(addr)
    }

    /// Format an address string without looking up symbols.
    pub fn format_address_raw(&self, addr: &Address) -> String {
        self.address_format.format(addr)
    }

    /// Format an address range.
    pub fn format_address_range(
        &self,
        start: &Address,
        end: &Address,
        program: Option<&Program>,
    ) -> String {
        format!(
            "{} - {}",
            self.format_address(start, program),
            self.format_address(end, program)
        )
    }

    // ------------------------------------------------------------------
    // Operand formatting
    // ------------------------------------------------------------------

    /// Format a single operand for display.
    ///
    /// If `program` is provided, address operands are resolved to labels
    /// when available.
    pub fn format_operand(&self, op: &Operand, program: Option<&Program>) -> String {
        match op {
            Operand::Register(name) => {
                // Register names are displayed as-is
                name.clone()
            }
            Operand::Scalar(value) => self.number_format.format_scalar(*value),
            Operand::Address(addr) => self.format_address(addr, program),
            Operand::Expression(e) => {
                // For expressions like "[rbp-0x8]", we keep them as-is
                e.clone()
            }
            Operand::Float(v) => {
                // Use float/double display from number format
                if self.number_format == NumberFormat::Auto {
                    format!("{:.6}", v)
                } else {
                    self.number_format.format_scalar((*v).to_bits() as i64)
                }
            }
            Operand::None => String::new(),
        }
    }

    /// Format all operands of an instruction, joined by commas.
    pub fn format_operands(&self, ins: &Instruction, program: Option<&Program>) -> String {
        let parts: Vec<String> = ins
            .operands
            .iter()
            .map(|op| self.format_operand(op, program))
            .collect();
        parts.join(", ")
    }

    /// Format a single operand with type annotation (for rich display).
    pub fn format_operand_rich(
        &self,
        op: &Operand,
        program: Option<&Program>,
    ) -> (String, &'static str) {
        match op {
            Operand::Register(name) => (name.clone(), "register"),
            Operand::Scalar(v) => (self.number_format.format_scalar(*v), "immediate"),
            Operand::Address(addr) => (self.format_address(addr, program), "address"),
            Operand::Expression(e) => (e.clone(), "expression"),
            Operand::Float(v) => (format!("{:.6}", v), "float"),
            Operand::None => (String::new(), "none"),
        }
    }

    // ------------------------------------------------------------------
    // Bytes formatting
    // ------------------------------------------------------------------

    /// Format a byte slice as a hex dump string.
    ///
    /// Example: `[0x48, 0x89, 0xE5]` -> `"48 89 E5"`
    pub fn format_bytes(&self, bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return String::new();
        }
        let mut s = String::with_capacity(bytes.len() * 3);
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            let _ = write!(s, "{:02X}", b);
        }
        s
    }

    /// Format bytes with a prefix indicating the data size.
    pub fn format_bytes_with_size(&self, bytes: &[u8]) -> String {
        match bytes.len() {
            0 => String::new(),
            1 => format!("db  {:02X}", bytes[0]),
            2 => {
                let val = u16::from_le_bytes([bytes[0], bytes[1]]);
                format!("dw  {:04X}h ({})", val, val)
            }
            4 => {
                let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                format!("dd  {:08X}h ({})", val, val)
            }
            8 => {
                let val = u64::from_le_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ]);
                format!("dq  {:016X}h", val)
            }
            _ => self.format_bytes(bytes),
        }
    }

    /// Format bytes as a C array initializer.
    pub fn format_bytes_as_c_array(&self, bytes: &[u8]) -> String {
        let parts: Vec<String> = bytes.iter().map(|b| format!("0x{:02X}", b)).collect();
        format!("{{ {} }}", parts.join(", "))
    }

    /// Format bytes as a Python bytes literal or list.
    pub fn format_bytes_as_python(&self, bytes: &[u8]) -> String {
        let parts: Vec<String> = bytes.iter().map(|b| format!("0x{:02X}", b)).collect();
        format!("[{}]", parts.join(", "))
    }

    // ------------------------------------------------------------------
    // Label formatting
    // ------------------------------------------------------------------

    /// Format a symbol label for display.
    ///
    /// Applies a prefix based on symbol type (e.g. "FUN_", "DAT_", "LAB_")
    /// when the symbol has its auto-generated name.
    pub fn format_label(&self, symbol: &Symbol) -> String {
        let name = symbol.name();

        // Check if the name is auto-generated (starts with known prefixes)
        let prefixes = ["FUN_", "DAT_", "LAB_", "SUB_", "sub_", "loc_", "unk_"];
        for prefix in &prefixes {
            if name.starts_with(prefix) {
                // Auto-generated name: show it as-is, perhaps dimmed
                return name;
            }
        }
        name
    }

    /// Format a label for the label column, with optional address.
    pub fn format_label_with_addr(&self, symbol: &Symbol, program: Option<&Program>) -> String {
        let name = self.format_label(symbol);
        let addr = symbol.address();
        if self.show_block_names {
            format!("{} ({})", name, self.format_address(addr, program))
        } else {
            name
        }
    }

    /// Format a label for display as an operand reference.
    pub fn format_label_ref(&self, symbol: &Symbol, _program: Option<&Program>) -> String {
        let name = self.format_label(symbol);
        let addr = symbol.address();
        if self.show_block_names {
            format!("{} [{}]", name, self.format_address_raw(addr))
        } else {
            name
        }
    }

    // ------------------------------------------------------------------
    // Comment formatting
    // ------------------------------------------------------------------

    /// Format a comment for display in the listing.
    ///
    /// Truncates very long comments and prefixes them with the appropriate
    /// comment marker.
    pub fn format_comment(&self, comment: &str) -> String {
        let trimmed = comment.trim();
        if trimmed.is_empty() {
            return String::new();
        }

        // Truncate extremely long comments
        let max_len = 256;
        if trimmed.len() > max_len {
            let mut s = String::with_capacity(max_len + 5);
            s.push_str(&trimmed[..max_len]);
            s.push_str("...");
            s
        } else {
            trimmed.to_string()
        }
    }

    /// Format a comment as a plate comment (multi-line banner above instruction).
    pub fn format_plate_comment(&self, comment: &str) -> Vec<String> {
        let trimmed = comment.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        let width = 60usize;
        let mut lines = Vec::new();
        lines.push("/".repeat(width + 4));
        for line in wrap_text(trimmed, width) {
            lines.push(format!("  * {}  *", pad_right(&line, width)));
        }
        lines.push("/".repeat(width + 4));
        lines
    }

    /// Format a comment as a pre-comment (single line before instruction).
    pub fn format_pre_comment(&self, comment: &str) -> String {
        format!("; {}", self.format_comment(comment))
    }

    /// Format a comment as an end-of-line comment.
    pub fn format_eol_comment(&self, comment: &str) -> String {
        format!("; {}", self.format_comment(comment))
    }

    /// Format a comment as a post-comment (line after instruction).
    pub fn format_post_comment(&self, comment: &str) -> String {
        self.format_pre_comment(comment)
    }

    /// Format a comment as a repeatable comment.
    pub fn format_repeatable_comment(&self, comment: &str) -> String {
        format!("| {}", self.format_comment(comment))
    }

    // ------------------------------------------------------------------
    // Reference formatting
    // ------------------------------------------------------------------

    /// Format a cross-reference for display.
    ///
    /// Reference display shows the reference type, source, and target
    /// addresses / labels.
    pub fn format_reference(
        &self,
        from_addr: &Address,
        to_addr: &Address,
        ref_type: &str,
        program: Option<&Program>,
    ) -> String {
        let from_label = self.format_address(from_addr, program);
        let to_label = self.format_address(to_addr, program);
        format!("{} -> {} ({})", from_label, to_label, ref_type)
    }

    /// Format a list of cross-references for the XRef column.
    pub fn format_xrefs(
        &self,
        xref_addrs: &[Address],
        program: Option<&Program>,
        max_display: usize,
    ) -> Vec<String> {
        let show = xref_addrs.len().min(max_display);
        let mut result: Vec<String> = xref_addrs[..show]
            .iter()
            .map(|a| self.format_address(a, program))
            .collect();

        if xref_addrs.len() > max_display {
            result.push(format!("... +{} more", xref_addrs.len() - max_display));
        }

        result
    }

    /// Format a single xref address for display.
    pub fn format_xref(&self, addr: &Address, program: Option<&Program>) -> String {
        self.format_address(addr, program)
    }

    // ------------------------------------------------------------------
    // Instruction formatting
    // ------------------------------------------------------------------

    /// Format the complete instruction (mnemonic + operands) for display.
    pub fn format_instruction(&self, ins: &Instruction, program: Option<&Program>) -> String {
        let ops = self.format_operands(ins, program);
        if ops.is_empty() {
            ins.mnemonic.clone()
        } else {
            format!("{} {}", ins.mnemonic, ops)
        }
    }

    /// Format a data item display.
    pub fn format_data_item(
        &self,
        addr: &Address,
        bytes: &[u8],
        data_type_name: Option<&str>,
        program: Option<&Program>,
    ) -> String {
        let addr_str = self.format_address(addr, program);
        let type_str = data_type_name.unwrap_or("db");
        let bytes_str = self.format_bytes(bytes);
        if type_str == "db" {
            format!("{}  {}  {}", addr_str, type_str, bytes_str)
        } else {
            format!(
                "{}  {}  {}",
                addr_str,
                type_str,
                self.number_format.format_bytes(bytes)
            )
        }
    }
}

// ----------------------------------------------------------------------------
// Helper functions
// ----------------------------------------------------------------------------

/// Wrap text to a given width, breaking at word boundaries when possible.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if width == 0 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut current = String::new();

    for word in words {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Right-pad a string to the given width with spaces.
fn pad_right(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        format!("{}{}", s, " ".repeat(width - s.len()))
    }
}

/// Left-pad a string to the given width.
#[allow(dead_code)]
fn pad_left(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        format!("{}{}", " ".repeat(width - s.len()), s)
    }
}

/// Truncate a string to the given maximum width, appending "..." if needed.
pub fn truncate_text(text: &str, max_chars: usize) -> String {
    if text.len() <= max_chars {
        text.to_string()
    } else if max_chars <= 3 {
        "...".to_string()
    } else {
        format!("{}...", &text[..max_chars - 3])
    }
}

/// Compute a display width estimate in monospace characters.
pub fn monospace_width(text: &str) -> usize {
    text.chars().count()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_format_compact_hex() {
        let addr = Address::new(0x401000);
        assert_eq!(AddressFormat::CompactHex.format(&addr), "00401000");
    }

    #[test]
    fn test_address_format_prefixed_hex() {
        let addr = Address::new(0x401000);
        assert_eq!(AddressFormat::PrefixedHex.format(&addr), "0x401000");
    }

    #[test]
    fn test_address_format_decimal() {
        let addr = Address::new(0x2A);
        assert_eq!(AddressFormat::Decimal.format(&addr), "42");
    }

    #[test]
    fn test_address_format_full_width() {
        let addr = Address::new(0x1000);
        assert_eq!(
            AddressFormat::FullWidthHex.format(&addr),
            "0x0000000000001000"
        );
    }

    #[test]
    fn test_number_format_hex() {
        assert_eq!(NumberFormat::Hex.format_scalar(255), "0xFF");
        assert_eq!(NumberFormat::Hex.format_scalar(0), "0x0");
        assert_eq!(NumberFormat::Hex.format_scalar(-1), "0xFFFFFFFFFFFFFFFF");
    }

    #[test]
    fn test_number_format_decimal() {
        assert_eq!(NumberFormat::Decimal.format_scalar(42), "42");
        assert_eq!(NumberFormat::Decimal.format_scalar(-5), "-5");
    }

    #[test]
    fn test_number_format_char() {
        assert_eq!(NumberFormat::Char.format_scalar(65), "'A'");
        assert_eq!(NumberFormat::Char.format_scalar(32), "' '");
        // Non-graphic char: ESC (27)
        assert_eq!(NumberFormat::Char.format_scalar(27), "'\\x1B'");
    }

    #[test]
    fn test_number_format_octal() {
        assert_eq!(NumberFormat::Octal.format_scalar(42), "0o52");
    }

    #[test]
    fn test_number_format_binary() {
        assert_eq!(NumberFormat::Binary.format_scalar(5), "0b101");
    }

    #[test]
    fn test_format_bytes() {
        let ff = FieldFormatter::default();
        assert_eq!(ff.format_bytes(&[0x48, 0x89, 0xE5]), "48 89 E5");
        assert_eq!(ff.format_bytes(&[]), "");
        assert_eq!(ff.format_bytes(&[0xFF]), "FF");
    }

    #[test]
    fn test_format_bytes_with_size() {
        let ff = FieldFormatter::default();
        assert_eq!(ff.format_bytes_with_size(&[0x42]), "db  42");
        assert_eq!(ff.format_bytes_with_size(&[0x34, 0x12]), "dw  1234h (4660)");
    }

    #[test]
    fn test_format_bytes_as_c_array() {
        let ff = FieldFormatter::default();
        assert_eq!(ff.format_bytes_as_c_array(&[0xDE, 0xAD]), "{ 0xDE, 0xAD }");
    }

    #[test]
    fn test_format_bytes_as_python() {
        let ff = FieldFormatter::default();
        assert_eq!(ff.format_bytes_as_python(&[0xBE, 0xEF]), "[0xBE, 0xEF]");
    }

    #[test]
    fn test_format_operand_register() {
        let ff = FieldFormatter::default();
        let op = Operand::Register("rax".to_string());
        assert_eq!(ff.format_operand(&op, None), "rax");
    }

    #[test]
    fn test_format_operand_scalar() {
        let ff = FieldFormatter::default();
        let op = Operand::Scalar(0x42);
        assert_eq!(ff.format_operand(&op, None), "0x42");
    }

    #[test]
    fn test_format_operand_address() {
        let ff = FieldFormatter::default();
        let op = Operand::Address(Address::new(0x401000));
        assert_eq!(ff.format_operand(&op, None), "00401000");
    }

    #[test]
    fn test_format_operand_expression() {
        let ff = FieldFormatter::default();
        let op = Operand::Expression("[rbp-0x8]".to_string());
        assert_eq!(ff.format_operand(&op, None), "[rbp-0x8]");
    }

    #[test]
    fn test_format_comment_truncation() {
        let ff = FieldFormatter::default();
        let long = "A".repeat(300);
        let formatted = ff.format_comment(&long);
        assert_eq!(formatted.len(), 259); // 256 + "..."
        assert!(formatted.ends_with("..."));
    }

    #[test]
    fn test_format_plate_comment() {
        let ff = FieldFormatter::default();
        let lines = ff.format_plate_comment("Entry point");
        assert!(!lines.is_empty());
        assert!(lines[0].starts_with('/'));
        assert!(lines.last().unwrap().starts_with('/'));
    }

    #[test]
    fn test_format_eol_comment() {
        let ff = FieldFormatter::default();
        assert_eq!(ff.format_eol_comment("test"), "; test");
    }

    #[test]
    fn test_format_reference() {
        let ff = FieldFormatter::default();
        let from = Address::new(0x401000);
        let to = Address::new(0x402000);
        let s = ff.format_reference(&from, &to, "CALL", None);
        assert!(s.contains("00401000"));
        assert!(s.contains("00402000"));
        assert!(s.contains("CALL"));
    }

    #[test]
    fn test_wrap_text() {
        let result = wrap_text("hello world test", 10);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "hello");
        assert_eq!(result[1], "world test");
    }

    #[test]
    fn test_truncate_text() {
        assert_eq!(truncate_text("hello", 10), "hello");
        assert_eq!(truncate_text("hello world", 8), "hello...");
        assert_eq!(truncate_text("ab", 1), "...");
    }

    #[test]
    fn test_address_format_sized() {
        let addr = Address::new(0x401000);
        assert_eq!(AddressFormat::CompactHex.format_sized(&addr, 4), "00401000");
        assert_eq!(
            AddressFormat::CompactHex.format_sized(&addr, 8),
            "0000000000401000"
        );
    }
}
