//! `SearchFormat` -- the trait for parsing user input into byte matchers.
//!
//! Ported from `ghidra.features.base.memsearch.format.SearchFormat`.

use crate::memsearch::gui::SearchSettings;
use crate::memsearch::matcher::ByteMatcher;

/// The type of data a search format handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchFormatType {
    /// Raw byte-level search (hex, binary).
    Byte,
    /// Integer value search (decimal).
    Integer,
    /// Floating-point value search (float, double).
    FloatingPoint,
    /// String text search.
    StringType,
}

/// Trait for search format implementations.
///
/// Each format can parse user input into a [`ByteMatcher`] and convert
/// matched bytes back into display strings.
///
/// Ported from `ghidra.features.base.memsearch.format.SearchFormat`.
pub trait SearchFormat {
    /// The name of this format (e.g., "Hex", "Binary", "String").
    fn name(&self) -> &str;

    /// A tooltip describing this format.
    fn tooltip(&self) -> &str;

    /// The format type category.
    fn format_type(&self) -> SearchFormatType;

    /// Parse user input with the given settings into a boxed `ByteMatcher`.
    fn parse(&self, input: &str, settings: &SearchSettings) -> Box<dyn ByteMatcher>;

    /// Convert a byte array to a display string according to this format.
    fn value_string(&self, bytes: &[u8], settings: &SearchSettings) -> String;

    /// Compare two byte arrays as values (for scan algorithms).
    /// Returns negative, zero, or positive.
    fn compare_values(&self, a: &[u8], b: &[u8], settings: &SearchSettings) -> i32;

    /// Convert text from one set of settings to another.
    fn convert_text(&self, text: &str, old_settings: &SearchSettings, new_settings: &SearchSettings) -> String;
}

/// Get all built-in search formats.
pub fn all_formats() -> Vec<&'static dyn SearchFormat> {
    use crate::memsearch::format::*;
    static HEX: HexSearchFormat = HexSearchFormat;
    static BINARY: BinarySearchFormat = BinarySearchFormat;
    static DECIMAL: DecimalSearchFormat = DecimalSearchFormat;
    static STRING: StringSearchFormat = StringSearchFormat;
    static REGEX: RegExSearchFormat = RegExSearchFormat;
    static FLOAT: FloatSearchFormat = FloatSearchFormat { long_name: "Floating Point", byte_size: 4 };
    static DOUBLE: FloatSearchFormat = FloatSearchFormat { long_name: "Floating Point (8)", byte_size: 8 };
    vec![&HEX, &BINARY, &DECIMAL, &STRING, &REGEX, &FLOAT, &DOUBLE]
}
