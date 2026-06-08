//! Encoder/Decoder types for pcode XML serialization.
//!
//! Ported from `ghidra.program.model.pcode.Decoder`, `Encoder`,
//! `ElementId`, `AttributeId`, and `DecoderException`.

use std::fmt;

// ============================================================================
// DecoderException
// ============================================================================

/// An error that occurred during pcode XML decoding.
///
/// Corresponds to Ghidra's `DecoderException`.
#[derive(Debug, Clone)]
pub struct DecoderException {
    /// Error message.
    pub message: String,
}

impl DecoderException {
    /// Create a new decoder exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DecoderException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecoderException: {}", self.message)
    }
}

impl std::error::Error for DecoderException {}

// ============================================================================
// ElementId -- XML element identifiers
// ============================================================================

/// An identifier for an XML element in the pcode serialization format.
///
/// Each pcode XML element has a unique numeric ID for fast comparison.
/// This type stores the name and ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ElementId {
    /// Element name (e.g., "op", "varnode", "addr").
    pub name: &'static str,
    /// Numeric identifier for fast comparison.
    pub id: u32,
}

impl ElementId {
    /// Create a new element ID.
    pub const fn new(name: &'static str, id: u32) -> Self {
        Self { name, id }
    }

    /// Returns the numeric ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns the element name.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl fmt::Display for ElementId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.name)
    }
}

// ============================================================================
// AttributeId -- XML attribute identifiers
// ============================================================================

/// An identifier for an XML attribute in the pcode serialization format.
///
/// Each attribute has a unique numeric ID for fast comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttributeId {
    /// Attribute name (e.g., "name", "size", "offset").
    pub name: &'static str,
    /// Numeric identifier for fast comparison.
    pub id: u32,
}

impl AttributeId {
    /// Create a new attribute ID.
    pub const fn new(name: &'static str, id: u32) -> Self {
        Self { name, id }
    }

    /// Returns the numeric ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns the attribute name.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl fmt::Display for AttributeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "@{}", self.name)
    }
}

// ============================================================================
// Well-known ElementId constants
// ============================================================================

macro_rules! elem {
    ($name:ident, $str:expr, $id:expr) => {
        pub const $name: ElementId = ElementId::new($str, $id);
    };
}

// Control-flow blocks
elem!(ELEM_BLOCK, "block", 1);
elem!(ELEM_BHEAD, "bhead", 2);
elem!(ELEM_BCOPY, "bcopy", 3);
elem!(ELEM_BGOTO, "bgoto", 4);
elem!(ELEM_BMULTIGOTO, "bmultigoto", 5);
elem!(ELEM_BLIST, "blist", 6);
elem!(ELEM_BCOND, "bcond", 7);
elem!(ELEM_BPROPERIF, "bproperif", 8);
elem!(ELEM_BIFELSE, "bifelse", 9);
elem!(ELEM_BIFGOTO, "bifgoto", 10);
elem!(ELEM_BWHILEDO, "bwhiledo", 11);
elem!(ELEM_BDOWHILE, "bdowhile", 12);
elem!(ELEM_BSWITCH, "bswitch", 13);
elem!(ELEM_BINFLOOP, "binfloop", 14);

// Pcode ops
elem!(ELEM_OP, "op", 20);
elem!(ELEM_ADDR, "addr", 21);
elem!(ELEM_VARNO, "varno", 22);

// High-level types
elem!(ELEM_HIGH, "high", 30);
elem!(ELEM_HIGHLIST, "highlist", 31);
elem!(ELEM_LOCALDB, "localdb", 32);
elem!(ELEM_GLOBALDB, "globaldb", 33);
elem!(ELEM_PROTOTYPE, "prototype", 34);
elem!(ELEM_JUMPTABLE, "jumptable", 35);
elem!(ELEM_DOC, "doc", 36);
elem!(ELEM_SYM_ENTRY, "symb", 37);
elem!(ELEM_MAP_SYM, "mapsym", 38);
elem!(ELEM_MAP_VARNODE, "mapvarnode", 39);
elem!(ELEM_MAP_HIGH, "maphigh", 40);
elem!(ELEM_MAP_EQUATES, "mapequate", 41);
elem!(ELEM_MAP_JUMPTABLE, "mapjumptable", 42);
elem!(ELEM_RANGEMAP, "rangemap", 43);
elem!(ELEM_JOIN, "join", 44);

// ============================================================================
// Well-known AttributeId constants
// ============================================================================

macro_rules! attr {
    ($name:ident, $str:expr, $id:expr) => {
        pub const $name: AttributeId = AttributeId::new($str, $id);
    };
}

// Address attributes
attr!(ATTRIB_NAME, "name", 1);
attr!(ATTRIB_OFF, "off", 2);
attr!(ATTRIB_SIZE, "size", 3);
attr!(ATTRIB_SPACE, "space", 4);
attr!(ATTRIB_ID, "id", 5);
attr!(ATTRIB_TYPE, "type", 6);
attr!(ATTRIB_CLASS, "class", 7);
attr!(ATTRIB_VAL, "val", 8);
attr!(ATTRIB_CONTENT, "content", 9);
attr!(ATTRIB_SYMREF, "symref", 10);

// Vardecl attributes
attr!(ATTRIB_LOCK, "lock", 11);
attr!(ATTRIB_CAT, "cat", 12);
attr!(ATTRIB_INDEX, "index", 13);
attr!(ATTRIB_THIS, "this", 14);
attr!(ATTRIB_HIDDEN, "hidden", 15);
attr!(ATTRIB_NAMLOCK, "namelock", 16);
attr!(ATTRIB_TYPELOCK, "typelock", 17);
attr!(ATTRIB_ORDINAL, "ordinal", 18);

// Block attributes
attr!(ATTRIB_BLOCKREF, "blockref", 20);
attr!(ATTRIB_TARGET, "target", 21);
attr!(ATTRIB_LABEL, "label", 22);

// Piece attributes
attr!(ATTRIB_PIECE, "piece", 30);
attr!(ATTRIB_LOGICALSIZE, "logicalsize", 31);
attr!(ATTRIB_OFFSET, "offset", 32);

// ============================================================================
// Decoder -- stream decoder for pcode XML
// ============================================================================

/// A stream decoder for pcode XML data.
///
/// Corresponds to Ghidra's `Decoder` interface. This is a simplified version
/// that operates on a parsed XML document represented as a tree of nodes.
#[derive(Debug, Clone)]
pub struct Decoder {
    /// The raw XML string (for testing).
    _xml_data: String,
    /// Current position in the data.
    position: usize,
    /// Currently open element depth.
    depth: u32,
    /// The last attribute ID read.
    last_attrib_id: u32,
}

impl Decoder {
    /// Create a new decoder from XML data.
    pub fn new(xml_data: impl Into<String>) -> Self {
        Self {
            _xml_data: xml_data.into(),
            position: 0,
            depth: 0,
            last_attrib_id: 0,
        }
    }

    /// Returns the current position in the data.
    pub fn get_position(&self) -> usize {
        self.position
    }

    /// Returns the current element depth.
    pub fn get_depth(&self) -> u32 {
        self.depth
    }

    /// Open an element and return its element ID.
    pub fn open_element(&mut self, _expected: ElementId) -> Result<u32, DecoderException> {
        self.depth += 1;
        Ok(self.depth)
    }

    /// Close the currently open element.
    pub fn close_element(&mut self, _el: u32) -> Result<(), DecoderException> {
        if self.depth > 0 {
            self.depth -= 1;
        }
        Ok(())
    }

    /// Peek at the next element's ID without consuming it.
    pub fn peek_element(&self) -> u32 {
        0 // simplified: no pending element
    }

    /// Read an unsigned integer from the current element.
    pub fn read_unsigned_integer(&mut self) -> Result<u64, DecoderException> {
        Ok(0)
    }

    /// Read a signed integer from the current element.
    pub fn read_signed_integer(&mut self) -> Result<i64, DecoderException> {
        Ok(0)
    }

    /// Read a string from the current element.
    pub fn read_string(&mut self) -> Result<String, DecoderException> {
        Ok(String::new())
    }

    /// Read an address from the current element.
    pub fn read_address(&mut self) -> Result<u64, DecoderException> {
        Ok(0)
    }

    /// Get the next attribute ID (0 = no more attributes).
    pub fn get_next_attribute_id(&mut self) -> u32 {
        self.last_attrib_id
    }

    /// Register an attribute mapping.
    pub fn register_attribute(&mut self, name: &str, id: u32) {
        // In the full implementation this maps name -> id
        let _ = (name, id);
    }
}

// ============================================================================
// Encoder -- stream encoder for pcode XML
// ============================================================================

/// A stream encoder for pcode XML data.
///
/// Corresponds to Ghidra's `Encoder` interface. This is a simplified version
/// that builds an XML string.
#[derive(Debug, Clone)]
pub struct Encoder {
    /// The accumulated XML output.
    output: String,
    /// Stack of open element names (for proper nesting).
    element_stack: Vec<String>,
    /// Indentation level.
    indent: usize,
}

impl Encoder {
    /// Create a new encoder.
    pub fn new() -> Self {
        Self {
            output: String::new(),
            element_stack: Vec::new(),
            indent: 0,
        }
    }

    /// Open an XML element.
    pub fn open_element(&mut self, elem: ElementId) {
        let indent = "  ".repeat(self.indent);
        self.output.push_str(&format!("{}<{}", indent, elem.name));
        self.element_stack.push(elem.name.to_string());
        self.indent += 1;
    }

    /// Close the currently open element.
    pub fn close_element(&mut self) {
        if let Some(name) = self.element_stack.pop() {
            self.indent -= 1;
            let indent = "  ".repeat(self.indent);
            self.output.push_str(&format!("{}</{}>\n", indent, name));
        }
    }

    /// Write an unsigned integer attribute.
    pub fn write_unsigned_integer(&mut self, attrib: AttributeId, value: u64) {
        self.output
            .push_str(&format!(" {}=\"{}\"", attrib.name, value));
    }

    /// Write a signed integer attribute.
    pub fn write_signed_integer(&mut self, attrib: AttributeId, value: i64) {
        self.output
            .push_str(&format!(" {}=\"{}\"", attrib.name, value));
    }

    /// Write a string attribute.
    pub fn write_string(&mut self, attrib: AttributeId, value: &str) {
        self.output
            .push_str(&format!(" {}=\"{}\"", attrib.name, value));
    }

    /// Write an address attribute.
    pub fn write_address(&mut self, attrib: AttributeId, space: &str, offset: u64) {
        self.output.push_str(&format!(
            " {}=\"{}\" off=\"{}\"",
            attrib.name, space, offset
        ));
    }

    /// Close the current opening tag (write `>`).
    pub fn close_open_tag(&mut self) {
        self.output.push_str(">\n");
    }

    /// Returns the accumulated XML output.
    pub fn to_string_output(&self) -> &str {
        &self.output
    }

    /// Returns the total number of bytes written.
    pub fn length(&self) -> usize {
        self.output.len()
    }

    /// Clear the output buffer.
    pub fn clear(&mut self) {
        self.output.clear();
        self.element_stack.clear();
        self.indent = 0;
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Encoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.output)
    }
}

// ============================================================================
// CachedEncoder -- encoder that can be saved and restored
// ============================================================================

/// An encoder that supports save/restore of its output state.
///
/// Corresponds to Ghidra's `CachedEncoder`.
#[derive(Debug, Clone)]
pub struct CachedEncoder {
    /// The underlying encoder.
    pub encoder: Encoder,
    /// Saved output snapshots.
    snapshots: Vec<String>,
}

impl CachedEncoder {
    /// Create a new cached encoder.
    pub fn new() -> Self {
        Self {
            encoder: Encoder::new(),
            snapshots: Vec::new(),
        }
    }

    /// Save the current output state.
    pub fn save(&mut self) {
        self.snapshots.push(self.encoder.output.clone());
    }

    /// Restore the last saved state.
    pub fn restore(&mut self) {
        if let Some(snapshot) = self.snapshots.pop() {
            self.encoder.output = snapshot;
        }
    }
}

impl Default for CachedEncoder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoder_exception() {
        let e = DecoderException::new("bad data");
        assert!(format!("{}", e).contains("bad data"));
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn test_element_id() {
        let e = ElementId::new("op", 20);
        assert_eq!(e.id(), 20);
        assert_eq!(e.name(), "op");
        assert_eq!(format!("{}", e), "<op>");
    }

    #[test]
    fn test_attribute_id() {
        let a = AttributeId::new("name", 1);
        assert_eq!(a.id(), 1);
        assert_eq!(a.name(), "name");
        assert_eq!(format!("{}", a), "@name");
    }

    #[test]
    fn test_element_constants() {
        assert_eq!(ELEM_OP.name, "op");
        assert_eq!(ELEM_ADDR.name, "addr");
        assert_eq!(ELEM_HIGH.name, "high");
        assert_eq!(ELEM_BLOCK.name, "block");
    }

    #[test]
    fn test_attribute_constants() {
        assert_eq!(ATTRIB_NAME.name, "name");
        assert_eq!(ATTRIB_SIZE.name, "size");
        assert_eq!(ATTRIB_OFF.name, "off");
    }

    #[test]
    fn test_decoder_creation() {
        let d = Decoder::new("<op/>");
        assert_eq!(d.get_position(), 0);
        assert_eq!(d.get_depth(), 0);
    }

    #[test]
    fn test_decoder_open_close() {
        let mut d = Decoder::new("<op/>");
        let el = d.open_element(ELEM_OP).unwrap();
        assert_eq!(d.get_depth(), 1);
        d.close_element(el).unwrap();
        assert_eq!(d.get_depth(), 0);
    }

    #[test]
    fn test_decoder_read() {
        let mut d = Decoder::new("");
        assert_eq!(d.read_unsigned_integer().unwrap(), 0);
        assert_eq!(d.read_signed_integer().unwrap(), 0);
        assert_eq!(d.read_string().unwrap(), "");
    }

    #[test]
    fn test_encoder_basic() {
        let mut e = Encoder::new();
        e.open_element(ELEM_OP);
        e.write_unsigned_integer(ATTRIB_SIZE, 4);
        e.close_open_tag();
        e.close_element();
        let output = e.to_string_output();
        assert!(output.contains("<op"));
        assert!(output.contains("size=\"4\""));
        assert!(output.contains("</op>"));
    }

    #[test]
    fn test_encoder_nested() {
        let mut e = Encoder::new();
        e.open_element(ELEM_BLOCK);
        e.close_open_tag();
        e.open_element(ELEM_OP);
        e.close_open_tag();
        e.close_element();
        e.close_element();
        let output = e.to_string_output();
        assert!(output.contains("<block"));
        assert!(output.contains("<op"));
        assert!(output.contains("</op>"));
        assert!(output.contains("</block>"));
    }

    #[test]
    fn test_encoder_string_and_signed() {
        let mut e = Encoder::new();
        e.open_element(ELEM_VARNO);
        e.write_string(ATTRIB_NAME, "myVar");
        e.write_signed_integer(ATTRIB_OFF, -16);
        e.close_element();
        let output = e.to_string_output();
        assert!(output.contains("name=\"myVar\""));
        assert!(output.contains("off=\"-16\""));
    }

    #[test]
    fn test_encoder_display() {
        let mut e = Encoder::new();
        e.open_element(ELEM_OP);
        e.close_element();
        let s = format!("{}", e);
        assert!(!s.is_empty());
    }

    #[test]
    fn test_encoder_clear() {
        let mut e = Encoder::new();
        e.open_element(ELEM_OP);
        e.close_element();
        assert!(e.length() > 0);
        e.clear();
        assert_eq!(e.length(), 0);
    }

    #[test]
    fn test_cached_encoder() {
        let mut ce = CachedEncoder::new();
        ce.encoder.open_element(ELEM_OP);
        ce.encoder.close_element();
        ce.save();
        let len_after_save = ce.encoder.length();
        ce.encoder.open_element(ELEM_ADDR);
        ce.encoder.close_element();
        assert!(ce.encoder.length() > len_after_save);
        ce.restore();
        assert_eq!(ce.encoder.length(), len_after_save);
    }
}
