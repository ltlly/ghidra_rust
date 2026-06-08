//! ExternalLibXmlMgr -- XML manager for external library table.
//!
//! Ported from `ghidra.app.util.xml.ExternalLibXmlMgr`.
//!
//! This module handles reading and writing XML for the external library
//! table, which stores resolved external references.  It parses
//! `EXT_LIBRARY_TABLE` XML elements containing `EXT_LIBRARY` entries,
//! each with a `NAME` and `PATH` attribute.
//!
//! # XML Format
//!
//! ```xml
//! <EXT_LIBRARY_TABLE>
//!   <EXT_LIBRARY NAME="libc" PATH="/usr/lib/libc.so"/>
//!   <EXT_LIBRARY NAME="kernel32.dll" PATH="C:\Windows\System32\kernel32.dll"/>
//! </EXT_LIBRARY_TABLE>
//! ```
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::{
//!     ExternalLibXmlMgr, ExternalManagerDB, ExternalLocationDB,
//! };
//! use ghidra_core::symbol::SourceType;
//!
//! let mut mgr = ExternalManagerDB::new();
//! let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);
//!
//! // Write XML
//! let xml = xml_mgr.write_to_string();
//! assert!(xml.contains("EXT_LIBRARY_TABLE"));
//! ```

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Write};

use super::external_manager_db::ExternalManagerDB;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur during XML processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalLibXmlError {
    /// XML parsing error.
    ParseError(String),
    /// Invalid input provided.
    InvalidInput(String),
    /// I/O error.
    IoError(String),
    /// General error.
    Other(String),
}

impl fmt::Display for ExternalLibXmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExternalLibXmlError::ParseError(msg) => {
                write!(f, "XML parse error: {}", msg)
            }
            ExternalLibXmlError::InvalidInput(msg) => {
                write!(f, "Invalid input: {}", msg)
            }
            ExternalLibXmlError::IoError(msg) => {
                write!(f, "I/O error: {}", msg)
            }
            ExternalLibXmlError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ExternalLibXmlError {}

impl From<io::Error> for ExternalLibXmlError {
    fn from(e: io::Error) -> Self {
        ExternalLibXmlError::IoError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// ExternalLibEntry
// ---------------------------------------------------------------------------

/// Represents a single external library entry from the XML.
///
/// Each entry has a library name and an optional path to the library
/// file in the project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalLibEntry {
    /// The name of the external library (e.g., "libc", "kernel32.dll").
    pub name: String,
    /// The path to the library file, or empty/None if not set.
    pub path: Option<String>,
}

impl ExternalLibEntry {
    /// Create a new external library entry.
    pub fn new(name: impl Into<String>, path: Option<String>) -> Self {
        Self {
            name: name.into(),
            path,
        }
    }

    /// Create an entry with just a name (no path).
    pub fn name_only(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: None,
        }
    }

    /// Returns true if this entry has a path set.
    pub fn has_path(&self) -> bool {
        self.path.as_ref().map_or(false, |p| !p.is_empty())
    }

    /// Returns the path, or an empty string if not set.
    pub fn path_str(&self) -> &str {
        self.path.as_deref().unwrap_or("")
    }
}

impl fmt::Display for ExternalLibEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.path {
            Some(p) if !p.is_empty() => {
                write!(f, "{}: {}", self.name, p)
            }
            _ => write!(f, "{}", self.name),
        }
    }
}

// ---------------------------------------------------------------------------
// ExternalLibXmlMgr
// ---------------------------------------------------------------------------

/// XML manager for the external library table.
///
/// This is the Rust port of Ghidra's `ExternalLibXmlMgr`.  It handles
/// reading and writing the external library table to/from XML format.
///
/// The external library table stores information about external
/// libraries referenced by the program, including the library name and
/// optional path to the library file.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{
///     ExternalLibXmlMgr, ExternalManagerDB, ExternalLibEntry,
/// };
/// use ghidra_core::symbol::SourceType;
///
/// let mut mgr = ExternalManagerDB::new();
/// let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);
///
/// // Parse XML entries
/// let entries = vec![
///     ExternalLibEntry::new("libc", Some("/usr/lib/libc.so".to_string())),
///     ExternalLibEntry::name_only("kernel32.dll"),
/// ];
///
/// // Write entries
/// for entry in &entries {
///     xml_mgr.add_entry(entry.clone());
/// }
///
/// let xml = xml_mgr.write_to_string();
/// assert!(xml.contains("EXT_LIBRARY_TABLE"));
/// ```
pub struct ExternalLibXmlMgr<'a> {
    /// Reference to the external manager.
    ext_manager: &'a mut ExternalManagerDB,
    /// Parsed entries from XML.
    entries: Vec<ExternalLibEntry>,
    /// Messages/errors encountered during processing.
    messages: Vec<String>,
}

impl<'a> ExternalLibXmlMgr<'a> {
    /// Create a new XML manager for the external library table.
    ///
    /// # Arguments
    ///
    /// * `ext_manager` -- mutable reference to the external manager.
    pub fn new(ext_manager: &'a mut ExternalManagerDB) -> Self {
        Self {
            ext_manager,
            entries: Vec::new(),
            messages: Vec::new(),
        }
    }

    /// Parse an XML string containing external library entries.
    ///
    /// The XML should contain an `EXT_LIBRARY_TABLE` root element with
    /// `EXT_LIBRARY` child elements, each having `NAME` and optionally
    /// `PATH` attributes.
    ///
    /// # Arguments
    ///
    /// * `xml` -- the XML string to parse.
    ///
    /// # Returns
    ///
    /// The number of entries parsed.
    ///
    /// # Errors
    ///
    /// Returns an error if the XML is malformed.
    pub fn read(&mut self, xml: &str) -> Result<usize, ExternalLibXmlError> {
        self.entries.clear();

        // Simple XML parsing for the EXT_LIBRARY_TABLE format
        let mut count = 0;

        // Find all EXT_LIBRARY elements
        let mut remaining = xml;
        while let Some(start) = remaining.find("<EXT_LIBRARY ") {
            let after_start = &remaining[start..];
            if let Some(end) = after_start.find("/>") {
                let element = &after_start[..end + 2];
                match self.parse_element(element) {
                    Ok(entry) => {
                        self.entries.push(entry);
                        count += 1;
                    }
                    Err(e) => {
                        self.messages
                            .push(format!("Error parsing element: {}", e));
                    }
                }
                remaining = &after_start[end + 2..];
            } else if let Some(end) = after_start.find('>') {
                // Handle <EXT_LIBRARY ...></EXT_LIBRARY> format
                let element = &after_start[..end + 1];
                match self.parse_element(element) {
                    Ok(entry) => {
                        self.entries.push(entry);
                        count += 1;
                    }
                    Err(e) => {
                        self.messages
                            .push(format!("Error parsing element: {}", e));
                    }
                }
                remaining = &after_start[end + 1..];
            } else {
                break;
            }
        }

        // Apply parsed entries to the external manager
        for entry in &self.entries {
            if let Some(path) = &entry.path {
                if !path.is_empty() {
                    // Only set path if the library already exists and
                    // doesn't have a path set yet (matching Java behavior)
                    let current_path = self
                        .ext_manager
                        .get_external_library_path(&entry.name);
                    if current_path.is_none()
                        || current_path.as_ref().map_or(true, |p| p.is_empty())
                    {
                        let _ = self
                            .ext_manager
                            .set_external_path(&entry.name, path, true);
                    }
                }
            }
        }

        Ok(count)
    }

    /// Parse a single EXT_LIBRARY XML element.
    fn parse_element(&self, element: &str) -> Result<ExternalLibEntry, ExternalLibXmlError> {
        let name = self
            .extract_attribute(element, "NAME")
            .ok_or_else(|| {
                ExternalLibXmlError::ParseError(
                    "Missing NAME attribute".to_string(),
                )
            })?;

        let path = self.extract_attribute(element, "PATH");

        Ok(ExternalLibEntry::new(name, path))
    }

    /// Extract an attribute value from an XML element string.
    fn extract_attribute(&self, element: &str, attr_name: &str) -> Option<String> {
        let pattern = format!("{}=\"", attr_name);
        if let Some(start) = element.find(&pattern) {
            let value_start = start + pattern.len();
            let remaining = &element[value_start..];
            if let Some(end) = remaining.find('"') {
                return Some(remaining[..end].to_string());
            }
        }

        // Try single quotes
        let pattern = format!("{}='", attr_name);
        if let Some(start) = element.find(&pattern) {
            let value_start = start + pattern.len();
            let remaining = &element[value_start..];
            if let Some(end) = remaining.find('\'') {
                return Some(remaining[..end].to_string());
            }
        }

        None
    }

    /// Add an entry to the manager.
    pub fn add_entry(&mut self, entry: ExternalLibEntry) {
        self.entries.push(entry);
    }

    /// Write the external library table to a string in XML format.
    ///
    /// Returns a string containing the XML representation of the
    /// external library entries.
    pub fn write_to_string(&self) -> String {
        let mut output = String::new();
        output.push_str("<EXT_LIBRARY_TABLE>\n");

        // Write entries from the external manager
        let library_names = self.ext_manager.get_external_library_names();
        for name in &library_names {
            let path = self.ext_manager.get_external_library_path(name);
            let path_str = path.as_deref().unwrap_or("");

            output.push_str(&format!(
                "  <EXT_LIBRARY NAME=\"{}\" PATH=\"{}\"/>\n",
                self.escape_xml(name),
                self.escape_xml(path_str)
            ));
        }

        // Also write any locally added entries not in the manager
        for entry in &self.entries {
            let already_written = library_names.contains(&entry.name);
            if !already_written {
                output.push_str(&format!(
                    "  <EXT_LIBRARY NAME=\"{}\" PATH=\"{}\"/>\n",
                    self.escape_xml(&entry.name),
                    self.escape_xml(entry.path_str())
                ));
            }
        }

        output.push_str("</EXT_LIBRARY_TABLE>\n");
        output
    }

    /// Write the external library table to a writer.
    ///
    /// # Arguments
    ///
    /// * `writer` -- the writer to write to.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(
        &self,
        writer: &mut W,
    ) -> Result<(), ExternalLibXmlError> {
        let xml = self.write_to_string();
        writer.write_all(xml.as_bytes())?;
        Ok(())
    }

    /// Escape special XML characters.
    fn escape_xml(&self, s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;")
    }

    /// Returns the parsed entries.
    pub fn entries(&self) -> &[ExternalLibEntry] {
        &self.entries
    }

    /// Returns any messages encountered during processing.
    pub fn messages(&self) -> &[String] {
        &self.messages
    }

    /// Returns the number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.messages.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> ExternalManagerDB {
        use ghidra_core::symbol::SourceType;
        let mut mgr = ExternalManagerDB::new();
        let _ = mgr.add_library("libc", SourceType::Imported);
        let _ = mgr.add_library("kernel32.dll", SourceType::Imported);
        let _ = mgr.set_external_path("libc", "/usr/lib/libc.so", true);
        mgr
    }

    // -- ExternalLibEntry tests --

    #[test]
    fn test_entry_creation() {
        let entry =
            ExternalLibEntry::new("libc", Some("/usr/lib/libc.so".to_string()));
        assert_eq!(entry.name, "libc");
        assert_eq!(entry.path, Some("/usr/lib/libc.so".to_string()));
        assert!(entry.has_path());
    }

    #[test]
    fn test_entry_name_only() {
        let entry = ExternalLibEntry::name_only("kernel32.dll");
        assert_eq!(entry.name, "kernel32.dll");
        assert_eq!(entry.path, None);
        assert!(!entry.has_path());
    }

    #[test]
    fn test_entry_empty_path() {
        let entry = ExternalLibEntry::new("libc", Some("".to_string()));
        assert_eq!(entry.name, "libc");
        assert!(!entry.has_path());
    }

    #[test]
    fn test_entry_display_with_path() {
        let entry =
            ExternalLibEntry::new("libc", Some("/usr/lib/libc.so".to_string()));
        let display = format!("{}", entry);
        assert_eq!(display, "libc: /usr/lib/libc.so");
    }

    #[test]
    fn test_entry_display_without_path() {
        let entry = ExternalLibEntry::name_only("kernel32.dll");
        let display = format!("{}", entry);
        assert_eq!(display, "kernel32.dll");
    }

    #[test]
    fn test_entry_path_str() {
        let entry =
            ExternalLibEntry::new("libc", Some("/usr/lib/libc.so".to_string()));
        assert_eq!(entry.path_str(), "/usr/lib/libc.so");

        let entry = ExternalLibEntry::name_only("kernel32.dll");
        assert_eq!(entry.path_str(), "");
    }

    #[test]
    fn test_entry_clone() {
        let entry =
            ExternalLibEntry::new("libc", Some("/usr/lib/libc.so".to_string()));
        let cloned = entry.clone();
        assert_eq!(cloned.name, entry.name);
        assert_eq!(cloned.path, entry.path);
    }

    #[test]
    fn test_entry_eq() {
        let entry1 =
            ExternalLibEntry::new("libc", Some("/usr/lib/libc.so".to_string()));
        let entry2 =
            ExternalLibEntry::new("libc", Some("/usr/lib/libc.so".to_string()));
        assert_eq!(entry1, entry2);

        let entry3 = ExternalLibEntry::name_only("libc");
        assert_ne!(entry1, entry3);
    }

    // -- ExternalLibXmlMgr tests --

    #[test]
    fn test_xml_mgr_creation() {
        let mut mgr = create_test_manager();
        let xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        assert_eq!(xml_mgr.entry_count(), 0);
        assert!(xml_mgr.messages().is_empty());
    }

    #[test]
    fn test_write_to_string() {
        let mut mgr = create_test_manager();
        let xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        let xml = xml_mgr.write_to_string();
        assert!(xml.contains("<EXT_LIBRARY_TABLE>"));
        assert!(xml.contains("</EXT_LIBRARY_TABLE>"));
        assert!(xml.contains("NAME=\"libc\""));
        assert!(xml.contains("NAME=\"kernel32.dll\""));
        assert!(xml.contains("PATH=\"/usr/lib/libc.so\""));
    }

    #[test]
    fn test_write_to_string_empty_manager() {
        let mut mgr = ExternalManagerDB::new();
        let xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        let xml = xml_mgr.write_to_string();
        assert!(xml.contains("<EXT_LIBRARY_TABLE>"));
        assert!(xml.contains("</EXT_LIBRARY_TABLE>"));
        // Should not contain any EXT_LIBRARY elements
        assert!(!xml.contains("<EXT_LIBRARY "));
    }

    #[test]
    fn test_write_to_writer() {
        let mut mgr = create_test_manager();
        let xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        let mut buffer = Vec::new();
        xml_mgr.write(&mut buffer).unwrap();

        let xml = String::from_utf8(buffer).unwrap();
        assert!(xml.contains("<EXT_LIBRARY_TABLE>"));
        assert!(xml.contains("NAME=\"libc\""));
    }

    #[test]
    fn test_read_simple_xml() {
        let mut mgr = ExternalManagerDB::new();
        let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        let xml = r#"<EXT_LIBRARY_TABLE>
  <EXT_LIBRARY NAME="libc" PATH="/usr/lib/libc.so"/>
  <EXT_LIBRARY NAME="kernel32.dll" PATH=""/>
</EXT_LIBRARY_TABLE>"#;

        let count = xml_mgr.read(xml).unwrap();
        assert_eq!(count, 2);
        assert_eq!(xml_mgr.entry_count(), 2);
        assert_eq!(xml_mgr.entries()[0].name, "libc");
        assert_eq!(
            xml_mgr.entries()[0].path,
            Some("/usr/lib/libc.so".to_string())
        );
        assert_eq!(xml_mgr.entries()[1].name, "kernel32.dll");
        assert_eq!(xml_mgr.entries()[1].path, Some("".to_string()));
    }

    #[test]
    fn test_read_xml_no_path() {
        let mut mgr = ExternalManagerDB::new();
        let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        let xml = r#"<EXT_LIBRARY_TABLE>
  <EXT_LIBRARY NAME="libc"/>
</EXT_LIBRARY_TABLE>"#;

        let count = xml_mgr.read(xml).unwrap();
        assert_eq!(count, 1);
        assert_eq!(xml_mgr.entries()[0].name, "libc");
        assert_eq!(xml_mgr.entries()[0].path, None);
    }

    #[test]
    fn test_read_empty_xml() {
        let mut mgr = ExternalManagerDB::new();
        let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        let xml = "<EXT_LIBRARY_TABLE></EXT_LIBRARY_TABLE>";
        let count = xml_mgr.read(xml).unwrap();
        assert_eq!(count, 0);
        assert_eq!(xml_mgr.entry_count(), 0);
    }

    #[test]
    fn test_read_single_quotes() {
        let mut mgr = ExternalManagerDB::new();
        let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        let xml = "<EXT_LIBRARY_TABLE><EXT_LIBRARY NAME='libc' PATH='/usr/lib/libc.so'/></EXT_LIBRARY_TABLE>";
        let count = xml_mgr.read(xml).unwrap();
        assert_eq!(count, 1);
        assert_eq!(xml_mgr.entries()[0].name, "libc");
        assert_eq!(
            xml_mgr.entries()[0].path,
            Some("/usr/lib/libc.so".to_string())
        );
    }

    #[test]
    fn test_read_missing_name_attribute() {
        let mut mgr = ExternalManagerDB::new();
        let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        let xml =
            "<EXT_LIBRARY_TABLE><EXT_LIBRARY PATH=\"/usr/lib/libc.so\"/></EXT_LIBRARY_TABLE>";
        let count = xml_mgr.read(xml).unwrap();
        // Should fail to parse this element
        assert_eq!(count, 0);
        assert!(!xml_mgr.messages().is_empty());
    }

    #[test]
    fn test_escape_xml() {
        let mut mgr = ExternalManagerDB::new();
        let xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        assert_eq!(xml_mgr.escape_xml("test"), "test");
        assert_eq!(xml_mgr.escape_xml("test&foo"), "test&amp;foo");
        assert_eq!(xml_mgr.escape_xml("test<foo>"), "test&lt;foo&gt;");
        assert_eq!(xml_mgr.escape_xml("test\"foo'"), "test&quot;foo&apos;");
    }

    #[test]
    fn test_add_entry() {
        let mut mgr = ExternalManagerDB::new();
        let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        xml_mgr.add_entry(ExternalLibEntry::new(
            "libc",
            Some("/usr/lib/libc.so".to_string()),
        ));
        assert_eq!(xml_mgr.entry_count(), 1);
    }

    #[test]
    fn test_clear() {
        let mut mgr = ExternalManagerDB::new();
        let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        xml_mgr.add_entry(ExternalLibEntry::name_only("libc"));
        assert_eq!(xml_mgr.entry_count(), 1);

        xml_mgr.clear();
        assert_eq!(xml_mgr.entry_count(), 0);
        assert!(xml_mgr.messages().is_empty());
    }

    #[test]
    fn test_roundtrip_write_read() {
        let mut mgr = create_test_manager();
        let xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        // Write to string
        let xml = xml_mgr.write_to_string();

        // Read back into a new manager
        let mut mgr2 = ExternalManagerDB::new();
        let mut xml_mgr2 = ExternalLibXmlMgr::new(&mut mgr2);
        let count = xml_mgr2.read(&xml).unwrap();

        // Should have parsed the entries
        assert_eq!(count, 2);
        let names: Vec<&str> = xml_mgr2.entries().iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"libc"));
        assert!(names.contains(&"kernel32.dll"));
    }

    #[test]
    fn test_read_multiple_entries() {
        let mut mgr = ExternalManagerDB::new();
        let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        let xml = r#"<EXT_LIBRARY_TABLE>
  <EXT_LIBRARY NAME="libc" PATH="/usr/lib/libc.so"/>
  <EXT_LIBRARY NAME="libm" PATH="/usr/lib/libm.so"/>
  <EXT_LIBRARY NAME="libpthread" PATH="/usr/lib/libpthread.so"/>
  <EXT_LIBRARY NAME="libdl" PATH=""/>
  <EXT_LIBRARY NAME="librt"/>
</EXT_LIBRARY_TABLE>"#;

        let count = xml_mgr.read(xml).unwrap();
        assert_eq!(count, 5);

        assert_eq!(xml_mgr.entries()[0].name, "libc");
        assert!(xml_mgr.entries()[0].has_path());
        assert_eq!(
            xml_mgr.entries()[0].path_str(),
            "/usr/lib/libc.so"
        );

        assert_eq!(xml_mgr.entries()[1].name, "libm");
        assert!(xml_mgr.entries()[1].has_path());
        assert_eq!(
            xml_mgr.entries()[1].path_str(),
            "/usr/lib/libm.so"
        );

        assert_eq!(xml_mgr.entries()[2].name, "libpthread");
        assert!(xml_mgr.entries()[2].has_path());
        assert_eq!(
            xml_mgr.entries()[2].path_str(),
            "/usr/lib/libpthread.so"
        );

        assert_eq!(xml_mgr.entries()[3].name, "libdl");
        assert!(!xml_mgr.entries()[3].has_path());

        assert_eq!(xml_mgr.entries()[4].name, "librt");
        assert!(!xml_mgr.entries()[4].has_path());
    }

    #[test]
    fn test_error_display() {
        let err =
            ExternalLibXmlError::ParseError("bad XML".to_string());
        assert_eq!(err.to_string(), "XML parse error: bad XML");

        let err =
            ExternalLibXmlError::InvalidInput("null".to_string());
        assert_eq!(err.to_string(), "Invalid input: null");

        let err = ExternalLibXmlError::IoError("write failed".to_string());
        assert_eq!(err.to_string(), "I/O error: write failed");

        let err = ExternalLibXmlError::Other("something".to_string());
        assert_eq!(err.to_string(), "something");
    }

    #[test]
    fn test_error_clone() {
        let err =
            ExternalLibXmlError::ParseError("test".to_string());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = io::Error::new(io::ErrorKind::Other, "test error");
        let err: ExternalLibXmlError = io_err.into();
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_write_with_special_characters() {
        let mut mgr = ExternalManagerDB::new();
        let mut xml_mgr = ExternalLibXmlMgr::new(&mut mgr);

        // Add entry with special characters
        xml_mgr.add_entry(ExternalLibEntry::new(
            "lib<test>",
            Some("/usr/lib/lib\"test\".so".to_string()),
        ));

        let xml = xml_mgr.write_to_string();
        assert!(xml.contains("lib&lt;test&gt;"));
        assert!(xml.contains("lib&quot;test&quot;.so"));
    }
}
