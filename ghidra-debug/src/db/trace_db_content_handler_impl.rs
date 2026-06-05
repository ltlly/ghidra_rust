//! Content handler implementations for trace database files.
//!
//! Ported from Ghidra's `ghidra.trace.database.DBTraceContentHandler`
//! and `DBTraceLinkContentHandler`.
//!
//! Ghidra uses content handlers to manage how trace data is read from
//! and written to files on disk. The content handler defines the file
//! format, serialization, and deserialization logic.
//!
//! For the Rust port, this module defines the content type identifiers
//! and serialization format metadata.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// ContentType
// ---------------------------------------------------------------------------

/// Identifies the content type of a trace file.
///
/// Ported from Ghidra's content handler type system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceContentType {
    /// A trace stored directly in a database file.
    Database,
    /// A trace linked to an external file.
    Link,
    /// An exported trace in a portable format.
    Export,
    /// A trace captured from a live session.
    Capture,
}

impl TraceContentType {
    /// Get the file extension associated with this content type.
    pub fn file_extension(&self) -> &'static str {
        match self {
            Self::Database => ".tdb",
            Self::Link => ".tlk",
            Self::Export => ".export",
            Self::Capture => ".capture",
        }
    }

    /// Get a human-readable description of this content type.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Database => "Trace Database",
            Self::Link => "Linked Trace",
            Self::Export => "Exported Trace",
            Self::Capture => "Captured Trace",
        }
    }
}

// ---------------------------------------------------------------------------
// TraceContentMetadata
// ---------------------------------------------------------------------------

/// Metadata about a trace's content, stored in the file header.
///
/// Ported from Ghidra's content handler metadata fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContentMetadata {
    /// The content type.
    pub content_type: TraceContentType,
    /// The schema version of the trace file format.
    pub schema_version: u32,
    /// The name of the trace.
    pub name: String,
    /// Creation timestamp (milliseconds since epoch).
    pub created_at: i64,
    /// Last modification timestamp.
    pub modified_at: i64,
    /// The Ghidra version that created this trace.
    pub creator_version: String,
    /// The base language ID (e.g., "x86:LE:64:default").
    pub language_id: Option<String>,
    /// The compiler spec ID.
    pub compiler_spec_id: Option<String>,
    /// The executable path of the traced program.
    pub executable_path: Option<String>,
}

impl TraceContentMetadata {
    /// Create new metadata for a database trace.
    pub fn new_database(name: impl Into<String>) -> Self {
        Self {
            content_type: TraceContentType::Database,
            schema_version: 0,
            name: name.into(),
            created_at: chrono::Utc::now().timestamp_millis(),
            modified_at: chrono::Utc::now().timestamp_millis(),
            creator_version: env!("CARGO_PKG_VERSION").to_string(),
            language_id: None,
            compiler_spec_id: None,
            executable_path: None,
        }
    }

    /// Create new metadata for a linked trace.
    pub fn new_link(name: impl Into<String>) -> Self {
        Self {
            content_type: TraceContentType::Link,
            ..Self::new_database(name)
        }
    }

    /// Set the language information.
    pub fn with_language(
        mut self,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        self.language_id = Some(language_id.into());
        self.compiler_spec_id = Some(compiler_spec_id.into());
        self
    }

    /// Set the executable path.
    pub fn with_executable_path(mut self, path: impl Into<String>) -> Self {
        self.executable_path = Some(path.into());
        self
    }

    /// Update the modification timestamp.
    pub fn touch(&mut self) {
        self.modified_at = chrono::Utc::now().timestamp_millis();
    }
}

// ---------------------------------------------------------------------------
// ContentHandler trait
// ---------------------------------------------------------------------------

/// Trait for reading and writing trace content.
///
/// Ported from `ghidra.trace.database.DBTraceContentHandler`.
pub trait TraceContentHandler {
    /// Get the content metadata.
    fn metadata(&self) -> &TraceContentMetadata;

    /// Get a mutable reference to the content metadata.
    fn metadata_mut(&mut self) -> &mut TraceContentMetadata;

    /// Whether the content has been modified since last save.
    fn is_modified(&self) -> bool;

    /// Mark the content as saved (clears modified flag).
    fn mark_saved(&mut self);

    /// Get the save file path, if any.
    fn save_path(&self) -> Option<&str>;
}

// ---------------------------------------------------------------------------
// LinkContentHandler
// ---------------------------------------------------------------------------

/// A content handler for linked traces.
///
/// Ported from `ghidra.trace.database.DBTraceLinkContentHandler`.
/// Linked traces point to an external data source rather than
/// containing their data inline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkContentHandler {
    /// The metadata.
    pub metadata: TraceContentMetadata,
    /// The URL or path to the linked data source.
    pub link_url: String,
    /// Whether the link target is currently available.
    pub is_available: bool,
}

impl LinkContentHandler {
    /// Create a new link content handler.
    pub fn new(name: impl Into<String>, link_url: impl Into<String>) -> Self {
        Self {
            metadata: TraceContentMetadata::new_link(name),
            link_url: link_url.into(),
            is_available: false,
        }
    }

    /// Check if the link target is available.
    pub fn check_availability(&mut self) -> bool {
        // In a real implementation, this would check if the link target exists
        self.is_available
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_properties() {
        assert_eq!(TraceContentType::Database.file_extension(), ".tdb");
        assert_eq!(TraceContentType::Link.description(), "Linked Trace");
    }

    #[test]
    fn test_content_metadata_new() {
        let meta = TraceContentMetadata::new_database("test_trace");
        assert_eq!(meta.content_type, TraceContentType::Database);
        assert_eq!(meta.name, "test_trace");
        assert_eq!(meta.schema_version, 0);
        assert!(meta.language_id.is_none());
    }

    #[test]
    fn test_content_metadata_with_language() {
        let meta = TraceContentMetadata::new_database("test")
            .with_language("x86:LE:64:default", "default");
        assert_eq!(meta.language_id.as_deref(), Some("x86:LE:64:default"));
        assert_eq!(meta.compiler_spec_id.as_deref(), Some("default"));
    }

    #[test]
    fn test_content_metadata_with_executable() {
        let meta = TraceContentMetadata::new_database("test")
            .with_executable_path("/usr/bin/test");
        assert_eq!(meta.executable_path.as_deref(), Some("/usr/bin/test"));
    }

    #[test]
    fn test_content_metadata_touch() {
        let mut meta = TraceContentMetadata::new_database("test");
        let before = meta.modified_at;
        // Sleep a bit to ensure time changes (in practice this is called later)
        meta.touch();
        assert!(meta.modified_at >= before);
    }

    #[test]
    fn test_link_content_handler() {
        let mut handler = LinkContentHandler::new("linked_trace", "tcp://localhost:1234");
        assert_eq!(handler.metadata.content_type, TraceContentType::Link);
        assert_eq!(handler.link_url, "tcp://localhost:1234");
        assert!(!handler.is_available);
    }

    #[test]
    fn test_content_type_all_variants() {
        let types = [
            TraceContentType::Database,
            TraceContentType::Link,
            TraceContentType::Export,
            TraceContentType::Capture,
        ];
        for ct in &types {
            assert!(!ct.file_extension().is_empty());
            assert!(!ct.description().is_empty());
        }
    }
}
