//! Trace database content handlers.
//!
//! Ported from Ghidra's `DBTraceContentHandler` and `DBTraceLinkContentHandler`.
//! These handle serialization and deserialization of trace database content
//! for saving, loading, and linking traces.

use serde::{Deserialize, Serialize};

/// Error type for content handler operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ContentHandlerError {
    /// I/O error during content handling.
    #[error("I/O error: {0}")]
    Io(String),
    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
    /// Unsupported content type.
    #[error("unsupported content type: {0}")]
    UnsupportedContentType(String),
    /// Version mismatch.
    #[error("version mismatch: expected {expected}, got {actual}")]
    VersionMismatch {
        /// Expected version.
        expected: u32,
        /// Actual version.
        actual: u32,
    },
}

/// The content type identifier for a trace database.
pub const TRACE_CONTENT_TYPE: &str = "GhidraTraceDB";

/// The link content type identifier for linked traces.
pub const TRACE_LINK_CONTENT_TYPE: &str = "GhidraTraceDBLink";

/// Version of the current trace database format.
pub const CURRENT_VERSION: u32 = 1;

/// Handler for reading and writing trace database content.
///
/// Ported from Ghidra's `DBTraceContentHandler`. This manages the
/// serialization of a trace's complete database state to and from
/// a byte stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceContentHandler {
    /// The content type.
    pub content_type: String,
    /// The format version.
    pub version: u32,
    /// Whether this is a read-only handler.
    pub read_only: bool,
}

impl DBTraceContentHandler {
    /// Create a new content handler for the given content type.
    pub fn new(content_type: impl Into<String>) -> Self {
        Self {
            content_type: content_type.into(),
            version: CURRENT_VERSION,
            read_only: false,
        }
    }

    /// Create a read-only content handler.
    pub fn read_only(content_type: impl Into<String>) -> Self {
        Self {
            content_type: content_type.into(),
            version: CURRENT_VERSION,
            read_only: true,
        }
    }

    /// Get the content type.
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// Get the format version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Check if this handler supports the given content type.
    pub fn supports_content_type(&self, content_type: &str) -> bool {
        self.content_type == content_type
    }

    /// Validate the format version.
    pub fn validate_version(&self) -> Result<(), ContentHandlerError> {
        if self.version > CURRENT_VERSION {
            Err(ContentHandlerError::VersionMismatch {
                expected: CURRENT_VERSION,
                actual: self.version,
            })
        } else {
            Ok(())
        }
    }
}

/// Handler for linked trace database content.
///
/// Ported from Ghidra's `DBTraceLinkContentHandler`. This handles
/// the case where a trace database is a link (symlink) to another
/// trace, rather than containing its own data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceLinkContentHandler {
    /// The base content handler.
    pub base: DBTraceContentHandler,
    /// The URL of the linked trace.
    pub linked_url: String,
    /// Whether the link is absolute or relative.
    pub is_absolute: bool,
}

impl DBTraceLinkContentHandler {
    /// Create a new link content handler.
    pub fn new(linked_url: impl Into<String>, is_absolute: bool) -> Self {
        Self {
            base: DBTraceContentHandler::new(TRACE_LINK_CONTENT_TYPE),
            linked_url: linked_url.into(),
            is_absolute,
        }
    }

    /// Get the linked URL.
    pub fn linked_url(&self) -> &str {
        &self.linked_url
    }

    /// Whether the link is absolute.
    pub fn is_absolute(&self) -> bool {
        self.is_absolute
    }
}

/// Metadata about a trace database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDatabaseInfo {
    /// The content handler that created this info.
    pub content_type: String,
    /// The database name.
    pub name: String,
    /// The creation time (Unix timestamp).
    pub created_at: u64,
    /// The last modification time (Unix timestamp).
    pub modified_at: u64,
    /// The Ghidra version that created this database.
    pub ghidra_version: String,
    /// Custom properties.
    pub properties: std::collections::BTreeMap<String, String>,
}

impl TraceDatabaseInfo {
    /// Create new database info.
    pub fn new(
        content_type: impl Into<String>,
        name: impl Into<String>,
        created_at: u64,
    ) -> Self {
        Self {
            content_type: content_type.into(),
            name: name.into(),
            created_at,
            modified_at: created_at,
            ghidra_version: String::new(),
            properties: std::collections::BTreeMap::new(),
        }
    }

    /// Set the Ghidra version.
    pub fn with_ghidra_version(mut self, version: impl Into<String>) -> Self {
        self.ghidra_version = version.into();
        self
    }

    /// Add a custom property.
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }

    /// Update the modification time.
    pub fn touch(&mut self, now: u64) {
        self.modified_at = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_handler_new() {
        let handler = DBTraceContentHandler::new(TRACE_CONTENT_TYPE);
        assert_eq!(handler.content_type(), TRACE_CONTENT_TYPE);
        assert_eq!(handler.version(), CURRENT_VERSION);
        assert!(!handler.read_only);
    }

    #[test]
    fn test_content_handler_read_only() {
        let handler = DBTraceContentHandler::read_only(TRACE_CONTENT_TYPE);
        assert!(handler.read_only);
    }

    #[test]
    fn test_content_handler_validate_version() {
        let handler = DBTraceContentHandler::new(TRACE_CONTENT_TYPE);
        assert!(handler.validate_version().is_ok());

        let handler_bad = DBTraceContentHandler {
            content_type: TRACE_CONTENT_TYPE.into(),
            version: CURRENT_VERSION + 1,
            read_only: false,
        };
        assert!(handler_bad.validate_version().is_err());
    }

    #[test]
    fn test_content_handler_supports() {
        let handler = DBTraceContentHandler::new(TRACE_CONTENT_TYPE);
        assert!(handler.supports_content_type(TRACE_CONTENT_TYPE));
        assert!(!handler.supports_content_type("other"));
    }

    #[test]
    fn test_link_content_handler() {
        let handler = DBTraceLinkContentHandler::new("/path/to/trace.db", true);
        assert_eq!(handler.linked_url(), "/path/to/trace.db");
        assert!(handler.is_absolute());
        assert_eq!(handler.base.content_type(), TRACE_LINK_CONTENT_TYPE);
    }

    #[test]
    fn test_link_content_handler_relative() {
        let handler = DBTraceLinkContentHandler::new("../other/trace.db", false);
        assert!(!handler.is_absolute());
    }

    #[test]
    fn test_database_info() {
        let info = TraceDatabaseInfo::new(TRACE_CONTENT_TYPE, "test_trace", 1000)
            .with_ghidra_version("11.0")
            .with_property("arch", "x86");
        assert_eq!(info.name, "test_trace");
        assert_eq!(info.created_at, 1000);
        assert_eq!(info.ghidra_version, "11.0");
        assert_eq!(info.properties.get("arch").unwrap(), "x86");
    }

    #[test]
    fn test_database_info_touch() {
        let mut info = TraceDatabaseInfo::new(TRACE_CONTENT_TYPE, "test", 1000);
        assert_eq!(info.modified_at, 1000);
        info.touch(2000);
        assert_eq!(info.modified_at, 2000);
    }

    #[test]
    fn test_content_handler_error_display() {
        let err = ContentHandlerError::VersionMismatch {
            expected: 1,
            actual: 2,
        };
        assert!(err.to_string().contains("version mismatch"));
    }

    #[test]
    fn test_constants() {
        assert!(!TRACE_CONTENT_TYPE.is_empty());
        assert!(!TRACE_LINK_CONTENT_TYPE.is_empty());
        assert!(CURRENT_VERSION > 0);
    }

    #[test]
    fn test_content_handler_serde() {
        let handler = DBTraceContentHandler::new(TRACE_CONTENT_TYPE);
        let json = serde_json::to_string(&handler).unwrap();
        let back: DBTraceContentHandler = serde_json::from_str(&json).unwrap();
        assert_eq!(back.content_type, TRACE_CONTENT_TYPE);
    }

    #[test]
    fn test_database_info_serde() {
        let info = TraceDatabaseInfo::new(TRACE_CONTENT_TYPE, "test", 0);
        let json = serde_json::to_string(&info).unwrap();
        let back: TraceDatabaseInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test");
    }
}
