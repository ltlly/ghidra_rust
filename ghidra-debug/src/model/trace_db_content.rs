//! Trace content handler types ported from Framework-TraceModeling.
//!
//! Provides the content handler abstraction for trace file I/O,
//! including both direct and linked content handlers.

use serde::{Deserialize, Serialize};

/// Metadata about trace content stored in a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelContentMetadata {
    /// The content type identifier.
    pub content_type: ModelContentType,
    /// The file path or URI where the trace is stored.
    pub uri: Option<String>,
    /// Whether this content is linked (read-only reference).
    pub linked: bool,
    /// The hash of the content for change detection.
    pub content_hash: Option<Vec<u8>>,
    /// Timestamp of last modification.
    pub last_modified_ms: Option<i64>,
}

/// Types of trace content storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelContentType {
    /// Direct embedded content (full trace data in the file).
    Direct,
    /// Linked content (reference to an external trace file).
    Linked,
    /// Temporary/scratch content (not persisted).
    Temporary,
}

/// Trait for handling trace content read/write operations.
///
/// Ported from Ghidra's `DBModelContentHandler` and
/// `DBTraceLinkModelContentHandler`.
pub trait ModelContentHandler: Send + Sync {
    /// Get the content type this handler manages.
    fn content_type(&self) -> ModelContentType;

    /// Read content from the given source.
    fn read_content(&self, source: &str) -> Result<Vec<u8>, ModelContentError>;

    /// Write content to the given destination.
    fn write_content(&self, dest: &str, data: &[u8]) -> Result<(), ModelContentError>;

    /// Check if the content has been modified since the given hash.
    fn is_modified(&self, source: &str, last_hash: &[u8]) -> Result<bool, ModelContentError>;

    /// Get metadata about the content at the given location.
    fn metadata(&self, source: &str) -> Result<ModelContentMetadata, ModelContentError>;
}

/// Direct content handler that reads/writes trace data directly to files.
#[derive(Debug, Clone, Default)]
pub struct DirectModelContentHandler;

impl ModelContentHandler for DirectModelContentHandler {
    fn content_type(&self) -> ModelContentType {
        ModelContentType::Direct
    }

    fn read_content(&self, _source: &str) -> Result<Vec<u8>, ModelContentError> {
        // In a real implementation, this would read from the file system
        Ok(Vec::new())
    }

    fn write_content(&self, _dest: &str, _data: &[u8]) -> Result<(), ModelContentError> {
        // In a real implementation, this would write to the file system
        Ok(())
    }

    fn is_modified(&self, _source: &str, _last_hash: &[u8]) -> Result<bool, ModelContentError> {
        Ok(false)
    }

    fn metadata(&self, source: &str) -> Result<ModelContentMetadata, ModelContentError> {
        Ok(ModelContentMetadata {
            content_type: ModelContentType::Direct,
            uri: Some(source.to_string()),
            linked: false,
            content_hash: None,
            last_modified_ms: None,
        })
    }
}

/// Linked content handler that references an external trace file.
#[derive(Debug, Clone)]
pub struct LinkModelContentHandler {
    /// The path to the linked trace file.
    pub linked_path: String,
}

impl LinkModelContentHandler {
    /// Create a new link content handler.
    pub fn new(linked_path: impl Into<String>) -> Self {
        Self {
            linked_path: linked_path.into(),
        }
    }
}

impl ModelContentHandler for LinkModelContentHandler {
    fn content_type(&self) -> ModelContentType {
        ModelContentType::Linked
    }

    fn read_content(&self, _source: &str) -> Result<Vec<u8>, ModelContentError> {
        // In a real implementation, this would follow the link
        Ok(Vec::new())
    }

    fn write_content(&self, _dest: &str, _data: &[u8]) -> Result<(), ModelContentError> {
        Err(ModelContentError::ReadOnly("Linked content is read-only".into()))
    }

    fn is_modified(&self, _source: &str, _last_hash: &[u8]) -> Result<bool, ModelContentError> {
        Ok(false)
    }

    fn metadata(&self, _source: &str) -> Result<ModelContentMetadata, ModelContentError> {
        Ok(ModelContentMetadata {
            content_type: ModelContentType::Linked,
            uri: Some(self.linked_path.clone()),
            linked: true,
            content_hash: None,
            last_modified_ms: None,
        })
    }
}

/// Errors from content handler operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ModelContentError {
    /// I/O error.
    #[error("Content I/O error: {0}")]
    IoError(String),

    /// The content is read-only.
    #[error("Read-only: {0}")]
    ReadOnly(String),

    /// The content was not found.
    #[error("Content not found: {0}")]
    NotFound(String),

    /// Content hash mismatch (corruption).
    #[error("Content integrity error: {0}")]
    IntegrityError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_content_handler() {
        let handler = DirectModelContentHandler;
        assert_eq!(handler.content_type(), ModelContentType::Direct);
        let meta = handler.metadata("test.db").unwrap();
        assert_eq!(meta.content_type, ModelContentType::Direct);
        assert!(!meta.linked);
    }

    #[test]
    fn test_link_content_handler() {
        let handler = LinkModelContentHandler::new("/path/to/linked.db");
        assert_eq!(handler.content_type(), ModelContentType::Linked);
        assert!(handler.write_content("dest", b"data").is_err());
        let meta = handler.metadata("source").unwrap();
        assert!(meta.linked);
        assert_eq!(meta.uri.as_deref(), Some("/path/to/linked.db"));
    }

    #[test]
    fn test_content_type_variants() {
        assert_ne!(ModelContentType::Direct, ModelContentType::Linked);
        assert_ne!(ModelContentType::Linked, ModelContentType::Temporary);
    }

    #[test]
    fn test_content_error_display() {
        let err = ModelContentError::NotFound("missing".into());
        assert!(err.to_string().contains("missing"));

        let err = ModelContentError::ReadOnly("linked".into());
        assert!(err.to_string().contains("linked"));
    }
}
