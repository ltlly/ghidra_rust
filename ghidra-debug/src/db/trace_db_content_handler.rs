//! Content handler for trace database serialization.
//!
//! Ported from Ghidra's `DBTraceContentHandler` and `DBTraceLinkContentHandler`.
//!
//! Handles serialization and deserialization of trace content,
//! including the link-based content handler that supports
//! external content references.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The type of content being stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContentType {
    /// Raw binary data.
    Binary,
    /// UTF-8 text.
    Text,
    /// JSON data.
    Json,
    /// Serialized object.
    Serialized,
    /// A link to external content.
    Link,
}

/// Metadata about a content entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    /// The content type.
    pub content_type: ContentType,
    /// The size in bytes.
    pub size: u64,
    /// A hash of the content for integrity checking.
    pub hash: Option<String>,
    /// When this content was created.
    pub created_at: Option<i64>,
    /// When this content was last modified.
    pub modified_at: Option<i64>,
}

/// A content handler for trace database content.
///
/// Manages serialization/deserialization of trace data stored
/// in the database.
pub struct DBTraceContentHandler {
    /// Cached content entries by key.
    cache: HashMap<String, Vec<u8>>,
    /// Metadata for each content entry.
    metadata: HashMap<String, ContentMetadata>,
    /// Maximum cache size in bytes.
    max_cache_bytes: usize,
    /// Current cache size in bytes.
    current_cache_bytes: usize,
}

impl DBTraceContentHandler {
    /// Create a new content handler.
    pub fn new(max_cache_bytes: usize) -> Self {
        Self {
            cache: HashMap::new(),
            metadata: HashMap::new(),
            max_cache_bytes,
            current_cache_bytes: 0,
        }
    }

    /// Store content under the given key.
    pub fn put(&mut self, key: &str, data: Vec<u8>, content_type: ContentType) {
        let size = data.len();
        self.evict_if_needed(size);

        self.metadata.insert(
            key.to_string(),
            ContentMetadata {
                content_type,
                size: size as u64,
                hash: None,
                created_at: None,
                modified_at: None,
            },
        );

        self.current_cache_bytes += size;
        self.cache.insert(key.to_string(), data);
    }

    /// Retrieve content by key.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.cache.get(key).map(|v| v.as_slice())
    }

    /// Get the metadata for a content entry.
    pub fn get_metadata(&self, key: &str) -> Option<&ContentMetadata> {
        self.metadata.get(key)
    }

    /// Remove a content entry.
    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        if let Some(meta) = self.metadata.remove(key) {
            self.current_cache_bytes -= meta.size as usize;
        }
        self.cache.remove(key)
    }

    /// Check if a content entry exists.
    pub fn contains(&self, key: &str) -> bool {
        self.cache.contains_key(key)
    }

    /// Get the current cache size in bytes.
    pub fn cache_size(&self) -> usize {
        self.current_cache_bytes
    }

    /// Get the number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.cache.len()
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.cache.clear();
        self.metadata.clear();
        self.current_cache_bytes = 0;
    }

    /// Evict entries if the cache would exceed the limit.
    fn evict_if_needed(&mut self, needed: usize) {
        while self.current_cache_bytes + needed > self.max_cache_bytes && !self.cache.is_empty() {
            // Evict the first entry (simple FIFO eviction)
            if let Some(key) = self.cache.keys().next().cloned() {
                self.remove(&key);
            }
        }
    }
}

/// A link-based content handler that stores references to external content.
///
/// Instead of storing content directly in the database, this handler
/// stores file paths or URLs that reference external content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkContentEntry {
    /// The link target (file path or URL).
    pub target: String,
    /// Whether this is a relative path.
    pub is_relative: bool,
    /// The content type of the linked resource.
    pub content_type: ContentType,
}

/// A content handler that supports link-based references.
pub struct DBTraceLinkContentHandler {
    /// The base directory for resolving relative links.
    base_dir: PathBuf,
    /// Link entries indexed by key.
    links: HashMap<String, LinkContentEntry>,
    /// Resolved content cache.
    resolved_cache: HashMap<String, Vec<u8>>,
}

impl DBTraceLinkContentHandler {
    /// Create a new link content handler.
    pub fn new(base_dir: PathBuf) -> Self {
        Self {
            base_dir,
            links: HashMap::new(),
            resolved_cache: HashMap::new(),
        }
    }

    /// Add a link entry.
    pub fn add_link(&mut self, key: &str, entry: LinkContentEntry) {
        self.links.insert(key.to_string(), entry);
        self.resolved_cache.remove(key);
    }

    /// Get a link entry by key.
    pub fn get_link(&self, key: &str) -> Option<&LinkContentEntry> {
        self.links.get(key)
    }

    /// Remove a link entry.
    pub fn remove_link(&mut self, key: &str) -> Option<LinkContentEntry> {
        self.resolved_cache.remove(key);
        self.links.remove(key)
    }

    /// Resolve a link to its full path.
    pub fn resolve_path(&self, key: &str) -> Option<PathBuf> {
        self.links.get(key).map(|entry| {
            if entry.is_relative {
                self.base_dir.join(&entry.target)
            } else {
                PathBuf::from(&entry.target)
            }
        })
    }

    /// Get all link keys.
    pub fn link_keys(&self) -> Vec<&str> {
        self.links.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a link exists.
    pub fn has_link(&self, key: &str) -> bool {
        self.links.contains_key(key)
    }

    /// Get the number of links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Get the base directory.
    pub fn base_dir(&self) -> &PathBuf {
        &self.base_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_handler_put_get() {
        let mut handler = DBTraceContentHandler::new(1024);
        handler.put("key1", vec![1, 2, 3], ContentType::Binary);

        assert_eq!(handler.get("key1"), Some([1u8, 2, 3].as_slice()));
        assert!(handler.contains("key1"));
        assert_eq!(handler.entry_count(), 1);
        assert_eq!(handler.cache_size(), 3);
    }

    #[test]
    fn test_content_handler_eviction() {
        let mut handler = DBTraceContentHandler::new(10);
        handler.put("a", vec![0; 5], ContentType::Binary);
        handler.put("b", vec![0; 3], ContentType::Binary);
        // Cache is 8 bytes. Adding 5 more needs eviction.
        handler.put("c", vec![0; 5], ContentType::Binary);
        // Something should be evicted to stay within budget
        assert!(handler.entry_count() <= 2);
        assert!(handler.cache_size() <= 10);
    }

    #[test]
    fn test_content_handler_metadata() {
        let mut handler = DBTraceContentHandler::new(1024);
        handler.put("data", vec![0; 100], ContentType::Json);

        let meta = handler.get_metadata("data").unwrap();
        assert_eq!(meta.content_type, ContentType::Json);
        assert_eq!(meta.size, 100);
    }

    #[test]
    fn test_link_content_handler() {
        let mut handler = DBTraceLinkContentHandler::new(PathBuf::from("/base"));
        handler.add_link(
            "trace1",
            LinkContentEntry {
                target: "traces/trace1.db".into(),
                is_relative: true,
                content_type: ContentType::Binary,
            },
        );

        let resolved = handler.resolve_path("trace1").unwrap();
        assert_eq!(resolved, PathBuf::from("/base/traces/trace1.db"));

        assert_eq!(handler.link_count(), 1);
        assert!(handler.has_link("trace1"));
        assert!(!handler.has_link("trace2"));
    }

    #[test]
    fn test_link_absolute() {
        let mut handler = DBTraceLinkContentHandler::new(PathBuf::from("/base"));
        handler.add_link(
            "ext",
            LinkContentEntry {
                target: "/external/data.bin".into(),
                is_relative: false,
                content_type: ContentType::Binary,
            },
        );

        let resolved = handler.resolve_path("ext").unwrap();
        assert_eq!(resolved, PathBuf::from("/external/data.bin"));
    }
}
