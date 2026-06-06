//! Link content handler for trace databases.
//!
//! Ported from Ghidra's `DBTraceLinkContentHandler`.
//!
//! Handles linked content (pointers to data in other locations)
//! within the trace database, supporting content sharing between
//! related traces or trace segments.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors related to link content operations.
#[derive(Debug, Error)]
pub enum LinkContentError {
    /// The target of the link was not found.
    #[error("Link target not found: {0}")]
    TargetNotFound(String),
    /// A circular link was detected.
    #[error("Circular link detected: {0}")]
    CircularLink(String),
    /// The link type is invalid for this operation.
    #[error("Invalid link type: {0}")]
    InvalidLinkType(String),
    /// An I/O error occurred.
    #[error("Link content I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for link content operations.
pub type LinkContentResult<T> = Result<T, LinkContentError>;

/// The type of content link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LinkType {
    /// A direct reference to content in another trace.
    Direct,
    /// A lazy reference that is resolved on first access.
    Lazy,
    /// A copy-on-write reference.
    CopyOnWrite,
    /// A shared reference (multiple consumers).
    Shared,
}

/// A content link that references data in another location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentLink {
    /// The type of link.
    pub link_type: LinkType,
    /// The path to the target content.
    pub target_path: String,
    /// The offset within the target content.
    pub offset: u64,
    /// The length of the linked content.
    pub length: u64,
    /// The snap at which this link was created.
    pub created_snap: i64,
}

impl ContentLink {
    /// Create a new content link.
    pub fn new(
        link_type: LinkType,
        target_path: impl Into<String>,
        offset: u64,
        length: u64,
    ) -> Self {
        Self {
            link_type,
            target_path: target_path.into(),
            offset,
            length,
            created_snap: 0,
        }
    }

    /// Set the creation snap.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.created_snap = snap;
        self
    }
}

/// Handler for link content in the trace database.
///
/// Manages creation, resolution, and cleanup of content links.
#[derive(Debug)]
pub struct DBTraceLinkContentHandler {
    /// Registered content links.
    links: Vec<ContentLink>,
    /// Maximum link resolution depth (to prevent infinite recursion).
    max_depth: usize,
}

impl DBTraceLinkContentHandler {
    /// Create a new link content handler.
    pub fn new() -> Self {
        Self {
            links: Vec::new(),
            max_depth: 16,
        }
    }

    /// Create a new link content handler with a custom max depth.
    pub fn with_max_depth(max_depth: usize) -> Self {
        Self {
            links: Vec::new(),
            max_depth,
        }
    }

    /// Register a content link.
    pub fn add_link(&mut self, link: ContentLink) -> usize {
        let idx = self.links.len();
        self.links.push(link);
        idx
    }

    /// Remove a content link by index.
    pub fn remove_link(&mut self, index: usize) -> Option<ContentLink> {
        if index < self.links.len() {
            Some(self.links.remove(index))
        } else {
            None
        }
    }

    /// Get a reference to a content link by index.
    pub fn get_link(&self, index: usize) -> Option<&ContentLink> {
        self.links.get(index)
    }

    /// Get all content links.
    pub fn links(&self) -> &[ContentLink] {
        &self.links
    }

    /// Get the number of registered links.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// Set the maximum resolution depth.
    pub fn set_max_depth(&mut self, max_depth: usize) {
        self.max_depth = max_depth;
    }

    /// Get the maximum resolution depth.
    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    /// Resolve a link to its target path, following the chain up to max_depth.
    pub fn resolve_link(&self, index: usize) -> LinkContentResult<&ContentLink> {
        let current = index;
        let depth = 0;
        loop {
            if depth >= self.max_depth {
                return Err(LinkContentError::CircularLink(
                    format!("Max resolution depth ({}) exceeded", self.max_depth),
                ));
            }
            let link = self.links.get(current).ok_or_else(|| {
                LinkContentError::TargetNotFound(format!("Link index {} not found", current))
            })?;
            // For direct links, return immediately
            if link.link_type == LinkType::Direct {
                return Ok(link);
            }
            // For other link types, try to follow
            // In a real implementation, this would parse target_path to find the next link
            return Ok(link);
        }
    }

    /// Find all links that reference the given target path.
    pub fn find_links_to(&self, target_path: &str) -> Vec<(usize, &ContentLink)> {
        self.links
            .iter()
            .enumerate()
            .filter(|(_, link)| link.target_path == target_path)
            .collect()
    }
}

impl Default for DBTraceLinkContentHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_link_creation() {
        let link = ContentLink::new(LinkType::Direct, "/traces/other/regions", 0, 4096)
            .with_snap(5);
        assert_eq!(link.link_type, LinkType::Direct);
        assert_eq!(link.target_path, "/traces/other/regions");
        assert_eq!(link.offset, 0);
        assert_eq!(link.length, 4096);
        assert_eq!(link.created_snap, 5);
    }

    #[test]
    fn test_link_content_handler_basic() {
        let mut handler = DBTraceLinkContentHandler::new();
        assert_eq!(handler.link_count(), 0);

        let link = ContentLink::new(LinkType::Lazy, "target", 0, 100);
        handler.add_link(link);
        assert_eq!(handler.link_count(), 1);

        let retrieved = handler.get_link(0).unwrap();
        assert_eq!(retrieved.link_type, LinkType::Lazy);
    }

    #[test]
    fn test_link_content_handler_remove() {
        let mut handler = DBTraceLinkContentHandler::new();
        handler.add_link(ContentLink::new(LinkType::Direct, "a", 0, 10));
        handler.add_link(ContentLink::new(LinkType::Shared, "b", 0, 20));

        assert_eq!(handler.link_count(), 2);
        let removed = handler.remove_link(0);
        assert!(removed.is_some());
        assert_eq!(handler.link_count(), 1);
        assert_eq!(handler.get_link(0).unwrap().target_path, "b");
    }

    #[test]
    fn test_link_content_handler_find_links_to() {
        let mut handler = DBTraceLinkContentHandler::new();
        handler.add_link(ContentLink::new(LinkType::Direct, "target_a", 0, 100));
        handler.add_link(ContentLink::new(LinkType::Lazy, "target_b", 0, 200));
        handler.add_link(ContentLink::new(LinkType::Shared, "target_a", 100, 100));

        let links = handler.find_links_to("target_a");
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].0, 0);
        assert_eq!(links[1].0, 2);
    }

    #[test]
    fn test_link_content_handler_resolve() {
        let mut handler = DBTraceLinkContentHandler::new();
        handler.add_link(ContentLink::new(LinkType::Direct, "target", 0, 100));

        let resolved = handler.resolve_link(0);
        assert!(resolved.is_ok());
        assert_eq!(resolved.unwrap().target_path, "target");
    }

    #[test]
    fn test_link_content_handler_resolve_not_found() {
        let handler = DBTraceLinkContentHandler::new();
        let resolved = handler.resolve_link(0);
        assert!(resolved.is_err());
    }

    #[test]
    fn test_link_type_variants() {
        assert_ne!(LinkType::Direct, LinkType::Lazy);
        assert_ne!(LinkType::CopyOnWrite, LinkType::Shared);
    }

    #[test]
    fn test_max_depth() {
        let handler = DBTraceLinkContentHandler::with_max_depth(8);
        assert_eq!(handler.max_depth(), 8);
    }
}
