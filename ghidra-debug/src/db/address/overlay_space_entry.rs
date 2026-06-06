//! DBTraceOverlaySpaceEntry persisted overlay record.

/// A persisted overlay address space entry.
#[derive(Debug, Clone)]
pub struct DbTraceOverlaySpaceEntry {
    /// Row key.
    pub key: i64,
    /// Overlay space name.
    pub name: String,
    /// Base space name.
    pub base_space: String,
}

impl DbTraceOverlaySpaceEntry {
    /// Create a new entry.
    pub fn new(key: i64, name: impl Into<String>, base_space: impl Into<String>) -> Self {
        Self {
            key,
            name: name.into(),
            base_space: base_space.into(),
        }
    }
}
