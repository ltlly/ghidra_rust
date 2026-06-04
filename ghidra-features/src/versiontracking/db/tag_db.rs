//! Database-backed VTMatchTag.

use crate::versiontracking::types::VtMatchTag;

/// Database-backed match tag.
///
/// Maps to a row in the match tag table.
#[derive(Debug, Clone)]
pub struct VtMatchTagDB {
    /// Database key
    pub key: i64,
    /// Tag name
    name: String,
}

impl VtMatchTagDB {
    /// Create a new tag DB record.
    pub fn new(key: i64, name: &str) -> Self {
        Self {
            key,
            name: name.to_string(),
        }
    }

    /// Returns the tag name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the database key.
    pub fn get_key(&self) -> i64 {
        self.key
    }

    /// Convert to a VtMatchTag.
    pub fn to_tag(&self) -> VtMatchTag {
        VtMatchTag::new(&self.name)
    }

    /// Create from a VtMatchTag.
    pub fn from_tag(key: i64, tag: &VtMatchTag) -> Self {
        Self {
            key,
            name: tag.name().to_string(),
        }
    }
}

impl std::fmt::Display for VtMatchTagDB {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TagDB(key={}, name={})", self.key, self.name)
    }
}

impl PartialEq for VtMatchTagDB {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for VtMatchTagDB {}

impl PartialOrd for VtMatchTagDB {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VtMatchTagDB {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_db_create() {
        let tag = VtMatchTagDB::new(1, "verified");
        assert_eq!(tag.key, 1);
        assert_eq!(tag.name(), "verified");
    }

    #[test]
    fn test_tag_db_roundtrip() {
        let tag = VtMatchTag::new("test_tag");
        let db = VtMatchTagDB::from_tag(5, &tag);
        assert_eq!(db.get_key(), 5);
        let restored = db.to_tag();
        assert_eq!(restored.name(), "test_tag");
    }

    #[test]
    fn test_tag_db_ordering() {
        let a = VtMatchTagDB::new(1, "alpha");
        let b = VtMatchTagDB::new(2, "beta");
        assert!(a < b);
    }

    #[test]
    fn test_tag_db_equality() {
        let a = VtMatchTagDB::new(1, "same");
        let b = VtMatchTagDB::new(2, "same");
        assert_eq!(a, b);
    }
}
