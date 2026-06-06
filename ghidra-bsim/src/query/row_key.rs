//! Abstract row key for BSim database records.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.description.RowKey`.

/// An abstract key used to identify rows in BSim database tables.
///
/// Each `RowKey` holds at least a 64-bit long value that serves as the
/// (least significant) portion of the key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RowKey {
    /// The 64-bit long value of this row key.
    pub long_value: u64,
    /// Optional string identifier (for SQL-based keys).
    pub string_id: Option<String>,
}

impl RowKey {
    /// Create a new RowKey with the given 64-bit value.
    pub fn new(long_value: u64) -> Self {
        Self {
            long_value,
            string_id: None,
        }
    }

    /// Create a new RowKey with a 64-bit value and optional string ID.
    pub fn with_string(long_value: u64, string_id: String) -> Self {
        Self {
            long_value,
            string_id: Some(string_id),
        }
    }

    /// Get the (least significant) 64-bits of the row key.
    pub fn get_long(&self) -> u64 {
        self.long_value
    }

    /// Get the optional string identifier.
    pub fn string_id(&self) -> Option<&str> {
        self.string_id.as_deref()
    }
}

impl Default for RowKey {
    fn default() -> Self {
        Self::new(0)
    }
}

impl PartialOrd for RowKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RowKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.long_value.cmp(&other.long_value)
    }
}

impl std::fmt::Display for RowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.string_id {
            Some(id) => write!(f, "RowKey({}, {})", self.long_value, id),
            None => write!(f, "RowKey({})", self.long_value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let k = RowKey::new(42);
        assert_eq!(k.get_long(), 42);
        assert!(k.string_id().is_none());
    }

    #[test]
    fn test_with_string() {
        let k = RowKey::with_string(100, "abc".to_string());
        assert_eq!(k.get_long(), 100);
        assert_eq!(k.string_id(), Some("abc"));
    }

    #[test]
    fn test_ordering() {
        let a = RowKey::new(1);
        let b = RowKey::new(2);
        assert!(a < b);
    }

    #[test]
    fn test_display() {
        let k = RowKey::new(42);
        assert_eq!(format!("{}", k), "RowKey(42)");

        let k2 = RowKey::with_string(100, "test".to_string());
        assert_eq!(format!("{}", k2), "RowKey(100, test)");
    }

    #[test]
    fn test_default() {
        let k = RowKey::default();
        assert_eq!(k.get_long(), 0);
    }
}
