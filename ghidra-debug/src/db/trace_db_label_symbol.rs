//! Label symbol implementation for the trace database.
//!
//! Ported from Ghidra's `DBTraceLabelSymbol` in
//! `ghidra.trace.database.symbol`. Labels are the most common symbol
//! type, associating a name with an address in a trace.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A label symbol entry in the trace database.
///
/// Ported from Ghidra's `DBTraceLabelSymbol`. Labels associate a
/// human-readable name with a specific address and time range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceLabelSymbol {
    /// Database row ID.
    pub id: i64,
    /// The label name.
    pub name: String,
    /// Parent namespace ID.
    pub parent_id: i64,
    /// Address space name.
    pub address_space: String,
    /// Address offset within the space.
    pub address_offset: u64,
    /// Source type (user, analysis, etc.).
    pub source: u8,
    /// Whether this is a primary label at its address.
    pub is_primary: bool,
    /// The lifespan during which this label exists.
    pub min_snap: i64,
    pub max_snap: i64,
}

impl DbTraceLabelSymbol {
    /// Create a new label symbol.
    pub fn new(
        id: i64,
        name: impl Into<String>,
        parent_id: i64,
        address_space: impl Into<String>,
        address_offset: u64,
        source: u8,
        is_primary: bool,
        min_snap: i64,
        max_snap: i64,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            parent_id,
            address_space: address_space.into(),
            address_offset,
            source,
            is_primary,
            min_snap,
            max_snap,
        }
    }

    /// Get the lifespan of this label.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }

    /// Whether this label is active at the given snap.
    pub fn is_active_at(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }

    /// Get the full address as (space, offset).
    pub fn address(&self) -> (&str, u64) {
        (&self.address_space, self.address_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_creation() {
        let label = DbTraceLabelSymbol::new(
            1, "main", 0, "ram", 0x1000, 0, true, 0, 100,
        );
        assert_eq!(label.name, "main");
        assert_eq!(label.address_offset, 0x1000);
        assert!(label.is_primary);
    }

    #[test]
    fn test_label_lifespan() {
        let label = DbTraceLabelSymbol::new(
            1, "func", 0, "ram", 0x2000, 0, false, 10, 50,
        );
        assert_eq!(label.lifespan(), Lifespan::span(10, 50));
        assert!(label.is_active_at(25));
        assert!(!label.is_active_at(5));
        assert!(!label.is_active_at(60));
    }

    #[test]
    fn test_label_address() {
        let label = DbTraceLabelSymbol::new(
            1, "sym", 0, "code", 0xABCD, 0, true, 0, 100,
        );
        let (space, offset) = label.address();
        assert_eq!(space, "code");
        assert_eq!(offset, 0xABCD);
    }
}
