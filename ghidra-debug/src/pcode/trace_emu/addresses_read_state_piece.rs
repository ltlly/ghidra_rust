//! AddressesReadTracePcodeExecutorStatePiece ported from
//! AddressesReadTracePcodeExecutorStatePiece.java.
//!
//! Tracks which addresses have been read during pcode execution.

use std::collections::BTreeSet;

/// Tracks addresses read during pcode execution.
#[derive(Debug, Default)]
pub struct AddressesReadTracePcodeExecutorStatePiece {
    /// Set of (space_name, offset) pairs that have been read.
    read_addresses: BTreeSet<(String, u64)>,
}

impl AddressesReadTracePcodeExecutorStatePiece {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a read at the given address.
    pub fn record_read(&mut self, space: impl Into<String>, offset: u64) {
        self.read_addresses.insert((space.into(), offset));
    }

    /// Check if an address has been read.
    pub fn was_read(&self, space: &str, offset: u64) -> bool {
        self.read_addresses.contains(&(space.to_string(), offset))
    }

    /// Get all read addresses.
    pub fn read_addresses(&self) -> &BTreeSet<(String, u64)> {
        &self.read_addresses
    }

    /// Clear all recorded reads.
    pub fn clear(&mut self) {
        self.read_addresses.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_check() {
        let mut piece = AddressesReadTracePcodeExecutorStatePiece::new();
        piece.record_read("ram", 0x1000);
        assert!(piece.was_read("ram", 0x1000));
        assert!(!piece.was_read("ram", 0x2000));
    }

    #[test]
    fn test_clear() {
        let mut piece = AddressesReadTracePcodeExecutorStatePiece::new();
        piece.record_read("ram", 0x100);
        piece.clear();
        assert!(!piece.was_read("ram", 0x100));
    }
}
