//! `MemoryMatch` -- a single search hit at an address.
//!
//! Ported from `ghidra.features.base.memsearch.searcher.MemoryMatch`.

/// A memory search hit at a specific address.
///
/// Matches can be updated with new byte values (from a scan or refresh
/// action). The original bytes that matched the initial search are
/// maintained in addition to the "refreshed" bytes.
///
/// Ported from `MemoryMatch.java`.
#[derive(Debug, Clone)]
pub struct MemoryMatch {
    /// The address where the match was found.
    address: u64,
    /// The current byte values at the match location.
    current_bytes: Vec<u8>,
    /// The previous byte values (before last update).
    previous_bytes: Vec<u8>,
}

impl MemoryMatch {
    /// Create a new memory match.
    pub fn new(address: u64, bytes: Vec<u8>) -> Self {
        assert!(!bytes.is_empty(), "Must provide at least 1 byte");
        Self {
            address,
            previous_bytes: bytes.clone(),
            current_bytes: bytes,
        }
    }

    /// Create a memory match with minimal data (address only).
    pub fn at_address(address: u64) -> Self {
        Self {
            address,
            current_bytes: Vec::new(),
            previous_bytes: Vec::new(),
        }
    }

    /// Update the bytes at this match location (e.g., after a refresh).
    ///
    /// The current bytes become the previous bytes, and the new bytes
    /// become the current bytes. This allows comparing old and new values
    /// using the [`has_changed`](MemoryMatch::has_changed) method.
    ///
    /// Note: the previous bytes are always updated to the old current value,
    /// even if the new bytes are the same. This allows scan algorithms to
    /// compare before and after refreshes.
    pub fn update_bytes(&mut self, new_bytes: Vec<u8>) {
        self.previous_bytes = self.current_bytes.clone();
        self.current_bytes = new_bytes;
    }

    /// Get the address of this match.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the length of the match in bytes.
    pub fn length(&self) -> usize {
        self.current_bytes.len()
    }

    /// Get the current byte values.
    pub fn current_bytes(&self) -> &[u8] {
        &self.current_bytes
    }

    /// Get the previous byte values.
    pub fn previous_bytes(&self) -> &[u8] {
        &self.previous_bytes
    }

    /// Check if the bytes have changed since the last update.
    pub fn has_changed(&self) -> bool {
        self.current_bytes != self.previous_bytes
    }
}

impl PartialOrd for MemoryMatch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MemoryMatch {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

impl PartialEq for MemoryMatch {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address
    }
}

impl Eq for MemoryMatch {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_match() {
        let m = MemoryMatch::new(0x401000, vec![0x55, 0x89, 0xE5]);
        assert_eq!(m.address(), 0x401000);
        assert_eq!(m.length(), 3);
        assert_eq!(m.current_bytes(), &[0x55, 0x89, 0xE5]);
        assert_eq!(m.previous_bytes(), &[0x55, 0x89, 0xE5]);
    }

    #[test]
    fn test_update_bytes() {
        let mut m = MemoryMatch::new(0x401000, vec![0x55, 0x89]);
        assert!(!m.has_changed());

        m.update_bytes(vec![0x56, 0x89]);
        assert!(m.has_changed());
        assert_eq!(m.current_bytes(), &[0x56, 0x89]);
        assert_eq!(m.previous_bytes(), &[0x55, 0x89]);
    }

    #[test]
    fn test_ordering() {
        let m1 = MemoryMatch::new(0x1000, vec![0x55]);
        let m2 = MemoryMatch::new(0x2000, vec![0x55]);
        assert!(m1 < m2);
    }

    #[test]
    fn test_equality() {
        let m1 = MemoryMatch::new(0x1000, vec![0x55]);
        let m2 = MemoryMatch::new(0x1000, vec![0x89]);
        assert_eq!(m1, m2); // equality is by address only
    }

    #[test]
    fn test_at_address() {
        let m = MemoryMatch::at_address(0x401000);
        assert_eq!(m.address(), 0x401000);
        assert_eq!(m.length(), 0);
    }
}
