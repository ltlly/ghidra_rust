//! TraceMemoryState - the observation state of memory at a snapshot.

use serde::{Deserialize, Serialize};

/// The state of a memory value at a given snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceMemoryState {
    /// The value was not observed at the snapshot.
    Unknown,
    /// The value was observed at the snapshot.
    Known,
    /// The value could not be observed at the snapshot.
    Error,
}

impl TraceMemoryState {
    /// The default state when the value is null in the database.
    pub const IMPLIED_BY_NULL: TraceMemoryState = TraceMemoryState::Unknown;

    /// Interpret a nullable state: null maps to `IMPLIED_BY_NULL`.
    pub fn or_implied(s: Option<Self>) -> Self {
        s.unwrap_or(Self::IMPLIED_BY_NULL)
    }

    /// Whether this state is implied by a null database entry.
    pub fn implied_by_null(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Whether this state causes truncation of a read.
    pub fn truncates(&self) -> bool {
        matches!(self, Self::Known)
    }
}

/// A region of memory with a known state in a trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceMemoryRegion {
    /// Start offset of the region.
    pub min_offset: u64,
    /// End offset of the region.
    pub max_offset: u64,
    /// The state of memory in this region.
    pub state: TraceMemoryState,
}

impl TraceMemoryRegion {
    /// Create a new memory region.
    pub fn new(min_offset: u64, max_offset: u64, state: TraceMemoryState) -> Self {
        Self {
            min_offset,
            max_offset,
            state,
        }
    }

    /// Size of this region in bytes.
    pub fn size(&self) -> u64 {
        self.max_offset - self.min_offset + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_implied_by_null() {
        assert!(TraceMemoryState::Unknown.implied_by_null());
        assert!(!TraceMemoryState::Known.implied_by_null());
        assert!(!TraceMemoryState::Error.implied_by_null());
    }

    #[test]
    fn test_or_implied() {
        assert_eq!(
            TraceMemoryState::or_implied(None),
            TraceMemoryState::Unknown
        );
        assert_eq!(
            TraceMemoryState::or_implied(Some(TraceMemoryState::Known)),
            TraceMemoryState::Known
        );
    }

    #[test]
    fn test_truncates() {
        assert!(TraceMemoryState::Known.truncates());
        assert!(!TraceMemoryState::Unknown.truncates());
    }

    #[test]
    fn test_region_size() {
        let r = TraceMemoryRegion::new(0x100, 0x1FF, TraceMemoryState::Known);
        assert_eq!(r.size(), 256);
    }

    #[test]
    fn test_serde() {
        let state = TraceMemoryState::Error;
        let json = serde_json::to_string(&state).unwrap();
        let back: TraceMemoryState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}
