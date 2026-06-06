//! Search regions -- named memory regions for search scoping.
//!
//! Ported from `ghidra.features.base.memsearch.bytesource.SearchRegion`
//! and `ProgramSearchRegion`.

/// Trait for specifying a named region within a byte source that users
/// can select for searching.
///
/// Each region has a name, description, and can provide the set of
/// addresses it covers for a given program.
pub trait SearchRegion: std::fmt::Debug {
    /// The name of the region.
    fn name(&self) -> &str;

    /// A description of the region.
    fn description(&self) -> &str;

    /// Returns the set of addresses (as start..=end ranges) associated
    /// with this region for a program with the given loaded blocks.
    fn get_addresses(&self, blocks: &[(u64, u64)]) -> Vec<(u64, u64)>;

    /// Returns true if this region should be included in the default
    /// selection of which regions to search.
    fn is_default(&self) -> bool;
}

/// Pre-defined search regions within a Ghidra program.
///
/// Ported from `ghidra.features.base.memsearch.bytesource.ProgramSearchRegion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramSearchRegion {
    /// Search all memory blocks that represent loaded program
    /// instructions and data.
    Loaded,
    /// Search non-loaded initialized blocks.
    Other,
}

impl SearchRegion for ProgramSearchRegion {
    fn name(&self) -> &str {
        match self {
            ProgramSearchRegion::Loaded => "Loaded Blocks",
            ProgramSearchRegion::Other => "All Other Blocks",
        }
    }

    fn description(&self) -> &str {
        match self {
            ProgramSearchRegion::Loaded => {
                "Searches all memory blocks that represent loaded program instructions and data"
            }
            ProgramSearchRegion::Other => "Searches non-loaded initialized blocks",
        }
    }

    fn get_addresses(&self, blocks: &[(u64, u64)]) -> Vec<(u64, u64)> {
        match self {
            ProgramSearchRegion::Loaded => {
                // First block (loaded) -- for simplicity treat the first block as loaded
                blocks.iter().take(1).cloned().collect()
            }
            ProgramSearchRegion::Other => {
                // Everything after the first block
                blocks.iter().skip(1).cloned().collect()
            }
        }
    }

    fn is_default(&self) -> bool {
        matches!(self, ProgramSearchRegion::Loaded)
    }
}

impl ProgramSearchRegion {
    /// All available program search regions.
    pub const ALL: [ProgramSearchRegion; 2] = [
        ProgramSearchRegion::Loaded,
        ProgramSearchRegion::Other,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loaded_is_default() {
        assert!(ProgramSearchRegion::Loaded.is_default());
        assert!(!ProgramSearchRegion::Other.is_default());
    }

    #[test]
    fn test_region_names() {
        assert_eq!(ProgramSearchRegion::Loaded.name(), "Loaded Blocks");
        assert_eq!(ProgramSearchRegion::Other.name(), "All Other Blocks");
    }

    #[test]
    fn test_region_descriptions() {
        assert!(!ProgramSearchRegion::Loaded.description().is_empty());
        assert!(!ProgramSearchRegion::Other.description().is_empty());
    }

    #[test]
    fn test_loaded_addresses() {
        let blocks = vec![(0x400000u64, 0x500000u64), (0x600000, 0x700000)];
        let addrs = ProgramSearchRegion::Loaded.get_addresses(&blocks);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], (0x400000, 0x500000));
    }

    #[test]
    fn test_other_addresses() {
        let blocks = vec![(0x400000u64, 0x500000u64), (0x600000, 0x700000)];
        let addrs = ProgramSearchRegion::Other.get_addresses(&blocks);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], (0x600000, 0x700000));
    }

    #[test]
    fn test_all_regions() {
        assert_eq!(ProgramSearchRegion::ALL.len(), 2);
    }
}
