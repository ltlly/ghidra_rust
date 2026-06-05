//! Search region factory for the debugger memory search.
//!
//! Ported from Ghidra's `DebuggerSearchRegionFactory`.
//!
//! Provides types for defining memory search scopes in the debugger:
//! full address space, readable, writable, or executable addresses.

use serde::{Deserialize, Serialize};

/// The type of memory region filter for searching.
///
/// Ported from Ghidra's `DebuggerSearchRegionFactory` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SearchRegionFilter {
    /// Search all addresses in the space.
    FullSpace,
    /// Search only readable addresses.
    Readable,
    /// Search only writable addresses.
    Writable,
    /// Search only executable addresses.
    Executable,
}

impl Default for SearchRegionFilter {
    fn default() -> Self {
        Self::Readable
    }
}

impl std::fmt::Display for SearchRegionFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullSpace => write!(f, "All Addresses"),
            Self::Readable => write!(f, "Readable Addresses"),
            Self::Writable => write!(f, "Writable Addresses"),
            Self::Executable => write!(f, "Executable Addresses"),
        }
    }
}

impl SearchRegionFilter {
    /// Get the description of this search region filter.
    pub fn description(&self) -> &'static str {
        match self {
            Self::FullSpace => "Searches all memory in the space, regardless of known validity.",
            Self::Readable => "Searches listed regions marked as readable in the space.",
            Self::Writable => "Searches listed regions marked as writable in the space.",
            Self::Executable => "Searches listed regions marked as executable in the space.",
        }
    }

    /// Check if a region with the given flags matches this filter.
    pub fn matches(&self, readable: bool, writable: bool, executable: bool) -> bool {
        match self {
            Self::FullSpace => true,
            Self::Readable => readable,
            Self::Writable => writable,
            Self::Executable => executable,
        }
    }

    /// Check if this filter is the default for a given address space.
    pub fn is_default_for_space(&self, _space: Option<&str>) -> bool {
        matches!(self, Self::Readable)
    }
}

/// A search region with filter and optional address space scope.
///
/// Ported from Ghidra's `DebuggerSearchRegionFactory.DebuggerSearchRegion`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchRegion {
    /// The filter type.
    pub filter: SearchRegionFilter,
    /// The address space name (None means all spaces).
    pub space_name: Option<String>,
}

impl SearchRegion {
    /// Create a new search region.
    pub fn new(filter: SearchRegionFilter) -> Self {
        Self {
            filter,
            space_name: None,
        }
    }

    /// Create a search region scoped to a specific address space.
    pub fn with_space(mut self, space: impl Into<String>) -> Self {
        self.space_name = Some(space.into());
        self
    }

    /// Get the display name for this search region.
    pub fn name(&self) -> String {
        match &self.space_name {
            Some(space) => format!("{} ({})", self.filter, space),
            None => self.filter.to_string(),
        }
    }

    /// Get the description for this search region.
    pub fn description(&self) -> &'static str {
        self.filter.description()
    }
}

/// All available search region filters.
pub const ALL_SEARCH_REGION_FILTERS: &[SearchRegionFilter] = &[
    SearchRegionFilter::FullSpace,
    SearchRegionFilter::Readable,
    SearchRegionFilter::Writable,
    SearchRegionFilter::Executable,
];

/// Create all search regions for a set of address spaces.
pub fn create_search_regions(spaces: &[String]) -> Vec<SearchRegion> {
    let mut regions = Vec::new();
    // Add filter without specific space (applies to all spaces)
    for &filter in ALL_SEARCH_REGION_FILTERS {
        regions.push(SearchRegion::new(filter));
    }
    // Add filters per-space
    for space in spaces {
        for &filter in ALL_SEARCH_REGION_FILTERS {
            regions.push(SearchRegion::new(filter).with_space(space));
        }
    }
    regions
}

/// Default emulator factory configuration.
///
/// Ported from Ghidra's `DefaultEmulatorFactory`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultEmulatorFactory {
    /// The title for this emulator factory.
    pub title: String,
}

impl DefaultEmulatorFactory {
    /// The default title.
    pub const TITLE: &'static str = "Default Concrete P-code Emulator";

    /// Create a new default emulator factory.
    pub fn new() -> Self {
        Self {
            title: Self::TITLE.to_string(),
        }
    }
}

impl Default for DefaultEmulatorFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_region_filter_display() {
        assert_eq!(SearchRegionFilter::FullSpace.to_string(), "All Addresses");
        assert_eq!(SearchRegionFilter::Readable.to_string(), "Readable Addresses");
        assert_eq!(SearchRegionFilter::Writable.to_string(), "Writable Addresses");
        assert_eq!(SearchRegionFilter::Executable.to_string(), "Executable Addresses");
    }

    #[test]
    fn test_search_region_filter_matches() {
        assert!(SearchRegionFilter::FullSpace.matches(false, false, false));
        assert!(SearchRegionFilter::Readable.matches(true, false, false));
        assert!(!SearchRegionFilter::Readable.matches(false, true, false));
        assert!(SearchRegionFilter::Writable.matches(false, true, false));
        assert!(SearchRegionFilter::Executable.matches(false, false, true));
    }

    #[test]
    fn test_search_region_filter_description() {
        assert!(!SearchRegionFilter::FullSpace.description().is_empty());
        assert!(!SearchRegionFilter::Readable.description().is_empty());
    }

    #[test]
    fn test_search_region_name() {
        let region = SearchRegion::new(SearchRegionFilter::Readable);
        assert_eq!(region.name(), "Readable Addresses");

        let region = SearchRegion::new(SearchRegionFilter::Executable).with_space("ram");
        assert_eq!(region.name(), "Executable Addresses (ram)");
    }

    #[test]
    fn test_create_search_regions() {
        let spaces = vec!["ram".to_string(), "register".to_string()];
        let regions = create_search_regions(&spaces);
        // 4 global + 4 per space * 2 spaces = 12
        assert_eq!(regions.len(), 12);
    }

    #[test]
    fn test_default_emulator_factory() {
        let factory = DefaultEmulatorFactory::new();
        assert_eq!(factory.title, DefaultEmulatorFactory::TITLE);
    }

    #[test]
    fn test_search_region_filter_default() {
        assert_eq!(SearchRegionFilter::default(), SearchRegionFilter::Readable);
    }

    #[test]
    fn test_all_search_region_filters() {
        assert_eq!(ALL_SEARCH_REGION_FILTERS.len(), 4);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let region = SearchRegion::new(SearchRegionFilter::Writable).with_space("stack");
        let json = serde_json::to_string(&region).unwrap();
        let deserialized: SearchRegion = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.filter, SearchRegionFilter::Writable);
        assert_eq!(deserialized.space_name.as_deref(), Some("stack"));
    }
}
