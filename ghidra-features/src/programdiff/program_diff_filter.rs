//! Advanced program diff filter with category presets and named filter sets.
//!
//! Ported from Ghidra's `ghidra.program.util.ProgramDiffFilter` Java class
//! (the enhanced version with category names, presets, and display labels).
//!
//! This module extends the basic bitmask-based [`ProgramDiffFilter`] defined
//! in the parent module with:
//!
//! - human-readable category names and labels
//! - preset filter configurations (all, none, code-only, data-only, etc.)
//! - filter builder pattern for constructing complex filters
//! - display-oriented helpers for UI integration
//!
//! # Key types
//!
//! - [`FilterCategory`] -- enumeration of diff filter categories with labels
//! - [`FilterPreset`] -- predefined filter configurations
//! - [`ProgramDiffFilterBuilder`] -- builder for constructing filters

use super::ProgramDiffFilter;

// ---------------------------------------------------------------------------
// FilterCategory
// ---------------------------------------------------------------------------

/// A named category of diff filter flags.
///
/// Each variant pairs a [`ProgramDiffFilter`] flag with its human-readable
/// label, description, and group membership for UI presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterCategory {
    /// Program bytes (memory content).
    Bytes,
    /// Code units (instructions and data).
    CodeUnits,
    /// Defined data types.
    DataTypes,
    /// Symbols (labels, functions, etc.).
    Symbols,
    /// Equates (named constants).
    Equates,
    /// Bookmarks.
    Bookmarks,
    /// Comments (plate, pre, end-of-line, repeatable).
    Comments,
    /// Function signatures and properties.
    Functions,
    /// Register variable references.
    Registers,
    /// User-defined properties / settings.
    Properties,
    /// Reference relationships.
    References,
    /// Memory blocks.
    MemoryBlocks,
    /// Imported/exported external symbols.
    Externals,
    /// Analysis options.
    Options,
    /// Relocation records.
    Relocations,
}

impl FilterCategory {
    /// All filter categories in display order.
    pub const ALL: &[FilterCategory] = &[
        Self::Bytes,
        Self::CodeUnits,
        Self::DataTypes,
        Self::Symbols,
        Self::Equates,
        Self::Bookmarks,
        Self::Comments,
        Self::Functions,
        Self::Registers,
        Self::Properties,
        Self::References,
        Self::MemoryBlocks,
        Self::Externals,
        Self::Options,
        Self::Relocations,
    ];

    /// Get the corresponding [`ProgramDiffFilter`] flag for this category.
    pub fn flag(&self) -> ProgramDiffFilter {
        match self {
            Self::Bytes => ProgramDiffFilter::BYTES,
            Self::CodeUnits => ProgramDiffFilter::CODE_UNITS,
            Self::DataTypes => ProgramDiffFilter::DATA_TYPES,
            Self::Symbols => ProgramDiffFilter::SYMBOLS,
            Self::Equates => ProgramDiffFilter::EQUATES,
            Self::Bookmarks => ProgramDiffFilter::BOOKMARKS,
            Self::Comments => ProgramDiffFilter::COMMENTS,
            Self::Functions => ProgramDiffFilter::FUNCTIONS,
            Self::Registers => ProgramDiffFilter::REGISTERS,
            Self::Properties => ProgramDiffFilter::PROPERTIES,
            Self::References => ProgramDiffFilter::REFERENCES,
            Self::MemoryBlocks => ProgramDiffFilter::MEMORY_BLOCKS,
            Self::Externals => ProgramDiffFilter::EXTERNALS,
            Self::Options => ProgramDiffFilter::OPTIONS,
            Self::Relocations => ProgramDiffFilter::RELOCATIONS,
        }
    }

    /// Get a human-readable label for this category.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Bytes => "Bytes",
            Self::CodeUnits => "Code Units",
            Self::DataTypes => "Data Types",
            Self::Symbols => "Symbols",
            Self::Equates => "Equates",
            Self::Bookmarks => "Bookmarks",
            Self::Comments => "Comments",
            Self::Functions => "Functions",
            Self::Registers => "Registers",
            Self::Properties => "Properties",
            Self::References => "References",
            Self::MemoryBlocks => "Memory Blocks",
            Self::Externals => "Externals",
            Self::Options => "Options",
            Self::Relocations => "Relocations",
        }
    }

    /// Get a description of what this category compares.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Bytes => "Compare program bytes (memory content).",
            Self::CodeUnits => "Compare code units (instructions and data).",
            Self::DataTypes => "Compare defined data types.",
            Self::Symbols => "Compare symbols (labels, functions, etc.).",
            Self::Equates => "Compare equates (named constants).",
            Self::Bookmarks => "Compare bookmarks.",
            Self::Comments => "Compare comments (plate, pre, end-of-line, repeatable).",
            Self::Functions => "Compare function signatures and properties.",
            Self::Registers => "Compare register variable references.",
            Self::Properties => "Compare user-defined properties / settings.",
            Self::References => "Compare reference relationships.",
            Self::MemoryBlocks => "Compare memory blocks.",
            Self::Externals => "Compare imported/exported external symbols.",
            Self::Options => "Compare analysis options.",
            Self::Relocations => "Compare relocation records.",
        }
    }

    /// Get the group this category belongs to (for UI grouping).
    pub fn group(&self) -> FilterGroup {
        match self {
            Self::Bytes | Self::CodeUnits | Self::MemoryBlocks => FilterGroup::Memory,
            Self::DataTypes | Self::Symbols | Self::Equates | Self::Registers => FilterGroup::Data,
            Self::Comments => FilterGroup::Comments,
            Self::Functions => FilterGroup::Functions,
            Self::References | Self::Externals => FilterGroup::References,
            Self::Bookmarks | Self::Properties | Self::Options | Self::Relocations => {
                FilterGroup::Metadata
            }
        }
    }

    /// Get the category from a [`ProgramDiffFilter`] flag, if it matches exactly one.
    pub fn from_flag(flag: ProgramDiffFilter) -> Option<FilterCategory> {
        for cat in Self::ALL {
            if cat.flag() == flag {
                return Some(*cat);
            }
        }
        None
    }
}

impl std::fmt::Display for FilterCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// FilterGroup
// ---------------------------------------------------------------------------

/// Groups of related filter categories for UI organization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterGroup {
    /// Memory-related categories (bytes, code units, memory blocks).
    Memory,
    /// Data-related categories (data types, symbols, equates, registers).
    Data,
    /// Comment categories.
    Comments,
    /// Function-related categories.
    Functions,
    /// Reference-related categories (references, externals).
    References,
    /// Metadata categories (bookmarks, properties, options, relocations).
    Metadata,
}

impl FilterGroup {
    /// All filter groups in display order.
    pub const ALL: &[FilterGroup] = &[
        Self::Memory,
        Self::Data,
        Self::Comments,
        Self::Functions,
        Self::References,
        Self::Metadata,
    ];

    /// Get a human-readable label for this group.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Memory => "Memory",
            Self::Data => "Data",
            Self::Comments => "Comments",
            Self::Functions => "Functions",
            Self::References => "References",
            Self::Metadata => "Metadata",
        }
    }

    /// Get all categories in this group.
    pub fn categories(&self) -> Vec<FilterCategory> {
        FilterCategory::ALL
            .iter()
            .filter(|cat| cat.group() == *self)
            .copied()
            .collect()
    }

    /// Get the combined filter flag for all categories in this group.
    pub fn combined_flag(&self) -> ProgramDiffFilter {
        let mut result = ProgramDiffFilter::empty();
        for cat in self.categories() {
            result |= cat.flag();
        }
        result
    }
}

impl std::fmt::Display for FilterGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// FilterPreset
// ---------------------------------------------------------------------------

/// Predefined filter configurations for common diff scenarios.
///
/// Ported from Ghidra's filter presets used in the diff dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterPreset {
    /// Compare everything.
    All,
    /// Compare nothing (empty filter).
    None,
    /// Compare only code-related aspects (bytes, code units, functions).
    CodeOnly,
    /// Compare only data-related aspects (data types, symbols, equates).
    DataOnly,
    /// Compare only comments.
    CommentsOnly,
    /// Compare only metadata (bookmarks, properties, options, relocations).
    MetadataOnly,
    /// Compare memory layout and bytes.
    MemoryOnly,
    /// Compare symbols and references.
    SymbolsAndReferences,
}

impl FilterPreset {
    /// All presets in display order.
    pub const ALL: &[FilterPreset] = &[
        Self::All,
        Self::None,
        Self::CodeOnly,
        Self::DataOnly,
        Self::CommentsOnly,
        Self::MetadataOnly,
        Self::MemoryOnly,
        Self::SymbolsAndReferences,
    ];

    /// Get the filter configuration for this preset.
    pub fn filter(&self) -> ProgramDiffFilter {
        match self {
            Self::All => ProgramDiffFilter::all(),
            Self::None => ProgramDiffFilter::empty(),
            Self::CodeOnly => {
                ProgramDiffFilter::BYTES
                    | ProgramDiffFilter::CODE_UNITS
                    | ProgramDiffFilter::FUNCTIONS
            }
            Self::DataOnly => {
                ProgramDiffFilter::DATA_TYPES
                    | ProgramDiffFilter::SYMBOLS
                    | ProgramDiffFilter::EQUATES
                    | ProgramDiffFilter::REGISTERS
            }
            Self::CommentsOnly => ProgramDiffFilter::COMMENTS,
            Self::MetadataOnly => {
                ProgramDiffFilter::BOOKMARKS
                    | ProgramDiffFilter::PROPERTIES
                    | ProgramDiffFilter::OPTIONS
                    | ProgramDiffFilter::RELOCATIONS
            }
            Self::MemoryOnly => {
                ProgramDiffFilter::BYTES
                    | ProgramDiffFilter::CODE_UNITS
                    | ProgramDiffFilter::MEMORY_BLOCKS
            }
            Self::SymbolsAndReferences => {
                ProgramDiffFilter::SYMBOLS
                    | ProgramDiffFilter::REFERENCES
                    | ProgramDiffFilter::EXTERNALS
            }
        }
    }

    /// Get a human-readable label for this preset.
    pub fn label(&self) -> &'static str {
        match self {
            Self::All => "All",
            Self::None => "None",
            Self::CodeOnly => "Code Only",
            Self::DataOnly => "Data Only",
            Self::CommentsOnly => "Comments Only",
            Self::MetadataOnly => "Metadata Only",
            Self::MemoryOnly => "Memory Only",
            Self::SymbolsAndReferences => "Symbols and References",
        }
    }

    /// Get a description of this preset.
    pub fn description(&self) -> &'static str {
        match self {
            Self::All => "Compare all aspects of the programs.",
            Self::None => "No comparison (empty filter).",
            Self::CodeOnly => "Compare bytes, code units, and functions.",
            Self::DataOnly => "Compare data types, symbols, equates, and registers.",
            Self::CommentsOnly => "Compare only comments.",
            Self::MetadataOnly => "Compare bookmarks, properties, options, and relocations.",
            Self::MemoryOnly => "Compare memory layout and bytes.",
            Self::SymbolsAndReferences => "Compare symbols, references, and externals.",
        }
    }
}

impl std::fmt::Display for FilterPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// ProgramDiffFilterBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing [`ProgramDiffFilter`] values.
///
/// Provides a fluent API for building filters from categories, groups,
/// or presets.
///
/// # Example
///
/// ```rust
/// use ghidra_features::programdiff::program_diff_filter::*;
/// use ghidra_features::programdiff::ProgramDiffFilter;
///
/// let filter = ProgramDiffFilterBuilder::new()
///     .include(FilterCategory::Bytes)
///     .include(FilterCategory::Symbols)
///     .include(FilterCategory::Comments)
///     .build();
///
/// assert!(filter.contains(ProgramDiffFilter::BYTES));
/// assert!(filter.contains(ProgramDiffFilter::SYMBOLS));
/// assert!(filter.contains(ProgramDiffFilter::COMMENTS));
/// assert!(!filter.contains(ProgramDiffFilter::DATA_TYPES));
/// ```
#[derive(Debug, Clone)]
pub struct ProgramDiffFilterBuilder {
    filter: ProgramDiffFilter,
}

impl ProgramDiffFilterBuilder {
    /// Create a new builder with an empty filter.
    pub fn new() -> Self {
        Self {
            filter: ProgramDiffFilter::empty(),
        }
    }

    /// Create a builder from an existing filter.
    pub fn from_filter(filter: ProgramDiffFilter) -> Self {
        Self { filter }
    }

    /// Create a builder from a preset.
    pub fn from_preset(preset: FilterPreset) -> Self {
        Self {
            filter: preset.filter(),
        }
    }

    /// Include a category in the filter.
    pub fn include(mut self, category: FilterCategory) -> Self {
        self.filter |= category.flag();
        self
    }

    /// Exclude a category from the filter.
    pub fn exclude(mut self, category: FilterCategory) -> Self {
        self.filter.remove(category.flag());
        self
    }

    /// Include all categories in a group.
    pub fn include_group(mut self, group: FilterGroup) -> Self {
        self.filter |= group.combined_flag();
        self
    }

    /// Exclude all categories in a group.
    pub fn exclude_group(mut self, group: FilterGroup) -> Self {
        self.filter.remove(group.combined_flag());
        self
    }

    /// Set a category's inclusion based on a boolean.
    pub fn set(mut self, category: FilterCategory, enabled: bool) -> Self {
        self.filter.set(category.flag(), enabled);
        self
    }

    /// Check if a category is included.
    pub fn has(&self, category: FilterCategory) -> bool {
        self.filter.contains(category.flag())
    }

    /// Get the list of included categories.
    pub fn included_categories(&self) -> Vec<FilterCategory> {
        FilterCategory::ALL
            .iter()
            .filter(|cat| self.filter.contains(cat.flag()))
            .copied()
            .collect()
    }

    /// Get the list of excluded categories.
    pub fn excluded_categories(&self) -> Vec<FilterCategory> {
        FilterCategory::ALL
            .iter()
            .filter(|cat| !self.filter.contains(cat.flag()))
            .copied()
            .collect()
    }

    /// Build the final filter.
    pub fn build(self) -> ProgramDiffFilter {
        self.filter
    }
}

impl Default for ProgramDiffFilterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/// Get a summary string describing which categories are enabled in a filter.
pub fn filter_summary(filter: ProgramDiffFilter) -> String {
    let included: Vec<&str> = FilterCategory::ALL
        .iter()
        .filter(|cat| filter.contains(cat.flag()))
        .map(|cat| cat.label())
        .collect();

    if included.is_empty() {
        "No categories selected".to_string()
    } else if included.len() == FilterCategory::ALL.len() {
        "All categories".to_string()
    } else {
        included.join(", ")
    }
}

/// Get a multi-line description of a filter's state.
pub fn filter_detail(filter: ProgramDiffFilter) -> String {
    let mut lines = Vec::new();
    for group in FilterGroup::ALL {
        let categories = group.categories();
        let any_enabled = categories.iter().any(|cat| filter.contains(cat.flag()));
        if any_enabled {
            lines.push(format!("[{}]", group.label()));
            for cat in &categories {
                let status = if filter.contains(cat.flag()) {
                    "ON"
                } else {
                    "off"
                };
                lines.push(format!("  {} {}", cat.label(), status));
            }
        }
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_category_flag() {
        assert_eq!(FilterCategory::Bytes.flag(), ProgramDiffFilter::BYTES);
        assert_eq!(FilterCategory::Symbols.flag(), ProgramDiffFilter::SYMBOLS);
        assert_eq!(FilterCategory::Comments.flag(), ProgramDiffFilter::COMMENTS);
    }

    #[test]
    fn test_filter_category_label() {
        assert_eq!(FilterCategory::Bytes.label(), "Bytes");
        assert_eq!(FilterCategory::CodeUnits.label(), "Code Units");
        assert_eq!(FilterCategory::MemoryBlocks.label(), "Memory Blocks");
    }

    #[test]
    fn test_filter_category_description() {
        for cat in FilterCategory::ALL {
            assert!(!cat.description().is_empty());
        }
    }

    #[test]
    fn test_filter_category_group() {
        assert_eq!(FilterCategory::Bytes.group(), FilterGroup::Memory);
        assert_eq!(FilterCategory::CodeUnits.group(), FilterGroup::Memory);
        assert_eq!(FilterCategory::MemoryBlocks.group(), FilterGroup::Memory);
        assert_eq!(FilterCategory::Symbols.group(), FilterGroup::Data);
        assert_eq!(FilterCategory::Comments.group(), FilterGroup::Comments);
        assert_eq!(FilterCategory::Functions.group(), FilterGroup::Functions);
        assert_eq!(FilterCategory::References.group(), FilterGroup::References);
        assert_eq!(FilterCategory::Bookmarks.group(), FilterGroup::Metadata);
    }

    #[test]
    fn test_filter_category_from_flag() {
        assert_eq!(
            FilterCategory::from_flag(ProgramDiffFilter::BYTES),
            Some(FilterCategory::Bytes)
        );
        assert_eq!(
            FilterCategory::from_flag(ProgramDiffFilter::SYMBOLS),
            Some(FilterCategory::Symbols)
        );
        // ALL should not match any single category
        assert!(FilterCategory::from_flag(ProgramDiffFilter::ALL).is_none());
        // NONE should not match
        assert!(FilterCategory::from_flag(ProgramDiffFilter::NONE).is_none());
    }

    #[test]
    fn test_filter_category_display() {
        assert_eq!(format!("{}", FilterCategory::Bytes), "Bytes");
        assert_eq!(format!("{}", FilterCategory::Functions), "Functions");
    }

    #[test]
    fn test_filter_category_all_count() {
        assert_eq!(FilterCategory::ALL.len(), 15);
    }

    #[test]
    fn test_filter_group_label() {
        assert_eq!(FilterGroup::Memory.label(), "Memory");
        assert_eq!(FilterGroup::Data.label(), "Data");
        assert_eq!(FilterGroup::Comments.label(), "Comments");
    }

    #[test]
    fn test_filter_group_categories() {
        let memory_cats = FilterGroup::Memory.categories();
        assert_eq!(memory_cats.len(), 3);
        assert!(memory_cats.contains(&FilterCategory::Bytes));
        assert!(memory_cats.contains(&FilterCategory::CodeUnits));
        assert!(memory_cats.contains(&FilterCategory::MemoryBlocks));

        let data_cats = FilterGroup::Data.categories();
        assert_eq!(data_cats.len(), 4);
    }

    #[test]
    fn test_filter_group_combined_flag() {
        let memory_flag = FilterGroup::Memory.combined_flag();
        assert!(memory_flag.contains(ProgramDiffFilter::BYTES));
        assert!(memory_flag.contains(ProgramDiffFilter::CODE_UNITS));
        assert!(memory_flag.contains(ProgramDiffFilter::MEMORY_BLOCKS));
        assert!(!memory_flag.contains(ProgramDiffFilter::SYMBOLS));
    }

    #[test]
    fn test_filter_group_display() {
        assert_eq!(format!("{}", FilterGroup::Memory), "Memory");
    }

    #[test]
    fn test_filter_preset_all() {
        let filter = FilterPreset::All.filter();
        assert_eq!(filter, ProgramDiffFilter::all());
    }

    #[test]
    fn test_filter_preset_none() {
        let filter = FilterPreset::None.filter();
        assert!(filter.is_empty());
    }

    #[test]
    fn test_filter_preset_code_only() {
        let filter = FilterPreset::CodeOnly.filter();
        assert!(filter.contains(ProgramDiffFilter::BYTES));
        assert!(filter.contains(ProgramDiffFilter::CODE_UNITS));
        assert!(filter.contains(ProgramDiffFilter::FUNCTIONS));
        assert!(!filter.contains(ProgramDiffFilter::DATA_TYPES));
        assert!(!filter.contains(ProgramDiffFilter::COMMENTS));
    }

    #[test]
    fn test_filter_preset_data_only() {
        let filter = FilterPreset::DataOnly.filter();
        assert!(filter.contains(ProgramDiffFilter::DATA_TYPES));
        assert!(filter.contains(ProgramDiffFilter::SYMBOLS));
        assert!(filter.contains(ProgramDiffFilter::EQUATES));
        assert!(filter.contains(ProgramDiffFilter::REGISTERS));
        assert!(!filter.contains(ProgramDiffFilter::BYTES));
    }

    #[test]
    fn test_filter_preset_comments_only() {
        let filter = FilterPreset::CommentsOnly.filter();
        assert_eq!(filter, ProgramDiffFilter::COMMENTS);
    }

    #[test]
    fn test_filter_preset_metadata_only() {
        let filter = FilterPreset::MetadataOnly.filter();
        assert!(filter.contains(ProgramDiffFilter::BOOKMARKS));
        assert!(filter.contains(ProgramDiffFilter::PROPERTIES));
        assert!(filter.contains(ProgramDiffFilter::OPTIONS));
        assert!(filter.contains(ProgramDiffFilter::RELOCATIONS));
        assert!(!filter.contains(ProgramDiffFilter::BYTES));
    }

    #[test]
    fn test_filter_preset_memory_only() {
        let filter = FilterPreset::MemoryOnly.filter();
        assert!(filter.contains(ProgramDiffFilter::BYTES));
        assert!(filter.contains(ProgramDiffFilter::CODE_UNITS));
        assert!(filter.contains(ProgramDiffFilter::MEMORY_BLOCKS));
        assert!(!filter.contains(ProgramDiffFilter::SYMBOLS));
    }

    #[test]
    fn test_filter_preset_symbols_and_references() {
        let filter = FilterPreset::SymbolsAndReferences.filter();
        assert!(filter.contains(ProgramDiffFilter::SYMBOLS));
        assert!(filter.contains(ProgramDiffFilter::REFERENCES));
        assert!(filter.contains(ProgramDiffFilter::EXTERNALS));
        assert!(!filter.contains(ProgramDiffFilter::BYTES));
    }

    #[test]
    fn test_filter_preset_label() {
        assert_eq!(FilterPreset::All.label(), "All");
        assert_eq!(FilterPreset::CodeOnly.label(), "Code Only");
        assert_eq!(
            FilterPreset::SymbolsAndReferences.label(),
            "Symbols and References"
        );
    }

    #[test]
    fn test_filter_preset_description() {
        for preset in FilterPreset::ALL {
            assert!(!preset.description().is_empty());
        }
    }

    #[test]
    fn test_filter_preset_display() {
        assert_eq!(format!("{}", FilterPreset::All), "All");
    }

    #[test]
    fn test_builder_basic() {
        let filter = ProgramDiffFilterBuilder::new()
            .include(FilterCategory::Bytes)
            .include(FilterCategory::Symbols)
            .build();

        assert!(filter.contains(ProgramDiffFilter::BYTES));
        assert!(filter.contains(ProgramDiffFilter::SYMBOLS));
        assert!(!filter.contains(ProgramDiffFilter::COMMENTS));
    }

    #[test]
    fn test_builder_exclude() {
        let filter = ProgramDiffFilterBuilder::from_preset(FilterPreset::All)
            .exclude(FilterCategory::Bytes)
            .exclude(FilterCategory::Symbols)
            .build();

        assert!(!filter.contains(ProgramDiffFilter::BYTES));
        assert!(!filter.contains(ProgramDiffFilter::SYMBOLS));
        assert!(filter.contains(ProgramDiffFilter::COMMENTS));
    }

    #[test]
    fn test_builder_include_group() {
        let filter = ProgramDiffFilterBuilder::new()
            .include_group(FilterGroup::Memory)
            .build();

        assert!(filter.contains(ProgramDiffFilter::BYTES));
        assert!(filter.contains(ProgramDiffFilter::CODE_UNITS));
        assert!(filter.contains(ProgramDiffFilter::MEMORY_BLOCKS));
        assert!(!filter.contains(ProgramDiffFilter::SYMBOLS));
    }

    #[test]
    fn test_builder_exclude_group() {
        let filter = ProgramDiffFilterBuilder::from_preset(FilterPreset::All)
            .exclude_group(FilterGroup::Memory)
            .build();

        assert!(!filter.contains(ProgramDiffFilter::BYTES));
        assert!(!filter.contains(ProgramDiffFilter::CODE_UNITS));
        assert!(!filter.contains(ProgramDiffFilter::MEMORY_BLOCKS));
        assert!(filter.contains(ProgramDiffFilter::SYMBOLS));
    }

    #[test]
    fn test_builder_set() {
        let filter = ProgramDiffFilterBuilder::new()
            .set(FilterCategory::Bytes, true)
            .set(FilterCategory::Symbols, true)
            .set(FilterCategory::Bytes, false)
            .build();

        assert!(!filter.contains(ProgramDiffFilter::BYTES));
        assert!(filter.contains(ProgramDiffFilter::SYMBOLS));
    }

    #[test]
    fn test_builder_has() {
        let builder = ProgramDiffFilterBuilder::from_preset(FilterPreset::CodeOnly);
        assert!(builder.has(FilterCategory::Bytes));
        assert!(!builder.has(FilterCategory::Symbols));
    }

    #[test]
    fn test_builder_included_categories() {
        let builder = ProgramDiffFilterBuilder::from_preset(FilterPreset::CodeOnly);
        let included = builder.included_categories();
        assert_eq!(included.len(), 3);
        assert!(included.contains(&FilterCategory::Bytes));
        assert!(included.contains(&FilterCategory::CodeUnits));
        assert!(included.contains(&FilterCategory::Functions));
    }

    #[test]
    fn test_builder_excluded_categories() {
        let builder = ProgramDiffFilterBuilder::from_preset(FilterPreset::CodeOnly);
        let excluded = builder.excluded_categories();
        assert_eq!(excluded.len(), 12);
        assert!(excluded.contains(&FilterCategory::Symbols));
    }

    #[test]
    fn test_builder_from_filter() {
        let original = ProgramDiffFilter::BYTES | ProgramDiffFilter::SYMBOLS;
        let builder = ProgramDiffFilterBuilder::from_filter(original);
        assert_eq!(builder.build(), original);
    }

    #[test]
    fn test_builder_default() {
        let builder = ProgramDiffFilterBuilder::default();
        assert!(builder.build().is_empty());
    }

    #[test]
    fn test_filter_summary() {
        assert_eq!(filter_summary(ProgramDiffFilter::all()), "All categories");
        assert_eq!(
            filter_summary(ProgramDiffFilter::empty()),
            "No categories selected"
        );

        let filter = ProgramDiffFilter::BYTES | ProgramDiffFilter::SYMBOLS;
        let summary = filter_summary(filter);
        assert!(summary.contains("Bytes"));
        assert!(summary.contains("Symbols"));
    }

    #[test]
    fn test_filter_detail() {
        let filter = ProgramDiffFilter::BYTES | ProgramDiffFilter::SYMBOLS;
        let detail = filter_detail(filter);
        assert!(detail.contains("[Memory]"));
        assert!(detail.contains("[Data]"));
        assert!(detail.contains("Bytes ON"));
        assert!(detail.contains("Symbols ON"));
        assert!(detail.contains("Code Units off"));
    }

    #[test]
    fn test_filter_detail_empty() {
        let detail = filter_detail(ProgramDiffFilter::empty());
        assert!(detail.is_empty());
    }

    #[test]
    fn test_filter_detail_all() {
        let detail = filter_detail(ProgramDiffFilter::all());
        assert!(detail.contains("[Memory]"));
        assert!(detail.contains("[Data]"));
        assert!(detail.contains("[Comments]"));
        assert!(detail.contains("[Functions]"));
        assert!(detail.contains("[References]"));
        assert!(detail.contains("[Metadata]"));
    }
}
