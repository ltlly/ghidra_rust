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
//! - fine-grained comment type filtering (EOL, pre, post, plate, repeatable)
//! - function tag and source map diff filtering
//!
//! # Key types
//!
//! - [`FilterCategory`] -- enumeration of diff filter categories with labels
//! - [`FilterPreset`] -- predefined filter configurations
//! - [`ProgramDiffFilterBuilder`] -- builder for constructing filters
//!
//! # Extended filter flags
//!
//! The extended filter provides additional flags beyond the base
//! [`ProgramDiffFilter`]:
//!
//! - [`ProgramDiffFilterEx::EOL_COMMENT`] -- end-of-line comment differences
//! - [`ProgramDiffFilterEx::PRE_COMMENT`] -- pre-comment differences
//! - [`ProgramDiffFilterEx::POST_COMMENT`] -- post-comment differences
//! - [`ProgramDiffFilterEx::PLATE_COMMENT`] -- plate comment differences
//! - [`ProgramDiffFilterEx::REPEATABLE_COMMENT`] -- repeatable comment differences
//! - [`ProgramDiffFilterEx::FUNCTION_TAG`] -- function tag differences
//! - [`ProgramDiffFilterEx::SOURCE_MAP`] -- source map differences

use super::ProgramDiffFilter;

// ---------------------------------------------------------------------------
// ProgramDiffFilterEx -- extended filter with fine-grained comment types
// ---------------------------------------------------------------------------

/// Extended program diff filter with fine-grained comment type and additional
/// category flags.
///
/// Ported from Ghidra's `ProgramDiffFilter` Java class constants for
/// individual comment types (`EOL_COMMENT_DIFFS`, `PRE_COMMENT_DIFFS`,
/// `POST_COMMENT_DIFFS`, `PLATE_COMMENT_DIFFS`, `REPEATABLE_COMMENT_DIFFS`),
/// `FUNCTION_TAG_DIFFS`, and `SOURCE_MAP_DIFFS`.
///
/// This struct wraps a `u32` bitmask and provides individual constants for
/// each comment type, as well as a `COMMENT_DIFFS` combination and
/// `ALL_DIFFS` that includes all extended types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgramDiffFilterEx(u32);

impl ProgramDiffFilterEx {
    /// No filter flags set.
    pub const NONE: Self = Self(0);
    /// Program context (register) differences.
    pub const PROGRAM_CONTEXT: Self = Self(1 << 0);
    /// Byte differences.
    pub const BYTE: Self = Self(1 << 1);
    /// Code unit differences.
    pub const CODE_UNIT: Self = Self(1 << 2);
    /// End-of-line comment differences.
    pub const EOL_COMMENT: Self = Self(1 << 3);
    /// Pre-comment differences.
    pub const PRE_COMMENT: Self = Self(1 << 4);
    /// Post-comment differences.
    pub const POST_COMMENT: Self = Self(1 << 5);
    /// Plate comment differences.
    pub const PLATE_COMMENT: Self = Self(1 << 6);
    /// Repeatable comment differences.
    pub const REPEATABLE_COMMENT: Self = Self(1 << 7);
    /// Memory, variable, and external reference differences.
    pub const REFERENCE: Self = Self(1 << 8);
    /// Equate differences.
    pub const EQUATE: Self = Self(1 << 9);
    /// Symbol differences.
    pub const SYMBOL: Self = Self(1 << 10);
    /// Function differences.
    pub const FUNCTION: Self = Self(1 << 11);
    /// Bookmark differences.
    pub const BOOKMARK: Self = Self(1 << 12);
    /// User-defined property differences.
    pub const USER_DEFINED: Self = Self(1 << 13);
    /// Function tag differences.
    pub const FUNCTION_TAG: Self = Self(1 << 14);
    /// Source map differences.
    pub const SOURCE_MAP: Self = Self(1 << 15);

    /// Total number of primary difference types.
    pub const NUM_PRIMARY_TYPES: usize = 16;

    /// All comment diff types combined.
    pub const COMMENT_DIFFS: Self = Self(
        Self::EOL_COMMENT.0
            | Self::PRE_COMMENT.0
            | Self::POST_COMMENT.0
            | Self::PLATE_COMMENT.0
            | Self::REPEATABLE_COMMENT.0,
    );

    /// All defined diff types combined.
    pub const ALL_DIFFS: Self = Self(
        Self::BYTE.0
            | Self::CODE_UNIT.0
            | Self::COMMENT_DIFFS.0
            | Self::REFERENCE.0
            | Self::USER_DEFINED.0
            | Self::SYMBOL.0
            | Self::EQUATE.0
            | Self::FUNCTION.0
            | Self::BOOKMARK.0
            | Self::FUNCTION_TAG.0
            | Self::PROGRAM_CONTEXT.0
            | Self::SOURCE_MAP.0,
    );

    /// Create a filter with no flags set.
    pub const fn empty() -> Self {
        Self::NONE
    }

    /// Create a filter with all flags set.
    pub const fn all() -> Self {
        Self::ALL_DIFFS
    }

    /// Create a filter from a raw bitmask, masked to valid types.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & Self::ALL_DIFFS.0)
    }

    /// Get the raw bitmask.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check if a flag is set.
    pub const fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Check if a flag is set (any bit overlap, matching Java's `getFilter`).
    pub const fn has_any(&self, other: Self) -> bool {
        (self.0 & other.0) != 0
    }

    /// Set a flag.
    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }

    /// Clear a flag.
    pub fn remove(&mut self, other: Self) {
        self.0 &= !other.0;
    }

    /// Set or clear a flag based on a boolean.
    pub fn set(&mut self, other: Self, enabled: bool) {
        if enabled {
            self.insert(other);
        } else {
            self.remove(other);
        }
    }

    /// Check if no flags are set.
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Set all defined types to true (Java `selectAll()`).
    pub fn select_all(&mut self) {
        self.0 = Self::ALL_DIFFS.0;
    }

    /// Set all defined types to false (Java `clearAll()`).
    pub fn clear_all(&mut self) {
        self.0 = 0;
    }

    /// Add another filter's flags to this one (Java `addToFilter()`).
    pub fn add_to_filter(&mut self, other: &Self) {
        self.0 |= other.0;
    }

    /// Get all primary (individual) diff type flags.
    pub fn primary_types() -> &'static [ProgramDiffFilterEx] {
        &[
            Self::PROGRAM_CONTEXT,
            Self::BYTE,
            Self::CODE_UNIT,
            Self::EOL_COMMENT,
            Self::PRE_COMMENT,
            Self::POST_COMMENT,
            Self::PLATE_COMMENT,
            Self::REPEATABLE_COMMENT,
            Self::REFERENCE,
            Self::EQUATE,
            Self::SYMBOL,
            Self::FUNCTION,
            Self::BOOKMARK,
            Self::USER_DEFINED,
            Self::FUNCTION_TAG,
            Self::SOURCE_MAP,
        ]
    }

    /// Convert a type flag to its name (Java `typeToName()`).
    pub fn type_to_name(ty: ProgramDiffFilterEx) -> &'static str {
        match ty {
            Self::PROGRAM_CONTEXT => "PROGRAM_CONTEXT_DIFFS",
            Self::BYTE => "BYTE_DIFFS",
            Self::CODE_UNIT => "CODE_UNIT_DIFFS",
            Self::EOL_COMMENT => "EOL_COMMENT_DIFFS",
            Self::PRE_COMMENT => "PRE_COMMENT_DIFFS",
            Self::POST_COMMENT => "POST_COMMENT_DIFFS",
            Self::PLATE_COMMENT => "PLATE_COMMENT_DIFFS",
            Self::REPEATABLE_COMMENT => "REPEATABLE_COMMENT_DIFFS",
            Self::REFERENCE => "REFERENCE_DIFFS",
            Self::EQUATE => "EQUATE_DIFFS",
            Self::SYMBOL => "SYMBOL_DIFFS",
            Self::FUNCTION => "FUNCTION_DIFFS",
            Self::BOOKMARK => "BOOKMARK_DIFFS",
            Self::USER_DEFINED => "USER_DEFINED_DIFFS",
            Self::FUNCTION_TAG => "FUNCTION_TAG_DIFFS",
            Self::SOURCE_MAP => "SOURCE_MAP_DIFFS",
            Self::COMMENT_DIFFS => "COMMENT_DIFFS",
            Self::ALL_DIFFS => "ALL_DIFFS",
            _ => "",
        }
    }

    /// Convert this filter to a human-readable string (Java `toString()`).
    pub fn to_display_string(&self) -> String {
        let mut buf = String::from("ProgramDiffFilter:\n");
        for &ty in Self::primary_types() {
            buf.push_str(&format!(
                "  {}={}\n",
                Self::type_to_name(ty),
                self.has_any(ty)
            ));
        }
        buf
    }
}

impl std::ops::BitOr for ProgramDiffFilterEx {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for ProgramDiffFilterEx {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::BitOrAssign for ProgramDiffFilterEx {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl Default for ProgramDiffFilterEx {
    fn default() -> Self {
        Self::empty()
    }
}

/// Convert a base [`ProgramDiffFilter`] to an extended [`ProgramDiffFilterEx`].
///
/// Maps the coarser-grained base filter flags to their extended equivalents.
/// The `COMMENTS` flag in the base filter expands to all individual comment
/// types in the extended filter.
pub fn to_extended_filter(base: ProgramDiffFilter) -> ProgramDiffFilterEx {
    let mut ext = ProgramDiffFilterEx::empty();

    if base.contains(ProgramDiffFilter::BYTES) {
        ext.insert(ProgramDiffFilterEx::BYTE);
    }
    if base.contains(ProgramDiffFilter::CODE_UNITS) {
        ext.insert(ProgramDiffFilterEx::CODE_UNIT);
    }
    if base.contains(ProgramDiffFilter::DATA_TYPES) {
        ext.insert(ProgramDiffFilterEx::USER_DEFINED);
    }
    if base.contains(ProgramDiffFilter::SYMBOLS) {
        ext.insert(ProgramDiffFilterEx::SYMBOL);
    }
    if base.contains(ProgramDiffFilter::EQUATES) {
        ext.insert(ProgramDiffFilterEx::EQUATE);
    }
    if base.contains(ProgramDiffFilter::BOOKMARKS) {
        ext.insert(ProgramDiffFilterEx::BOOKMARK);
    }
    if base.contains(ProgramDiffFilter::COMMENTS) {
        ext.insert(ProgramDiffFilterEx::COMMENT_DIFFS);
    }
    if base.contains(ProgramDiffFilter::FUNCTIONS) {
        ext.insert(ProgramDiffFilterEx::FUNCTION);
    }
    if base.contains(ProgramDiffFilter::REGISTERS) {
        ext.insert(ProgramDiffFilterEx::PROGRAM_CONTEXT);
    }
    if base.contains(ProgramDiffFilter::PROPERTIES) {
        ext.insert(ProgramDiffFilterEx::USER_DEFINED);
    }
    if base.contains(ProgramDiffFilter::REFERENCES) {
        ext.insert(ProgramDiffFilterEx::REFERENCE);
    }
    if base.contains(ProgramDiffFilter::EXTERNALS) {
        ext.insert(ProgramDiffFilterEx::REFERENCE);
    }
    if base.contains(ProgramDiffFilter::OPTIONS) {
        ext.insert(ProgramDiffFilterEx::USER_DEFINED);
    }
    if base.contains(ProgramDiffFilter::RELOCATIONS) {
        ext.insert(ProgramDiffFilterEx::SOURCE_MAP);
    }

    ext
}

/// Convert an extended [`ProgramDiffFilterEx`] back to a base [`ProgramDiffFilter`].
///
/// Individual comment types are combined into the base `COMMENTS` flag.
/// Extended types without a direct base equivalent map to the closest match.
pub fn to_base_filter(ext: ProgramDiffFilterEx) -> ProgramDiffFilter {
    let mut base = ProgramDiffFilter::empty();

    if ext.has_any(ProgramDiffFilterEx::BYTE) {
        base.insert(ProgramDiffFilter::BYTES);
    }
    if ext.has_any(ProgramDiffFilterEx::CODE_UNIT) {
        base.insert(ProgramDiffFilter::CODE_UNITS);
    }
    if ext.has_any(ProgramDiffFilterEx::COMMENT_DIFFS) {
        base.insert(ProgramDiffFilter::COMMENTS);
    }
    if ext.has_any(ProgramDiffFilterEx::REFERENCE) {
        base.insert(ProgramDiffFilter::REFERENCES);
    }
    if ext.has_any(ProgramDiffFilterEx::EQUATE) {
        base.insert(ProgramDiffFilter::EQUATES);
    }
    if ext.has_any(ProgramDiffFilterEx::SYMBOL) {
        base.insert(ProgramDiffFilter::SYMBOLS);
    }
    if ext.has_any(ProgramDiffFilterEx::FUNCTION) {
        base.insert(ProgramDiffFilter::FUNCTIONS);
    }
    if ext.has_any(ProgramDiffFilterEx::BOOKMARK) {
        base.insert(ProgramDiffFilter::BOOKMARKS);
    }
    if ext.has_any(ProgramDiffFilterEx::USER_DEFINED) {
        base.insert(ProgramDiffFilter::PROPERTIES);
    }
    if ext.has_any(ProgramDiffFilterEx::FUNCTION_TAG) {
        base.insert(ProgramDiffFilter::FUNCTIONS);
    }
    if ext.has_any(ProgramDiffFilterEx::PROGRAM_CONTEXT) {
        base.insert(ProgramDiffFilter::REGISTERS);
    }
    if ext.has_any(ProgramDiffFilterEx::SOURCE_MAP) {
        base.insert(ProgramDiffFilter::RELOCATIONS);
    }

    base
}

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

    // -- ProgramDiffFilterEx tests ------------------------------------------

    #[test]
    fn test_ex_filter_empty_and_all() {
        let empty = ProgramDiffFilterEx::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.bits(), 0);

        let all = ProgramDiffFilterEx::all();
        assert!(!all.is_empty());
        assert!(all.has_any(ProgramDiffFilterEx::BYTE));
        assert!(all.has_any(ProgramDiffFilterEx::COMMENT_DIFFS));
        assert!(all.has_any(ProgramDiffFilterEx::FUNCTION_TAG));
        assert!(all.has_any(ProgramDiffFilterEx::SOURCE_MAP));
    }

    #[test]
    fn test_ex_filter_comment_types() {
        let mut f = ProgramDiffFilterEx::empty();
        f.insert(ProgramDiffFilterEx::EOL_COMMENT);
        assert!(f.has_any(ProgramDiffFilterEx::EOL_COMMENT));
        assert!(!f.has_any(ProgramDiffFilterEx::PRE_COMMENT));
        // has_any checks any overlap, so one comment type overlaps with COMMENT_DIFFS
        assert!(f.has_any(ProgramDiffFilterEx::COMMENT_DIFFS));
        // But contains checks ALL bits, so one type does NOT contain COMMENT_DIFFS
        assert!(!f.contains(ProgramDiffFilterEx::COMMENT_DIFFS));

        f.insert(ProgramDiffFilterEx::PRE_COMMENT);
        f.insert(ProgramDiffFilterEx::POST_COMMENT);
        f.insert(ProgramDiffFilterEx::PLATE_COMMENT);
        f.insert(ProgramDiffFilterEx::REPEATABLE_COMMENT);
        assert!(f.has_any(ProgramDiffFilterEx::COMMENT_DIFFS));
        assert!(f.contains(ProgramDiffFilterEx::COMMENT_DIFFS));
    }

    #[test]
    fn test_ex_filter_comment_diffs_combination() {
        let f = ProgramDiffFilterEx::COMMENT_DIFFS;
        assert!(f.has_any(ProgramDiffFilterEx::EOL_COMMENT));
        assert!(f.has_any(ProgramDiffFilterEx::PRE_COMMENT));
        assert!(f.has_any(ProgramDiffFilterEx::POST_COMMENT));
        assert!(f.has_any(ProgramDiffFilterEx::PLATE_COMMENT));
        assert!(f.has_any(ProgramDiffFilterEx::REPEATABLE_COMMENT));
        assert!(!f.has_any(ProgramDiffFilterEx::BYTE));
    }

    #[test]
    fn test_ex_filter_function_tag_and_source_map() {
        let mut f = ProgramDiffFilterEx::empty();
        f.insert(ProgramDiffFilterEx::FUNCTION_TAG);
        f.insert(ProgramDiffFilterEx::SOURCE_MAP);
        assert!(f.has_any(ProgramDiffFilterEx::FUNCTION_TAG));
        assert!(f.has_any(ProgramDiffFilterEx::SOURCE_MAP));
        assert!(!f.has_any(ProgramDiffFilterEx::BYTE));
    }

    #[test]
    fn test_ex_filter_select_all_and_clear_all() {
        let mut f = ProgramDiffFilterEx::empty();
        assert!(f.is_empty());
        f.select_all();
        assert_eq!(f, ProgramDiffFilterEx::all());
        f.clear_all();
        assert!(f.is_empty());
    }

    #[test]
    fn test_ex_filter_add_to_filter() {
        let mut f1 = ProgramDiffFilterEx::BYTE;
        let f2 = ProgramDiffFilterEx::SYMBOL | ProgramDiffFilterEx::EOL_COMMENT;
        f1.add_to_filter(&f2);
        assert!(f1.has_any(ProgramDiffFilterEx::BYTE));
        assert!(f1.has_any(ProgramDiffFilterEx::SYMBOL));
        assert!(f1.has_any(ProgramDiffFilterEx::EOL_COMMENT));
    }

    #[test]
    fn test_ex_filter_from_bits() {
        let f = ProgramDiffFilterEx::from_bits(ProgramDiffFilterEx::BYTE.0 | 0x80000000);
        assert!(f.has_any(ProgramDiffFilterEx::BYTE));
        // High bits should be masked off
        assert_eq!(f.bits() & 0x80000000, 0);
    }

    #[test]
    fn test_ex_filter_primary_types() {
        let types = ProgramDiffFilterEx::primary_types();
        assert_eq!(types.len(), 16);
    }

    #[test]
    fn test_ex_filter_type_to_name() {
        assert_eq!(
            ProgramDiffFilterEx::type_to_name(ProgramDiffFilterEx::BYTE),
            "BYTE_DIFFS"
        );
        assert_eq!(
            ProgramDiffFilterEx::type_to_name(ProgramDiffFilterEx::EOL_COMMENT),
            "EOL_COMMENT_DIFFS"
        );
        assert_eq!(
            ProgramDiffFilterEx::type_to_name(ProgramDiffFilterEx::FUNCTION_TAG),
            "FUNCTION_TAG_DIFFS"
        );
        assert_eq!(
            ProgramDiffFilterEx::type_to_name(ProgramDiffFilterEx::SOURCE_MAP),
            "SOURCE_MAP_DIFFS"
        );
        assert_eq!(
            ProgramDiffFilterEx::type_to_name(ProgramDiffFilterEx::COMMENT_DIFFS),
            "COMMENT_DIFFS"
        );
        assert_eq!(
            ProgramDiffFilterEx::type_to_name(ProgramDiffFilterEx::ALL_DIFFS),
            "ALL_DIFFS"
        );
        // Unknown type returns empty
        assert_eq!(ProgramDiffFilterEx::type_to_name(ProgramDiffFilterEx(0)), "");
    }

    #[test]
    fn test_ex_filter_to_display_string() {
        let f = ProgramDiffFilterEx::BYTE | ProgramDiffFilterEx::EOL_COMMENT;
        let s = f.to_display_string();
        assert!(s.contains("BYTE_DIFFS=true"));
        assert!(s.contains("EOL_COMMENT_DIFFS=true"));
        assert!(s.contains("SYMBOL_DIFFS=false"));
    }

    #[test]
    fn test_ex_filter_set() {
        let mut f = ProgramDiffFilterEx::empty();
        f.set(ProgramDiffFilterEx::BYTE, true);
        assert!(f.has_any(ProgramDiffFilterEx::BYTE));
        f.set(ProgramDiffFilterEx::BYTE, false);
        assert!(!f.has_any(ProgramDiffFilterEx::BYTE));
    }

    #[test]
    fn test_ex_filter_default() {
        let f = ProgramDiffFilterEx::default();
        assert!(f.is_empty());
    }

    #[test]
    fn test_ex_filter_bitwise_ops() {
        let f1 = ProgramDiffFilterEx::BYTE | ProgramDiffFilterEx::SYMBOL;
        assert!(f1.has_any(ProgramDiffFilterEx::BYTE));
        assert!(f1.has_any(ProgramDiffFilterEx::SYMBOL));

        let f2 = f1 & ProgramDiffFilterEx::BYTE;
        assert!(f2.has_any(ProgramDiffFilterEx::BYTE));
        assert!(!f2.has_any(ProgramDiffFilterEx::SYMBOL));
    }

    #[test]
    fn test_to_extended_filter_basic() {
        let base = ProgramDiffFilter::BYTES | ProgramDiffFilter::SYMBOLS;
        let ext = to_extended_filter(base);
        assert!(ext.has_any(ProgramDiffFilterEx::BYTE));
        assert!(ext.has_any(ProgramDiffFilterEx::SYMBOL));
        assert!(!ext.has_any(ProgramDiffFilterEx::COMMENT_DIFFS));
    }

    #[test]
    fn test_to_extended_filter_comments() {
        let base = ProgramDiffFilter::COMMENTS;
        let ext = to_extended_filter(base);
        assert!(ext.has_any(ProgramDiffFilterEx::EOL_COMMENT));
        assert!(ext.has_any(ProgramDiffFilterEx::PRE_COMMENT));
        assert!(ext.has_any(ProgramDiffFilterEx::POST_COMMENT));
        assert!(ext.has_any(ProgramDiffFilterEx::PLATE_COMMENT));
        assert!(ext.has_any(ProgramDiffFilterEx::REPEATABLE_COMMENT));
    }

    #[test]
    fn test_to_extended_filter_all() {
        let base = ProgramDiffFilter::all();
        let ext = to_extended_filter(base);
        assert!(ext.has_any(ProgramDiffFilterEx::BYTE));
        assert!(ext.has_any(ProgramDiffFilterEx::COMMENT_DIFFS));
        assert!(ext.has_any(ProgramDiffFilterEx::REFERENCE));
    }

    #[test]
    fn test_to_base_filter_basic() {
        let ext = ProgramDiffFilterEx::BYTE | ProgramDiffFilterEx::SYMBOL;
        let base = to_base_filter(ext);
        assert!(base.contains(ProgramDiffFilter::BYTES));
        assert!(base.contains(ProgramDiffFilter::SYMBOLS));
        assert!(!base.contains(ProgramDiffFilter::COMMENTS));
    }

    #[test]
    fn test_to_base_filter_comment_diffs() {
        let ext = ProgramDiffFilterEx::COMMENT_DIFFS;
        let base = to_base_filter(ext);
        assert!(base.contains(ProgramDiffFilter::COMMENTS));
    }

    #[test]
    fn test_to_base_filter_function_tag() {
        let ext = ProgramDiffFilterEx::FUNCTION_TAG;
        let base = to_base_filter(ext);
        assert!(base.contains(ProgramDiffFilter::FUNCTIONS));
    }

    #[test]
    fn test_to_base_filter_source_map() {
        let ext = ProgramDiffFilterEx::SOURCE_MAP;
        let base = to_base_filter(ext);
        assert!(base.contains(ProgramDiffFilter::RELOCATIONS));
    }

    #[test]
    fn test_roundtrip_base_to_extended_and_back() {
        let original = ProgramDiffFilter::BYTES | ProgramDiffFilter::SYMBOLS | ProgramDiffFilter::COMMENTS;
        let ext = to_extended_filter(original);
        let back = to_base_filter(ext);
        assert!(back.contains(ProgramDiffFilter::BYTES));
        assert!(back.contains(ProgramDiffFilter::SYMBOLS));
        assert!(back.contains(ProgramDiffFilter::COMMENTS));
    }
}
