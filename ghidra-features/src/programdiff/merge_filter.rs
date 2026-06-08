//! Program merge filter for controlling how differences are applied.
//!
//! Ported from Ghidra's `ghidra.program.util.ProgramMergeFilter` Java class.
//!
//! The merge filter controls which types of program differences are applied
//! when merging changes from one program to another. Each category can be
//! set to Ignore, Replace, or Merge independently.

/// Action to take when applying a difference.
///
/// Ported from Ghidra's `ProgramMergeFilter.IGNORE/REPLACE/MERGE` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MergeAction {
    /// Don't apply this type of difference.
    Ignore = 0,
    /// Replace the value in program 1 with the value from program 2.
    Replace = 1,
    /// Merge the value from program 2 into program 1 (where applicable).
    Merge = 2,
}

impl MergeAction {
    /// Get the action from an ordinal value.
    pub fn from_ordinal(ord: usize) -> Option<Self> {
        match ord {
            0 => Some(Self::Ignore),
            1 => Some(Self::Replace),
            2 => Some(Self::Merge),
            _ => None,
        }
    }

    /// Get a human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ignore => "Ignore",
            Self::Replace => "Replace",
            Self::Merge => "Merge",
        }
    }
}

impl std::fmt::Display for MergeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Categories of program data that can be filtered for merge operations.
///
/// Each variant represents a distinct category of program information
/// that may be independently configured for merge behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MergeCategory {
    /// Program context register values.
    ProgramContext,
    /// Raw memory bytes.
    Bytes,
    /// Instructions.
    Instructions,
    /// Defined data.
    Data,
    /// Code units (instructions + data).
    CodeUnits,
    /// Equates (named constants).
    Equates,
    /// References (memory, external, stack).
    References,
    /// Plate comments (function header comments).
    PlateComments,
    /// Pre-comments (before a code unit).
    PreComments,
    /// End-of-line comments.
    EolComments,
    /// Repeatable comments.
    RepeatableComments,
    /// Post-comments (after a code unit).
    PostComments,
    /// All comment types combined.
    Comments,
    /// Symbols/labels.
    Symbols,
    /// Whether to set the primary label when merging symbols.
    PrimarySymbol,
    /// Bookmarks.
    Bookmarks,
    /// User-defined properties.
    Properties,
    /// Function signatures and properties.
    Functions,
    /// Function tags.
    FunctionTags,
    /// Source map entries.
    SourceMap,
    /// All categories combined.
    All,
}

/// Filter controlling how differences are applied during program merge.
///
/// Ported from Ghidra's `ProgramMergeFilter` Java class.
///
/// Each category of program data can be independently set to Ignore, Replace,
/// or Merge. This filter is used by the diff controller to determine which
/// differences to apply when the user initiates a merge operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramMergeFilter {
    /// Map from category to action.
    filters: Vec<(MergeCategory, MergeAction)>,
}

impl ProgramMergeFilter {
    /// Create a new merge filter with all categories set to Ignore.
    pub fn new() -> Self {
        Self {
            filters: Vec::new(),
        }
    }

    /// Create a merge filter with all categories set to the given action.
    pub fn all_with_action(action: MergeAction) -> Self {
        let mut filter = Self::new();
        filter.set_filter(MergeCategory::All, action);
        filter
    }

    /// Create a merge filter with default settings (Replace for most, Merge for comments).
    pub fn defaults() -> Self {
        let mut filter = Self::new();
        filter.set_filter(MergeCategory::ProgramContext, MergeAction::Replace);
        filter.set_filter(MergeCategory::Bytes, MergeAction::Replace);
        filter.set_filter(MergeCategory::CodeUnits, MergeAction::Replace);
        filter.set_filter(MergeCategory::References, MergeAction::Replace);
        filter.set_filter(MergeCategory::PlateComments, MergeAction::Merge);
        filter.set_filter(MergeCategory::PreComments, MergeAction::Merge);
        filter.set_filter(MergeCategory::EolComments, MergeAction::Merge);
        filter.set_filter(MergeCategory::RepeatableComments, MergeAction::Merge);
        filter.set_filter(MergeCategory::PostComments, MergeAction::Merge);
        filter.set_filter(MergeCategory::Symbols, MergeAction::Merge);
        filter.set_filter(MergeCategory::PrimarySymbol, MergeAction::Replace);
        filter.set_filter(MergeCategory::Bookmarks, MergeAction::Replace);
        filter.set_filter(MergeCategory::Properties, MergeAction::Replace);
        filter.set_filter(MergeCategory::Functions, MergeAction::Replace);
        filter.set_filter(MergeCategory::FunctionTags, MergeAction::Merge);
        filter.set_filter(MergeCategory::SourceMap, MergeAction::Ignore);
        filter
    }

    /// Set the action for a specific category.
    pub fn set_filter(&mut self, category: MergeCategory, action: MergeAction) {
        // Remove existing entry for this category
        self.filters.retain(|(c, _)| *c != category);
        self.filters.push((category, action));
    }

    /// Get the action for a specific category.
    pub fn get_filter(&self, category: MergeCategory) -> MergeAction {
        // Check for exact match first
        for (c, a) in &self.filters {
            if *c == category {
                return *a;
            }
        }
        // Check if "All" is set
        for (c, a) in &self.filters {
            if *c == MergeCategory::All {
                return *a;
            }
        }
        MergeAction::Ignore
    }

    /// Check if a category is set to anything other than Ignore.
    pub fn is_enabled(&self, category: MergeCategory) -> bool {
        self.get_filter(category) != MergeAction::Ignore
    }

    /// Check if any category is set to a non-Ignore action.
    pub fn has_any_enabled(&self) -> bool {
        for (c, _) in &self.filters {
            if *c == MergeCategory::All {
                continue;
            }
            if self.get_filter(*c) != MergeAction::Ignore {
                return true;
            }
        }
        false
    }

    /// Get all categories and their current actions.
    pub fn entries(&self) -> &[(MergeCategory, MergeAction)] {
        &self.filters
    }
}

impl Default for ProgramMergeFilter {
    fn default() -> Self {
        Self::defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_action_from_ordinal() {
        assert_eq!(MergeAction::from_ordinal(0), Some(MergeAction::Ignore));
        assert_eq!(MergeAction::from_ordinal(1), Some(MergeAction::Replace));
        assert_eq!(MergeAction::from_ordinal(2), Some(MergeAction::Merge));
        assert_eq!(MergeAction::from_ordinal(3), None);
    }

    #[test]
    fn test_merge_action_label() {
        assert_eq!(MergeAction::Ignore.label(), "Ignore");
        assert_eq!(MergeAction::Replace.label(), "Replace");
        assert_eq!(MergeAction::Merge.label(), "Merge");
    }

    #[test]
    fn test_merge_filter_default_is_ignore() {
        let filter = ProgramMergeFilter::new();
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Ignore);
        assert_eq!(
            filter.get_filter(MergeCategory::Symbols),
            MergeAction::Ignore
        );
    }

    #[test]
    fn test_merge_filter_set_and_get() {
        let mut filter = ProgramMergeFilter::new();
        filter.set_filter(MergeCategory::Bytes, MergeAction::Replace);
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Replace);
        assert_eq!(
            filter.get_filter(MergeCategory::Symbols),
            MergeAction::Ignore
        );
    }

    #[test]
    fn test_merge_filter_all_category() {
        let filter = ProgramMergeFilter::all_with_action(MergeAction::Replace);
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Replace);
        assert_eq!(
            filter.get_filter(MergeCategory::Symbols),
            MergeAction::Replace
        );
        assert_eq!(
            filter.get_filter(MergeCategory::Comments),
            MergeAction::Replace
        );
    }

    #[test]
    fn test_merge_filter_specific_overrides_all() {
        let mut filter = ProgramMergeFilter::all_with_action(MergeAction::Replace);
        filter.set_filter(MergeCategory::Bytes, MergeAction::Merge);
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Merge);
        assert_eq!(
            filter.get_filter(MergeCategory::Symbols),
            MergeAction::Replace
        );
    }

    #[test]
    fn test_merge_filter_defaults() {
        let filter = ProgramMergeFilter::defaults();
        assert_eq!(
            filter.get_filter(MergeCategory::Bytes),
            MergeAction::Replace
        );
        assert_eq!(
            filter.get_filter(MergeCategory::EolComments),
            MergeAction::Merge
        );
        assert_eq!(
            filter.get_filter(MergeCategory::SourceMap),
            MergeAction::Ignore
        );
    }

    #[test]
    fn test_merge_filter_is_enabled() {
        let mut filter = ProgramMergeFilter::new();
        assert!(!filter.is_enabled(MergeCategory::Bytes));
        filter.set_filter(MergeCategory::Bytes, MergeAction::Replace);
        assert!(filter.is_enabled(MergeCategory::Bytes));
        filter.set_filter(MergeCategory::Bytes, MergeAction::Ignore);
        assert!(!filter.is_enabled(MergeCategory::Bytes));
    }

    #[test]
    fn test_merge_filter_has_any_enabled() {
        let mut filter = ProgramMergeFilter::new();
        assert!(!filter.has_any_enabled());
        filter.set_filter(MergeCategory::Bytes, MergeAction::Replace);
        assert!(filter.has_any_enabled());
    }

    #[test]
    fn test_merge_filter_override_category() {
        let mut filter = ProgramMergeFilter::new();
        filter.set_filter(MergeCategory::Bytes, MergeAction::Replace);
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Replace);
        filter.set_filter(MergeCategory::Bytes, MergeAction::Merge);
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Merge);
    }
}
