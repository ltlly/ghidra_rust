//! Diff apply settings and option management.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.diff.DiffApplySettingsOptionManager`
//! and `ghidra.app.plugin.core.diff.DiffApplySettingsProvider` Java classes.
//!
//! Manages the settings for how differences are applied during a merge,
//! including default settings and per-session overrides.

use super::merge_filter::{MergeAction, MergeCategory, ProgramMergeFilter};

/// Choice for categories that only support Ignore/Replace (no merge).
///
/// Ported from Ghidra's `DiffApplySettingsOptionManager.REPLACE_CHOICE` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReplaceChoice {
    /// Don't apply this type of difference.
    Ignore,
    /// Replace the value in program 1 with the value from program 2.
    Replace,
}

impl ReplaceChoice {
    /// Get a human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ignore => "Ignore",
            Self::Replace => "Replace",
        }
    }

    /// Convert to a MergeAction.
    pub fn to_merge_action(&self) -> MergeAction {
        match self {
            Self::Ignore => MergeAction::Ignore,
            Self::Replace => MergeAction::Replace,
        }
    }
}

impl std::fmt::Display for ReplaceChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Choice for categories that support Ignore/Replace/Merge.
///
/// Ported from Ghidra's `DiffApplySettingsOptionManager.MERGE_CHOICE` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MergeChoice {
    /// Don't apply this type of difference.
    Ignore,
    /// Replace the value in program 1 with the value from program 2.
    Replace,
    /// Merge the value from program 2 into program 1.
    Merge,
}

impl MergeChoice {
    /// Get a human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ignore => "Ignore",
            Self::Replace => "Replace",
            Self::Merge => "Merge",
        }
    }

    /// Convert to a MergeAction.
    pub fn to_merge_action(&self) -> MergeAction {
        match self {
            Self::Ignore => MergeAction::Ignore,
            Self::Replace => MergeAction::Replace,
            Self::Merge => MergeAction::Merge,
        }
    }
}

impl std::fmt::Display for MergeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Special choice for symbols that includes primary label handling.
///
/// Ported from Ghidra's `DiffApplySettingsOptionManager.SYMBOL_MERGE_CHOICE` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolMergeChoice {
    /// Don't apply symbol differences.
    Ignore,
    /// Replace symbols in program 1 with those from program 2.
    Replace,
    /// Merge symbols from program 2 into program 1, don't change primary.
    MergeDontSetPrimary,
    /// Merge symbols from program 2 into program 1, set primary as in program 2.
    MergeAndSetPrimary,
}

impl SymbolMergeChoice {
    /// Get a human-readable label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ignore => "Ignore",
            Self::Replace => "Replace",
            Self::MergeDontSetPrimary => "Merge",
            Self::MergeAndSetPrimary => "Merge & Set Primary",
        }
    }

    /// Convert to a (MergeAction, MergeAction) tuple of (symbols_action, primary_action).
    pub fn to_merge_actions(&self) -> (MergeAction, MergeAction) {
        match self {
            Self::Ignore => (MergeAction::Ignore, MergeAction::Ignore),
            Self::Replace => (MergeAction::Replace, MergeAction::Replace),
            Self::MergeDontSetPrimary => (MergeAction::Merge, MergeAction::Ignore),
            Self::MergeAndSetPrimary => (MergeAction::Merge, MergeAction::Replace),
        }
    }
}

impl std::fmt::Display for SymbolMergeChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Manages the options for Diff apply settings.
///
/// Ported from Ghidra's `DiffApplySettingsOptionManager` Java class.
///
/// This struct manages the default apply settings and provides methods
/// to convert between different representations of merge choices.
#[derive(Debug, Clone)]
pub struct DiffApplySettingsOptionManager {
    /// Default program context setting.
    pub program_context: ReplaceChoice,
    /// Default bytes setting.
    pub bytes: ReplaceChoice,
    /// Default code units setting.
    pub code_units: ReplaceChoice,
    /// Default references setting.
    pub references: ReplaceChoice,
    /// Default plate comments setting.
    pub plate_comments: MergeChoice,
    /// Default pre-comments setting.
    pub pre_comments: MergeChoice,
    /// Default end-of-line comments setting.
    pub eol_comments: MergeChoice,
    /// Default repeatable comments setting.
    pub repeatable_comments: MergeChoice,
    /// Default post-comments setting.
    pub post_comments: MergeChoice,
    /// Default symbols setting.
    pub symbols: SymbolMergeChoice,
    /// Default bookmarks setting.
    pub bookmarks: ReplaceChoice,
    /// Default properties setting.
    pub properties: ReplaceChoice,
    /// Default functions setting.
    pub functions: ReplaceChoice,
    /// Default function tags setting.
    pub function_tags: MergeChoice,
    /// Default source map setting.
    pub source_map: ReplaceChoice,
}

impl DiffApplySettingsOptionManager {
    /// Create a new option manager with Ghidra's default settings.
    pub fn new() -> Self {
        Self {
            program_context: ReplaceChoice::Replace,
            bytes: ReplaceChoice::Replace,
            code_units: ReplaceChoice::Replace,
            references: ReplaceChoice::Replace,
            plate_comments: MergeChoice::Merge,
            pre_comments: MergeChoice::Merge,
            eol_comments: MergeChoice::Merge,
            repeatable_comments: MergeChoice::Merge,
            post_comments: MergeChoice::Merge,
            symbols: SymbolMergeChoice::MergeAndSetPrimary,
            bookmarks: ReplaceChoice::Replace,
            properties: ReplaceChoice::Replace,
            functions: ReplaceChoice::Replace,
            function_tags: MergeChoice::Merge,
            source_map: ReplaceChoice::Ignore,
        }
    }

    /// Get the default apply filter based on current settings.
    pub fn get_default_apply_filter(&self) -> ProgramMergeFilter {
        let mut filter = ProgramMergeFilter::new();

        filter.set_filter(
            MergeCategory::ProgramContext,
            self.program_context.to_merge_action(),
        );
        filter.set_filter(MergeCategory::Bytes, self.bytes.to_merge_action());
        filter.set_filter(
            MergeCategory::CodeUnits,
            self.code_units.to_merge_action(),
        );
        filter.set_filter(
            MergeCategory::References,
            self.references.to_merge_action(),
        );
        filter.set_filter(
            MergeCategory::PlateComments,
            self.plate_comments.to_merge_action(),
        );
        filter.set_filter(
            MergeCategory::PreComments,
            self.pre_comments.to_merge_action(),
        );
        filter.set_filter(
            MergeCategory::EolComments,
            self.eol_comments.to_merge_action(),
        );
        filter.set_filter(
            MergeCategory::RepeatableComments,
            self.repeatable_comments.to_merge_action(),
        );
        filter.set_filter(
            MergeCategory::PostComments,
            self.post_comments.to_merge_action(),
        );

        let (symbols_action, primary_action) = self.symbols.to_merge_actions();
        filter.set_filter(MergeCategory::Symbols, symbols_action);
        filter.set_filter(MergeCategory::PrimarySymbol, primary_action);

        filter.set_filter(MergeCategory::Bookmarks, self.bookmarks.to_merge_action());
        filter.set_filter(MergeCategory::Properties, self.properties.to_merge_action());
        filter.set_filter(MergeCategory::Functions, self.functions.to_merge_action());
        filter.set_filter(
            MergeCategory::FunctionTags,
            self.function_tags.to_merge_action(),
        );
        filter.set_filter(MergeCategory::SourceMap, self.source_map.to_merge_action());

        filter
    }

    /// Save settings from a merge filter.
    pub fn save_from_filter(&mut self, filter: &ProgramMergeFilter) {
        self.program_context = Self::action_to_replace_choice(filter.get_filter(MergeCategory::ProgramContext));
        self.bytes = Self::action_to_replace_choice(filter.get_filter(MergeCategory::Bytes));
        self.code_units = Self::action_to_replace_choice(filter.get_filter(MergeCategory::CodeUnits));
        self.references = Self::action_to_replace_choice(filter.get_filter(MergeCategory::References));
        self.plate_comments = Self::action_to_merge_choice(filter.get_filter(MergeCategory::PlateComments));
        self.pre_comments = Self::action_to_merge_choice(filter.get_filter(MergeCategory::PreComments));
        self.eol_comments = Self::action_to_merge_choice(filter.get_filter(MergeCategory::EolComments));
        self.repeatable_comments = Self::action_to_merge_choice(filter.get_filter(MergeCategory::RepeatableComments));
        self.post_comments = Self::action_to_merge_choice(filter.get_filter(MergeCategory::PostComments));
        self.bookmarks = Self::action_to_replace_choice(filter.get_filter(MergeCategory::Bookmarks));
        self.properties = Self::action_to_replace_choice(filter.get_filter(MergeCategory::Properties));
        self.functions = Self::action_to_replace_choice(filter.get_filter(MergeCategory::Functions));
        self.function_tags = Self::action_to_merge_choice(filter.get_filter(MergeCategory::FunctionTags));
        self.source_map = Self::action_to_replace_choice(filter.get_filter(MergeCategory::SourceMap));

        // Handle symbols specially
        let symbols_action = filter.get_filter(MergeCategory::Symbols);
        let primary_action = filter.get_filter(MergeCategory::PrimarySymbol);
        self.symbols = Self::actions_to_symbol_merge_choice(symbols_action, primary_action);
    }

    /// Convert a MergeAction to a ReplaceChoice.
    fn action_to_replace_choice(action: MergeAction) -> ReplaceChoice {
        match action {
            MergeAction::Ignore | MergeAction::Merge => ReplaceChoice::Ignore,
            MergeAction::Replace => ReplaceChoice::Replace,
        }
    }

    /// Convert a MergeAction to a MergeChoice.
    fn action_to_merge_choice(action: MergeAction) -> MergeChoice {
        match action {
            MergeAction::Ignore => MergeChoice::Ignore,
            MergeAction::Replace => MergeChoice::Replace,
            MergeAction::Merge => MergeChoice::Merge,
        }
    }

    /// Convert symbol and primary actions to a SymbolMergeChoice.
    fn actions_to_symbol_merge_choice(
        symbols: MergeAction,
        primary: MergeAction,
    ) -> SymbolMergeChoice {
        match (symbols, primary) {
            (MergeAction::Ignore, _) => SymbolMergeChoice::Ignore,
            (MergeAction::Replace, _) => SymbolMergeChoice::Replace,
            (MergeAction::Merge, MergeAction::Replace) => SymbolMergeChoice::MergeAndSetPrimary,
            (MergeAction::Merge, _) => SymbolMergeChoice::MergeDontSetPrimary,
        }
    }
}

impl Default for DiffApplySettingsOptionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// The DiffApplySettingsProvider manages the UI state for diff apply settings.
///
/// Ported from Ghidra's `DiffApplySettingsProvider` Java class.
///
/// This is the non-UI portion of the provider, tracking the current filter
/// state and notifying listeners of changes.
#[derive(Debug, Clone)]
pub struct DiffApplySettingsState {
    /// The current apply filter.
    apply_filter: ProgramMergeFilter,
    /// Whether program context is enabled.
    pgm_context_enabled: bool,
}

impl DiffApplySettingsState {
    /// Create a new settings state with the given filter.
    pub fn new(apply_filter: ProgramMergeFilter) -> Self {
        Self {
            apply_filter,
            pgm_context_enabled: true,
        }
    }

    /// Get the current apply filter.
    pub fn get_apply_filter(&self) -> &ProgramMergeFilter {
        &self.apply_filter
    }

    /// Set the apply filter.
    pub fn set_apply_filter(&mut self, filter: ProgramMergeFilter) {
        self.apply_filter = filter;
    }

    /// Check if program context is enabled.
    pub fn is_pgm_context_enabled(&self) -> bool {
        self.pgm_context_enabled
    }

    /// Set whether program context is enabled.
    pub fn set_pgm_context_enabled(&mut self, enabled: bool) {
        self.pgm_context_enabled = enabled;
        if !enabled {
            self.apply_filter
                .set_filter(MergeCategory::ProgramContext, MergeAction::Ignore);
        }
    }

    /// Check if any apply setting is set to a non-Ignore action.
    pub fn has_apply_selection(&self) -> bool {
        self.apply_filter.has_any_enabled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_choice_display() {
        assert_eq!(ReplaceChoice::Ignore.to_string(), "Ignore");
        assert_eq!(ReplaceChoice::Replace.to_string(), "Replace");
    }

    #[test]
    fn test_merge_choice_display() {
        assert_eq!(MergeChoice::Ignore.to_string(), "Ignore");
        assert_eq!(MergeChoice::Replace.to_string(), "Replace");
        assert_eq!(MergeChoice::Merge.to_string(), "Merge");
    }

    #[test]
    fn test_symbol_merge_choice_display() {
        assert_eq!(SymbolMergeChoice::Ignore.to_string(), "Ignore");
        assert_eq!(SymbolMergeChoice::Replace.to_string(), "Replace");
        assert_eq!(
            SymbolMergeChoice::MergeDontSetPrimary.to_string(),
            "Merge"
        );
        assert_eq!(
            SymbolMergeChoice::MergeAndSetPrimary.to_string(),
            "Merge & Set Primary"
        );
    }

    #[test]
    fn test_symbol_merge_choice_actions() {
        let (s, p) = SymbolMergeChoice::Ignore.to_merge_actions();
        assert_eq!(s, MergeAction::Ignore);
        assert_eq!(p, MergeAction::Ignore);

        let (s, p) = SymbolMergeChoice::Replace.to_merge_actions();
        assert_eq!(s, MergeAction::Replace);
        assert_eq!(p, MergeAction::Replace);

        let (s, p) = SymbolMergeChoice::MergeDontSetPrimary.to_merge_actions();
        assert_eq!(s, MergeAction::Merge);
        assert_eq!(p, MergeAction::Ignore);

        let (s, p) = SymbolMergeChoice::MergeAndSetPrimary.to_merge_actions();
        assert_eq!(s, MergeAction::Merge);
        assert_eq!(p, MergeAction::Replace);
    }

    #[test]
    fn test_option_manager_defaults() {
        let mgr = DiffApplySettingsOptionManager::new();
        assert_eq!(mgr.bytes, ReplaceChoice::Replace);
        assert_eq!(mgr.plate_comments, MergeChoice::Merge);
        assert_eq!(mgr.symbols, SymbolMergeChoice::MergeAndSetPrimary);
        assert_eq!(mgr.source_map, ReplaceChoice::Ignore);
    }

    #[test]
    fn test_option_manager_default_filter() {
        let mgr = DiffApplySettingsOptionManager::new();
        let filter = mgr.get_default_apply_filter();
        assert_eq!(filter.get_filter(MergeCategory::Bytes), MergeAction::Replace);
        assert_eq!(
            filter.get_filter(MergeCategory::PlateComments),
            MergeAction::Merge
        );
        assert_eq!(
            filter.get_filter(MergeCategory::SourceMap),
            MergeAction::Ignore
        );
    }

    #[test]
    fn test_option_manager_save_from_filter() {
        let mut mgr = DiffApplySettingsOptionManager::new();
        let mut filter = ProgramMergeFilter::new();
        filter.set_filter(MergeCategory::Bytes, MergeAction::Merge);
        filter.set_filter(MergeCategory::PlateComments, MergeAction::Replace);
        mgr.save_from_filter(&filter);
        assert_eq!(mgr.bytes, ReplaceChoice::Ignore); // Merge -> Ignore for replace-only
        assert_eq!(mgr.plate_comments, MergeChoice::Replace);
    }

    #[test]
    fn test_settings_state_basic() {
        let filter = ProgramMergeFilter::defaults();
        let mut state = DiffApplySettingsState::new(filter);
        assert!(state.has_apply_selection());
        assert!(state.is_pgm_context_enabled());
        state.set_pgm_context_enabled(false);
        assert!(!state.is_pgm_context_enabled());
        assert_eq!(
            state.get_apply_filter().get_filter(MergeCategory::ProgramContext),
            MergeAction::Ignore
        );
    }
}
