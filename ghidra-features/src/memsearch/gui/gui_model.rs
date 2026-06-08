//! `SearchGuiModel` -- maintains the state of all search controls.
//!
//! Ported from `ghidra.features.base.memsearch.gui.SearchGuiModel`.

use crate::memsearch::combiner::Combiner;
use crate::memsearch::gui::SearchSettings;

/// Maintains the state of all settings and controls for the memory search window.
///
/// Ported from `SearchGuiModel.java`.
pub struct SearchGuiModel {
    settings: SearchSettings,
    combiner: Combiner,
    has_selection: bool,
    auto_restrict_selection: bool,
    region_choices: Vec<String>,
}

impl SearchGuiModel {
    /// Create a new search GUI model with the given settings.
    pub fn new(settings: SearchSettings) -> Self {
        Self {
            settings,
            combiner: Combiner::Replace,
            has_selection: false,
            auto_restrict_selection: false,
            region_choices: Vec::new(),
        }
    }

    /// Get the current search settings.
    pub fn settings(&self) -> &SearchSettings {
        &self.settings
    }

    /// Update the search settings.
    pub fn set_settings(&mut self, settings: SearchSettings) {
        self.settings = settings;
    }

    /// Get the current combiner.
    pub fn combiner(&self) -> Combiner {
        self.combiner
    }

    /// Set the combiner.
    pub fn set_combiner(&mut self, combiner: Combiner) {
        self.combiner = combiner;
    }

    /// Returns true if there is a current selection in the program.
    pub fn has_selection(&self) -> bool {
        self.has_selection
    }

    /// Set whether there is a current selection.
    pub fn set_has_selection(&mut self, has_selection: bool) {
        self.has_selection = has_selection;
    }

    /// Returns true if search should automatically restrict to selection.
    pub fn auto_restrict_selection(&self) -> bool {
        self.auto_restrict_selection
    }

    /// Set whether to automatically restrict search to selection.
    pub fn set_auto_restrict_selection(&mut self, restrict: bool) {
        self.auto_restrict_selection = restrict;
    }

    /// Get the list of available region names.
    pub fn region_choices(&self) -> &[String] {
        &self.region_choices
    }

    /// Set the available region choices.
    pub fn set_region_choices(&mut self, regions: Vec<String>) {
        self.region_choices = regions;
    }

    /// Get the current search format name based on settings.
    pub fn current_format_name(&self) -> &str {
        match self.settings.format_index() {
            0 => "Hex",
            1 => "Binary",
            2 => "Decimal",
            3 => "String",
            4 => "Reg Ex",
            5 => "Float",
            6 => "Double",
            _ => "Hex",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_creation() {
        let model = SearchGuiModel::new(SearchSettings::default());
        assert_eq!(model.combiner(), Combiner::Replace);
        assert!(!model.has_selection());
    }

    #[test]
    fn test_model_set_combiner() {
        let mut model = SearchGuiModel::new(SearchSettings::default());
        model.set_combiner(Combiner::Union);
        assert_eq!(model.combiner(), Combiner::Union);
    }

    #[test]
    fn test_model_selection() {
        let mut model = SearchGuiModel::new(SearchSettings::default());
        model.set_has_selection(true);
        assert!(model.has_selection());
    }

    #[test]
    fn test_current_format() {
        let model = SearchGuiModel::new(SearchSettings::default());
        assert_eq!(model.current_format_name(), "Hex");
    }
}
