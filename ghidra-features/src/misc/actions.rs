//! Miscellaneous actions.
//!
//! Ported from `ghidra.app.plugin.core.misc` classes.
//!
//! Provides various utility actions available in the Ghidra tool,
//! including memory map display, program information, and debug actions.

/// Miscellaneous action types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MiscAction {
    /// Display memory map.
    ShowMemoryMap,
    /// Display program information.
    ShowProgramInfo,
    /// Display processor information.
    ShowProcessorInfo,
    /// Toggle listing display options.
    ToggleDisplayOptions,
    /// Clear all bookmarks.
    ClearAllBookmarks,
    /// Set program language.
    SetProgramLanguage,
    /// Set image base.
    SetImageBase,
    /// Analyze modified files.
    AnalyzeChangedFiles,
    /// Export function info.
    ExportFunctionInfo,
    /// Reload program from disk.
    ReloadFromDisk,
}

impl MiscAction {
    /// Get the action name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ShowMemoryMap => "Show Memory Map",
            Self::ShowProgramInfo => "Show Program Info",
            Self::ShowProcessorInfo => "Show Processor Info",
            Self::ToggleDisplayOptions => "Toggle Display Options",
            Self::ClearAllBookmarks => "Clear All Bookmarks",
            Self::SetProgramLanguage => "Set Program Language",
            Self::SetImageBase => "Set Image Base",
            Self::AnalyzeChangedFiles => "Analyze Changed Files",
            Self::ExportFunctionInfo => "Export Function Info",
            Self::ReloadFromDisk => "Reload From Disk",
        }
    }

    /// Whether this action requires a loaded program.
    pub fn requires_program(&self) -> bool {
        match self {
            Self::ToggleDisplayOptions => false,
            _ => true,
        }
    }

    /// Get the description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::ShowMemoryMap => "Display the program's memory map",
            Self::ShowProgramInfo => "Display program metadata",
            Self::ShowProcessorInfo => "Display processor-specific information",
            Self::ToggleDisplayOptions => "Toggle display options panel",
            Self::ClearAllBookmarks => "Remove all bookmarks from the program",
            Self::SetProgramLanguage => "Change the program's language/compiler spec",
            Self::SetImageBase => "Set the program's image base address",
            Self::AnalyzeChangedFiles => "Re-analyze files with external changes",
            Self::ExportFunctionInfo => "Export function information to a file",
            Self::ReloadFromDisk => "Reload the current program from disk",
        }
    }
}

/// Tracks the state of miscellaneous actions.
#[derive(Debug, Default)]
pub struct MiscActionState {
    /// Whether the memory map is currently shown.
    pub memory_map_visible: bool,
    /// Whether the program info dialog is shown.
    pub program_info_visible: bool,
    /// Current display options.
    pub display_options_visible: bool,
}

impl MiscActionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Toggle the visibility of a component.
    pub fn toggle(&mut self, action: MiscAction) {
        match action {
            MiscAction::ShowMemoryMap => self.memory_map_visible = !self.memory_map_visible,
            MiscAction::ShowProgramInfo => self.program_info_visible = !self.program_info_visible,
            MiscAction::ToggleDisplayOptions => {
                self.display_options_visible = !self.display_options_visible;
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_misc_action_names() {
        assert_eq!(MiscAction::ShowMemoryMap.name(), "Show Memory Map");
        assert_eq!(MiscAction::SetImageBase.name(), "Set Image Base");
    }

    #[test]
    fn test_requires_program() {
        assert!(MiscAction::ShowMemoryMap.requires_program());
        assert!(!MiscAction::ToggleDisplayOptions.requires_program());
    }

    #[test]
    fn test_action_descriptions() {
        assert!(!MiscAction::ReloadFromDisk.description().is_empty());
    }

    #[test]
    fn test_misc_action_state_toggle() {
        let mut state = MiscActionState::new();
        assert!(!state.memory_map_visible);
        state.toggle(MiscAction::ShowMemoryMap);
        assert!(state.memory_map_visible);
        state.toggle(MiscAction::ShowMemoryMap);
        assert!(!state.memory_map_visible);
    }

    #[test]
    fn test_toggle_all_variants() {
        let mut state = MiscActionState::new();
        state.toggle(MiscAction::ShowMemoryMap);
        state.toggle(MiscAction::ShowProgramInfo);
        state.toggle(MiscAction::ToggleDisplayOptions);
        assert!(state.memory_map_visible);
        assert!(state.program_info_visible);
        assert!(state.display_options_visible);
    }
}
