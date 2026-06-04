//! Clear options controlling which program annotations to clear.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.clear.ClearOptions`.

use ghidra_core::symbol::SourceType;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The type of program annotation to clear.
///
/// Each variant corresponds to a checkbox in Ghidra's "Clear With Options" dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClearType {
    /// Clear disassembled instructions.
    Instructions,
    /// Clear defined data.
    Data,
    /// Clear user-defined symbols (labels).
    Symbols,
    /// Clear comments (pre, post, end-of-line, plate, repeatable).
    Comments,
    /// Clear properties set on code units.
    Properties,
    /// Clear functions and their metadata.
    Functions,
    /// Clear register values (context register).
    Registers,
    /// Clear equates (named constants applied to operands).
    Equates,
    /// Clear user-defined references.
    UserReferences,
    /// Clear analysis-produced references.
    AnalysisReferences,
    /// Clear import references.
    ImportReferences,
    /// Clear default references.
    DefaultReferences,
    /// Clear bookmarks.
    Bookmarks,
}

/// Options controlling which items to clear during a clear operation.
///
/// Corresponds to Ghidra's `ClearOptions` class. Each clear type can be
/// independently enabled or disabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearOptions {
    /// The set of clear types that are currently enabled.
    types_to_clear: HashSet<ClearType>,
}

impl ClearOptions {
    /// Creates options with all clear types enabled (the default Ghidra behavior).
    pub fn all() -> Self {
        Self {
            types_to_clear: [
                ClearType::Instructions,
                ClearType::Data,
                ClearType::Symbols,
                ClearType::Comments,
                ClearType::Properties,
                ClearType::Functions,
                ClearType::Registers,
                ClearType::Equates,
                ClearType::UserReferences,
                ClearType::AnalysisReferences,
                ClearType::ImportReferences,
                ClearType::DefaultReferences,
                ClearType::Bookmarks,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Creates options with a specific default state.
    ///
    /// If `default_clear_state` is `true`, all types are enabled.
    /// If `false`, no types are enabled.
    pub fn new(default_clear_state: bool) -> Self {
        if default_clear_state {
            Self::all()
        } else {
            Self {
                types_to_clear: HashSet::new(),
            }
        }
    }

    /// Sets whether a given clear type should be cleared.
    pub fn set_should_clear(&mut self, clear_type: ClearType, should_clear: bool) {
        if should_clear {
            self.types_to_clear.insert(clear_type);
        } else {
            self.types_to_clear.remove(&clear_type);
        }
    }

    /// Returns `true` if the given clear type is enabled.
    pub fn should_clear(&self, clear_type: ClearType) -> bool {
        self.types_to_clear.contains(&clear_type)
    }

    /// Returns the set of [`SourceType`]s for which references should be cleared.
    ///
    /// Maps the reference-related `ClearType` variants to their corresponding
    /// `SourceType` values.
    pub fn get_reference_source_types_to_clear(&self) -> HashSet<SourceType> {
        let mut source_types = HashSet::new();
        if self.should_clear(ClearType::UserReferences) {
            source_types.insert(SourceType::UserDefined);
        }
        if self.should_clear(ClearType::DefaultReferences) {
            source_types.insert(SourceType::Default);
        }
        if self.should_clear(ClearType::ImportReferences) {
            source_types.insert(SourceType::Imported);
        }
        if self.should_clear(ClearType::AnalysisReferences) {
            source_types.insert(SourceType::Analysis);
        }
        source_types
    }

    /// Returns `true` if any clear type is enabled.
    pub fn clear_any(&self) -> bool {
        !self.types_to_clear.is_empty()
    }

    /// Returns `true` if both instructions and data are being cleared.
    ///
    /// When both are cleared, references are implicitly cleared as well,
    /// so the caller can skip the explicit reference clearing step.
    pub fn clears_all_code(&self) -> bool {
        self.should_clear(ClearType::Instructions) && self.should_clear(ClearType::Data)
    }
}

impl Default for ClearOptions {
    /// Default: clear everything.
    fn default() -> Self {
        Self::all()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_clears_everything() {
        let opts = ClearOptions::default();
        assert!(opts.clear_any());
        assert!(opts.should_clear(ClearType::Instructions));
        assert!(opts.should_clear(ClearType::Data));
        assert!(opts.should_clear(ClearType::Symbols));
        assert!(opts.should_clear(ClearType::Comments));
        assert!(opts.should_clear(ClearType::Properties));
        assert!(opts.should_clear(ClearType::Functions));
        assert!(opts.should_clear(ClearType::Registers));
        assert!(opts.should_clear(ClearType::Equates));
        assert!(opts.should_clear(ClearType::UserReferences));
        assert!(opts.should_clear(ClearType::AnalysisReferences));
        assert!(opts.should_clear(ClearType::ImportReferences));
        assert!(opts.should_clear(ClearType::DefaultReferences));
        assert!(opts.should_clear(ClearType::Bookmarks));
    }

    #[test]
    fn test_new_false_clears_nothing() {
        let opts = ClearOptions::new(false);
        assert!(!opts.clear_any());
        assert!(!opts.should_clear(ClearType::Instructions));
        assert!(!opts.should_clear(ClearType::Data));
    }

    #[test]
    fn test_set_should_clear_toggle() {
        let mut opts = ClearOptions::new(false);
        assert!(!opts.should_clear(ClearType::Symbols));
        opts.set_should_clear(ClearType::Symbols, true);
        assert!(opts.should_clear(ClearType::Symbols));
        opts.set_should_clear(ClearType::Symbols, false);
        assert!(!opts.should_clear(ClearType::Symbols));
    }

    #[test]
    fn test_reference_source_types() {
        let mut opts = ClearOptions::new(false);
        opts.set_should_clear(ClearType::UserReferences, true);
        opts.set_should_clear(ClearType::AnalysisReferences, true);

        let sources = opts.get_reference_source_types_to_clear();
        assert!(sources.contains(&SourceType::UserDefined));
        assert!(sources.contains(&SourceType::Analysis));
        assert!(!sources.contains(&SourceType::Default));
        assert!(!sources.contains(&SourceType::Imported));
    }

    #[test]
    fn test_clears_all_code() {
        let mut opts = ClearOptions::new(false);
        assert!(!opts.clears_all_code());
        opts.set_should_clear(ClearType::Instructions, true);
        assert!(!opts.clears_all_code());
        opts.set_should_clear(ClearType::Data, true);
        assert!(opts.clears_all_code());
    }

    #[test]
    fn test_clear_any_with_single_type() {
        let mut opts = ClearOptions::new(false);
        assert!(!opts.clear_any());
        opts.set_should_clear(ClearType::Bookmarks, true);
        assert!(opts.clear_any());
    }

    #[test]
    fn test_all_reference_types() {
        let opts = ClearOptions::all();
        let sources = opts.get_reference_source_types_to_clear();
        assert_eq!(sources.len(), 4);
        assert!(sources.contains(&SourceType::UserDefined));
        assert!(sources.contains(&SourceType::Default));
        assert!(sources.contains(&SourceType::Imported));
        assert!(sources.contains(&SourceType::Analysis));
    }
}
