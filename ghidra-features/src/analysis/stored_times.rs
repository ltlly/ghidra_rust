//! StoredAnalyzerTimes and StoredAnalyzerTimesPropertyEditor.
//!
//! Re-exports [`StoredAnalyzerTimes`] from `base::analyzer::worker` and
//! adds the [`StoredAnalyzerTimesPropertyEditor`] for UI display.

pub use crate::base::analyzer::StoredAnalyzerTimes;

/// Property editor for stored analyzer times.
///
/// Ported from Ghidra's `StoredAnalyzerTimesPropertyEditor`. Provides
/// a view/editor for the cumulative analyzer timing data stored in
/// program options.
#[derive(Debug, Clone)]
pub struct StoredAnalyzerTimesPropertyEditor {
    /// Display text.
    display_text: String,
}

impl StoredAnalyzerTimesPropertyEditor {
    /// Create a new property editor.
    pub fn new() -> Self {
        Self {
            display_text: String::new(),
        }
    }

    /// Set the display text.
    pub fn set_display_text(&mut self, text: String) {
        self.display_text = text;
    }

    /// Get the display text.
    pub fn display_text(&self) -> &str {
        &self.display_text
    }
}

impl Default for StoredAnalyzerTimesPropertyEditor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_editor() {
        let editor = StoredAnalyzerTimesPropertyEditor::new();
        assert!(editor.display_text().is_empty());
    }
}
