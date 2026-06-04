//! Tip of the Day plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.totd` package.
//!
//! Displays tips to the user on startup, cycling through a list of
//! useful hints about Ghidra features.
//!
//! # Key Types
//!
//! - [`TipOfTheDayPlugin`] -- Plugin providing the tip display
//! - [`Tip`] -- A single tip entry
//! - [`TipDatabase`] -- Collection of tips

use serde::{Deserialize, Serialize};

/// Default number of tips.
pub const DEFAULT_TIP_COUNT: usize = 30;

/// Option key for showing tips on startup.
pub const SHOW_TIPS: &str = "Show Tips on Startup";

/// Option key for the last shown tip index.
pub const TIP_INDEX: &str = "Last Tip Index";

// ---------------------------------------------------------------------------
// Tip
// ---------------------------------------------------------------------------

/// A single tip.
///
/// Ported from `ghidra.app.plugin.core.totd.TipOfTheDayDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tip {
    /// The tip text.
    pub text: String,
    /// Optional help topic for more info.
    pub help_topic: Option<String>,
    /// Category (e.g., "Navigation", "Editing", "Analysis").
    pub category: String,
}

impl Tip {
    /// Create a new tip.
    pub fn new(text: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            help_topic: None,
            category: category.into(),
        }
    }

    /// Create a tip with a help topic.
    pub fn with_help(
        text: impl Into<String>,
        category: impl Into<String>,
        help_topic: impl Into<String>,
    ) -> Self {
        Self {
            text: text.into(),
            help_topic: Some(help_topic.into()),
            category: category.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tip database
// ---------------------------------------------------------------------------

/// Collection of tips.
#[derive(Debug, Clone)]
pub struct TipDatabase {
    tips: Vec<Tip>,
    current_index: usize,
}

impl TipDatabase {
    /// Create a new tip database with the given tips.
    pub fn new(tips: Vec<Tip>) -> Self {
        Self {
            tips,
            current_index: 0,
        }
    }

    /// Create a database with default Ghidra tips.
    pub fn with_defaults() -> Self {
        let tips = vec![
            Tip::new("Use Ctrl+Shift+E to search for a symbol by name.", "Navigation"),
            Tip::new("Right-click in the listing to access context-sensitive actions.", "Editing"),
            Tip::new("Use the Decompiler window (Ctrl+E) to see decompiled C code.", "Decompilation"),
            Tip::new("Press 'D' to define data, 'C' to disassemble at the cursor.", "Editing"),
            Tip::new("Use bookmarks (Ctrl+D) to mark locations for quick navigation.", "Navigation"),
            Tip::new("Drag and drop files onto Ghidra to import them.", "Importing"),
            Tip::new("Use the Byte Viewer to inspect raw memory contents.", "Analysis"),
            Tip::new("Press 'L' to set a label at the current address.", "Editing"),
            Tip::new("Use Function ID to match known library functions.", "Analysis"),
            Tip::new("The Equate feature lets you name constant values (Ctrl+E on a number).", "Editing"),
        ];
        Self::new(tips)
    }

    /// Get the current tip.
    pub fn current_tip(&self) -> Option<&Tip> {
        self.tips.get(self.current_index)
    }

    /// Advance to the next tip and return it.
    pub fn next_tip(&mut self) -> Option<&Tip> {
        if self.tips.is_empty() {
            return None;
        }
        self.current_index = (self.current_index + 1) % self.tips.len();
        self.current_tip()
    }

    /// Go to the previous tip.
    pub fn previous_tip(&mut self) -> Option<&Tip> {
        if self.tips.is_empty() {
            return None;
        }
        self.current_index = if self.current_index == 0 {
            self.tips.len() - 1
        } else {
            self.current_index - 1
        };
        self.current_tip()
    }

    /// Get the current index.
    pub fn current_index(&self) -> usize {
        self.current_index
    }

    /// Set the current index.
    pub fn set_index(&mut self, index: usize) {
        if index < self.tips.len() {
            self.current_index = index;
        }
    }

    /// Number of tips.
    pub fn len(&self) -> usize {
        self.tips.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.tips.is_empty()
    }

    /// Get all tips.
    pub fn tips(&self) -> &[Tip] {
        &self.tips
    }
}

// ---------------------------------------------------------------------------
// Tip of the Day plugin
// ---------------------------------------------------------------------------

/// Plugin providing the Tip of the Day dialog.
///
/// Ported from `ghidra.app.plugin.core.totd.TipOfTheDayPlugin`.
#[derive(Debug)]
pub struct TipOfTheDayPlugin {
    /// The tip database.
    database: TipDatabase,
    /// Whether to show tips on startup.
    show_on_startup: bool,
}

impl TipOfTheDayPlugin {
    /// Create a new Tip of the Day plugin with default tips.
    pub fn new() -> Self {
        Self {
            database: TipDatabase::with_defaults(),
            show_on_startup: true,
        }
    }

    /// Get the tip database.
    pub fn database(&self) -> &TipDatabase {
        &self.database
    }

    /// Get a mutable reference to the tip database.
    pub fn database_mut(&mut self) -> &mut TipDatabase {
        &mut self.database
    }

    /// Whether to show tips on startup.
    pub fn show_on_startup(&self) -> bool {
        self.show_on_startup
    }

    /// Set whether to show tips on startup.
    pub fn set_show_on_startup(&mut self, show: bool) {
        self.show_on_startup = show;
    }

    /// Get the current tip text.
    pub fn current_tip_text(&self) -> Option<&str> {
        self.database.current_tip().map(|t| t.text.as_str())
    }

    /// Show the next tip.
    pub fn next_tip(&mut self) -> Option<&str> {
        self.database.next_tip().map(|t| t.text.as_str())
    }
}

impl Default for TipOfTheDayPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tip_creation() {
        let tip = Tip::new("Use Ctrl+G to go to address.", "Navigation");
        assert_eq!(tip.text, "Use Ctrl+G to go to address.");
        assert_eq!(tip.category, "Navigation");
        assert!(tip.help_topic.is_none());
    }

    #[test]
    fn test_tip_with_help() {
        let tip = Tip::with_help("tip", "cat", "HelpTopic");
        assert_eq!(tip.help_topic, Some("HelpTopic".into()));
    }

    #[test]
    fn test_tip_database_creation() {
        let tips = vec![
            Tip::new("Tip 1", "A"),
            Tip::new("Tip 2", "B"),
            Tip::new("Tip 3", "A"),
        ];
        let db = TipDatabase::new(tips);
        assert_eq!(db.len(), 3);
        assert!(!db.is_empty());
        assert_eq!(db.current_index(), 0);
    }

    #[test]
    fn test_tip_database_navigation() {
        let mut db = TipDatabase::new(vec![
            Tip::new("A", ""),
            Tip::new("B", ""),
            Tip::new("C", ""),
        ]);

        assert_eq!(db.current_tip().unwrap().text, "A");

        db.next_tip();
        assert_eq!(db.current_tip().unwrap().text, "B");

        db.next_tip();
        assert_eq!(db.current_tip().unwrap().text, "C");

        db.next_tip(); // wraps around
        assert_eq!(db.current_tip().unwrap().text, "A");
    }

    #[test]
    fn test_tip_database_previous() {
        let mut db = TipDatabase::new(vec![Tip::new("A", ""), Tip::new("B", "")]);
        assert_eq!(db.current_tip().unwrap().text, "A");

        db.previous_tip(); // wraps to last
        assert_eq!(db.current_tip().unwrap().text, "B");

        db.previous_tip();
        assert_eq!(db.current_tip().unwrap().text, "A");
    }

    #[test]
    fn test_tip_database_set_index() {
        let mut db = TipDatabase::new(vec![Tip::new("A", ""), Tip::new("B", ""), Tip::new("C", "")]);
        db.set_index(2);
        assert_eq!(db.current_index(), 2);
        assert_eq!(db.current_tip().unwrap().text, "C");

        db.set_index(99); // out of range, no change
        assert_eq!(db.current_index(), 2);
    }

    #[test]
    fn test_tip_database_empty() {
        let mut db = TipDatabase::new(vec![]);
        assert!(db.is_empty());
        assert!(db.current_tip().is_none());
        assert!(db.next_tip().is_none());
        assert!(db.previous_tip().is_none());
    }

    #[test]
    fn test_tip_database_with_defaults() {
        let db = TipDatabase::with_defaults();
        assert_eq!(db.len(), 10);
        assert!(db.current_tip().is_some());
    }

    #[test]
    fn test_tip_of_the_day_plugin() {
        let mut plugin = TipOfTheDayPlugin::new();
        assert!(plugin.show_on_startup());
        assert!(plugin.current_tip_text().is_some());

        plugin.set_show_on_startup(false);
        assert!(!plugin.show_on_startup());

        let first = plugin.current_tip_text().unwrap().to_string();
        let second = plugin.next_tip().unwrap().to_string();
        assert_ne!(first, second);
    }
}
