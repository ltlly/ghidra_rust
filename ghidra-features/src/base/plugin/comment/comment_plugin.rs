//! Comment Plugin -- manages comments in the program listing.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.comments` package.
//!
//! This module provides the comment plugin that manages comments in the
//! program listing. Supports various comment types (end-of-line, pre, post,
//! plate, repeatable) and operations like add, edit, delete, and history.
//!
//! # Architecture
//!
//! ```text
//! CommentPlugin
//!   ├── CommentManager (comment CRUD operations)
//!   ├── CommentDialog (edit dialog)
//!   ├── CommentHistory (change history)
//!   └── CommentActions (context menu actions)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::plugin::comment::comment_plugin::CommentPlugin;
//!
//! let mut plugin = CommentPlugin::new("Comments");
//! plugin.init();
//! assert_eq!(plugin.name(), "Comments");
//! ```

use std::collections::HashMap;
use std::fmt;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// CommentType -- types of comments
// ---------------------------------------------------------------------------

/// The type of a comment.
///
/// Ported from Ghidra's `ghidra.program.model.listing.CommentType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// End-of-line comment (appears after the instruction).
    Eol,
    /// Pre-comment (appears before the code unit).
    Pre,
    /// Post-comment (appears after the code unit).
    Post,
    /// Plate comment (appears as a banner above the code unit).
    Plate,
    /// Repeatable comment (appears wherever the code unit is referenced).
    Repeatable,
}

impl CommentType {
    /// Returns the display name for this comment type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Eol => "EOL Comment",
            Self::Pre => "Pre Comment",
            Self::Post => "Post Comment",
            Self::Plate => "Plate Comment",
            Self::Repeatable => "Repeatable Comment",
        }
    }

    /// Returns the ordinal value.
    pub fn ordinal(&self) -> i32 {
        match self {
            Self::Eol => 0,
            Self::Pre => 1,
            Self::Post => 2,
            Self::Plate => 3,
            Self::Repeatable => 4,
        }
    }

    /// Returns all comment types.
    pub fn all() -> &'static [CommentType] {
        &[
            Self::Eol,
            Self::Pre,
            Self::Post,
            Self::Plate,
            Self::Repeatable,
        ]
    }
}

impl fmt::Display for CommentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// Comment -- a single comment
// ---------------------------------------------------------------------------

/// A comment at an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// The address (as hex string).
    pub address: String,
    /// The comment type.
    pub comment_type: CommentType,
    /// The comment text.
    pub text: String,
    /// The author.
    pub author: String,
    /// The creation timestamp.
    pub created_at: String,
}

impl Comment {
    /// Creates a new comment.
    pub fn new(
        address: impl Into<String>,
        comment_type: CommentType,
        text: impl Into<String>,
        author: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            comment_type,
            text: text.into(),
            author: author.into(),
            created_at: format_timestamp(SystemTime::now()),
        }
    }

    /// Returns whether the comment is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CommentHistoryEntry -- a change to a comment
// ---------------------------------------------------------------------------

/// A single entry in a comment's change history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentHistoryEntry {
    /// The user who made the change.
    pub user_name: String,
    /// When the change was made.
    pub timestamp: String,
    /// The comment text after the change.
    pub comment_text: String,
    /// The action taken.
    pub action: CommentHistoryAction,
}

/// The type of action in a comment history entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentHistoryAction {
    /// Comment was added.
    Added,
    /// Comment was modified.
    Modified,
    /// Comment was deleted.
    Deleted,
}

impl fmt::Display for CommentHistoryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Added => write!(f, "Added"),
            Self::Modified => write!(f, "Modified"),
            Self::Deleted => write!(f, "Deleted"),
        }
    }
}

impl CommentHistoryEntry {
    /// Creates a new history entry.
    pub fn new(
        user_name: impl Into<String>,
        comment_text: impl Into<String>,
        action: CommentHistoryAction,
    ) -> Self {
        Self {
            user_name: user_name.into(),
            timestamp: format_timestamp(SystemTime::now()),
            comment_text: comment_text.into(),
            action,
        }
    }
}

// ---------------------------------------------------------------------------
// CommentHistoryStore -- per-address, per-type history tracking
// ---------------------------------------------------------------------------

/// Stores comment change history for all addresses and comment types.
#[derive(Debug, Clone, Default)]
pub struct CommentHistoryStore {
    /// History entries keyed by (address, comment_type_ordinal).
    entries: HashMap<(String, i32), Vec<CommentHistoryEntry>>,
}

impl CommentHistoryStore {
    /// Creates a new empty history store.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Records a comment change.
    pub fn record_change(
        &mut self,
        address: &str,
        comment_type: CommentType,
        entry: CommentHistoryEntry,
    ) {
        let key = (address.to_string(), comment_type.ordinal());
        self.entries.entry(key).or_default().push(entry);
    }

    /// Returns the history for a given address and comment type.
    pub fn get_history(&self, address: &str, comment_type: CommentType) -> Option<&Vec<CommentHistoryEntry>> {
        let key = (address.to_string(), comment_type.ordinal());
        self.entries.get(&key)
    }

    /// Returns the total number of history entries.
    pub fn total_entries(&self) -> usize {
        self.entries.values().map(|v| v.len()).sum()
    }

    /// Clears all history.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

// ---------------------------------------------------------------------------
// CommentPlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The comment plugin.
///
/// Manages comments in the program listing. Supports various comment types
/// and operations like add, edit, delete, and history.
///
/// Ported from Ghidra's `CommentsPlugin` Java class.
#[derive(Debug)]
pub struct CommentPlugin {
    /// The plugin name.
    name: String,
    /// Comments by (address, comment_type_ordinal).
    comments: HashMap<(String, i32), Comment>,
    /// Comment history.
    history: CommentHistoryStore,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Plugin options.
    options: HashMap<String, CommentOption>,
}

/// A comment plugin option.
#[derive(Debug, Clone)]
pub enum CommentOption {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i32),
    /// String option.
    String(String),
}

impl fmt::Display for CommentOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
        }
    }
}

impl CommentPlugin {
    /// Creates a new comment plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comments: HashMap::new(),
            history: CommentHistoryStore::new(),
            initialized: false,
            disposed: false,
            options: HashMap::new(),
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initializes the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.comments.clear();
        self.history.clear();
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Adds or updates a comment.
    pub fn set_comment(&mut self, comment: Comment) {
        let key = (comment.address.clone(), comment.comment_type.ordinal());
        let action = if self.comments.contains_key(&key) {
            CommentHistoryAction::Modified
        } else {
            CommentHistoryAction::Added
        };
        let entry = CommentHistoryEntry::new(&comment.author, &comment.text, action);
        self.history.record_change(&comment.address, comment.comment_type, entry);
        self.comments.insert(key, comment);
    }

    /// Returns a comment at the given address and type.
    pub fn get_comment(&self, address: &str, comment_type: CommentType) -> Option<&Comment> {
        let key = (address.to_string(), comment_type.ordinal());
        self.comments.get(&key)
    }

    /// Deletes a comment at the given address and type.
    pub fn delete_comment(&mut self, address: &str, comment_type: CommentType) -> Option<Comment> {
        let key = (address.to_string(), comment_type.ordinal());
        if let Some(comment) = self.comments.remove(&key) {
            let entry = CommentHistoryEntry::new(
                &comment.author,
                "",
                CommentHistoryAction::Deleted,
            );
            self.history.record_change(address, comment_type, entry);
            Some(comment)
        } else {
            None
        }
    }

    /// Returns all comments at the given address.
    pub fn get_comments_at(&self, address: &str) -> Vec<&Comment> {
        self.comments
            .iter()
            .filter(|((addr, _), _)| addr == address)
            .map(|(_, comment)| comment)
            .collect()
    }

    /// Returns all comments of the given type.
    pub fn get_comments_of_type(&self, comment_type: CommentType) -> Vec<&Comment> {
        let ordinal = comment_type.ordinal();
        self.comments
            .iter()
            .filter(|((_, t), _)| *t == ordinal)
            .map(|(_, comment)| comment)
            .collect()
    }

    /// Returns the total number of comments.
    pub fn comment_count(&self) -> usize {
        self.comments.len()
    }

    /// Returns a reference to the comment history.
    pub fn history(&self) -> &CommentHistoryStore {
        &self.history
    }

    /// Returns the history for a given address and comment type.
    pub fn get_history(&self, address: &str, comment_type: CommentType) -> Option<&Vec<CommentHistoryEntry>> {
        self.history.get_history(address, comment_type)
    }

    /// Sets a plugin option.
    pub fn set_option(&mut self, key: impl Into<String>, value: CommentOption) {
        self.options.insert(key.into(), value);
    }

    /// Gets a plugin option.
    pub fn get_option(&self, key: &str) -> Option<&CommentOption> {
        self.options.get(key)
    }
}

impl Default for CommentPlugin {
    fn default() -> Self {
        Self::new("CommentPlugin")
    }
}

impl fmt::Display for CommentPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommentPlugin({}, comments={})", self.name, self.comment_count())
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Formats a SystemTime as a human-readable string.
fn format_timestamp(time: SystemTime) -> String {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = CommentPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert_eq!(plugin.comment_count(), 0);
        assert!(!plugin.is_initialized());
    }

    #[test]
    fn test_comment_types() {
        assert_eq!(CommentType::Eol.display_name(), "EOL Comment");
        assert_eq!(CommentType::Pre.display_name(), "Pre Comment");
        assert_eq!(CommentType::Post.display_name(), "Post Comment");
        assert_eq!(CommentType::Plate.display_name(), "Plate Comment");
        assert_eq!(CommentType::Repeatable.display_name(), "Repeatable Comment");
        assert_eq!(CommentType::all().len(), 5);
    }

    #[test]
    fn test_set_get_comment() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        let comment = Comment::new("0x401000", CommentType::Eol, "test comment", "user");
        plugin.set_comment(comment);
        assert_eq!(plugin.comment_count(), 1);
        let retrieved = plugin.get_comment("0x401000", CommentType::Eol);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().text, "test comment");
    }

    #[test]
    fn test_delete_comment() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        let comment = Comment::new("0x401000", CommentType::Eol, "test", "user");
        plugin.set_comment(comment);
        assert_eq!(plugin.comment_count(), 1);
        plugin.delete_comment("0x401000", CommentType::Eol);
        assert_eq!(plugin.comment_count(), 0);
    }

    #[test]
    fn test_comment_history() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        let comment = Comment::new("0x401000", CommentType::Eol, "original", "user");
        plugin.set_comment(comment);
        let comment = Comment::new("0x401000", CommentType::Eol, "modified", "user");
        plugin.set_comment(comment);
        let history = plugin.get_history("0x401000", CommentType::Eol);
        assert!(history.is_some());
        assert_eq!(history.unwrap().len(), 2);
    }

    #[test]
    fn test_get_comments_at() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.set_comment(Comment::new("0x401000", CommentType::Eol, "eol", "user"));
        plugin.set_comment(Comment::new("0x401000", CommentType::Pre, "pre", "user"));
        plugin.set_comment(Comment::new("0x402000", CommentType::Eol, "other", "user"));
        assert_eq!(plugin.get_comments_at("0x401000").len(), 2);
        assert_eq!(plugin.get_comments_at("0x402000").len(), 1);
    }

    #[test]
    fn test_init_dispose() {
        let mut plugin = CommentPlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }
}
