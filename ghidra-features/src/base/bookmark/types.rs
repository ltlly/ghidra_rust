//! Bookmark type definitions, corresponding to Ghidra's `BookmarkType`.
//!
//! Ghidra defines built-in bookmark types (NOTE, INFO, WARNING, ERROR, ANALYSIS)
//! that carry a display priority, marker color, and optional icon identifier.
//! Users and plugins can register additional custom types.

use std::fmt;

// ---------------------------------------------------------------------------
// BookmarkType
// ---------------------------------------------------------------------------

/// Represents a category of bookmark within a program.
///
/// Corresponds to Ghidra's `BookmarkType` which defines built-in types
/// (NOTE, INFO, WARNING, ERROR, ANALYSIS) and allows plugins to register
/// custom types.
///
/// Each type carries:
/// - A human-readable type string (e.g., "Note", "Warning")
/// - A marker display priority (lower values appear closer to the top)
/// - An optional marker color (as an RGB hex string)
/// - An optional icon identifier (for GUI rendering)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BookmarkType {
    /// The type string identifier (e.g. "Note", "Warning").
    type_string: String,
    /// Marker priority; lower values are higher priority.
    marker_priority: i32,
    /// Marker color as an RGB hex string (e.g. "#FF0000"), or None for default.
    marker_color: Option<String>,
    /// Icon identifier for GUI rendering, or None if no icon.
    icon_id: Option<String>,
}

impl BookmarkType {
    // Built-in type strings (matching Ghidra's constants).
    pub const NOTE: &'static str = "Note";
    pub const INFO: &'static str = "Info";
    pub const WARNING: &'static str = "Warning";
    pub const ERROR: &'static str = "Error";
    pub const ANALYSIS: &'static str = "Analysis";

    // Default marker priorities (relative to MarkerService.BOOKMARK_PRIORITY).
    const BOOKMARK_PRIORITY: i32 = 1;
    const BIG_CHANGE: i32 = 1000;
    const NOTE_PRIORITY: i32 = Self::BOOKMARK_PRIORITY;
    const ERROR_PRIORITY: i32 = Self::BOOKMARK_PRIORITY + Self::BIG_CHANGE;
    const WARNING_PRIORITY: i32 = Self::BOOKMARK_PRIORITY + (Self::BIG_CHANGE / 2);
    const INFO_PRIORITY: i32 = Self::BOOKMARK_PRIORITY + 4;
    const ANALYSIS_PRIORITY: i32 = Self::BOOKMARK_PRIORITY + 6;
    const DEFAULT_PRIORITY: i32 = Self::BOOKMARK_PRIORITY + 8;

    /// Creates a new BookmarkType with the given properties.
    pub fn new(
        type_string: impl Into<String>,
        marker_priority: i32,
        marker_color: Option<String>,
        icon_id: Option<String>,
    ) -> Self {
        Self {
            type_string: type_string.into(),
            marker_priority,
            marker_color,
            icon_id,
        }
    }

    /// Creates the built-in "Note" bookmark type.
    pub fn note() -> Self {
        Self::new(
            Self::NOTE,
            Self::NOTE_PRIORITY,
            Some("#AABBCC".into()),
            Some("icon.plugin.bookmark.type.note".into()),
        )
    }

    /// Creates the built-in "Info" bookmark type.
    pub fn info() -> Self {
        Self::new(
            Self::INFO,
            Self::INFO_PRIORITY,
            Some("#6699FF".into()),
            Some("icon.plugin.bookmark.type.info".into()),
        )
    }

    /// Creates the built-in "Warning" bookmark type.
    pub fn warning() -> Self {
        Self::new(
            Self::WARNING,
            Self::WARNING_PRIORITY,
            Some("#FF9900".into()),
            Some("icon.plugin.bookmark.type.warning".into()),
        )
    }

    /// Creates the built-in "Error" bookmark type.
    pub fn error() -> Self {
        Self::new(
            Self::ERROR,
            Self::ERROR_PRIORITY,
            Some("#FF0000".into()),
            Some("icon.plugin.bookmark.type.error".into()),
        )
    }

    /// Creates the built-in "Analysis" bookmark type.
    pub fn analysis() -> Self {
        Self::new(
            Self::ANALYSIS,
            Self::ANALYSIS_PRIORITY,
            Some("#99CC00".into()),
            Some("icon.plugin.bookmark.type.analysis".into()),
        )
    }

    /// Returns the type string (e.g. "Note", "Warning").
    pub fn type_string(&self) -> &str {
        &self.type_string
    }

    /// Returns the marker priority. Lower values are higher priority.
    pub fn marker_priority(&self) -> i32 {
        self.marker_priority
    }

    /// Returns the marker color, or None for the default color.
    pub fn marker_color(&self) -> Option<&str> {
        self.marker_color.as_deref()
    }

    /// Returns the icon identifier, or None if no icon is configured.
    pub fn icon_id(&self) -> Option<&str> {
        self.icon_id.as_deref()
    }

    /// Returns the default priority for types that do not specify one.
    pub fn default_priority() -> i32 {
        Self::DEFAULT_PRIORITY
    }

    /// Returns all built-in types.
    pub fn builtin_types() -> Vec<BookmarkType> {
        vec![
            Self::note(),
            Self::info(),
            Self::warning(),
            Self::error(),
            Self::analysis(),
        ]
    }
}

impl fmt::Display for BookmarkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.type_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_type_strings() {
        assert_eq!(BookmarkType::NOTE, "Note");
        assert_eq!(BookmarkType::INFO, "Info");
        assert_eq!(BookmarkType::WARNING, "Warning");
        assert_eq!(BookmarkType::ERROR, "Error");
        assert_eq!(BookmarkType::ANALYSIS, "Analysis");
    }

    #[test]
    fn test_note_type() {
        let note = BookmarkType::note();
        assert_eq!(note.type_string(), "Note");
        assert_eq!(note.marker_priority(), BookmarkType::BOOKMARK_PRIORITY);
        assert!(note.marker_color().is_some());
        assert!(note.icon_id().is_some());
    }

    #[test]
    fn test_priority_ordering() {
        let note = BookmarkType::note();
        let info = BookmarkType::info();
        let warning = BookmarkType::warning();
        let error = BookmarkType::error();
        let analysis = BookmarkType::analysis();

        // Lower number = higher priority
        assert!(note.marker_priority() < info.marker_priority());
        assert!(info.marker_priority() < analysis.marker_priority());
        assert!(analysis.marker_priority() < warning.marker_priority());
        assert!(warning.marker_priority() < error.marker_priority());
    }

    #[test]
    fn test_custom_type() {
        let custom = BookmarkType::new("Custom", 42, Some("#FFFFFF".into()), None);
        assert_eq!(custom.type_string(), "Custom");
        assert_eq!(custom.marker_priority(), 42);
        assert_eq!(custom.marker_color(), Some("#FFFFFF"));
        assert!(custom.icon_id().is_none());
    }

    #[test]
    fn test_builtin_types_count() {
        assert_eq!(BookmarkType::builtin_types().len(), 5);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", BookmarkType::note()), "Note");
    }
}
