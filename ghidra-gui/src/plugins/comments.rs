//! Comment management plugin -- add, edit, and delete code unit comments.
//!
//! Ports `ghidra.app.plugin.core.comments`:
//! - [`CommentType`] enum (EOL, PRE, POST, PLATE, Repeatable)
//! - [`CommentsDialog`] model (manages the five comment fields)
//! - [`CommentsPlugin`] (actions and state machine)

use ghidra_core::addr::Address;
use ghidra_core::program::listing::CommentType as CoreCommentType;

// ---------------------------------------------------------------------------
// CommentType -- re-export from core with extensions
// ---------------------------------------------------------------------------

/// The five comment types supported by Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommentType {
    /// End-of-line comment (appears after the code unit on the same line).
    Eol,
    /// Pre-comment (appears on lines above the code unit).
    Pre,
    /// Post-comment (appears on lines below the code unit).
    Post,
    /// Plate comment (appears above the code unit, separated by a blank line).
    Plate,
    /// Repeatable comment (shown at call sites and xrefs).
    Repeatable,
}

impl CommentType {
    /// All five types in display order.
    pub const ALL: [CommentType; 5] = [
        CommentType::Eol,
        CommentType::Pre,
        CommentType::Post,
        CommentType::Plate,
        CommentType::Repeatable,
    ];

    /// Human-readable label for tab titles and menus.
    pub fn display_name(&self) -> &'static str {
        match self {
            CommentType::Eol => "EOL Comment",
            CommentType::Pre => "Pre Comment",
            CommentType::Post => "Post Comment",
            CommentType::Plate => "Plate Comment",
            CommentType::Repeatable => "Repeatable Comment",
        }
    }

    /// Tab index (0..4) matching the UI order.
    pub fn tab_index(&self) -> usize {
        match self {
            CommentType::Eol => 0,
            CommentType::Pre => 1,
            CommentType::Post => 2,
            CommentType::Plate => 3,
            CommentType::Repeatable => 4,
        }
    }

    /// Construct from a tab index.
    pub fn from_tab_index(idx: usize) -> Option<CommentType> {
        match idx {
            0 => Some(CommentType::Eol),
            1 => Some(CommentType::Pre),
            2 => Some(CommentType::Post),
            3 => Some(CommentType::Plate),
            4 => Some(CommentType::Repeatable),
            _ => None,
        }
    }
}

/// Convert from the core crate's CommentType.
impl From<CoreCommentType> for CommentType {
    fn from(ct: CoreCommentType) -> Self {
        match ct {
            CoreCommentType::Eol => CommentType::Eol,
            CoreCommentType::Pre => CommentType::Pre,
            CoreCommentType::Post => CommentType::Post,
            CoreCommentType::Plate => CommentType::Plate,
            CoreCommentType::Repeatable => CommentType::Repeatable,
        }
    }
}

// ---------------------------------------------------------------------------
// CommentSet -- the five comment strings for one address
// ---------------------------------------------------------------------------

/// Container holding all five comment strings for a single code unit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommentSet {
    pub eol: Option<String>,
    pub pre: Option<String>,
    pub post: Option<String>,
    pub plate: Option<String>,
    pub repeatable: Option<String>,
}

impl CommentSet {
    /// Create an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the comment for the given type.
    pub fn get(&self, ct: CommentType) -> Option<&str> {
        match ct {
            CommentType::Eol => self.eol.as_deref(),
            CommentType::Pre => self.pre.as_deref(),
            CommentType::Post => self.post.as_deref(),
            CommentType::Plate => self.plate.as_deref(),
            CommentType::Repeatable => self.repeatable.as_deref(),
        }
    }

    /// Set the comment for the given type.  Passing `None` or an empty
    /// string clears the comment.
    pub fn set(&mut self, ct: CommentType, value: Option<String>) {
        let v = value.filter(|s| !s.is_empty());
        match ct {
            CommentType::Eol => self.eol = v,
            CommentType::Pre => self.pre = v,
            CommentType::Post => self.post = v,
            CommentType::Plate => self.plate = v,
            CommentType::Repeatable => self.repeatable = v,
        }
    }

    /// Returns `true` if the set has any non-empty comment.
    pub fn has_any(&self) -> bool {
        self.eol.is_some()
            || self.pre.is_some()
            || self.post.is_some()
            || self.plate.is_some()
            || self.repeatable.is_some()
    }
}

// ---------------------------------------------------------------------------
// CommentsDialog -- model for the comment editing dialog
// ---------------------------------------------------------------------------

/// The state of the "Set Comments" dialog.
///
/// In the Java version this drives a `JTabbedPane` with five
/// `JTextArea`s.  Here we model just the data and change-tracking
/// logic.
pub struct CommentsDialog {
    /// The address being edited.
    address: Address,
    /// The original comments (before editing).
    original: CommentSet,
    /// The working copy the user is editing.
    working: CommentSet,
    /// Which tab is selected (0..4).
    selected_tab: usize,
    /// `true` if the user made unsaved changes.
    was_changed: bool,
    /// Whether pressing Enter commits the comment.
    enter_mode: bool,
}

impl CommentsDialog {
    /// Create a new dialog targeting the given address and existing comments.
    pub fn new(address: Address, existing: CommentSet) -> Self {
        Self {
            address,
            original: existing.clone(),
            working: existing,
            selected_tab: 0,
            was_changed: false,
            enter_mode: false,
        }
    }

    /// The address being edited.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the text for a specific comment type.
    pub fn get_text(&self, ct: CommentType) -> &str {
        self.working.get(ct).unwrap_or("")
    }

    /// Set the text for a specific comment type.
    pub fn set_text(&mut self, ct: CommentType, text: impl Into<String>) {
        let text = text.into();
        let current = self.working.get(ct).unwrap_or("");
        if current != text {
            self.working.set(ct, Some(text));
            self.was_changed = true;
        }
    }

    /// Select a tab by comment type.
    pub fn select_tab(&mut self, ct: CommentType) {
        self.selected_tab = ct.tab_index();
    }

    /// Get the currently selected tab index.
    pub fn selected_tab(&self) -> usize {
        self.selected_tab
    }

    /// Get the currently selected comment type.
    pub fn selected_type(&self) -> CommentType {
        CommentType::from_tab_index(self.selected_tab).unwrap_or(CommentType::Eol)
    }

    /// Whether unsaved changes exist.
    pub fn is_changed(&self) -> bool {
        self.was_changed
    }

    /// Get or set the enter-mode flag.
    pub fn enter_mode(&self) -> bool {
        self.enter_mode
    }

    /// Set the enter-mode flag.
    pub fn set_enter_mode(&mut self, mode: bool) {
        self.enter_mode = mode;
    }

    /// Apply the current working comments.
    ///
    /// Returns the comment set to write to the program, or `None` if
    /// nothing changed.
    pub fn apply(&mut self) -> Option<CommentSet> {
        if !self.was_changed {
            return None;
        }
        let result = self.working.clone();
        self.original = self.working.clone();
        self.was_changed = false;
        Some(result)
    }

    /// Cancel editing and revert to the original state.
    ///
    /// Returns `true` if there were unsaved changes.
    pub fn cancel(&mut self) -> bool {
        let had_changes = self.was_changed;
        self.working = self.original.clone();
        self.was_changed = false;
        had_changes
    }

    /// Confirm and close the dialog.
    ///
    /// Returns the final comment set if changes were made.
    pub fn ok(&mut self) -> Option<CommentSet> {
        let result = self.apply();
        result
    }

    /// Whether any field differs from the original.
    pub fn has_changes(&self) -> bool {
        self.working != self.original
    }
}

// ---------------------------------------------------------------------------
// CommentsPlugin -- plugin state
// ---------------------------------------------------------------------------

/// Tracks the plugin-wide "Enter accepts comment" option.
pub struct CommentsPlugin {
    /// Global enter-mode preference.
    enter_mode: bool,
}

impl CommentsPlugin {
    /// Create a new plugin with default settings.
    pub fn new() -> Self {
        Self { enter_mode: false }
    }

    /// Get the global enter-mode setting.
    pub fn enter_mode(&self) -> bool {
        self.enter_mode
    }

    /// Set the global enter-mode setting.
    pub fn set_enter_mode(&mut self, mode: bool) {
        self.enter_mode = mode;
    }

    /// Create a [`CommentsDialog`] pre-populated with the global enter mode.
    pub fn create_dialog(&self, address: Address, existing: CommentSet) -> CommentsDialog {
        let mut dialog = CommentsDialog::new(address, existing);
        dialog.set_enter_mode(self.enter_mode);
        dialog
    }

    /// Determine which comment type is relevant for a given location.
    ///
    /// This mirrors `CommentTypeUtils.getCommentType()` from the Java
    /// source, which inspects the `ProgramLocation` to decide whether
    /// the user clicked on a pre, post, plate, eol, or repeatable field.
    pub fn resolve_comment_type(
        code_unit_exists: bool,
        in_comment_field: bool,
        is_function_repeatable: bool,
        default: CommentType,
    ) -> CommentType {
        if is_function_repeatable {
            return CommentType::Repeatable;
        }
        if in_comment_field && code_unit_exists {
            return default;
        }
        default
    }
}

impl Default for CommentsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // -- CommentType tests --------------------------------------------------

    #[test]
    fn comment_type_display_names() {
        assert_eq!(CommentType::Eol.display_name(), "EOL Comment");
        assert_eq!(CommentType::Pre.display_name(), "Pre Comment");
        assert_eq!(CommentType::Post.display_name(), "Post Comment");
        assert_eq!(CommentType::Plate.display_name(), "Plate Comment");
        assert_eq!(CommentType::Repeatable.display_name(), "Repeatable Comment");
    }

    #[test]
    fn comment_type_tab_roundtrip() {
        for ct in &CommentType::ALL {
            let idx = ct.tab_index();
            assert_eq!(CommentType::from_tab_index(idx), Some(*ct));
        }
        assert!(CommentType::from_tab_index(99).is_none());
    }

    // -- CommentSet tests ---------------------------------------------------

    #[test]
    fn comment_set_default_empty() {
        let cs = CommentSet::new();
        assert!(!cs.has_any());
        assert_eq!(cs.get(CommentType::Eol), None);
    }

    #[test]
    fn comment_set_set_and_get() {
        let mut cs = CommentSet::new();
        cs.set(CommentType::Pre, Some("hello".into()));
        assert_eq!(cs.get(CommentType::Pre), Some("hello"));
        assert!(cs.has_any());
    }

    #[test]
    fn comment_set_empty_string_clears() {
        let mut cs = CommentSet::new();
        cs.set(CommentType::Post, Some("text".into()));
        cs.set(CommentType::Post, Some("".into()));
        assert_eq!(cs.get(CommentType::Post), None);
    }

    #[test]
    fn comment_set_none_clears() {
        let mut cs = CommentSet::new();
        cs.set(CommentType::Plate, Some("plate".into()));
        cs.set(CommentType::Plate, None);
        assert_eq!(cs.get(CommentType::Plate), None);
    }

    // -- CommentsDialog tests -----------------------------------------------

    #[test]
    fn dialog_new_has_no_changes() {
        let dialog = CommentsDialog::new(addr(0x1000), CommentSet::new());
        assert!(!dialog.is_changed());
        assert!(!dialog.has_changes());
    }

    #[test]
    fn dialog_set_text_marks_changed() {
        let mut dialog = CommentsDialog::new(addr(0x1000), CommentSet::new());
        dialog.set_text(CommentType::Eol, "some comment");
        assert!(dialog.is_changed());
        assert_eq!(dialog.get_text(CommentType::Eol), "some comment");
    }

    #[test]
    fn dialog_cancel_reverts() {
        let mut dialog = CommentsDialog::new(addr(0x1000), CommentSet::new());
        dialog.set_text(CommentType::Pre, "draft");
        assert!(dialog.cancel());
        assert_eq!(dialog.get_text(CommentType::Pre), "");
        assert!(!dialog.is_changed());
    }

    #[test]
    fn dialog_cancel_no_changes_returns_false() {
        let mut dialog = CommentsDialog::new(addr(0x1000), CommentSet::new());
        assert!(!dialog.cancel());
    }

    #[test]
    fn dialog_apply_returns_comment_set() {
        let mut dialog = CommentsDialog::new(addr(0x1000), CommentSet::new());
        dialog.set_text(CommentType::Eol, "end line");
        let result = dialog.apply().unwrap();
        assert_eq!(result.get(CommentType::Eol), Some("end line"));
        assert!(!dialog.is_changed()); // reset after apply
    }

    #[test]
    fn dialog_apply_no_changes_returns_none() {
        let mut dialog = CommentsDialog::new(addr(0x1000), CommentSet::new());
        assert!(dialog.apply().is_none());
    }

    #[test]
    fn dialog_tab_selection() {
        let mut dialog = CommentsDialog::new(addr(0x1000), CommentSet::new());
        dialog.select_tab(CommentType::Plate);
        assert_eq!(dialog.selected_tab(), 3);
        assert_eq!(dialog.selected_type(), CommentType::Plate);
    }

    #[test]
    fn dialog_ok_returns_changes() {
        let mut existing = CommentSet::new();
        existing.set(CommentType::Eol, Some("old".into()));
        let mut dialog = CommentsDialog::new(addr(0x1000), existing);
        dialog.set_text(CommentType::Eol, "new");
        let result = dialog.ok().unwrap();
        assert_eq!(result.get(CommentType::Eol), Some("new"));
    }

    #[test]
    fn dialog_set_same_text_no_change() {
        let mut existing = CommentSet::new();
        existing.set(CommentType::Eol, Some("same".into()));
        let mut dialog = CommentsDialog::new(addr(0x1000), existing);
        dialog.set_text(CommentType::Eol, "same");
        assert!(!dialog.is_changed());
    }

    // -- CommentsPlugin tests -----------------------------------------------

    #[test]
    fn plugin_enter_mode() {
        let mut plugin = CommentsPlugin::new();
        assert!(!plugin.enter_mode());
        plugin.set_enter_mode(true);
        assert!(plugin.enter_mode());
    }

    #[test]
    fn plugin_create_dialog_inherits_enter_mode() {
        let mut plugin = CommentsPlugin::new();
        plugin.set_enter_mode(true);
        let dialog = plugin.create_dialog(addr(0x1000), CommentSet::new());
        assert!(dialog.enter_mode());
    }

    #[test]
    fn plugin_resolve_comment_type_default() {
        let ct = CommentsPlugin::resolve_comment_type(false, false, false, CommentType::Eol);
        assert_eq!(ct, CommentType::Eol);
    }

    #[test]
    fn plugin_resolve_comment_type_function_repeatable() {
        let ct = CommentsPlugin::resolve_comment_type(true, true, true, CommentType::Eol);
        assert_eq!(ct, CommentType::Repeatable);
    }

    #[test]
    fn plugin_resolve_comment_type_in_field() {
        let ct = CommentsPlugin::resolve_comment_type(true, true, false, CommentType::Pre);
        assert_eq!(ct, CommentType::Pre);
    }
}
