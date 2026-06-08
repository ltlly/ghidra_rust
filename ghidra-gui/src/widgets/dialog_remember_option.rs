//! Dialog remember option.
//!
//! Port of Ghidra's `DialogRememberOption` class. Instances of this type are
//! used to add a checkbox to a dialog so that the dialog results can be saved
//! and reused in future uses of that dialog (e.g., "Apply to all",
//! "Remember my decision").

/// A "remember my decision" option for dialogs.
///
/// When added to an `OptionDialog`, this presents a checkbox that, when
/// selected, saves the user's choice. Subsequent calls to show the same
/// dialog (or another dialog constructed with the same instance) will
/// immediately return the saved result instead of actually showing the dialog.
///
/// # Usage with egui
///
/// In the immediate-mode egui paradigm, the `show` method renders the
/// checkbox inside a dialog. The caller checks `has_remembered_result()`
/// before showing the dialog to see if a cached result is available.
///
/// ```ignore
/// use ghidra_gui::widgets::dialog_remember_option::DialogRememberOption;
///
/// let mut remember = DialogRememberOption::new("Apply to all");
/// if remember.has_remembered_result() {
///     // Use the remembered result directly
///     let result = remember.remembered_result();
/// } else {
///     // Show the dialog and render the checkbox
///     // ... (in egui ui)
///     // If user checked the box and chose an option:
///     // remember.remember_result(choice);
/// }
/// ```
pub struct DialogRememberOption {
    /// The checkbox label text (e.g., "Apply to all").
    description: String,
    /// The saved result from a previous dialog invocation.
    remembered_result: Option<i32>,
    /// Whether the checkbox is currently checked (for rendering).
    checked: bool,
}

impl DialogRememberOption {
    /// Create a new remember option with the given description.
    ///
    /// The `description` is the checkbox text, e.g., "Apply to all" or
    /// "Remember my decision".
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            remembered_result: None,
            checked: false,
        }
    }

    /// Get the description (checkbox label text).
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the remembered result, if any.
    ///
    /// Returns `None` if no result has been saved yet.
    pub fn remembered_result(&self) -> Option<i32> {
        self.remembered_result
    }

    /// Returns `true` if a previous dialog result was saved.
    pub fn has_remembered_result(&self) -> bool {
        self.remembered_result.is_some()
    }

    /// Save the result from the dialog.
    ///
    /// This should be called when the user has checked the "remember" checkbox
    /// and made a choice. Subsequent calls to `has_remembered_result()` will
    /// return `true`.
    pub fn remember_result(&mut self, choice: i32) {
        self.remembered_result = Some(choice);
    }

    /// Clear any previously remembered result, resetting the option.
    pub fn clear(&mut self) {
        self.remembered_result = None;
        self.checked = false;
    }

    /// Get the current checked state of the checkbox.
    pub fn is_checked(&self) -> bool {
        self.checked
    }

    /// Set the checked state of the checkbox.
    pub fn set_checked(&mut self, checked: bool) {
        self.checked = checked;
    }

    /// Render the remember checkbox in an egui UI.
    ///
    /// Returns `true` if the checked state changed this frame.
    pub fn show(&mut self, ui: &mut egui::Ui) -> bool {
        ui.checkbox(&mut self.checked, &self.description).changed()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let opt = DialogRememberOption::new("Apply to all");
        assert_eq!(opt.description(), "Apply to all");
        assert!(!opt.has_remembered_result());
        assert_eq!(opt.remembered_result(), None);
    }

    #[test]
    fn test_remember_result() {
        let mut opt = DialogRememberOption::new("Remember");
        assert!(!opt.has_remembered_result());

        opt.remember_result(42);
        assert!(opt.has_remembered_result());
        assert_eq!(opt.remembered_result(), Some(42));
    }

    #[test]
    fn test_clear() {
        let mut opt = DialogRememberOption::new("Remember");
        opt.remember_result(1);
        opt.set_checked(true);

        opt.clear();
        assert!(!opt.has_remembered_result());
        assert_eq!(opt.remembered_result(), None);
        assert!(!opt.is_checked());
    }

    #[test]
    fn test_checked_state() {
        let mut opt = DialogRememberOption::new("Check me");
        assert!(!opt.is_checked());

        opt.set_checked(true);
        assert!(opt.is_checked());

        opt.set_checked(false);
        assert!(!opt.is_checked());
    }

    #[test]
    fn test_overwrite_remembered_result() {
        let mut opt = DialogRememberOption::new("Apply");
        opt.remember_result(1);
        assert_eq!(opt.remembered_result(), Some(1));

        opt.remember_result(2);
        assert_eq!(opt.remembered_result(), Some(2));
    }

    #[test]
    fn test_description_from_string() {
        let opt = DialogRememberOption::new(String::from("Test"));
        assert_eq!(opt.description(), "Test");
    }
}
