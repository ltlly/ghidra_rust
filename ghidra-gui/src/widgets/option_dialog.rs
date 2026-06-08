//! Option dialog.
//!
//! Port of Ghidra's `OptionDialog` class. Provides modal dialogs that present
//! the user with one or more choices. In egui immediate-mode style, the dialog
//! is shown via [`OptionDialog::show`], which returns the user's choice.

/// Message severity for the dialog icon/color.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    Error,
    Info,
    Warning,
    Question,
    Plain,
}

impl Default for MessageType {
    fn default() -> Self {
        MessageType::Info
    }
}

/// The result of an option dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DialogResult {
    /// No choice made yet (dialog still open).
    None,
    /// The user pressed Cancel or closed the dialog.
    Cancel,
    /// Option 1 was selected.
    Option1,
    /// Option 2 was selected.
    Option2,
    /// Option 3 was selected.
    Option3,
    /// Yes was selected.
    Yes,
    /// No was selected.
    No,
    /// OK was selected.
    Ok,
}

impl DialogResult {
    pub fn is_none(&self) -> bool {
        *self == DialogResult::None
    }
}

/// State for an option dialog.
///
/// In egui, this struct is used with the `show` method to render a modal
/// dialog. The caller checks the `result` field after `show` returns to
/// determine the user's choice.
pub struct OptionDialog {
    /// Dialog title.
    title: String,
    /// The message displayed in the dialog body.
    message: String,
    /// Message severity.
    message_type: MessageType,
    /// The buttons to display (label text).
    buttons: Vec<String>,
    /// Whether to add a Cancel button.
    add_cancel: bool,
    /// The result of the dialog.
    result: DialogResult,
    /// Whether the dialog is currently open.
    open: bool,
    /// Optional default button index.
    default_button: Option<usize>,
}

impl OptionDialog {
    /// Create a simple OK dialog.
    pub fn ok(title: impl Into<String>, message: impl Into<String>, message_type: MessageType) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            message_type,
            buttons: vec!["OK".to_string()],
            add_cancel: false,
            result: DialogResult::None,
            open: true,
            default_button: Some(0),
        }
    }

    /// Create a Yes/No dialog.
    pub fn yes_no(title: impl Into<String>, message: impl Into<String>, message_type: MessageType) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            message_type,
            buttons: vec!["Yes".to_string(), "No".to_string()],
            add_cancel: false,
            result: DialogResult::None,
            open: true,
            default_button: Some(0),
        }
    }

    /// Create a Yes/No/Cancel dialog.
    pub fn yes_no_cancel(
        title: impl Into<String>,
        message: impl Into<String>,
        message_type: MessageType,
    ) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            message_type,
            buttons: vec!["Yes".to_string(), "No".to_string()],
            add_cancel: true,
            result: DialogResult::None,
            open: true,
            default_button: Some(0),
        }
    }

    /// Create a custom dialog with the given option labels.
    pub fn custom(
        title: impl Into<String>,
        message: impl Into<String>,
        options: Vec<String>,
        message_type: MessageType,
        add_cancel: bool,
    ) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            message_type,
            buttons: options,
            add_cancel,
            result: DialogResult::None,
            open: true,
            default_button: Some(0),
        }
    }

    /// Returns `true` if the dialog is still open.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Get the dialog result.
    pub fn result(&self) -> DialogResult {
        self.result
    }

    /// Close the dialog with the given result.
    pub fn close(&mut self, result: DialogResult) {
        self.result = result;
        self.open = false;
    }

    /// Reset the dialog for reuse.
    pub fn reset(&mut self) {
        self.result = DialogResult::None;
        self.open = true;
    }

    /// Get the icon color for the message type.
    fn icon_color(&self) -> egui::Color32 {
        match self.message_type {
            MessageType::Error => egui::Color32::from_rgb(220, 50, 50),
            MessageType::Warning => egui::Color32::from_rgb(230, 180, 50),
            MessageType::Info | MessageType::Question => egui::Color32::from_rgb(80, 140, 220),
            MessageType::Plain => egui::Color32::GRAY,
        }
    }

    /// Get the icon symbol for the message type.
    fn icon_symbol(&self) -> &str {
        match self.message_type {
            MessageType::Error => "X",
            MessageType::Warning => "!",
            MessageType::Info => "i",
            MessageType::Question => "?",
            MessageType::Plain => " ",
        }
    }

    /// Show the dialog using egui. Returns `true` if the dialog made a choice
    /// this frame.
    pub fn show(&mut self, ctx: &egui::Context) -> bool {
        if !self.open {
            return false;
        }

        let mut made_choice = false;
        let title = self.title.clone();
        let message = self.message.clone();
        let buttons = self.buttons.clone();
        let add_cancel = self.add_cancel;
        let icon_color = self.icon_color();
        let icon_symbol = self.icon_symbol().to_string();

        egui::Window::new(&title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(icon_color, egui::RichText::new(&icon_symbol).size(24.0));
                    ui.label(&message);
                });

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(4.0);

                ui.horizontal(|ui| {
                    for (i, label) in buttons.iter().enumerate() {
                        let result = match label.as_str() {
                            "OK" => DialogResult::Ok,
                            "Yes" => DialogResult::Yes,
                            "No" => DialogResult::No,
                            "Cancel" => DialogResult::Cancel,
                            _ => match i {
                                0 => DialogResult::Option1,
                                1 => DialogResult::Option2,
                                2 => DialogResult::Option3,
                                _ => DialogResult::Option1,
                            },
                        };
                        if ui.button(label).clicked() {
                            self.result = result;
                            self.open = false;
                            made_choice = true;
                        }
                    }
                    if add_cancel {
                        if ui.button("Cancel").clicked() {
                            self.result = DialogResult::Cancel;
                            self.open = false;
                            made_choice = true;
                        }
                    }
                });
            });

        made_choice
    }
}

/// Static helper methods for common dialog patterns.
impl OptionDialog {
    /// Show a simple info message dialog.
    pub fn show_info(ctx: &egui::Context, title: &str, message: &str) {
        let mut dialog = OptionDialog::ok(title, message, MessageType::Info);
        dialog.show(ctx);
    }

    /// Show a warning dialog.
    pub fn show_warning(ctx: &egui::Context, title: &str, message: &str) {
        let mut dialog = OptionDialog::ok(title, message, MessageType::Warning);
        dialog.show(ctx);
    }

    /// Show an error dialog.
    pub fn show_error(ctx: &egui::Context, title: &str, message: &str) {
        let mut dialog = OptionDialog::ok(title, message, MessageType::Error);
        dialog.show(ctx);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok_dialog() {
        let dialog = OptionDialog::ok("Title", "Message", MessageType::Info);
        assert!(dialog.is_open());
        assert_eq!(dialog.result(), DialogResult::None);
        assert_eq!(dialog.buttons.len(), 1);
        assert_eq!(dialog.buttons[0], "OK");
        assert!(!dialog.add_cancel);
    }

    #[test]
    fn test_yes_no_dialog() {
        let dialog = OptionDialog::yes_no("Title", "Question?", MessageType::Question);
        assert!(dialog.is_open());
        assert_eq!(dialog.buttons.len(), 2);
        assert_eq!(dialog.buttons[0], "Yes");
        assert_eq!(dialog.buttons[1], "No");
    }

    #[test]
    fn test_yes_no_cancel_dialog() {
        let dialog =
            OptionDialog::yes_no_cancel("Title", "Save changes?", MessageType::Warning);
        assert!(dialog.add_cancel);
    }

    #[test]
    fn test_custom_dialog() {
        let dialog = OptionDialog::custom(
            "Custom",
            "Pick one",
            vec!["A".into(), "B".into(), "C".into()],
            MessageType::Plain,
            true,
        );
        assert_eq!(dialog.buttons.len(), 3);
        assert!(dialog.add_cancel);
    }

    #[test]
    fn test_close_with_result() {
        let mut dialog = OptionDialog::ok("T", "M", MessageType::Info);
        assert!(dialog.is_open());
        dialog.close(DialogResult::Ok);
        assert!(!dialog.is_open());
        assert_eq!(dialog.result(), DialogResult::Ok);
    }

    #[test]
    fn test_reset() {
        let mut dialog = OptionDialog::ok("T", "M", MessageType::Info);
        dialog.close(DialogResult::Ok);
        dialog.reset();
        assert!(dialog.is_open());
        assert_eq!(dialog.result(), DialogResult::None);
    }

    #[test]
    fn test_dialog_result_is_none() {
        assert!(DialogResult::None.is_none());
        assert!(!DialogResult::Ok.is_none());
    }

    #[test]
    fn test_message_type_default() {
        assert_eq!(MessageType::default(), MessageType::Info);
    }

    #[test]
    fn test_icon_color() {
        let d = OptionDialog::ok("T", "M", MessageType::Error);
        let c = d.icon_color();
        assert_eq!(c, egui::Color32::from_rgb(220, 50, 50));

        let d = OptionDialog::ok("T", "M", MessageType::Warning);
        let c = d.icon_color();
        assert_eq!(c, egui::Color32::from_rgb(230, 180, 50));

        let d = OptionDialog::ok("T", "M", MessageType::Info);
        let c = d.icon_color();
        assert_eq!(c, egui::Color32::from_rgb(80, 140, 220));

        let d = OptionDialog::ok("T", "M", MessageType::Plain);
        let c = d.icon_color();
        assert_eq!(c, egui::Color32::GRAY);
    }

    #[test]
    fn test_icon_symbol() {
        let d = OptionDialog::ok("T", "M", MessageType::Error);
        assert_eq!(d.icon_symbol(), "X");
        let d = OptionDialog::ok("T", "M", MessageType::Question);
        assert_eq!(d.icon_symbol(), "?");
    }
}
