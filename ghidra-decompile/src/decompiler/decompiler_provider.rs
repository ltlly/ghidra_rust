//! Decompiler provider and action context.
//!
//! Port of Ghidra's decompiler plugin/provider types:
//! - `DecompilerProvider`: the main provider that hosts the decompiler view
//! - `DecompilerActionContext`: context for decompiler actions
//! - `PrimaryDecompilerProvider`: the primary (focused) provider
//! - `OverlayMessagePainter`: paints overlay messages on the decompiler view
//! - `DecompilerClipboardProvider`: clipboard integration

/// Action context for decompiler actions.
///
/// Port of `ghidra.app.plugin.core.decompile.DecompilerActionContext`.
#[derive(Debug, Clone)]
pub struct DecompilerActionContext {
    /// Address of the token under cursor.
    pub address: Option<u64>,
    /// The token text under cursor.
    pub token_text: Option<String>,
    /// The token syntax type index.
    pub syntax_type: i32,
    /// Whether a function is decompiled.
    pub has_function: bool,
    /// The function entry point (if any).
    pub function_entry: Option<u64>,
    /// Whether the context represents a valid state for actions.
    pub valid: bool,
}

impl DecompilerActionContext {
    /// Create a new action context.
    pub fn new() -> Self {
        Self {
            address: None,
            token_text: None,
            syntax_type: 0,
            has_function: false,
            function_entry: None,
            valid: false,
        }
    }

    /// Create a valid context for the given address and token.
    pub fn with_token(address: u64, token_text: impl Into<String>, syntax_type: i32) -> Self {
        Self {
            address: Some(address),
            token_text: Some(token_text.into()),
            syntax_type,
            has_function: true,
            function_entry: None,
            valid: true,
        }
    }

    /// Whether the context has a token under cursor.
    pub fn has_token(&self) -> bool {
        self.token_text.is_some()
    }
}

impl Default for DecompilerActionContext {
    fn default() -> Self {
        Self::new()
    }
}

/// The primary decompiler provider (the one with focus).
///
/// Port of `ghidra.app.plugin.core.decompile.PrimaryDecompilerProvider`.
#[derive(Debug)]
pub struct PrimaryDecompilerProvider {
    /// Provider id.
    pub id: String,
    /// Whether this provider has focus.
    pub focused: bool,
}

impl PrimaryDecompilerProvider {
    /// Create a new primary provider.
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into(), focused: false }
    }

    /// Whether this provider is focused.
    pub fn is_focused(&self) -> bool {
        self.focused
    }
}

/// Overlay message painter for the decompiler view.
///
/// Port of `ghidra.app.plugin.core.decompile.OverlayMessagePainter`.
#[derive(Debug, Clone, Default)]
pub struct OverlayMessagePainter {
    /// Current message to display.
    pub message: Option<String>,
    /// Message background color.
    pub background_color: String,
    /// Message text color.
    pub text_color: String,
}

impl OverlayMessagePainter {
    /// Create a new overlay message painter.
    pub fn new() -> Self {
        Self {
            background_color: "#333333".into(),
            text_color: "#ffffff".into(),
            ..Default::default()
        }
    }

    /// Show a message.
    pub fn show_message(&mut self, message: impl Into<String>) {
        self.message = Some(message.into());
    }

    /// Clear the message.
    pub fn clear_message(&mut self) {
        self.message = None;
    }

    /// Whether a message is being shown.
    pub fn has_message(&self) -> bool {
        self.message.is_some()
    }
}

/// Clipboard provider for the decompiler.
///
/// Port of `ghidra.app.plugin.core.decompile.DecompilerClipboardProvider`.
#[derive(Debug, Clone, Default)]
pub struct DecompilerClipboardProvider {
    /// Current clipboard content.
    content: Option<String>,
}

impl DecompilerClipboardProvider {
    /// Create a new clipboard provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy text to the clipboard.
    pub fn copy(&mut self, text: impl Into<String>) {
        self.content = Some(text.into());
    }

    /// Paste from the clipboard.
    pub fn paste(&self) -> Option<&str> {
        self.content.as_deref()
    }

    /// Whether the clipboard has content.
    pub fn has_content(&self) -> bool {
        self.content.is_some()
    }

    /// Clear the clipboard.
    pub fn clear(&mut self) {
        self.content = None;
    }
}

/// Display type casts action state.
///
/// Port of `ghidra.app.plugin.core.decompile.DisplayTypeCastsAction`.
#[derive(Debug, Clone)]
pub struct DisplayTypeCastsState {
    /// Whether type casts are currently displayed.
    pub show_type_casts: bool,
}

impl Default for DisplayTypeCastsState {
    fn default() -> Self {
        Self { show_type_casts: true }
    }
}

impl DisplayTypeCastsState {
    /// Toggle type cast display.
    pub fn toggle(&mut self) {
        self.show_type_casts = !self.show_type_casts;
    }
}

/// Location memento for the decompiler (saves/restores position).
///
/// Port of `ghidra.app.plugin.core.decompile.DecompilerLocationMemento`.
#[derive(Debug, Clone)]
pub struct DecompilerLocationMemento {
    /// Function entry point.
    pub function_entry: u64,
    /// Offset within the decompiled output.
    pub offset: u32,
    /// Token index.
    pub token_index: u32,
}

impl DecompilerLocationMemento {
    /// Create a new location memento.
    pub fn new(function_entry: u64, offset: u32, token_index: u32) -> Self {
        Self { function_entry, offset, token_index }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_context() {
        let ctx = DecompilerActionContext::new();
        assert!(!ctx.valid);
        assert!(!ctx.has_token());
    }

    #[test]
    fn test_action_context_with_token() {
        let ctx = DecompilerActionContext::with_token(0x1000, "main", 5);
        assert!(ctx.valid);
        assert!(ctx.has_token());
        assert_eq!(ctx.address, Some(0x1000));
    }

    #[test]
    fn test_primary_provider() {
        let mut p = PrimaryDecompilerProvider::new("provider1");
        assert!(!p.is_focused());
        p.focused = true;
        assert!(p.is_focused());
    }

    #[test]
    fn test_overlay_message_painter() {
        let mut painter = OverlayMessagePainter::new();
        assert!(!painter.has_message());
        painter.show_message("Decompiling...");
        assert!(painter.has_message());
        painter.clear_message();
        assert!(!painter.has_message());
    }

    #[test]
    fn test_clipboard_provider() {
        let mut cb = DecompilerClipboardProvider::new();
        assert!(!cb.has_content());
        cb.copy("int main() { return 0; }");
        assert!(cb.has_content());
        assert_eq!(cb.paste(), Some("int main() { return 0; }"));
        cb.clear();
        assert!(!cb.has_content());
    }

    #[test]
    fn test_display_type_casts_state() {
        let mut state = DisplayTypeCastsState::default();
        assert!(state.show_type_casts);
        state.toggle();
        assert!(!state.show_type_casts);
    }

    #[test]
    fn test_location_memento() {
        let m = DecompilerLocationMemento::new(0x401000, 100, 5);
        assert_eq!(m.function_entry, 0x401000);
        assert_eq!(m.offset, 100);
    }
}
