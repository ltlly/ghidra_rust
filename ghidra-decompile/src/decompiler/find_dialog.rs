//! Decompiler find dialog types.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompilerFindDialog`.

/// Options for searching within decompiler output.
#[derive(Debug, Clone)]
pub struct DecompilerFindDialog {
    /// The search query text.
    pub query: String,
    /// Whether to search case-sensitively.
    pub case_sensitive: bool,
    /// Whether to use regular expressions.
    pub use_regex: bool,
    /// Whether to search only in the current function.
    pub current_function_only: bool,
    /// Whether the dialog is currently visible.
    pub visible: bool,
}

impl DecompilerFindDialog {
    /// Create a new find dialog.
    pub fn new() -> Self {
        Self {
            query: String::new(),
            case_sensitive: true,
            use_regex: false,
            current_function_only: true,
            visible: false,
        }
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the dialog.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Whether the dialog is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the search query.
    pub fn set_query(&mut self, query: impl Into<String>) {
        self.query = query.into();
    }

    /// Set case sensitivity.
    pub fn set_case_sensitive(&mut self, case_sensitive: bool) {
        self.case_sensitive = case_sensitive;
    }

    /// Set regex mode.
    pub fn set_use_regex(&mut self, use_regex: bool) {
        self.use_regex = use_regex;
    }
}

impl Default for DecompilerFindDialog {
    fn default() -> Self {
        Self::new()
    }
}

/// Overlay message displayed over the decompiler output (e.g., "Decompiling...").
#[derive(Debug, Clone)]
pub struct OverlayMessagePainter {
    /// The message text.
    pub message: String,
    /// Whether the overlay is currently visible.
    pub visible: bool,
    /// The background color (ARGB).
    pub bg_color: u32,
    /// The text color (ARGB).
    pub text_color: u32,
    /// Opacity (0.0..=1.0).
    pub opacity: f32,
}

impl OverlayMessagePainter {
    /// Create a new overlay message painter.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            visible: false,
            bg_color: 0xC0FFFFFF, // semi-transparent white
            text_color: 0xFF000000,
            opacity: 0.75,
        }
    }

    /// Show the overlay with a message.
    pub fn show(&mut self, message: impl Into<String>) {
        self.message = message.into();
        self.visible = true;
    }

    /// Hide the overlay.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Whether the overlay is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the opacity.
    pub fn set_opacity(&mut self, opacity: f32) {
        self.opacity = opacity.clamp(0.0, 1.0);
    }
}

impl Default for OverlayMessagePainter {
    fn default() -> Self {
        Self::new("Decompiling...")
    }
}

/// Provider for the decompiler view (manages the decompiler panel and its data).
///
/// Port of Ghidra's `ghidra.app.plugin.core.decompile.DecompilerProvider`.
#[derive(Debug, Clone)]
pub struct DecompilerProvider {
    /// The provider name.
    pub name: String,
    /// The current function address.
    pub current_function: Option<u64>,
    /// Whether the provider is currently busy (decompiling).
    pub busy: bool,
    /// The overlay message painter.
    pub overlay: OverlayMessagePainter,
    /// Whether this is the primary decompiler provider.
    pub is_primary: bool,
}

impl DecompilerProvider {
    /// Create a new decompiler provider.
    pub fn new(name: impl Into<String>, is_primary: bool) -> Self {
        Self {
            name: name.into(),
            current_function: None,
            busy: false,
            overlay: OverlayMessagePainter::default(),
            is_primary,
        }
    }

    /// Set the current function.
    pub fn set_function(&mut self, entry: u64) {
        self.current_function = Some(entry);
    }

    /// Clear the current function.
    pub fn clear_function(&mut self) {
        self.current_function = None;
    }

    /// Mark the provider as busy.
    pub fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
        if busy {
            self.overlay.show("Decompiling...");
        } else {
            self.overlay.hide();
        }
    }

    /// Whether the provider is the primary decompiler provider.
    pub fn is_primary(&self) -> bool {
        self.is_primary
    }
}

/// The primary decompiler provider (singleton for the main decompiler view).
///
/// Port of Ghidra's `ghidra.app.plugin.core.decompile.PrimaryDecompilerProvider`.
#[derive(Debug, Clone)]
pub struct PrimaryDecompilerProvider {
    /// Base provider.
    pub provider: DecompilerProvider,
    /// Whether this provider handles the active program.
    pub handles_active_program: bool,
}

impl PrimaryDecompilerProvider {
    /// Create a new primary decompiler provider.
    pub fn new() -> Self {
        Self {
            provider: DecompilerProvider::new("Primary Decompiler", true),
            handles_active_program: true,
        }
    }

    /// Get the function address being decompiled.
    pub fn current_function(&self) -> Option<u64> {
        self.provider.current_function
    }
}

impl Default for PrimaryDecompilerProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_dialog_lifecycle() {
        let mut dialog = DecompilerFindDialog::new();
        assert!(!dialog.is_visible());
        dialog.show();
        assert!(dialog.is_visible());
        dialog.set_query("main");
        assert_eq!(dialog.query, "main");
        dialog.hide();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_find_dialog_options() {
        let mut dialog = DecompilerFindDialog::new();
        dialog.set_case_sensitive(false);
        dialog.set_use_regex(true);
        assert!(!dialog.case_sensitive);
        assert!(dialog.use_regex);
    }

    #[test]
    fn test_overlay_message_painter() {
        let mut overlay = OverlayMessagePainter::new("Loading...");
        assert!(!overlay.is_visible());
        overlay.show("Decompiling...");
        assert!(overlay.is_visible());
        assert_eq!(overlay.message, "Decompiling...");
        overlay.hide();
        assert!(!overlay.is_visible());
    }

    #[test]
    fn test_overlay_opacity() {
        let mut overlay = OverlayMessagePainter::default();
        overlay.set_opacity(1.5); // clamped to 1.0
        assert!((overlay.opacity - 1.0).abs() < f32::EPSILON);
        overlay.set_opacity(-0.5); // clamped to 0.0
        assert!((overlay.opacity - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_decompiler_provider() {
        let mut provider = DecompilerProvider::new("Test", false);
        assert!(!provider.is_primary());
        assert!(!provider.busy);

        provider.set_function(0x1000);
        assert_eq!(provider.current_function, Some(0x1000));

        provider.set_busy(true);
        assert!(provider.busy);
        assert!(provider.overlay.is_visible());

        provider.set_busy(false);
        assert!(!provider.busy);
        assert!(!provider.overlay.is_visible());

        provider.clear_function();
        assert!(provider.current_function.is_none());
    }

    #[test]
    fn test_primary_provider() {
        let provider = PrimaryDecompilerProvider::new();
        assert!(provider.provider.is_primary());
        assert!(provider.handles_active_program);
        assert!(provider.current_function().is_none());
    }
}
