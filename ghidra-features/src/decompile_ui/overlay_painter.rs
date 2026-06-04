//! Overlay message painter -- Rust port of
//! `ghidra.app.plugin.core.decompile.OverlayMessagePainter`.
//!
//! Paints a translucent overlay message on top of the decompiler panel,
//! typically used to indicate that a refresh is needed (e.g. when the
//! display is locked and the program has changed).

/// A painter that renders an optional overlay message on the decompiler view.
///
/// When active, the message is displayed in the center (or corner) of the
/// decompiler panel.  The message typically instructs the user to press a
/// key binding (e.g., "F5 to refresh") when the display is locked.
#[derive(Debug, Clone)]
pub struct OverlayMessagePainter {
    /// The current overlay message.  `None` or empty means "inactive".
    message: Option<String>,
    /// Whether the overlay is actively showing.
    active: bool,
}

impl OverlayMessagePainter {
    /// Create a new overlay painter with no message.
    pub fn new() -> Self {
        Self {
            message: None,
            active: false,
        }
    }

    /// Returns `true` if the overlay is active (a message is being shown).
    pub fn is_active(&self) -> bool {
        self.active && self.message.is_some()
    }

    /// Set the overlay message.  Pass an empty string or `None` to hide.
    pub fn set_message(&mut self, msg: impl Into<String>) {
        let s: String = msg.into();
        if s.is_empty() {
            self.message = None;
            self.active = false;
        } else {
            self.message = Some(s);
            self.active = true;
        }
    }

    /// Get the current overlay message.
    pub fn get_message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Clear the overlay.
    pub fn clear(&mut self) {
        self.message = None;
        self.active = false;
    }
}

impl Default for OverlayMessagePainter {
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

    #[test]
    fn test_overlay_painter_new() {
        let painter = OverlayMessagePainter::new();
        assert!(!painter.is_active());
        assert!(painter.get_message().is_none());
    }

    #[test]
    fn test_overlay_painter_set_message() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_message("F5 to refresh");
        assert!(painter.is_active());
        assert_eq!(painter.get_message(), Some("F5 to refresh"));
    }

    #[test]
    fn test_overlay_painter_clear() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_message("test");
        assert!(painter.is_active());

        painter.clear();
        assert!(!painter.is_active());
        assert!(painter.get_message().is_none());
    }

    #[test]
    fn test_overlay_painter_empty_string_hides() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_message("hello");
        painter.set_message("");
        assert!(!painter.is_active());
    }

    #[test]
    fn test_overlay_painter_clone() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_message("clone test");
        let cloned = painter.clone();
        assert_eq!(cloned.get_message(), Some("clone test"));
    }
}
