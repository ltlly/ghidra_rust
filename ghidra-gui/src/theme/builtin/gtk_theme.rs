//! GTK theme for Linux systems.
//!
//! Port of `generic.theme.builtin.GTKTheme`.

use super::super::{GTheme, LafType};

/// The GTK+ look-and-feel theme for Linux environments.
///
/// Ports `generic.theme.builtin.GTKTheme`.
#[derive(Debug, Clone)]
pub struct GtkTheme {
    inner: GTheme,
}

impl GtkTheme {
    /// Theme identifier.
    pub const THEME_ID: &'static str = "Ghidra GTK";

    /// Create a new GTK theme with defaults.
    pub fn new() -> Self {
        Self {
            inner: GTheme::with_laf(Self::THEME_ID, LafType::Gtk),
        }
    }

    /// Get the inner GTheme.
    pub fn as_theme(&self) -> &GTheme {
        &self.inner
    }

    /// Get the theme name.
    pub fn id(&self) -> &str {
        self.inner.name()
    }

    /// Get the look-and-feel type.
    pub fn laf_type(&self) -> LafType {
        self.inner.look_and_feel()
    }
}

impl Default for GtkTheme {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gtk_theme_creation() {
        let theme = GtkTheme::new();
        assert_eq!(theme.id(), GtkTheme::THEME_ID);
        assert_eq!(theme.laf_type(), LafType::Gtk);
    }

    #[test]
    fn gtk_theme_default() {
        let theme = GtkTheme::default();
        assert_eq!(theme.id(), GtkTheme::THEME_ID);
    }
}
