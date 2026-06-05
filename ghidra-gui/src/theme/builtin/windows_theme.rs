//! Windows look-and-feel themes.
//!
//! Ports `generic.theme.builtin.WindowsTheme` and
//! `generic.theme.builtin.WindowsClassicTheme`.

use super::super::{GTheme, LafType};

/// Windows look-and-feel theme.
///
/// Ports `generic.theme.builtin.WindowsTheme`.
#[derive(Debug, Clone)]
pub struct WindowsTheme {
    inner: GTheme,
}

impl WindowsTheme {
    /// Theme identifier.
    pub const THEME_ID: &'static str = "Ghidra Windows";

    /// Create a new Windows theme.
    pub fn new() -> Self {
        Self {
            inner: GTheme::with_laf(Self::THEME_ID, LafType::Windows),
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

impl Default for WindowsTheme {
    fn default() -> Self {
        Self::new()
    }
}

/// Windows Classic look-and-feel theme.
///
/// Ports `generic.theme.builtin.WindowsClassicTheme`.
#[derive(Debug, Clone)]
pub struct WindowsClassicTheme {
    inner: GTheme,
}

impl WindowsClassicTheme {
    /// Theme identifier.
    pub const THEME_ID: &'static str = "Ghidra Windows Classic";

    /// Create a new Windows Classic theme.
    pub fn new() -> Self {
        Self {
            inner: GTheme::with_laf(Self::THEME_ID, LafType::WindowsClassic),
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

impl Default for WindowsClassicTheme {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_theme_creation() {
        let theme = WindowsTheme::new();
        assert_eq!(theme.id(), WindowsTheme::THEME_ID);
        assert_eq!(theme.laf_type(), LafType::Windows);
    }

    #[test]
    fn windows_classic_theme_creation() {
        let theme = WindowsClassicTheme::new();
        assert_eq!(theme.id(), WindowsClassicTheme::THEME_ID);
        assert_eq!(theme.laf_type(), LafType::WindowsClassic);
    }
}
