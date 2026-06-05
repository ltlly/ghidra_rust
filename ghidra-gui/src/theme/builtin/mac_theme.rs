//! macOS theme.
//!
//! Port of `generic.theme.builtin.MacTheme`.

use super::super::{GTheme, LafType};

/// macOS Aqua look-and-feel theme.
///
/// Ports `generic.theme.builtin.MacTheme`.
#[derive(Debug, Clone)]
pub struct MacTheme {
    inner: GTheme,
}

impl MacTheme {
    /// Theme identifier.
    pub const THEME_ID: &'static str = "Ghidra Mac";

    /// Create a new macOS theme.
    pub fn new() -> Self {
        Self {
            inner: GTheme::with_laf(Self::THEME_ID, LafType::Mac),
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

impl Default for MacTheme {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_theme_creation() {
        let theme = MacTheme::new();
        assert_eq!(theme.id(), MacTheme::THEME_ID);
        assert_eq!(theme.laf_type(), LafType::Mac);
    }
}
