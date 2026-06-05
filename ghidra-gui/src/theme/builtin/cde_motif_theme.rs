//! Nimbus and CDE/Motif look-and-feel themes.
//!
//! Ports `generic.theme.builtin.NimbusTheme` and
//! `generic.theme.builtin.CDEMotifTheme`.

use super::super::{GTheme, LafType};

/// Nimbus look-and-feel theme.
///
/// Ports `generic.theme.builtin.NimbusTheme`.
#[derive(Debug, Clone)]
pub struct NimbusTheme {
    inner: GTheme,
}

impl NimbusTheme {
    /// Theme identifier.
    pub const THEME_ID: &'static str = "Ghidra Nimbus";

    /// Create a new Nimbus theme.
    pub fn new() -> Self {
        Self {
            inner: GTheme::with_laf(Self::THEME_ID, LafType::Nimbus),
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

impl Default for NimbusTheme {
    fn default() -> Self {
        Self::new()
    }
}

/// CDE/Motif look-and-feel theme.
///
/// Ports `generic.theme.builtin.CDEMotifTheme`.
#[derive(Debug, Clone)]
pub struct CdeMotifTheme {
    inner: GTheme,
}

impl CdeMotifTheme {
    /// Theme identifier.
    pub const THEME_ID: &'static str = "Ghidra CDE Motif";

    /// Create a new CDE/Motif theme.
    pub fn new() -> Self {
        Self {
            inner: GTheme::with_laf(Self::THEME_ID, LafType::Motif),
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

impl Default for CdeMotifTheme {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nimbus_theme_creation() {
        let theme = NimbusTheme::new();
        assert_eq!(theme.id(), NimbusTheme::THEME_ID);
        assert_eq!(theme.laf_type(), LafType::Nimbus);
    }

    #[test]
    fn cde_motif_theme_creation() {
        let theme = CdeMotifTheme::new();
        assert_eq!(theme.id(), CdeMotifTheme::THEME_ID);
        assert_eq!(theme.laf_type(), LafType::Motif);
    }
}
