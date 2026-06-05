//! Port of `generic.theme.laf.CustomNimbusLookAndFeel`.
//!
//! Custom extension of the Nimbus look-and-feel that overrides
//! default colors and fonts from the Ghidra theme system.

/// Custom Nimbus look-and-feel configuration.
///
/// Ported from Ghidra's `CustomNimbusLookAndFeel` which extends
/// `NimbusLookAndFeel` and customizes the UIDefaults table.
#[derive(Debug, Clone)]
pub struct CustomNimbusLookAndFeel {
    /// Whether this LAF is currently active.
    pub active: bool,
    /// Custom overrides to the UIDefaults table.
    pub overrides: Vec<LookAndFeelOverride>,
    /// Whether to use the Ghidra theme's font settings.
    pub apply_theme_fonts: bool,
    /// Whether to use the Ghidra theme's color settings.
    pub apply_theme_colors: bool,
}

/// A single override in the UIDefaults table.
#[derive(Debug, Clone)]
pub struct LookAndFeelOverride {
    /// The key in UIDefaults.
    pub key: String,
    /// The type of value.
    pub value_type: OverrideValueType,
    /// String representation of the value.
    pub value: String,
}

/// The type of a UIDefaults override value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideValueType {
    /// A color value (ARGB hex string).
    Color,
    /// A font descriptor.
    Font,
    /// An integer value.
    Integer,
    /// A boolean value.
    Boolean,
    /// An icon reference.
    Icon,
}

impl CustomNimbusLookAndFeel {
    /// Create a new custom Nimbus LAF.
    pub fn new() -> Self {
        Self {
            active: false,
            overrides: Vec::new(),
            apply_theme_fonts: true,
            apply_theme_colors: true,
        }
    }

    /// Add a color override.
    pub fn add_color_override(&mut self, key: impl Into<String>, argb: u32) {
        self.overrides.push(LookAndFeelOverride {
            key: key.into(),
            value_type: OverrideValueType::Color,
            value: format!("#{:08X}", argb),
        });
    }

    /// Add a font override.
    pub fn add_font_override(&mut self, key: impl Into<String>, font_desc: impl Into<String>) {
        self.overrides.push(LookAndFeelOverride {
            key: key.into(),
            value_type: OverrideValueType::Font,
            value: font_desc.into(),
        });
    }

    /// Get all overrides of the given type.
    pub fn overrides_of_type(&self, vtype: OverrideValueType) -> Vec<&LookAndFeelOverride> {
        self.overrides.iter().filter(|o| o.value_type == vtype).collect()
    }

    /// Clear all overrides.
    pub fn clear_overrides(&mut self) {
        self.overrides.clear();
    }
}

impl Default for CustomNimbusLookAndFeel {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_custom_nimbus_default() {
        let laf = CustomNimbusLookAndFeel::new();
        assert!(!laf.active);
        assert!(laf.apply_theme_fonts);
    }

    #[test]
    fn test_add_overrides() {
        let mut laf = CustomNimbusLookAndFeel::new();
        laf.add_color_override("Panel.background", 0xFF123456);
        laf.add_font_override("defaultFont", "SansSerif-12");
        assert_eq!(laf.overrides.len(), 2);
    }

    #[test]
    fn test_filter_by_type() {
        let mut laf = CustomNimbusLookAndFeel::new();
        laf.add_color_override("bg", 0xFF000000);
        laf.add_color_override("fg", 0xFFFFFFFF);
        laf.add_font_override("font", "Mono-14");
        assert_eq!(laf.overrides_of_type(OverrideValueType::Color).len(), 2);
        assert_eq!(laf.overrides_of_type(OverrideValueType::Font).len(), 1);
    }
}
