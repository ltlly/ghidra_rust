//! Look-and-feel manager types -- port of Ghidra's `generic.theme.laf` package.
//!
//! Provides the LookAndFeelManager trait and concrete LAF type enums for
//! managing Java Swing (or equivalent) look-and-feel installations.

use serde::{Deserialize, Serialize};

// ============================================================================
// LafType
// ============================================================================

/// Identifies a look-and-feel type.
///
/// Port of Ghidra's `generic.theme.LafType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LafType {
    /// FlatLaf dark theme.
    FlatDark,
    /// FlatLaf light theme.
    FlatLight,
    /// Metal (Java cross-platform).
    Metal,
    /// Nimbus (Java modern).
    Nimbus,
    /// GTK (Linux native).
    Gtk,
    /// macOS Aqua.
    Mac,
    /// Windows native.
    Windows,
    /// Windows Classic.
    WindowsClassic,
    /// Motif.
    Motif,
}

impl LafType {
    /// Returns the default LAF type for the current platform.
    pub fn default_for_platform() -> Self {
        if cfg!(target_os = "macos") {
            Self::Mac
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::FlatLight
        }
    }

    /// Whether this LAF uses dark defaults.
    pub fn uses_dark_defaults(&self) -> bool {
        matches!(self, Self::FlatDark)
    }

    /// Whether this LAF supports custom theme colors.
    pub fn supports_custom_colors(&self) -> bool {
        !matches!(self, Self::Gtk)
    }

    /// The display name for this LAF.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::FlatDark => "FlatLaf Dark",
            Self::FlatLight => "FlatLaf Light",
            Self::Metal => "Metal",
            Self::Nimbus => "Nimbus",
            Self::Gtk => "GTK+",
            Self::Mac => "macOS Aqua",
            Self::Windows => "Windows",
            Self::WindowsClassic => "Windows Classic",
            Self::Motif => "Motif",
        }
    }

    /// The Java LAF class name (for Swing interop).
    pub fn java_class_name(&self) -> &'static str {
        match self {
            Self::FlatDark => "com.formdev.flatlaf.FlatDarkLaf",
            Self::FlatLight => "com.formdev.flatlaf.FlatLightLaf",
            Self::Metal => "javax.swing.plaf.metal.MetalLookAndFeel",
            Self::Nimbus => "javax.swing.plaf.nimbus.NimbusLookAndFeel",
            Self::Gtk => "com.sun.java.swing.plaf.gtk.GTKLookAndFeel",
            Self::Mac => "com.apple.laf.AquaLookAndFeel",
            Self::Windows => "com.sun.java.swing.plaf.windows.WindowsLookAndFeel",
            Self::WindowsClassic => {
                "com.sun.java.swing.plaf.windows.WindowsClassicLookAndFeel"
            }
            Self::Motif => "com.sun.java.swing.plaf.motif.MotifLookAndFeel",
        }
    }

    /// Get all available LAF types.
    pub fn all() -> &'static [LafType] {
        &[
            Self::FlatDark,
            Self::FlatLight,
            Self::Metal,
            Self::Nimbus,
            Self::Gtk,
            Self::Mac,
            Self::Windows,
            Self::WindowsClassic,
            Self::Motif,
        ]
    }
}

impl Default for LafType {
    fn default() -> Self {
        Self::default_for_platform()
    }
}

impl std::fmt::Display for LafType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl std::str::FromStr for LafType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "flatdark" | "flat dark" | "flatdarklaf" => Ok(Self::FlatDark),
            "flatlight" | "flat light" | "flatlightlaf" => Ok(Self::FlatLight),
            "metal" => Ok(Self::Metal),
            "nimbus" => Ok(Self::Nimbus),
            "gtk" | "gtk+" => Ok(Self::Gtk),
            "mac" | "aqua" | "macos" => Ok(Self::Mac),
            "windows" => Ok(Self::Windows),
            "windowsclassic" | "windows classic" => Ok(Self::WindowsClassic),
            "motif" => Ok(Self::Motif),
            _ => Err(format!("unknown LAF type: {}", s)),
        }
    }
}

// ============================================================================
// LookAndFeelManager trait
// ============================================================================

/// Trait for look-and-feel managers.
///
/// Port of Ghidra's `LookAndFeelManager` abstract class.
pub trait LookAndFeelManager {
    /// Get the LAF type managed by this manager.
    fn laf_type(&self) -> LafType;

    /// Install the look-and-feel.
    fn install(&mut self) -> Result<(), String>;

    /// Uninstall the look-and-feel.
    fn uninstall(&mut self) -> Result<(), String>;

    /// Whether the LAF is currently installed.
    fn is_installed(&self) -> bool;

    /// Update a component's UI (e.g., after a theme change).
    fn update_component_ui(&self, component_id: &str);

    /// Refresh all registered component fonts.
    fn refresh_fonts(&mut self);

    /// Set the default cursor blink rate (in milliseconds).
    fn set_cursor_blink_rate(&mut self, rate_ms: u32);

    /// Get the default cursor blink rate.
    fn cursor_blink_rate(&self) -> u32;
}

/// Default cursor blink rate in milliseconds.
pub const DEFAULT_CURSOR_BLINK_RATE: u32 = 500;

/// Minimum font size.
pub const MIN_FONT_SIZE: u32 = 3;

// ============================================================================
// FontModifier
// ============================================================================

/// Font modification operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FontModifier {
    /// Bold.
    Bold,
    /// Italic.
    Italic,
    /// Underline.
    Underline,
    /// Strikethrough.
    Strikethrough,
}

/// Describes a font with family, size, and modifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FontDescriptor {
    /// Font family name.
    pub family: String,
    /// Font size in points.
    pub size: u32,
    /// Font modifiers (bold, italic, etc.).
    pub modifiers: Vec<FontModifier>,
}

impl FontDescriptor {
    /// Create a new font descriptor.
    pub fn new(family: impl Into<String>, size: u32) -> Self {
        Self {
            family: family.into(),
            size,
            modifiers: Vec::new(),
        }
    }

    /// Add a modifier.
    pub fn with_modifier(mut self, modifier: FontModifier) -> Self {
        self.modifiers.push(modifier);
        self
    }

    /// Add bold.
    pub fn bold(mut self) -> Self {
        self.modifiers.push(FontModifier::Bold);
        self
    }

    /// Add italic.
    pub fn italic(mut self) -> Self {
        self.modifiers.push(FontModifier::Italic);
        self
    }

    /// Whether this font is bold.
    pub fn is_bold(&self) -> bool {
        self.modifiers.contains(&FontModifier::Bold)
    }

    /// Whether this font is italic.
    pub fn is_italic(&self) -> bool {
        self.modifiers.contains(&FontModifier::Italic)
    }

    /// The CSS-style font string.
    pub fn to_css_string(&self) -> String {
        let mut parts = Vec::new();
        if self.is_italic() {
            parts.push("italic".to_string());
        }
        if self.is_bold() {
            parts.push("bold".to_string());
        }
        parts.push(format!("{}pt", self.size));
        parts.push(format!("\"{}\"", self.family));
        parts.join(" ")
    }
}

impl Default for FontDescriptor {
    fn default() -> Self {
        Self::new("Dialog", 12)
    }
}

impl std::fmt::Display for FontDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_css_string())
    }
}

// ============================================================================
// UiDefaultsMapper
// ============================================================================

/// Maps UI defaults (colors, fonts, etc.) between a LAF and Ghidra's theme system.
///
/// Port of Ghidra's `UiDefaultsMapper`.
#[derive(Debug, Clone, Default)]
pub struct UiDefaultsMapper {
    /// Map from LAF key to normalized Ghidra key.
    pub id_map: std::collections::HashMap<String, String>,
    /// Map from normalized Ghidra key to current value.
    pub current_values: std::collections::HashMap<String, String>,
}

impl UiDefaultsMapper {
    /// Create a new mapper.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a mapping from a LAF ID to a normalized ID.
    pub fn register_mapping(&mut self, laf_id: &str, normalized_id: &str) {
        self.id_map.insert(laf_id.to_string(), normalized_id.to_string());
    }

    /// Get the normalized ID for a LAF ID.
    pub fn get_normalized_id(&self, laf_id: &str) -> Option<&String> {
        self.id_map.get(laf_id)
    }

    /// Set the current value for a normalized ID.
    pub fn set_value(&mut self, normalized_id: &str, value: &str) {
        self.current_values.insert(normalized_id.to_string(), value.to_string());
    }

    /// Get the current value for a normalized ID.
    pub fn get_value(&self, normalized_id: &str) -> Option<&String> {
        self.current_values.get(normalized_id)
    }

    /// Number of registered mappings.
    pub fn len(&self) -> usize {
        self.id_map.len()
    }

    /// Whether the mapper is empty.
    pub fn is_empty(&self) -> bool {
        self.id_map.is_empty()
    }
}

// ============================================================================
// ComponentFontRegistry
// ============================================================================

/// Tracks which font ID each component is using, so the LAF manager can
/// update fonts when the theme changes.
#[derive(Debug, Clone, Default)]
pub struct ComponentFontRegistry {
    /// Map from component ID to font ID.
    pub registrations: std::collections::HashMap<String, String>,
}

impl ComponentFontRegistry {
    /// Create a new registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a component with a font ID.
    pub fn register(&mut self, component_id: &str, font_id: &str) {
        self.registrations.insert(component_id.to_string(), font_id.to_string());
    }

    /// Unregister a component.
    pub fn unregister(&mut self, component_id: &str) -> Option<String> {
        self.registrations.remove(component_id)
    }

    /// Get the font ID for a component.
    pub fn get_font_id(&self, component_id: &str) -> Option<&String> {
        self.registrations.get(component_id)
    }

    /// Number of registered components.
    pub fn len(&self) -> usize {
        self.registrations.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.registrations.is_empty()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_laf_type_display() {
        assert_eq!(LafType::FlatDark.to_string(), "FlatLaf Dark");
        assert_eq!(LafType::Metal.to_string(), "Metal");
        assert_eq!(LafType::Nimbus.to_string(), "Nimbus");
        assert_eq!(LafType::Mac.to_string(), "macOS Aqua");
    }

    #[test]
    fn test_laf_type_from_str() {
        assert_eq!("flatdark".parse::<LafType>().unwrap(), LafType::FlatDark);
        assert_eq!("Nimbus".parse::<LafType>().unwrap(), LafType::Nimbus);
        assert_eq!("gtk+".parse::<LafType>().unwrap(), LafType::Gtk);
        assert!("unknown".parse::<LafType>().is_err());
    }

    #[test]
    fn test_laf_type_dark_defaults() {
        assert!(LafType::FlatDark.uses_dark_defaults());
        assert!(!LafType::FlatLight.uses_dark_defaults());
        assert!(!LafType::Metal.uses_dark_defaults());
    }

    #[test]
    fn test_laf_type_java_class() {
        assert_eq!(
            LafType::FlatDark.java_class_name(),
            "com.formdev.flatlaf.FlatDarkLaf"
        );
        assert_eq!(
            LafType::Metal.java_class_name(),
            "javax.swing.plaf.metal.MetalLookAndFeel"
        );
    }

    #[test]
    fn test_laf_type_all() {
        assert_eq!(LafType::all().len(), 9);
    }

    #[test]
    fn test_font_descriptor() {
        let fd = FontDescriptor::new("Monospaced", 14).bold().italic();
        assert!(fd.is_bold());
        assert!(fd.is_italic());
        assert!(fd.to_css_string().contains("italic"));
        assert!(fd.to_css_string().contains("bold"));
        assert!(fd.to_css_string().contains("14pt"));
    }

    #[test]
    fn test_font_descriptor_default() {
        let fd = FontDescriptor::default();
        assert_eq!(fd.family, "Dialog");
        assert_eq!(fd.size, 12);
        assert!(!fd.is_bold());
    }

    #[test]
    fn test_ui_defaults_mapper() {
        let mut mapper = UiDefaultsMapper::new();
        assert!(mapper.is_empty());

        mapper.register_mapping("Button.background", "color.bg.button");
        assert_eq!(mapper.len(), 1);
        assert_eq!(
            mapper.get_normalized_id("Button.background"),
            Some(&"color.bg.button".to_string())
        );

        mapper.set_value("color.bg.button", "#ffffff");
        assert_eq!(
            mapper.get_value("color.bg.button"),
            Some(&"#ffffff".to_string())
        );
    }

    #[test]
    fn test_component_font_registry() {
        let mut registry = ComponentFontRegistry::new();
        assert!(registry.is_empty());

        registry.register("button1", "font.fixed");
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.get_font_id("button1"),
            Some(&"font.fixed".to_string())
        );

        let removed = registry.unregister("button1");
        assert_eq!(removed, Some("font.fixed".to_string()));
        assert!(registry.is_empty());
    }
}
