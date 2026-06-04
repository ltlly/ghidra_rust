//! Look-and-feel type enumeration.
//!
//! Ports `generic.theme.LafType`.

use std::fmt;

/// Supported look-and-feel types.
///
/// Ported from Ghidra's `generic.theme.LafType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum LafType {
    /// Metal (Java default).
    Metal,
    /// Nimbus.
    Nimbus,
    /// GTK+ (Linux).
    Gtk,
    /// CDE/Motif.
    Motif,
    /// Flat Light theme (cross-platform).
    FlatLight,
    /// Flat Dark theme (cross-platform, uses dark defaults).
    FlatDark,
    /// Windows native.
    Windows,
    /// Windows Classic.
    WindowsClassic,
    /// macOS native.
    Mac,
}

impl LafType {
    /// Get the display name.
    pub fn display_string(&self) -> &str {
        match self {
            LafType::Metal => "Metal",
            LafType::Nimbus => "Nimbus",
            LafType::Gtk => "GTK+",
            LafType::Motif => "Motif",
            LafType::FlatLight => "Flat Light",
            LafType::FlatDark => "Flat Dark",
            LafType::Windows => "Windows",
            LafType::WindowsClassic => "Windows Classic",
            LafType::Mac => "Mac OS X",
        }
    }

    /// Get the internal name.
    pub fn name(&self) -> &str {
        match self {
            LafType::Metal => "Metal",
            LafType::Nimbus => "Nimbus",
            LafType::Gtk => "GTK+",
            LafType::Motif => "CDE/Motif",
            LafType::FlatLight => "Flat Light",
            LafType::FlatDark => "Flat Dark",
            LafType::Windows => "Windows",
            LafType::WindowsClassic => "Windows Classic",
            LafType::Mac => "Mac OS X",
        }
    }

    /// Whether this LAF uses dark defaults.
    pub fn uses_dark_defaults(&self) -> bool {
        matches!(self, LafType::FlatDark)
    }

    /// Parse a LAF type from its name string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Metal" => Some(LafType::Metal),
            "Nimbus" => Some(LafType::Nimbus),
            "GTK+" => Some(LafType::Gtk),
            "CDE/Motif" | "Motif" => Some(LafType::Motif),
            "Flat Light" => Some(LafType::FlatLight),
            "Flat Dark" => Some(LafType::FlatDark),
            "Windows" => Some(LafType::Windows),
            "Windows Classic" => Some(LafType::WindowsClassic),
            "Mac OS X" => Some(LafType::Mac),
            _ => None,
        }
    }

    /// Whether this LAF is supported on the current platform.
    pub fn is_supported(&self) -> bool {
        // In the Rust port, Flat themes are always supported (cross-platform).
        match self {
            LafType::FlatLight | LafType::FlatDark => true,
            LafType::Metal | LafType::Nimbus => true, // Always available
            _ => false, // Platform-specific; would need runtime detection
        }
    }

    /// Get the default LAF for the current platform.
    pub fn default_look_and_feel() -> Self {
        if cfg!(target_os = "macos") {
            LafType::Mac
        } else if cfg!(target_os = "windows") {
            LafType::Windows
        } else {
            LafType::FlatLight
        }
    }

    /// All available LAF types.
    pub fn all() -> &'static [LafType] {
        &[
            LafType::Metal,
            LafType::Nimbus,
            LafType::Gtk,
            LafType::Motif,
            LafType::FlatLight,
            LafType::FlatDark,
            LafType::Windows,
            LafType::WindowsClassic,
            LafType::Mac,
        ]
    }
}

impl fmt::Display for LafType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_laf_type_display() {
        assert_eq!(LafType::Metal.to_string(), "Metal");
        assert_eq!(LafType::Motif.to_string(), "Motif");
    }

    #[test]
    fn test_laf_type_from_name() {
        assert_eq!(LafType::from_name("Metal"), Some(LafType::Metal));
        assert_eq!(LafType::from_name("Flat Dark"), Some(LafType::FlatDark));
        assert_eq!(LafType::from_name("Unknown"), None);
    }

    #[test]
    fn test_laf_type_dark_defaults() {
        assert!(LafType::FlatDark.uses_dark_defaults());
        assert!(!LafType::FlatLight.uses_dark_defaults());
        assert!(!LafType::Metal.uses_dark_defaults());
    }

    #[test]
    fn test_laf_type_supported() {
        assert!(LafType::FlatLight.is_supported());
        assert!(LafType::FlatDark.is_supported());
    }

    #[test]
    fn test_laf_type_all() {
        assert_eq!(LafType::all().len(), 9);
    }

    #[test]
    fn test_default_look_and_feel() {
        // Just verify it doesn't panic
        let _ = LafType::default_look_and_feel();
    }

    #[test]
    fn test_serialization() {
        let t = LafType::FlatDark;
        let json = serde_json::to_string(&t).unwrap();
        let deserialized: LafType = serde_json::from_str(&json).unwrap();
        assert_eq!(t, deserialized);
    }
}
