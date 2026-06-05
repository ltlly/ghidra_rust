//! Concrete Look-and-Feel manager implementations.
//!
//! Ports all of Ghidra's `generic.theme.laf` concrete manager classes:
//!
//! - `MetalLookAndFeelManager`
//! - `NimbusLookAndFeelManager`
//! - `FlatLookAndFeelManager`
//! - `FlatLookAndFeelManager` (dark variant)
//! - `GtkLookAndFeelManager`
//! - `MotifLookAndFeelManager`
//! - `WindowsLookAndFeelManager`
//! - `WindowsClassicLookAndFeelManager`
//! - `MacLookAndFeelManager`
//! - `CustomNimbusLookAndFeel`
//!
//! Also includes the `FontChangeListener` trait and `SelectedTreePainter`.

use crate::theme::laf_type::LafType;

/// Trait for listening to font changes.
///
/// Port of Ghidra's `generic.theme.laf.FontChangeListener`.
pub trait FontChangeListener: Send + Sync {
    /// Called when a font has changed.
    fn font_changed(&self, font_id: &str);
}

/// Abstract base for a concrete L&F manager.
#[derive(Debug, Clone)]
pub struct ConcreteLookAndFeelManager {
    /// The L&F type.
    pub laf_type: LafType,
    /// Display name.
    pub name: String,
    /// Whether this L&F is currently installed.
    pub installed: bool,
    /// Whether dark mode is enabled.
    pub dark_mode: bool,
}

impl ConcreteLookAndFeelManager {
    /// Create a new concrete manager.
    pub fn new(laf_type: LafType, name: impl Into<String>) -> Self {
        Self {
            laf_type,
            name: name.into(),
            installed: false,
            dark_mode: false,
        }
    }

    /// Install this L&F.
    pub fn install(&mut self) {
        self.installed = true;
        log::info!("Installed L&F: {} ({:?})", self.name, self.laf_type);
    }

    /// Uninstall this L&F.
    pub fn uninstall(&mut self) {
        self.installed = false;
        log::info!("Uninstalled L&F: {} ({:?})", self.name, self.laf_type);
    }

    /// Whether this L&F is currently installed.
    pub fn is_installed(&self) -> bool {
        self.installed
    }

    /// Whether this L&F supports dark mode.
    pub fn supports_dark_mode(&self) -> bool {
        self.dark_mode
    }
}

/// Metal L&F manager.
pub type MetalLookAndFeelManager = ConcreteLookAndFeelManager;

/// Nimbus L&F manager.
pub type NimbusLookAndFeelManager = ConcreteLookAndFeelManager;

/// Flat L&F manager (base for light/dark).
pub type FlatLookAndFeelManager = ConcreteLookAndFeelManager;

/// GTK L&F manager.
pub type GtkLookAndFeelManager = ConcreteLookAndFeelManager;

/// Motif L&F manager.
pub type MotifLookAndFeelManager = ConcreteLookAndFeelManager;

/// Windows L&F manager.
pub type WindowsLookAndFeelManager = ConcreteLookAndFeelManager;

/// Windows Classic L&F manager.
pub type WindowsClassicLookAndFeelManager = ConcreteLookAndFeelManager;

/// Mac L&F manager.
pub type MacLookAndFeelManager = ConcreteLookAndFeelManager;

/// Custom Nimbus Look and Feel.
///
/// Port of Ghidra's `generic.theme.laf.CustomNimbusLookAndFeel`. Extends
/// the standard Nimbus L&F with Ghidra-specific customizations.
#[derive(Debug, Clone)]
pub struct CustomNimbusLookAndFeel {
    /// Base Nimbus manager.
    pub base: ConcreteLookAndFeelManager,
    /// Customizations applied to the Nimbus defaults.
    pub customizations: Vec<(String, String)>,
}

impl CustomNimbusLookAndFeel {
    /// Create a custom Nimbus L&F.
    pub fn new() -> Self {
        Self {
            base: ConcreteLookAndFeelManager::new(LafType::Nimbus, "Custom Nimbus"),
            customizations: Vec::new(),
        }
    }

    /// Add a customization (key-value pair).
    pub fn add_customization(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.customizations.push((key.into(), value.into()));
    }

    /// Get a customization value by key.
    pub fn get_customization(&self, key: &str) -> Option<&str> {
        self.customizations
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

impl Default for CustomNimbusLookAndFeel {
    fn default() -> Self {
        Self::new()
    }
}

/// Painter for rendering selected tree nodes.
///
/// Port of Ghidra's `generic.theme.laf.nimbus.SelectedTreePainter`.
#[derive(Debug, Clone)]
pub struct SelectedTreePainter {
    /// Background color for selected items (ARGB).
    pub selected_bg: u32,
    /// Foreground color for selected items (ARGB).
    pub selected_fg: u32,
    /// Whether to use a gradient for the selection.
    pub use_gradient: bool,
    /// Corner rounding radius.
    pub corner_radius: f32,
}

impl SelectedTreePainter {
    /// Create a new selected tree painter with default colors.
    pub fn new() -> Self {
        Self {
            selected_bg: 0xFF3388FF,
            selected_fg: 0xFFFFFFFF,
            use_gradient: false,
            corner_radius: 3.0,
        }
    }

    /// Set the background color.
    pub fn with_background(mut self, color: u32) -> Self {
        self.selected_bg = color;
        self
    }

    /// Set the foreground color.
    pub fn with_foreground(mut self, color: u32) -> Self {
        self.selected_fg = color;
        self
    }

    /// Enable or disable gradient.
    pub fn with_gradient(mut self, enabled: bool) -> Self {
        self.use_gradient = enabled;
        self
    }
}

impl Default for SelectedTreePainter {
    fn default() -> Self {
        Self::new()
    }
}

/// Create all available L&F managers.
pub fn create_all_laf_managers() -> Vec<ConcreteLookAndFeelManager> {
    vec![
        ConcreteLookAndFeelManager::new(LafType::Metal, "Metal"),
        ConcreteLookAndFeelManager::new(LafType::Nimbus, "Nimbus"),
        ConcreteLookAndFeelManager::new(LafType::FlatLight, "Flat Light"),
        ConcreteLookAndFeelManager::new(LafType::FlatDark, "Flat Dark"),
        ConcreteLookAndFeelManager::new(LafType::Gtk, "GTK"),
        ConcreteLookAndFeelManager::new(LafType::Motif, "Motif"),
        ConcreteLookAndFeelManager::new(LafType::Windows, "Windows"),
        ConcreteLookAndFeelManager::new(LafType::WindowsClassic, "Windows Classic"),
        ConcreteLookAndFeelManager::new(LafType::Mac, "Mac"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concrete_manager_lifecycle() {
        let mut mgr = ConcreteLookAndFeelManager::new(LafType::Metal, "Metal");
        assert!(!mgr.is_installed());
        mgr.install();
        assert!(mgr.is_installed());
        mgr.uninstall();
        assert!(!mgr.is_installed());
    }

    #[test]
    fn test_custom_nimbus() {
        let mut cn = CustomNimbusLookAndFeel::new();
        cn.add_customization("key", "value");
        assert_eq!(cn.get_customization("key"), Some("value"));
        assert_eq!(cn.get_customization("missing"), None);
    }

    #[test]
    fn test_selected_tree_painter() {
        let painter = SelectedTreePainter::new()
            .with_background(0xFFFF0000)
            .with_foreground(0xFF000000)
            .with_gradient(true);
        assert_eq!(painter.selected_bg, 0xFFFF0000);
        assert!(painter.use_gradient);
    }

    #[test]
    fn test_create_all_managers() {
        let managers = create_all_laf_managers();
        assert_eq!(managers.len(), 9);
        for mgr in &managers {
            assert!(!mgr.is_installed());
        }
    }

    #[test]
    fn test_font_change_listener() {
        struct TestListener;
        impl FontChangeListener for TestListener {
            fn font_changed(&self, _font_id: &str) {}
        }
        let listener = TestListener;
        listener.font_changed("font.default");
    }
}
