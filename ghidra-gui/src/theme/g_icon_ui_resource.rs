//! UI resource wrapper for theme icons.
//!
//! Ports `generic.theme.GIconUIResource`.

use super::g_icon::GIcon;

/// A GIcon that is also a UI resource, capable of providing both the
/// theme-managed icon and the direct icon reference.
///
/// In the Java implementation this extends GIcon and implements
/// javax.swing.Icon + UIResource. In Rust we store the same data.
#[derive(Debug, Clone)]
pub struct GIconUIResource {
    /// The underlying GIcon theme id.
    pub icon: GIcon,
}

impl GIconUIResource {
    /// Create a new GIconUIResource wrapping the given GIcon.
    pub fn new(icon: GIcon) -> Self {
        Self { icon }
    }

    /// Get the theme id.
    pub fn theme_id(&self) -> String {
        self.icon.id()
    }
}

impl From<GIcon> for GIconUIResource {
    fn from(icon: GIcon) -> Self {
        Self::new(icon)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g_icon_ui_resource() {
        let icon = GIcon::new("icon.test");
        let resource = GIconUIResource::new(icon);
        assert_eq!(resource.theme_id(), "icon.test");
    }

    #[test]
    fn test_from_g_icon() {
        let icon = GIcon::new("icon.another");
        let resource: GIconUIResource = icon.into();
        assert_eq!(resource.theme_id(), "icon.another");
    }
}
