//! UI resource wrapper for theme colors.
//!
//! Ports `generic.theme.GColorUIResource`.

use super::g_color::GColor;

/// A GColor that is also a UI resource.
///
/// In the Java implementation this extends GColor and implements
/// UIResource so the look-and-feel knows not to override it.
#[derive(Debug, Clone)]
pub struct GColorUIResource {
    /// The underlying GColor.
    pub color: GColor,
}

impl GColorUIResource {
    /// Create a new GColorUIResource wrapping the given GColor.
    pub fn new(color: GColor) -> Self {
        Self { color }
    }

    /// Create from a theme id.
    pub fn from_id(id: impl Into<String>) -> Self {
        Self {
            color: GColor::new(id),
        }
    }

    /// Get the theme id.
    pub fn theme_id(&self) -> String {
        self.color.id()
    }
}

impl From<GColor> for GColorUIResource {
    fn from(color: GColor) -> Self {
        Self::new(color)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g_color_ui_resource_from_id() {
        let resource = GColorUIResource::from_id("color.bg.test");
        assert_eq!(resource.theme_id(), "color.bg.test");
    }

    #[test]
    fn test_from_g_color() {
        let color = GColor::new("color.fg.test");
        let resource: GColorUIResource = color.into();
        assert_eq!(resource.theme_id(), "color.fg.test");
    }
}
