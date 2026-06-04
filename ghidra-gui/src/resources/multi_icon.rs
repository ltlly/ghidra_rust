//! Multi-icon composition.
//!
//! Ports Ghidra's `resources.MultiIcon` and `resources.MultiIconBuilder`.
//! A multi-icon is a composite icon composed of a base icon overlaid with
//! additional icons at specific quadrant positions.

/// Quadrant position for overlay icons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Quadrant {
    /// Top-left corner.
    TopLeft,
    /// Top-right corner.
    TopRight,
    /// Bottom-left corner.
    BottomLeft,
    /// Bottom-right corner.
    BottomRight,
}

impl Quadrant {
    /// X offset factor (0.0 for left, 1.0 for right).
    pub fn x_factor(&self) -> f32 {
        match self {
            Quadrant::TopLeft | Quadrant::BottomLeft => 0.0,
            Quadrant::TopRight | Quadrant::BottomRight => 1.0,
        }
    }

    /// Y offset factor (0.0 for top, 1.0 for bottom).
    pub fn y_factor(&self) -> f32 {
        match self {
            Quadrant::TopLeft | Quadrant::TopRight => 0.0,
            Quadrant::BottomLeft | Quadrant::BottomRight => 1.0,
        }
    }
}

/// Identifies an icon by its resource name or path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IconId {
    /// A named icon from the resource manager.
    Name(String),
    /// A file path to an icon.
    Path(String),
    /// A built-in system icon.
    Builtin(BuiltinIcon),
}

/// Built-in icons that can be used as overlays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinIcon {
    /// A check mark overlay.
    Check,
    /// An "X" overlay.
    Error,
    /// A warning triangle.
    Warning,
    /// An information "i" icon.
    Info,
    /// A lock overlay.
    Lock,
    /// A plus sign overlay.
    Add,
    /// A minus sign overlay.
    Remove,
}

/// An overlay positioned at a specific quadrant.
#[derive(Debug, Clone)]
pub struct IconOverlay {
    /// The icon to overlay.
    pub icon_id: IconId,
    /// The quadrant position.
    pub position: Quadrant,
    /// Scale factor for the overlay (0.0 .. 1.0 relative to base icon).
    pub scale: f32,
}

impl IconOverlay {
    /// Create a new icon overlay.
    pub fn new(icon_id: IconId, position: Quadrant) -> Self {
        Self {
            icon_id,
            position,
            scale: 0.5,
        }
    }

    /// Set the scale factor.
    pub fn with_scale(mut self, scale: f32) -> Self {
        self.scale = scale.clamp(0.1, 1.0);
        self
    }
}

/// A composite icon with a base icon and zero or more overlays.
///
/// Ported from `resources.MultiIcon` and `resources.MultiIconBuilder`.
#[derive(Debug, Clone)]
pub struct MultiIcon {
    /// The base icon.
    pub base_icon: IconId,
    /// The overlay icons.
    pub overlays: Vec<IconOverlay>,
    /// Total width in pixels.
    pub width: u32,
    /// Total height in pixels.
    pub height: u32,
}

impl MultiIcon {
    /// Create a new multi-icon with the given base.
    pub fn new(base_icon: IconId) -> Self {
        Self {
            base_icon,
            overlays: Vec::new(),
            width: 16,
            height: 16,
        }
    }

    /// Create a builder for constructing multi-icons fluently.
    pub fn builder(base_icon: IconId) -> MultiIconBuilder {
        MultiIconBuilder::new(base_icon)
    }

    /// Add an overlay icon.
    pub fn add_overlay(&mut self, overlay: IconOverlay) {
        self.overlays.push(overlay);
    }

    /// Set the icon dimensions.
    pub fn set_size(&mut self, width: u32, height: u32) {
        self.width = width;
        self.height = height;
    }

    /// Get the number of overlays.
    pub fn overlay_count(&self) -> usize {
        self.overlays.len()
    }

    /// Check whether this icon has any overlays.
    pub fn has_overlays(&self) -> bool {
        !self.overlays.is_empty()
    }
}

/// Builder for constructing [`MultiIcon`] instances fluently.
///
/// Ported from `resources.MultiIconBuilder`.
#[derive(Debug)]
pub struct MultiIconBuilder {
    icon: MultiIcon,
}

impl MultiIconBuilder {
    /// Create a new builder with the given base icon.
    pub fn new(base_icon: IconId) -> Self {
        Self {
            icon: MultiIcon::new(base_icon),
        }
    }

    /// Add an overlay at a quadrant position.
    pub fn overlay(mut self, icon_id: IconId, position: Quadrant) -> Self {
        self.icon.add_overlay(IconOverlay::new(icon_id, position));
        self
    }

    /// Add an overlay with a custom scale.
    pub fn overlay_scaled(
        mut self,
        icon_id: IconId,
        position: Quadrant,
        scale: f32,
    ) -> Self {
        self.icon
            .add_overlay(IconOverlay::new(icon_id, position).with_scale(scale));
        self
    }

    /// Set the icon dimensions.
    pub fn size(mut self, width: u32, height: u32) -> Self {
        self.icon.set_size(width, height);
        self
    }

    /// Build the final multi-icon.
    pub fn build(self) -> MultiIcon {
        self.icon
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quadrant_factors() {
        assert_eq!(Quadrant::TopLeft.x_factor(), 0.0);
        assert_eq!(Quadrant::TopLeft.y_factor(), 0.0);
        assert_eq!(Quadrant::BottomRight.x_factor(), 1.0);
        assert_eq!(Quadrant::BottomRight.y_factor(), 1.0);
    }

    #[test]
    fn test_multi_icon_basic() {
        let icon = MultiIcon::new(IconId::Name("base".into()));
        assert!(!icon.has_overlays());
        assert_eq!(icon.overlay_count(), 0);
    }

    #[test]
    fn test_multi_icon_builder() {
        let icon = MultiIcon::builder(IconId::Name("base".into()))
            .overlay(
                IconId::Builtin(BuiltinIcon::Check),
                Quadrant::BottomRight,
            )
            .overlay_scaled(
                IconId::Builtin(BuiltinIcon::Lock),
                Quadrant::TopRight,
                0.3,
            )
            .size(32, 32)
            .build();

        assert!(icon.has_overlays());
        assert_eq!(icon.overlay_count(), 2);
        assert_eq!(icon.width, 32);
        assert_eq!(icon.height, 32);
        assert_eq!(icon.overlays[0].position, Quadrant::BottomRight);
        assert_eq!(icon.overlays[1].position, Quadrant::TopRight);
        assert!((icon.overlays[1].scale - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_overlay_scale_clamped() {
        let overlay = IconOverlay::new(
            IconId::Builtin(BuiltinIcon::Error),
            Quadrant::TopLeft,
        )
        .with_scale(5.0);
        assert!((overlay.scale - 1.0).abs() < 0.01);

        let overlay = IconOverlay::new(
            IconId::Builtin(BuiltinIcon::Error),
            Quadrant::TopLeft,
        )
        .with_scale(0.01);
        assert!((overlay.scale - 0.1).abs() < 0.01);
    }
}
