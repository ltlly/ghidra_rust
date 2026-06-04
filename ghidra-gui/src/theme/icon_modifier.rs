//! Port of `generic.theme.IconModifier`.
//!
//! Modifiers that can be applied to icons (overlay, size, disabled).

/// An icon modifier that can transform an icon.
///
/// Mirrors `generic.theme.IconModifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum IconModifier {
    /// Make the icon appear disabled (grayed out).
    Disabled,
    /// Make the icon smaller.
    Small,
    /// Make the icon larger.
    Large,
    /// Flip the icon horizontally.
    FlipHorizontal,
    /// Flip the icon vertically.
    FlipVertical,
    /// Rotate the icon by degrees (90, 180, 270).
    Rotate(u16),
}

impl IconModifier {
    /// Parse from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "disabled" => Some(Self::Disabled),
            "small" => Some(Self::Small),
            "large" => Some(Self::Large),
            "flip_h" | "fliphorizontal" => Some(Self::FlipHorizontal),
            "flip_v" | "flipvertical" => Some(Self::FlipVertical),
            _ => {
                if let Some(degrees) = s.strip_prefix("rotate") {
                    degrees.trim().parse::<u16>().ok().map(Self::Rotate)
                } else {
                    None
                }
            }
        }
    }
}

impl std::fmt::Display for IconModifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "Disabled"),
            Self::Small => write!(f, "Small"),
            Self::Large => write!(f, "Large"),
            Self::FlipHorizontal => write!(f, "FlipHorizontal"),
            Self::FlipVertical => write!(f, "FlipVertical"),
            Self::Rotate(d) => write!(f, "Rotate{}", d),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icon_modifier_parse() {
        assert_eq!(IconModifier::from_str("disabled"), Some(IconModifier::Disabled));
        assert_eq!(IconModifier::from_str("small"), Some(IconModifier::Small));
        assert_eq!(IconModifier::from_str("large"), Some(IconModifier::Large));
        assert_eq!(IconModifier::from_str("rotate180"), Some(IconModifier::Rotate(180)));
        assert_eq!(IconModifier::from_str("unknown"), None);
    }

    #[test]
    fn test_icon_modifier_display() {
        assert_eq!(IconModifier::Disabled.to_string(), "Disabled");
        assert_eq!(IconModifier::Rotate(90).to_string(), "Rotate90");
    }
}
