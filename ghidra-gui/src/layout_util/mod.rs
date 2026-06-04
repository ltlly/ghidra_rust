//! Layout utility types.
//!
//! Ports Ghidra's `ghidra.util.layout` types for border management and
//! layout helpers.

/// Standard border types used in Ghidra GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BorderType {
    /// No border.
    None,
    /// An etched border (raised or lowered).
    Etched,
    /// A titled border with a label.
    Titled,
    /// An empty border with padding.
    Empty,
    /// A line border with a single pixel.
    Line,
    /// A compound border (combination of borders).
    Compound,
}

impl Default for BorderType {
    fn default() -> Self {
        Self::None
    }
}

/// Configuration for a border.
#[derive(Debug, Clone)]
pub struct BorderConfig {
    /// The border type.
    pub border_type: BorderType,
    /// Title text (for titled borders).
    pub title: Option<String>,
    /// Padding in pixels.
    pub padding: u32,
    /// Whether the border is raised (for etched borders).
    pub raised: bool,
}

impl Default for BorderConfig {
    fn default() -> Self {
        Self {
            border_type: BorderType::default(),
            title: None,
            padding: 0,
            raised: true,
        }
    }
}

impl BorderConfig {
    /// Create an empty border with padding.
    pub fn empty(padding: u32) -> Self {
        Self {
            border_type: BorderType::Empty,
            padding,
            ..Default::default()
        }
    }

    /// Create a titled border.
    pub fn titled(title: impl Into<String>) -> Self {
        Self {
            border_type: BorderType::Titled,
            title: Some(title.into()),
            ..Default::default()
        }
    }

    /// Create an etched border.
    pub fn etched() -> Self {
        Self {
            border_type: BorderType::Etched,
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_border_type_default() {
        assert_eq!(BorderType::default(), BorderType::None);
    }

    #[test]
    fn test_border_config_empty() {
        let config = BorderConfig::empty(10);
        assert_eq!(config.border_type, BorderType::Empty);
        assert_eq!(config.padding, 10);
    }

    #[test]
    fn test_border_config_titled() {
        let config = BorderConfig::titled("Options");
        assert_eq!(config.border_type, BorderType::Titled);
        assert_eq!(config.title.as_deref(), Some("Options"));
    }

    #[test]
    fn test_border_config_etched() {
        let config = BorderConfig::etched();
        assert_eq!(config.border_type, BorderType::Etched);
        assert!(config.raised);
    }
}
