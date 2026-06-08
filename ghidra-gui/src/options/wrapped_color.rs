//! Port of `ghidra.framework.options.WrappedColor`.
//!
//! A wrapper for persisting color values as options. Stores an RGBA color
//! that can be serialized to/from a key/value state map.

use super::option_type::OptionType;
use super::option_value::OptionValue;
use super::wrapped_option::WrappedOption;
use crate::gui_util::web_colors::RgbaColor;

/// Wrapper for an [`RgbaColor`] that can be persisted as an option value.
///
/// Ported from Ghidra's `ghidra.framework.options.WrappedColor`.
#[derive(Debug, Clone, PartialEq)]
pub struct WrappedColor {
    /// The wrapped RGBA color value.
    color: RgbaColor,
}

impl WrappedColor {
    /// Create a new wrapped color.
    pub fn new(color: RgbaColor) -> Self {
        Self { color }
    }

    /// Get the inner color value.
    pub fn color(&self) -> &RgbaColor {
        &self.color
    }

    /// Consume the wrapper and return the color.
    pub fn into_color(self) -> RgbaColor {
        self.color
    }
}

impl Default for WrappedColor {
    fn default() -> Self {
        Self {
            color: RgbaColor::new(0, 0, 0),
        }
    }
}

impl WrappedOption for WrappedColor {
    fn get_object(&self) -> OptionValue {
        OptionValue::Color(self.color)
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        for (key, val) in state {
            if key == "color" {
                if let OptionValue::Int(rgb) = val {
                    self.color = RgbaColor::from_argb(*rgb as u32);
                }
            }
        }
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        vec![(
            "color".to_string(),
            OptionValue::Int(self.color.to_argb() as i32),
        )]
    }

    fn option_type(&self) -> OptionType {
        OptionType::ColorType
    }
}

impl std::fmt::Display for WrappedColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WrappedColor: #{:02X}{:02X}{:02X}",
            self.color.r, self.color.g, self.color.b
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapped_color_new() {
        let wc = WrappedColor::new(RgbaColor::new(255, 0, 0));
        assert_eq!(wc.color().r, 255);
        assert_eq!(wc.color().g, 0);
        assert_eq!(wc.color().b, 0);
    }

    #[test]
    fn test_wrapped_color_default() {
        let wc = WrappedColor::default();
        assert_eq!(wc.color().r, 0);
        assert_eq!(wc.color().g, 0);
        assert_eq!(wc.color().b, 0);
    }

    #[test]
    fn test_wrapped_color_option_type() {
        let wc = WrappedColor::new(RgbaColor::new(128, 64, 32));
        assert_eq!(wc.option_type(), OptionType::ColorType);
    }

    #[test]
    fn test_wrapped_color_get_object() {
        let wc = WrappedColor::new(RgbaColor::new(10, 20, 30));
        match wc.get_object() {
            OptionValue::Color(c) => {
                assert_eq!(c.r, 10);
                assert_eq!(c.g, 20);
                assert_eq!(c.b, 30);
            }
            _ => panic!("Expected Color option value"),
        }
    }

    #[test]
    fn test_wrapped_color_roundtrip() {
        let wc = WrappedColor::new(RgbaColor::new(128, 64, 32));
        let state = wc.write_state();
        let mut wc2 = WrappedColor::default();
        wc2.read_state(&state);
        assert_eq!(wc.color(), wc2.color());
    }

    #[test]
    fn test_wrapped_color_display() {
        let wc = WrappedColor::new(RgbaColor::new(255, 128, 0));
        let s = format!("{}", wc);
        assert!(s.contains("FF8000"));
    }

    #[test]
    fn test_wrapped_color_into() {
        let wc = WrappedColor::new(RgbaColor::new(1, 2, 3));
        let c = wc.into_color();
        assert_eq!(c.r, 1);
        assert_eq!(c.g, 2);
        assert_eq!(c.b, 3);
    }
}
