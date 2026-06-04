//! Wrapped option trait for complex values.
//!
//! Ports `ghidra.framework.options.WrappedOption`.

use super::option_type::OptionType;
use super::option_value::OptionValue;

/// Trait for objects that can be saved as a set of primitives.
///
/// Ported from Ghidra's `ghidra.framework.options.WrappedOption`.
pub trait WrappedOption {
    /// Get the value as an `OptionValue`.
    fn get_object(&self) -> OptionValue;

    /// Read state from a key/value map.
    fn read_state(&mut self, state: &[(String, OptionValue)]);

    /// Write state into a key/value map.
    fn write_state(&self) -> Vec<(String, OptionValue)>;

    /// Get the option type for this wrapped option.
    fn option_type(&self) -> OptionType;
}

/// A wrapped color value.
#[derive(Debug, Clone)]
pub struct WrappedColor {
    color: crate::gui_util::web_colors::RgbaColor,
}

impl WrappedColor {
    pub fn new(color: crate::gui_util::web_colors::RgbaColor) -> Self {
        Self { color }
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
                    self.color = crate::gui_util::web_colors::RgbaColor::from_argb(*rgb as u32);
                }
            }
        }
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        vec![("color".to_string(), OptionValue::Int(self.color.to_argb() as i32))]
    }

    fn option_type(&self) -> OptionType {
        OptionType::ColorType
    }
}

/// A wrapped font value.
#[derive(Debug, Clone)]
pub struct WrappedFont {
    font: super::option_value::FontDescriptor,
}

impl WrappedFont {
    pub fn new(font: super::option_value::FontDescriptor) -> Self {
        Self { font }
    }
}

impl WrappedOption for WrappedFont {
    fn get_object(&self) -> OptionValue {
        OptionValue::Font(self.font.clone())
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        let mut family = String::from("monospaced");
        let mut size: f32 = 12.0;
        let mut style: u32 = 0;
        for (key, val) in state {
            match key.as_str() {
                "family" => {
                    if let OptionValue::String(s) = val {
                        family = s.clone();
                    }
                }
                "size" => {
                    if let OptionValue::Int(s) = val {
                        size = *s as f32;
                    }
                }
                "style" => {
                    if let OptionValue::Int(s) = val {
                        style = *s as u32;
                    }
                }
                _ => {}
            }
        }
        self.font = super::option_value::FontDescriptor::new(family, style, size);
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        vec![
            ("family".to_string(), OptionValue::String(self.font.family.clone())),
            ("size".to_string(), OptionValue::Int(self.font.size as i32)),
            ("style".to_string(), OptionValue::Int(self.font.style as i32)),
        ]
    }

    fn option_type(&self) -> OptionType {
        OptionType::FontType
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui_util::web_colors::RgbaColor;

    #[test]
    fn test_wrapped_color() {
        let wc = WrappedColor::new(RgbaColor::new(255, 0, 0));
        assert_eq!(wc.option_type(), OptionType::ColorType);
        if let OptionValue::Color(c) = wc.get_object() {
            assert_eq!(c.r, 255);
        } else {
            panic!("Expected Color value");
        }
    }

    #[test]
    fn test_wrapped_color_roundtrip() {
        let wc = WrappedColor::new(RgbaColor::new(128, 64, 32));
        let state = wc.write_state();
        let mut wc2 = WrappedColor::new(RgbaColor::new(0, 0, 0));
        wc2.read_state(&state);
        assert_eq!(wc.get_object(), wc2.get_object());
    }

    #[test]
    fn test_wrapped_font() {
        let wf = WrappedFont::new(super::super::option_value::FontDescriptor::bold("Arial", 14.0));
        assert_eq!(wf.option_type(), OptionType::FontType);
    }

    #[test]
    fn test_wrapped_font_roundtrip() {
        let wf = WrappedFont::new(super::super::option_value::FontDescriptor::new("Courier", 1, 16.0));
        let state = wf.write_state();
        let mut wf2 = WrappedFont::new(super::super::option_value::FontDescriptor::plain("default", 12.0));
        wf2.read_state(&state);
        if let OptionValue::Font(f) = wf2.get_object() {
            assert_eq!(f.family, "Courier");
            assert_eq!(f.style, 1);
            assert_eq!(f.size, 16.0);
        } else {
            panic!("Expected Font value");
        }
    }
}
