//! Port of `ghidra.framework.options.WrappedFont`.
//!
//! A wrapper for persisting font values as options. Stores a font descriptor
//! (family, style, size) that can be serialized to/from a key/value state map.

use super::option_type::OptionType;
use super::option_value::{FontDescriptor, OptionValue};
use super::wrapped_option::WrappedOption;

/// Wrapper for a [`FontDescriptor`] that can be persisted as an option value.
///
/// Ported from Ghidra's `ghidra.framework.options.WrappedFont`.
#[derive(Debug, Clone)]
pub struct WrappedFont {
    /// The wrapped font descriptor.
    font: FontDescriptor,
}

impl WrappedFont {
    /// Create a new wrapped font from a font descriptor.
    pub fn new(font: FontDescriptor) -> Self {
        Self { font }
    }

    /// Get a reference to the inner font descriptor.
    pub fn font(&self) -> &FontDescriptor {
        &self.font
    }

    /// Consume the wrapper and return the font descriptor.
    pub fn into_font(self) -> FontDescriptor {
        self.font
    }
}

impl Default for WrappedFont {
    fn default() -> Self {
        Self {
            font: FontDescriptor::plain("monospaced", 12.0),
        }
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
        self.font = FontDescriptor::new(family, style, size);
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

impl std::fmt::Display for WrappedFont {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WrappedFont: {} {}pt{}{}",
            self.font.family,
            self.font.size,
            if self.font.is_bold() { " bold" } else { "" },
            if self.font.is_italic() { " italic" } else { "" },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapped_font_new() {
        let wf = WrappedFont::new(FontDescriptor::plain("Arial", 14.0));
        assert_eq!(wf.font().family, "Arial");
        assert_eq!(wf.font().size, 14.0);
        assert_eq!(wf.font().style, 0);
    }

    #[test]
    fn test_wrapped_font_default() {
        let wf = WrappedFont::default();
        assert_eq!(wf.font().family, "monospaced");
        assert_eq!(wf.font().size, 12.0);
    }

    #[test]
    fn test_wrapped_font_option_type() {
        let wf = WrappedFont::new(FontDescriptor::bold("Courier", 16.0));
        assert_eq!(wf.option_type(), OptionType::FontType);
    }

    #[test]
    fn test_wrapped_font_roundtrip() {
        let wf = WrappedFont::new(FontDescriptor::new("Courier", 1, 16.0));
        let state = wf.write_state();
        assert_eq!(state.len(), 3);

        let mut wf2 = WrappedFont::default();
        wf2.read_state(&state);
        assert_eq!(wf2.font().family, "Courier");
        assert_eq!(wf2.font().style, 1);
        assert_eq!(wf2.font().size, 16.0);
    }

    #[test]
    fn test_wrapped_font_bold_italic() {
        let wf = WrappedFont::new(FontDescriptor::new("Helvetica", 3, 18.0));
        assert!(wf.font().is_bold());
        assert!(wf.font().is_italic());
    }

    #[test]
    fn test_wrapped_font_display() {
        let wf = WrappedFont::new(FontDescriptor::bold("Arial", 14.0));
        let s = format!("{}", wf);
        assert!(s.contains("Arial"));
        assert!(s.contains("14"));
        assert!(s.contains("bold"));
    }

    #[test]
    fn test_wrapped_font_into() {
        let wf = WrappedFont::new(FontDescriptor::plain("Mono", 10.0));
        let f = wf.into_font();
        assert_eq!(f.family, "Mono");
        assert_eq!(f.size, 10.0);
    }
}
