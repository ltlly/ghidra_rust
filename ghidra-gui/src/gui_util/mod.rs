//! GUI utility types: HTML formatting, web colors, color utilities, help
//! locations.
//!
//! Ports key types from `ghidra.util` (HTMLUtilities, WebColors, ColorUtils,
//! HelpLocation) into idiomatic Rust.

pub mod color_utils;
pub mod help_location;
pub mod html;
pub mod web_colors;

pub use color_utils::ColorUtils;
pub use help_location::{DynamicHelpLocation, HelpLocation};
pub use html::HtmlUtilities;
pub use web_colors::WebColors;
