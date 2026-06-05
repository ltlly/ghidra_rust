//! GUI utility types: HTML formatting, web colors, color utilities, help
//! locations.
//!
//! Ports key types from `ghidra.util` (HTMLUtilities, WebColors, ColorUtils,
//! HelpLocation) into idiomatic Rust.

pub mod color_utils;
pub mod file_chooser;
pub mod help_location;
pub mod html;
pub mod layout_managers;
pub mod theme_events;
pub mod web_colors;

pub use color_utils::ColorUtils;
pub use file_chooser::{ExtensionFileFilter, GhidraFileChooserModel, GhidraFileFilter};
pub use help_location::{DynamicHelpLocation, HelpLocation};
pub use html::HtmlUtilities;
pub use layout_managers::{ColumnLayout, HorizontalLayout, MiddleLayout, PairLayout, StretchLayout, ThreeColumnLayout, VerticalLayout};
pub use theme_events::{AllValuesChangedThemeEvent, ColorChangedThemeEvent, FontChangedThemeEvent, IconChangedThemeEvent, ThemeChangeType, ThemeEvent, ThemeListener};
pub use web_colors::WebColors;
