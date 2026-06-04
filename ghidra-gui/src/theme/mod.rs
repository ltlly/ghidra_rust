//! Theme system for managing application colors, fonts, and icons.
//!
//! Ports the `generic.theme` package which provides theme value types,
//! a theme manager, and look-and-feel abstractions.
//!
//! # Architecture
//!
//! - [`ThemeValue`] -- generic base for values with id, direct value, or reference.
//! - [`ColorValue`], [`FontValue`], [`IconValue`] -- concrete theme value types.
//! - [`GThemeValueMap`] -- map of all theme values (colors, fonts, icons).
//! - [`GTheme`] -- a complete theme with name, LAF type, and values.
//! - [`LafType`] -- supported look-and-feel enumerations.
//! - [`ThemeManager`] -- singleton managing the active theme.
//! - [`ThemeEvent`] -- notification when theme values change.

pub mod color_value;
pub mod font_modifier;
pub mod font_value;
pub mod g_theme;
pub mod g_theme_value_map;
pub mod icon_modifier;
pub mod icon_value;
pub mod laf_type;
pub mod property_value;
pub mod theme_defaults;
pub mod theme_event;
pub mod theme_manager;
pub mod theme_reader;
pub mod theme_value;
pub mod theme_writer;

pub use color_value::ColorValue;
pub use font_modifier::FontModifier;
pub use font_value::FontValue;
pub use g_theme::GTheme;
pub use g_theme_value_map::GThemeValueMap;
pub use icon_modifier::IconModifier;
pub use icon_value::IconValue;
pub use laf_type::LafType;
pub use property_value::{BooleanPropertyValue, JavaPropertyValue, StringPropertyValue};
pub use theme_defaults::{ApplicationThemeDefaults, DefaultColors, DefaultFonts};
pub use theme_event::ThemeEvent;
pub use theme_manager::ThemeManager;
pub use theme_reader::{ThemeFile, ThemeReader};
pub use theme_value::ThemeValue;
pub use theme_writer::ThemeWriter;
