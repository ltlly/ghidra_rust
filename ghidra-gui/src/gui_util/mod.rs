//! GUI utility types: HTML formatting, web colors, color utilities, help
//! locations, bean utilities, and test helpers.
//!
//! Ports key types from `ghidra.util` (HTMLUtilities, WebColors, ColorUtils,
//! HelpLocation), `ghidra.util.bean`, `generic.test`, and `ghidra.test`
//! into idiomatic Rust.

pub mod bean_utils;
pub mod color_utils;
pub mod file_chooser;
pub mod help_location;
pub mod html;
pub mod html_element;
pub mod image_utils;
pub mod layout_managers;
pub mod test_utils;
pub mod theme_events;
pub mod web_colors;
pub mod dynamic_help_location;

// Missing GUI types: OptionsChangeListener, property editors, theme event wrappers,
// icon wrappers, task monitors, SwingRunnable
pub mod missing_gui_types;

pub use bean_utils::{OptionEditorModel, OptionEditorPanel, PropertyChangeEvent, PropertyValue};
pub use color_utils::ColorUtils;
pub use file_chooser::{ExtensionFileFilter, GhidraFileChooserModel, GhidraFileFilter};
pub use help_location::{DynamicHelpLocation, HelpLocation};
pub use html::HtmlUtilities;
pub use layout_managers::{ColumnLayout, HorizontalLayout, MiddleLayout, PairLayout, StretchLayout, ThreeColumnLayout, VerticalLayout};
pub use test_utils::{GuiTestAssertions, MockProvider, TestEnvironment, ToolStateVerifier};
pub use theme_events::{AllValuesChangedThemeEvent, ColorChangedThemeEvent, FontChangedThemeEvent, IconChangedThemeEvent, ThemeChangeType, ThemeEvent, ThemeListener};
pub use html_element::{HTMLElement, HtmlLineSplitter, PreservingWhitespaceHandler, TrimmingWhitespaceHandler, WhitespaceHandler};
pub use web_colors::WebColors;
pub use dynamic_help_location::{DynamicHelpLocation as DynamicHelpLocationExt, HelpContext, ResolvedHelpLocation};
