//! Framework options system.
//!
//! Ports the `ghidra.framework.options` package which provides a hierarchical
//! key/value options store with typed getters/setters, change listeners, and
//! persistence.
//!
//! # Architecture
//!
//! - [`OptionType`] -- enum of all supported value types.
//! - [`OptionValue`] -- a type-erased option value.
//! - [`Option`] -- a single registered option with current/default values.
//! - [`Options`] (trait) -- the interface for getting/setting options.
//! - [`ToolOptions`] -- the concrete options store used by tools.
//! - [`SubOptions`] -- a scoped view into a parent options store.
//! - [`FileOptions`] -- options persisted to a JSON file.
//! - [`HelpLocation`] -- identifies a help topic + anchor.
//! - [`ActionTrigger`] -- key stroke + mouse binding trigger.
//! - [`PreferenceState`] -- saved state for non-plugin preferences.

pub mod action_trigger;
pub mod editor_state;
pub mod file_options;
pub mod option;
pub mod option_type;
pub mod option_value;
pub mod options_trait;
pub mod preference_state;
pub mod sub_options;
pub mod tool_options;
pub mod wrapped_option;
pub mod wrapped_options;

// New modules ported from Ghidra's options framework
pub mod options_editor;
pub mod editor_state_factory;
pub mod enum_editor;
pub mod theme_options;
pub mod property_editors;
pub mod abstract_options;
pub mod options_listener;
pub mod custom_options_editor;

pub use action_trigger::ActionTrigger;
pub use editor_state::EditorState;
pub use file_options::FileOptions;
pub use option::OptionEntry;
pub use option_type::OptionType;
pub use option_value::OptionValue;
pub use options_listener::OptionsVetoException;
pub use options_trait::{Options, OptionsChangeListener};
pub use preference_state::PreferenceState;
pub use sub_options::SubOptions;
pub use tool_options::ToolOptions;
pub use wrapped_option::WrappedOption;
pub use wrapped_options::{
    CustomOption, KeyStroke, WrappedActionTrigger, WrappedCustomOption,
    WrappedDate, WrappedFile, WrappedKeyStroke,
};
