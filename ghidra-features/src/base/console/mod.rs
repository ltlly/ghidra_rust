//! Console plugin for the Ghidra scripting environment.
//!
//! Port of Ghidra's `ghidra.app.plugin.core.console` Java package. Provides:
//!
//! - [`ConsoleService`] -- trait for the console I/O service
//! - [`ConsoleComponentProvider`] -- text-based console with message display,
//!   error output, and search capabilities
//! - [`ConsolePlugin`] -- plugin wrapper that integrates with the Ghidra tool
//! - [`CodeCompletion`] -- code completion data structure
//! - [`ConsoleWord`] -- word-at-cursor extraction for navigation
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::console::{ConsoleService, ConsoleComponentProvider};
//!
//! let mut console = ConsoleComponentProvider::new("MyScript");
//! console.add_message("script", "Hello, world!");
//! console.add_error_message("script", "Something went wrong");
//! assert_eq!(console.get_text_length(), console.text_len());
//! ```

pub mod code_completion;
pub mod console_component_provider;
pub mod console_plugin;
pub mod console_word;
pub mod console_service;

pub use code_completion::CodeCompletion;
pub use console_component_provider::ConsoleComponentProvider;
pub use console_plugin::ConsolePlugin;
pub use console_word::ConsoleWord;
pub use console_service::ConsoleService;
