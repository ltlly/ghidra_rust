//! Console plugin factory and lifecycle management.
//!
//! Ported from `ghidra.app.plugin.core.console.ConsolePlugin` (Features/Base).
//!
//! This module provides [`ConsolePluginFactory`], a factory that creates
//! [`ConsolePlugin`] instances with standard configuration and integrates
//! with the Ghidra tool plugin lifecycle.
//!
//! # Java Original
//!
//! The Java `ConsolePlugin` extends `ProgramPlugin` and:
//! - Creates a `ConsoleComponentProvider` in its constructor
//! - Registers the `ConsoleService` service
//! - Delegates `init()`, `dispose()`, `programActivated()`, and
//!   `programDeactivated()` to the provider
//!
//! In Rust we express this as a factory + lifecycle trait because we do not
//! have Java's inheritance-based plugin model.

use super::ConsoleComponentProvider;
use super::ConsolePlugin;
use super::ConsoleService;
use super::ConsoleWord;

/// Metadata about a console plugin registration.
///
/// Corresponds to the `@PluginInfo` annotation on the Java class.
#[derive(Debug, Clone)]
pub struct ConsolePluginRegistration {
    /// Unique plugin name.
    pub name: String,
    /// Owner/package (e.g. "Core").
    pub owner: String,
    /// Category (e.g. "Common").
    pub category: String,
    /// Short description shown in plugin lists.
    pub short_description: String,
    /// Full description for help/documentation.
    pub description: String,
}

impl Default for ConsolePluginRegistration {
    fn default() -> Self {
        Self {
            name: "Console".to_string(),
            owner: "Core".to_string(),
            category: "Common".to_string(),
            short_description: "I/O Console".to_string(),
            description: "Displays an I/O console.".to_string(),
        }
    }
}

/// Factory for creating and configuring [`ConsolePlugin`] instances.
///
/// Mirrors the Java pattern where `ConsolePlugin` is instantiated by the
/// Ghidra plugin framework using its constructor and `@PluginInfo` metadata.
///
/// # Example
///
/// ```
/// use ghidra_features::console::*;
///
/// let plugin = ConsolePluginFactory::create("MyConsole");
/// assert_eq!(plugin.name(), "MyConsole");
/// assert!(!plugin.is_initialized());
/// ```
pub struct ConsolePluginFactory;

impl ConsolePluginFactory {
    /// Create a new console plugin with the given name.
    pub fn create(name: impl Into<String>) -> ConsolePlugin {
        ConsolePlugin::new(name)
    }

    /// Create a console plugin with default registration metadata.
    pub fn create_default() -> ConsolePlugin {
        ConsolePlugin::new("Console")
    }

    /// Return the default plugin registration metadata.
    ///
    /// This corresponds to the `@PluginInfo` annotation values on the
    /// Java `ConsolePlugin` class.
    pub fn registration_info() -> ConsolePluginRegistration {
        ConsolePluginRegistration::default()
    }

    /// Create a plugin and initialize it in one step.
    ///
    /// Equivalent to calling `create()` followed by `init()`.
    pub fn create_initialized(name: impl Into<String>) -> ConsolePlugin {
        let mut plugin = ConsolePlugin::new(name);
        plugin.init();
        plugin
    }
}

/// Extension trait that adds Java-style `ProgramPlugin` lifecycle methods
/// to any [`ConsoleService`] implementor.
///
/// In the Java codebase, `ConsolePlugin` extends `ProgramPlugin` which
/// provides `programActivated(Program)` / `programDeactivated(Program)`.
/// This trait expresses the same contract in Rust.
pub trait ConsolePluginLifecycle {
    /// Called when a program becomes the active program in the tool.
    fn program_activated(&mut self, program_name: &str);

    /// Called when a program is deactivated (closed or switched away from).
    fn program_deactivated(&mut self, program_name: &str);

    /// Get the currently active program name, if any.
    fn current_program(&self) -> Option<&str>;
}

/// Extension trait for console word navigation, mirroring the
/// `GoToMouseListener` and `CursorUpdateMouseMotionListener` inner classes
/// in `ConsoleComponentProvider.java`.
pub trait ConsoleNavigation {
    /// Attempt to resolve a word at the given offset as a navigable target
    /// (address or symbol name).
    ///
    /// Returns `Some(ConsoleWord)` with special characters stripped if the
    /// word could be an address or symbol; `None` otherwise.
    fn resolve_navigable_word(&self, text: &str, offset: usize) -> Option<ConsoleWord>;
}

/// Default implementation of navigable word resolution.
///
/// Mirrors the logic in `GoToMouseListener`: extract the word at the click
/// position, then try it raw, then try it with special characters removed.
pub fn resolve_navigable_word_default(text: &str, offset: usize) -> Option<ConsoleWord> {
    use super::ConsoleWord;
    use crate::base::console::console_word::get_word_at_position;

    let word = get_word_at_position(text, offset)?;
    let trimmed = word.without_special_characters();

    // In the Java code, the raw word is tried first (as an address),
    // then the trimmed word. Here we return the trimmed version since
    // we cannot check the address factory without a Program reference.
    if !trimmed.word.is_empty() {
        Some(trimmed)
    } else if !word.word.is_empty() {
        Some(word)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_factory_create() {
        let plugin = ConsolePluginFactory::create("TestConsole");
        assert_eq!(plugin.name(), "TestConsole");
        assert!(!plugin.is_initialized());
    }

    #[test]
    fn test_factory_create_default() {
        let plugin = ConsolePluginFactory::create_default();
        assert_eq!(plugin.name(), "Console");
    }

    #[test]
    fn test_factory_create_initialized() {
        let plugin = ConsolePluginFactory::create_initialized("InitConsole");
        assert!(plugin.is_initialized());
    }

    #[test]
    fn test_registration_info() {
        let info = ConsolePluginFactory::registration_info();
        assert_eq!(info.name, "Console");
        assert_eq!(info.owner, "Core");
        assert_eq!(info.category, "Common");
    }

    #[test]
    fn test_resolve_navigable_word_with_brackets() {
        let word = resolve_navigable_word_default("see [main] for details", 6);
        assert!(word.is_some());
        assert_eq!(word.unwrap().word, "main");
    }

    #[test]
    fn test_resolve_navigable_word_plain() {
        let word = resolve_navigable_word_default("function_start", 3);
        assert!(word.is_some());
        assert_eq!(word.unwrap().word, "function_start");
    }

    #[test]
    fn test_resolve_navigable_word_empty() {
        let word = resolve_navigable_word_default("", 0);
        assert!(word.is_none());
    }

    #[test]
    fn test_lifecycle_on_console_plugin() {
        // ConsolePlugin already implements program_activated/deactivated
        let mut plugin = ConsolePlugin::new("Test");
        plugin.program_activated("prog1");
        assert_eq!(plugin.current_program(), Some("prog1"));
        plugin.program_deactivated("prog1");
        assert!(plugin.current_program().is_none());
    }
}
