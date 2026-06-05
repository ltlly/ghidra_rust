//! String events and translation services.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.string` Java package.
//!
//! Provides event types for string table changes and translation
//! services for translating found strings.
//!
//! # Key Types
//!
//! - [`StringEvent`] -- base event for string changes
//! - [`StringAddedEvent`] -- event when a new string is discovered
//! - [`StringTranslationService`] -- trait for translating strings
//! - [`TranslateStringsPlugin`] -- plugin for string translation

use std::collections::HashMap;

use super::{FoundString, StringEncoding};

// ---------------------------------------------------------------------------
// String event types
// ---------------------------------------------------------------------------

/// A change event in the string table.
///
/// Ported from `ghidra.app.plugin.core.string.StringEvent`.
#[derive(Debug, Clone)]
pub enum StringEvent {
    /// A new string was found and added to the table.
    Added {
        /// The address of the added string.
        address: u64,
        /// The encoding of the added string.
        encoding: StringEncoding,
        /// The byte length of the added string.
        byte_length: usize,
    },
    /// A string was removed from the table (e.g., data was cleared).
    Removed {
        /// The address of the removed string.
        address: u64,
    },
    /// A string was modified (e.g., encoding changed).
    Modified {
        /// The address of the modified string.
        address: u64,
        /// The old encoding.
        old_encoding: StringEncoding,
        /// The new encoding.
        new_encoding: StringEncoding,
    },
    /// All strings were cleared from the table.
    Cleared,
}

impl StringEvent {
    /// The event type name.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::Added { .. } => "Added",
            Self::Removed { .. } => "Removed",
            Self::Modified { .. } => "Modified",
            Self::Cleared => "Cleared",
        }
    }

    /// The address affected by this event (if any).
    pub fn address(&self) -> Option<u64> {
        match self {
            Self::Added { address, .. } => Some(*address),
            Self::Removed { address, .. } => Some(*address),
            Self::Modified { address, .. } => Some(*address),
            Self::Cleared => None,
        }
    }
}

// ---------------------------------------------------------------------------
// String event log
// ---------------------------------------------------------------------------

/// A log of string events for a session.
#[derive(Debug, Clone, Default)]
pub struct StringEventLog {
    events: Vec<StringEvent>,
}

impl StringEventLog {
    /// Create a new event log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Log an event.
    pub fn push(&mut self, event: StringEvent) {
        self.events.push(event);
    }

    /// Get all events.
    pub fn events(&self) -> &[StringEvent] {
        &self.events
    }

    /// Number of events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
    }

    /// Get the number of "Added" events.
    pub fn added_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, StringEvent::Added { .. }))
            .count()
    }

    /// Get the number of "Removed" events.
    pub fn removed_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| matches!(e, StringEvent::Removed { .. }))
            .count()
    }
}

// ---------------------------------------------------------------------------
// String translation service
// ---------------------------------------------------------------------------

/// Options for string translation.
#[derive(Debug, Clone)]
pub struct TranslateOptions {
    /// Whether to show the translated value in the listing.
    pub show_translation: bool,
    /// The target language for translation.
    pub target_language: String,
    /// Maximum number of strings to translate in one batch.
    pub batch_size: usize,
    /// Whether to overwrite existing translations.
    pub overwrite_existing: bool,
}

impl Default for TranslateOptions {
    fn default() -> Self {
        Self {
            show_translation: false,
            target_language: "en".to_string(),
            batch_size: 100,
            overwrite_existing: false,
        }
    }
}

/// Service trait for translating strings.
///
/// Ported from `ghidra.app.services.StringTranslationService`.
pub trait StringTranslationService: Send + Sync {
    /// Translate a single string.
    fn translate(&self, text: &str, source_lang: &str, target_lang: &str) -> Option<String>;

    /// Get the service name.
    fn name(&self) -> &str;

    /// Whether the service is available (e.g., network service is reachable).
    fn is_available(&self) -> bool;
}

// ---------------------------------------------------------------------------
// Manual translation service
// ---------------------------------------------------------------------------

/// Manual string translation service that stores user-provided translations.
///
/// Ported from `ghidra.app.plugin.core.string.translate.ManualStringTranslationService`.
#[derive(Debug, Default)]
pub struct ManualStringTranslationService {
    /// User-provided translations keyed by (address, original_text).
    translations: HashMap<(u64, String), String>,
}

impl ManualStringTranslationService {
    /// Create a new manual translation service.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a translation for a string at an address.
    pub fn set_translation(
        &mut self,
        address: u64,
        original: impl Into<String>,
        translation: impl Into<String>,
    ) {
        self.translations
            .insert((address, original.into()), translation.into());
    }

    /// Get a translation for a string at an address.
    pub fn get_translation(&self, address: u64, original: &str) -> Option<&str> {
        self.translations
            .get(&(address, original.to_string()))
            .map(|s| s.as_str())
    }

    /// Remove a translation.
    pub fn remove_translation(&mut self, address: u64, original: &str) -> bool {
        self.translations
            .remove(&(address, original.to_string()))
            .is_some()
    }

    /// Clear all translations.
    pub fn clear(&mut self) {
        self.translations.clear();
    }

    /// Number of stored translations.
    pub fn translation_count(&self) -> usize {
        self.translations.len()
    }
}

impl StringTranslationService for ManualStringTranslationService {
    fn translate(&self, text: &str, _source_lang: &str, _target_lang: &str) -> Option<String> {
        // Manual service can't auto-translate; return None
        // In practice, translations are set via set_translation()
        self.translations
            .values()
            .find(|t| !t.is_empty())
            .cloned()
    }

    fn name(&self) -> &str {
        "Manual Translation Service"
    }

    fn is_available(&self) -> bool {
        true // always available
    }
}

// ---------------------------------------------------------------------------
// TranslateStringsPlugin
// ---------------------------------------------------------------------------

/// Plugin for translating strings in the string table.
///
/// Ported from `ghidra.app.plugin.core.string.translate.TranslateStringsPlugin`.
#[derive(Debug)]
pub struct TranslateStringsPlugin {
    /// Translation options.
    pub options: TranslateOptions,
    /// Registered translation services.
    services: Vec<String>,
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Event log.
    event_log: StringEventLog,
}

impl TranslateStringsPlugin {
    /// Create a new translate strings plugin.
    pub fn new() -> Self {
        Self {
            options: TranslateOptions::default(),
            services: Vec::new(),
            enabled: true,
            event_log: StringEventLog::new(),
        }
    }

    /// Register a translation service by name.
    pub fn add_service(&mut self, service_name: impl Into<String>) {
        self.services.push(service_name.into());
    }

    /// Get the registered service names.
    pub fn services(&self) -> &[String] {
        &self.services
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the event log.
    pub fn event_log(&self) -> &StringEventLog {
        &self.event_log
    }

    /// Get a mutable reference to the event log.
    pub fn event_log_mut(&mut self) -> &mut StringEventLog {
        &mut self.event_log
    }
}

impl Default for TranslateStringsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_event_added() {
        let event = StringEvent::Added {
            address: 0x1000,
            encoding: StringEncoding::Ascii,
            byte_length: 6,
        };
        assert_eq!(event.event_type(), "Added");
        assert_eq!(event.address(), Some(0x1000));
    }

    #[test]
    fn test_string_event_removed() {
        let event = StringEvent::Removed { address: 0x2000 };
        assert_eq!(event.event_type(), "Removed");
        assert_eq!(event.address(), Some(0x2000));
    }

    #[test]
    fn test_string_event_modified() {
        let event = StringEvent::Modified {
            address: 0x3000,
            old_encoding: StringEncoding::Ascii,
            new_encoding: StringEncoding::Utf16Le,
        };
        assert_eq!(event.event_type(), "Modified");
        assert_eq!(event.address(), Some(0x3000));
    }

    #[test]
    fn test_string_event_cleared() {
        let event = StringEvent::Cleared;
        assert_eq!(event.event_type(), "Cleared");
        assert_eq!(event.address(), None);
    }

    #[test]
    fn test_string_event_log() {
        let mut log = StringEventLog::new();
        assert!(log.is_empty());

        log.push(StringEvent::Added {
            address: 0x1000,
            encoding: StringEncoding::Ascii,
            byte_length: 6,
        });
        log.push(StringEvent::Added {
            address: 0x2000,
            encoding: StringEncoding::Utf16Le,
            byte_length: 10,
        });
        log.push(StringEvent::Removed { address: 0x1000 });

        assert_eq!(log.len(), 3);
        assert_eq!(log.added_count(), 2);
        assert_eq!(log.removed_count(), 1);
    }

    #[test]
    fn test_string_event_log_clear() {
        let mut log = StringEventLog::new();
        log.push(StringEvent::Cleared);
        assert_eq!(log.len(), 1);
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn test_translate_options_default() {
        let opts = TranslateOptions::default();
        assert!(!opts.show_translation);
        assert_eq!(opts.target_language, "en");
        assert_eq!(opts.batch_size, 100);
        assert!(!opts.overwrite_existing);
    }

    #[test]
    fn test_manual_translation_service() {
        let mut svc = ManualStringTranslationService::new();
        assert!(svc.is_available());
        assert_eq!(svc.name(), "Manual Translation Service");

        svc.set_translation(0x1000, "Hello", "Hola");
        assert_eq!(svc.get_translation(0x1000, "Hello"), Some("Hola"));
        assert_eq!(svc.get_translation(0x1000, "World"), None);
        assert_eq!(svc.translation_count(), 1);
    }

    #[test]
    fn test_manual_translation_service_remove() {
        let mut svc = ManualStringTranslationService::new();
        svc.set_translation(0x1000, "Hello", "Hola");
        assert!(svc.remove_translation(0x1000, "Hello"));
        assert_eq!(svc.translation_count(), 0);
        assert!(!svc.remove_translation(0x1000, "Hello"));
    }

    #[test]
    fn test_manual_translation_service_clear() {
        let mut svc = ManualStringTranslationService::new();
        svc.set_translation(0x1000, "A", "B");
        svc.set_translation(0x2000, "C", "D");
        assert_eq!(svc.translation_count(), 2);

        svc.clear();
        assert_eq!(svc.translation_count(), 0);
    }

    #[test]
    fn test_translate_strings_plugin() {
        let mut plugin = TranslateStringsPlugin::new();
        assert!(plugin.is_enabled());
        assert!(plugin.services().is_empty());

        plugin.add_service("LibreTranslate");
        plugin.add_service("Manual");
        assert_eq!(plugin.services().len(), 2);

        plugin.set_enabled(false);
        assert!(!plugin.is_enabled());
    }

    #[test]
    fn test_translate_strings_plugin_event_log() {
        let mut plugin = TranslateStringsPlugin::new();
        plugin.event_log_mut().push(StringEvent::Added {
            address: 0x1000,
            encoding: StringEncoding::Ascii,
            byte_length: 6,
        });
        assert_eq!(plugin.event_log().len(), 1);
    }
}
