//! String translation support -- ported from the `translate` sub-package
//! in `ghidra.app.plugin.core.string`.
//!
//! Provides translation of decoded strings using pluggable translation
//! backends (e.g., LibreTranslate, custom APIs).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TranslationService -- trait for translating strings
// ---------------------------------------------------------------------------

/// A trait for translating text from one language to another.
///
/// Ported from the `TranslateService` interface in the translate package.
pub trait TranslationService: Send + Sync {
    /// Translate text from `source_lang` to `target_lang`.
    fn translate(
        &self,
        text: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, TranslationError>;

    /// Get the name of this translation service.
    fn name(&self) -> &str;

    /// Whether this service is currently available (e.g., API is reachable).
    fn is_available(&self) -> bool;
}

// ---------------------------------------------------------------------------
// TranslationError
// ---------------------------------------------------------------------------

/// Errors that can occur during translation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TranslationError {
    /// The translation service is not available.
    ServiceUnavailable(String),
    /// The source or target language is unsupported.
    UnsupportedLanguage(String),
    /// The text is too long to translate in one request.
    TextTooLong(usize),
    /// An API error occurred.
    ApiError(String),
    /// Network error.
    NetworkError(String),
}

impl std::fmt::Display for TranslationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ServiceUnavailable(msg) => write!(f, "Service unavailable: {}", msg),
            Self::UnsupportedLanguage(lang) => write!(f, "Unsupported language: {}", lang),
            Self::TextTooLong(len) => write!(f, "Text too long: {} chars", len),
            Self::ApiError(msg) => write!(f, "API error: {}", msg),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for TranslationError {}

// ---------------------------------------------------------------------------
// TranslationResult
// ---------------------------------------------------------------------------

/// Result of a translation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationResult {
    /// The original text.
    pub original: String,
    /// The translated text.
    pub translated: String,
    /// The source language code.
    pub source_lang: String,
    /// The target language code.
    pub target_lang: String,
    /// The translation service that produced this result.
    pub service_name: String,
    /// Confidence score (0.0 - 1.0, if available).
    pub confidence: Option<f64>,
}

impl TranslationResult {
    /// Create a new translation result.
    pub fn new(
        original: impl Into<String>,
        translated: impl Into<String>,
        source_lang: impl Into<String>,
        target_lang: impl Into<String>,
        service_name: impl Into<String>,
    ) -> Self {
        Self {
            original: original.into(),
            translated: translated.into(),
            source_lang: source_lang.into(),
            target_lang: target_lang.into(),
            service_name: service_name.into(),
            confidence: None,
        }
    }
}

// ---------------------------------------------------------------------------
// NoopTranslationService -- a service that returns the text unchanged
// ---------------------------------------------------------------------------

/// A translation service that returns text unchanged (for testing or
/// when no real translation service is configured).
#[derive(Debug, Default)]
pub struct NoopTranslationService;

impl TranslationService for NoopTranslationService {
    fn translate(
        &self,
        text: &str,
        _source_lang: &str,
        _target_lang: &str,
    ) -> Result<String, TranslationError> {
        Ok(text.to_string())
    }

    fn name(&self) -> &str {
        "NoopTranslationService"
    }

    fn is_available(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// LibreTranslateConfig
// ---------------------------------------------------------------------------

/// Configuration for a LibreTranslate-compatible translation API.
///
/// Ported from `LibreTranslateService`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibreTranslateConfig {
    /// Base URL of the LibreTranslate server.
    pub base_url: String,
    /// API key (if required).
    pub api_key: Option<String>,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
}

impl LibreTranslateConfig {
    /// Create a new configuration.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: None,
            timeout_secs: 30,
        }
    }

    /// Set the API key.
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }
}

// ---------------------------------------------------------------------------
// TranslationManager -- manages translation backends
// ---------------------------------------------------------------------------

/// Manages translation service registration and provides a unified
/// translation interface.
///
/// Ported from the translation manager in the translate sub-package.
#[derive(Debug, Default)]
pub struct TranslationManager {
    /// Registered translation service names.
    service_names: Vec<String>,
    /// Default service name.
    default_service: Option<String>,
}

impl TranslationManager {
    /// Create a new translation manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a service name.
    pub fn register_service(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.service_names.contains(&name) {
            self.service_names.push(name.clone());
        }
        if self.default_service.is_none() {
            self.default_service = Some(name);
        }
    }

    /// Get registered service names.
    pub fn service_names(&self) -> &[String] {
        &self.service_names
    }

    /// Get the default service name.
    pub fn default_service(&self) -> Option<&str> {
        self.default_service.as_deref()
    }

    /// Set the default service.
    pub fn set_default_service(&mut self, name: Option<String>) {
        self.default_service = name;
    }
}

// ---------------------------------------------------------------------------
// LibreTranslateStringTranslationService
// ---------------------------------------------------------------------------

/// Translation service backed by a LibreTranslate-compatible API.
///
/// Ported from `ghidra.app.plugin.core.string.translate.libretranslate
/// .LibreTranslateStringTranslationService`.
#[derive(Debug)]
pub struct LibreTranslateStringTranslationService {
    /// Configuration for the LibreTranslate API.
    pub config: LibreTranslateConfig,
    /// Supported language codes.
    pub supported_languages: Vec<String>,
    /// Whether the service is currently reachable.
    pub reachable: bool,
}

impl LibreTranslateStringTranslationService {
    /// Create a new LibreTranslate translation service.
    pub fn new(config: LibreTranslateConfig) -> Self {
        Self {
            config,
            supported_languages: vec![
                "en".into(), "de".into(), "es".into(), "fr".into(),
                "it".into(), "pt".into(), "ru".into(), "zh".into(),
                "ja".into(), "ko".into(),
            ],
            reachable: false,
        }
    }

    /// Check if a language code is supported.
    pub fn supports_language(&self, lang: &str) -> bool {
        self.supported_languages.iter().any(|l| l == lang)
    }

    /// Set the reachability status (for testing).
    pub fn set_reachable(&mut self, reachable: bool) {
        self.reachable = reachable;
    }
}

impl TranslationService for LibreTranslateStringTranslationService {
    fn translate(
        &self,
        text: &str,
        source_lang: &str,
        target_lang: &str,
    ) -> Result<String, TranslationError> {
        if !self.reachable {
            return Err(TranslationError::ServiceUnavailable(
                "LibreTranslate server is not reachable".into(),
            ));
        }
        if !self.supports_language(source_lang) {
            return Err(TranslationError::UnsupportedLanguage(source_lang.into()));
        }
        if !self.supports_language(target_lang) {
            return Err(TranslationError::UnsupportedLanguage(target_lang.into()));
        }
        // In a real implementation, this would make an HTTP request.
        Ok(format!("[translated: {}]", text))
    }

    fn name(&self) -> &str {
        "LibreTranslate"
    }

    fn is_available(&self) -> bool {
        self.reachable
    }
}

// ---------------------------------------------------------------------------
// LibreTranslatePlugin
// ---------------------------------------------------------------------------

/// Plugin providing LibreTranslate integration for the string table.
///
/// Ported from `ghidra.app.plugin.core.string.translate.libretranslate
/// .LibreTranslatePlugin`.
#[derive(Debug)]
pub struct LibreTranslatePlugin {
    /// The translation service.
    pub service: LibreTranslateStringTranslationService,
    /// Whether the plugin is enabled.
    pub enabled: bool,
    /// Whether to show translations in the string table.
    pub show_translations: bool,
}

impl LibreTranslatePlugin {
    /// Create a new LibreTranslate plugin.
    pub fn new(config: LibreTranslateConfig) -> Self {
        Self {
            service: LibreTranslateStringTranslationService::new(config),
            enabled: true,
            show_translations: false,
        }
    }

    /// Toggle translation display.
    pub fn toggle_show_translations(&mut self) {
        self.show_translations = !self.show_translations;
    }
}

// ---------------------------------------------------------------------------
// Translation actions
// ---------------------------------------------------------------------------

/// Abstract base for translation actions.
///
/// Ported from `ghidra.app.plugin.core.string.translate.AbstractTranslateAction`.
#[derive(Debug, Clone)]
pub struct AbstractTranslateAction {
    /// The action name.
    pub name: String,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The menu group.
    pub menu_group: String,
    /// The popup menu path.
    pub popup_path: Vec<String>,
}

impl AbstractTranslateAction {
    /// Create a new abstract translate action.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            menu_group: "translate".into(),
            popup_path: vec!["Translate".into()],
        }
    }
}

/// Action to translate selected strings.
///
/// Ported from `ghidra.app.plugin.core.string.translate.TranslateAction`.
#[derive(Debug, Clone)]
pub struct TranslateAction {
    /// Base action properties.
    pub base: AbstractTranslateAction,
    /// Source language.
    pub source_lang: String,
    /// Target language.
    pub target_lang: String,
}

impl TranslateAction {
    /// Create a new translate action.
    pub fn new(source_lang: impl Into<String>, target_lang: impl Into<String>) -> Self {
        Self {
            base: AbstractTranslateAction::new("Translate Selection"),
            source_lang: source_lang.into(),
            target_lang: target_lang.into(),
        }
    }
}

/// Action to clear translations from the display.
///
/// Ported from `ghidra.app.plugin.core.string.translate.ClearTranslationAction`.
#[derive(Debug, Clone)]
pub struct ClearTranslationAction {
    /// Base action properties.
    pub base: AbstractTranslateAction,
}

impl ClearTranslationAction {
    /// Create a new clear translation action.
    pub fn new() -> Self {
        Self {
            base: AbstractTranslateAction::new("Clear Translations"),
        }
    }
}

impl Default for ClearTranslationAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to toggle showing translations in the string table.
///
/// Ported from `ghidra.app.plugin.core.string.translate.ToggleShowTranslationAction`.
#[derive(Debug, Clone)]
pub struct ToggleShowTranslationAction {
    /// Base action properties.
    pub base: AbstractTranslateAction,
    /// Whether translations are currently shown.
    pub showing: bool,
}

impl ToggleShowTranslationAction {
    /// Create a new toggle show translation action.
    pub fn new() -> Self {
        Self {
            base: AbstractTranslateAction::new("Toggle Show Translations"),
            showing: false,
        }
    }

    /// Toggle the showing state.
    pub fn toggle(&mut self) {
        self.showing = !self.showing;
    }
}

impl Default for ToggleShowTranslationAction {
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
    fn test_noop_translation_service() {
        let svc = NoopTranslationService;
        assert!(svc.is_available());
        assert_eq!(svc.name(), "NoopTranslationService");
        assert_eq!(svc.translate("hello", "en", "fr").unwrap(), "hello");
    }

    #[test]
    fn test_translation_result() {
        let r = TranslationResult::new("hello", "bonjour", "en", "fr", "TestService");
        assert_eq!(r.original, "hello");
        assert_eq!(r.translated, "bonjour");
        assert_eq!(r.source_lang, "en");
        assert_eq!(r.confidence, None);
    }

    #[test]
    fn test_translation_error_display() {
        let e = TranslationError::ServiceUnavailable("offline".into());
        assert!(format!("{}", e).contains("offline"));

        let e = TranslationError::UnsupportedLanguage("xx".into());
        assert!(format!("{}", e).contains("xx"));
    }

    #[test]
    fn test_libre_translate_config() {
        let cfg = LibreTranslateConfig::new("https://translate.example.com")
            .with_api_key("my_key");
        assert_eq!(cfg.base_url, "https://translate.example.com");
        assert_eq!(cfg.api_key.as_deref(), Some("my_key"));
        assert_eq!(cfg.timeout_secs, 30);
    }

    #[test]
    fn test_translation_manager() {
        let mut mgr = TranslationManager::new();
        assert!(mgr.service_names().is_empty());

        mgr.register_service("LibreTranslate");
        mgr.register_service("Noop");
        assert_eq!(mgr.service_names().len(), 2);
        assert_eq!(mgr.default_service(), Some("LibreTranslate"));

        mgr.set_default_service(Some("Noop".into()));
        assert_eq!(mgr.default_service(), Some("Noop"));
    }

    #[test]
    fn test_translation_manager_no_duplicate() {
        let mut mgr = TranslationManager::new();
        mgr.register_service("svc");
        mgr.register_service("svc");
        assert_eq!(mgr.service_names().len(), 1);
    }

    // -- LibreTranslateStringTranslationService tests --

    #[test]
    fn test_libre_translate_service_unreachable() {
        let cfg = LibreTranslateConfig::new("https://translate.example.com");
        let svc = LibreTranslateStringTranslationService::new(cfg);
        assert!(!svc.is_available());
        assert!(svc.translate("hello", "en", "fr").is_err());
    }

    #[test]
    fn test_libre_translate_service_reachable() {
        let cfg = LibreTranslateConfig::new("https://translate.example.com");
        let mut svc = LibreTranslateStringTranslationService::new(cfg);
        svc.set_reachable(true);
        assert!(svc.is_available());
        let result = svc.translate("hello", "en", "fr").unwrap();
        assert!(result.contains("translated"));
    }

    #[test]
    fn test_libre_translate_unsupported_language() {
        let cfg = LibreTranslateConfig::new("https://translate.example.com");
        let mut svc = LibreTranslateStringTranslationService::new(cfg);
        svc.set_reachable(true);
        assert!(svc.translate("hello", "xx", "fr").is_err());
        assert!(svc.translate("hello", "en", "xx").is_err());
    }

    #[test]
    fn test_libre_translate_supports_language() {
        let cfg = LibreTranslateConfig::new("https://translate.example.com");
        let svc = LibreTranslateStringTranslationService::new(cfg);
        assert!(svc.supports_language("en"));
        assert!(svc.supports_language("fr"));
        assert!(!svc.supports_language("xx"));
    }

    // -- LibreTranslatePlugin tests --

    #[test]
    fn test_libre_translate_plugin() {
        let cfg = LibreTranslateConfig::new("https://translate.example.com");
        let mut plugin = LibreTranslatePlugin::new(cfg);
        assert!(plugin.enabled);
        assert!(!plugin.show_translations);
        plugin.toggle_show_translations();
        assert!(plugin.show_translations);
        plugin.toggle_show_translations();
        assert!(!plugin.show_translations);
    }

    // -- Translation action tests --

    #[test]
    fn test_translate_action() {
        let action = TranslateAction::new("en", "fr");
        assert_eq!(action.base.name, "Translate Selection");
        assert_eq!(action.source_lang, "en");
        assert_eq!(action.target_lang, "fr");
        assert!(action.base.enabled);
    }

    #[test]
    fn test_clear_translation_action() {
        let action = ClearTranslationAction::new();
        assert_eq!(action.base.name, "Clear Translations");
        assert!(action.base.enabled);
    }

    #[test]
    fn test_toggle_show_translation_action() {
        let mut action = ToggleShowTranslationAction::new();
        assert!(!action.showing);
        action.toggle();
        assert!(action.showing);
        action.toggle();
        assert!(!action.showing);
    }
}
