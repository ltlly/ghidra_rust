// Port of help.HelpService, help.Help, docking.DefaultHelpService

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// A help location: a module name, help topic path, and optional anchor.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HelpLocation {
    /// The module name that owns this help topic.
    pub module_name: String,
    /// The path to the help file within the module (e.g., "help/topics/MyPlugin/page.html").
    pub help_path: String,
    /// Optional anchor name within the HTML file.
    pub anchor_name: Option<String>,
}

impl HelpLocation {
    pub fn new(module_name: &str, help_path: &str) -> Self {
        HelpLocation {
            module_name: module_name.to_string(),
            help_path: help_path.to_string(),
            anchor_name: None,
        }
    }

    pub fn with_anchor(module_name: &str, help_path: &str, anchor: &str) -> Self {
        HelpLocation {
            module_name: module_name.to_string(),
            help_path: help_path.to_string(),
            anchor_name: Some(anchor.to_string()),
        }
    }

    /// Prefix for shared help content.
    pub const HELP_SHARED: &'static str = "help/shared/";

    /// Prefix for help topics.
    pub const HELP_TOPICS: &'static str = "help/topics/";
}

impl std::fmt::Display for HelpLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.module_name, self.help_path)?;
        if let Some(ref anchor) = self.anchor_name {
            write!(f, "#{}", anchor)?;
        }
        Ok(())
    }
}

/// A dynamic help location that provides help based on the current state.
#[derive(Debug, Clone)]
pub struct DynamicHelpLocation {
    pub topic: String,
}

impl DynamicHelpLocation {
    pub fn new(topic: &str) -> Self {
        DynamicHelpLocation {
            topic: topic.to_string(),
        }
    }
}

/// Trait defining the help service interface.
///
/// Provides methods for registering, looking up, and displaying help content.
pub trait HelpService: Send + Sync {
    /// Show help for a registered help object.
    fn show_help(&self, help_object_id: &str, info_only: bool);

    /// Show help at a specific URL.
    fn show_help_url(&self, url: &str);

    /// Show help at a specific help location.
    fn show_help_location(&self, location: &HelpLocation);

    /// Exclude an object from the help system.
    fn exclude_from_help(&mut self, help_object_id: &str);

    /// Check if an object is excluded from help.
    fn is_excluded_from_help(&self, help_object_id: &str) -> bool;

    /// Register help for a specific object.
    fn register_help(&mut self, help_object_id: &str, location: HelpLocation);

    /// Register a dynamic help provider.
    fn register_dynamic_help(&mut self, help_object_id: &str, location: DynamicHelpLocation);

    /// Remove help registration for an object.
    fn clear_help(&mut self, help_object_id: &str);

    /// Get the registered help location for an object.
    fn get_help_location(&self, help_object_id: &str) -> Option<&HelpLocation>;

    /// Check if help content has been loaded and is available.
    fn help_exists(&self) -> bool;

    /// Reload help (e.g., after theme change).
    fn reload(&mut self);
}

// ---------------------------------------------------------------------------
// DefaultHelpService
// ---------------------------------------------------------------------------

/// A no-op help service that does nothing (placeholder before the full
/// help system is initialized).
pub struct DefaultHelpService {
    registrations: HashMap<String, HelpLocation>,
    excluded: std::collections::HashSet<String>,
}

impl DefaultHelpService {
    pub fn new() -> Self {
        DefaultHelpService {
            registrations: HashMap::new(),
            excluded: std::collections::HashSet::new(),
        }
    }
}

impl Default for DefaultHelpService {
    fn default() -> Self {
        Self::new()
    }
}

impl HelpService for DefaultHelpService {
    fn show_help(&self, _help_object_id: &str, _info_only: bool) {
        // no-op
    }

    fn show_help_url(&self, _url: &str) {
        // no-op
    }

    fn show_help_location(&self, _location: &HelpLocation) {
        // no-op
    }

    fn exclude_from_help(&mut self, help_object_id: &str) {
        self.excluded.insert(help_object_id.to_string());
    }

    fn is_excluded_from_help(&self, help_object_id: &str) -> bool {
        self.excluded.contains(help_object_id)
    }

    fn register_help(&mut self, help_object_id: &str, location: HelpLocation) {
        self.registrations
            .insert(help_object_id.to_string(), location);
    }

    fn register_dynamic_help(&mut self, help_object_id: &str, _location: DynamicHelpLocation) {
        // no-op for default service
        log::trace!("Dynamic help registered for: {}", help_object_id);
    }

    fn clear_help(&mut self, help_object_id: &str) {
        self.registrations.remove(help_object_id);
    }

    fn get_help_location(&self, help_object_id: &str) -> Option<&HelpLocation> {
        self.registrations.get(help_object_id)
    }

    fn help_exists(&self) -> bool {
        false
    }

    fn reload(&mut self) {
        // no-op
    }
}

// ---------------------------------------------------------------------------
// Help -- global singleton
// ---------------------------------------------------------------------------

/// The application-wide help service singleton.
///
/// Provides access to the currently installed help service. By default,
/// a `DefaultHelpService` (no-op) is used. The framework can install a
/// real help service at runtime.
pub struct Help;

static HELP_SERVICE: OnceLock<Mutex<Box<dyn HelpService>>> = OnceLock::new();

impl Help {
    /// Get the help service.
    pub fn get_help_service() -> &'static Mutex<Box<dyn HelpService>> {
        HELP_SERVICE.get_or_init(|| {
            Mutex::new(Box::new(DefaultHelpService::new()))
        })
    }

    /// Install a custom help service.
    pub fn install_help_service(service: Box<dyn HelpService>) {
        let lock = Self::get_help_service();
        if let Ok(mut guard) = lock.lock() {
            *guard = service;
        }
    }

    /// Show help for a registered object.
    pub fn show_help(help_object_id: &str, info_only: bool) {
        let lock = Self::get_help_service();
        if let Ok(guard) = lock.lock() {
            guard.show_help(help_object_id, info_only);
        }
    }

    /// Register help for an object.
    pub fn register_help(help_object_id: &str, location: HelpLocation) {
        let lock = Self::get_help_service();
        if let Ok(mut guard) = lock.lock() {
            guard.register_help(help_object_id, location);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_help_location_new() {
        let loc = HelpLocation::new("MyModule", "help/topics/MyPlugin/page.html");
        assert_eq!(loc.module_name, "MyModule");
        assert_eq!(loc.help_path, "help/topics/MyPlugin/page.html");
        assert!(loc.anchor_name.is_none());
    }

    #[test]
    fn test_help_location_with_anchor() {
        let loc = HelpLocation::with_anchor(
            "MyModule",
            "help/topics/MyPlugin/page.html",
            "section1",
        );
        assert_eq!(loc.anchor_name.as_deref(), Some("section1"));
    }

    #[test]
    fn test_help_location_display() {
        let loc = HelpLocation::with_anchor("Mod", "path/to/file.html", "anchor");
        assert_eq!(format!("{}", loc), "Mod/path/to/file.html#anchor");
    }

    #[test]
    fn test_default_help_service() {
        let mut svc = DefaultHelpService::new();
        assert!(!svc.help_exists());
        assert!(!svc.is_excluded_from_help("obj1"));

        svc.exclude_from_help("obj1");
        assert!(svc.is_excluded_from_help("obj1"));

        let loc = HelpLocation::new("Mod", "path");
        svc.register_help("obj2", loc.clone());
        assert_eq!(svc.get_help_location("obj2"), Some(&loc));

        svc.clear_help("obj2");
        assert!(svc.get_help_location("obj2").is_none());
    }

    #[test]
    fn test_help_singleton() {
        let lock = Help::get_help_service();
        let guard = lock.lock().unwrap();
        assert!(!guard.help_exists());
    }
}
