//! `DefaultHelpService` -- no-op fallback when no help content is available.
//!
//! Ported from `docking.DefaultHelpService`.

use std::collections::{HashMap, HashSet};

use crate::help_location::{DynamicHelpLocation, HelpLocation};
use crate::help_service::{HelpDescriptorObj, HelpService};

/// A no-op implementation of [`HelpService`].
///
/// All display methods are no-ops, and `help_exists()` returns `false`.
/// This is installed by default and replaced once help content is loaded.
#[derive(Debug)]
pub struct DefaultHelpService {
    /// Registered help locations, keyed by object id.
    registrations: HashMap<String, HelpLocation>,
    /// Excluded object ids.
    excluded: HashSet<String>,
}

impl DefaultHelpService {
    /// Create a new default help service.
    pub fn new() -> Self {
        Self {
            registrations: HashMap::new(),
            excluded: HashSet::new(),
        }
    }

    /// Returns diagnostic info for the given help object id.
    pub fn get_help_info(&self, object_id: &str) -> String {
        if self.excluded.contains(object_id) {
            return format!("Object '{}' is excluded from help", object_id);
        }
        match self.registrations.get(object_id) {
            Some(loc) => format!("Help registered at: {}", loc),
            None => format!("No help registered for '{}'", object_id),
        }
    }
}

impl Default for DefaultHelpService {
    fn default() -> Self {
        Self::new()
    }
}

impl HelpService for DefaultHelpService {
    fn show_help_object(&self, _help_object: &dyn HelpDescriptorObj, _info_only: bool) {
        // no-op
    }

    fn show_help_url(&self, _url: &str) {
        // no-op
    }

    fn show_help_location(&self, _location: &HelpLocation) {
        // no-op
    }

    fn exclude_from_help(&mut self, help_object: &dyn HelpDescriptorObj) {
        self.excluded.insert(help_object.help_object_id());
    }

    fn is_excluded_from_help(&self, help_object: &dyn HelpDescriptorObj) -> bool {
        self.excluded.contains(&help_object.help_object_id())
    }

    fn register_help(&mut self, help_object: &dyn HelpDescriptorObj, location: HelpLocation) {
        self.registrations.insert(help_object.help_object_id(), location);
    }

    fn register_dynamic_help(
        &mut self,
        _help_object: &dyn HelpDescriptorObj,
        _location: DynamicHelpLocation,
    ) {
        // no-op in default service; a real service would store the closure
    }

    fn clear_help(&mut self, help_object: &dyn HelpDescriptorObj) {
        self.registrations.remove(&help_object.help_object_id());
    }

    fn get_help_location(&self, object: &dyn HelpDescriptorObj) -> Option<&HelpLocation> {
        self.registrations.get(&object.help_object_id())
    }

    fn help_exists(&self) -> bool {
        false
    }

    fn reload(&mut self) {
        // no-op
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestObj(String);
    impl HelpDescriptorObj for TestObj {
        fn help_object_id(&self) -> String {
            self.0.clone()
        }
    }

    #[test]
    fn test_default_service_no_help() {
        let svc = DefaultHelpService::new();
        assert!(!svc.help_exists());
    }

    #[test]
    fn test_register_and_get() {
        let mut svc = DefaultHelpService::new();
        let obj = TestObj("button_ok".into());
        let loc = HelpLocation::new("Core", "buttons.html");
        svc.register_help(&obj, loc.clone());
        assert_eq!(svc.get_help_location(&obj), Some(&loc));
    }

    #[test]
    fn test_clear_help() {
        let mut svc = DefaultHelpService::new();
        let obj = TestObj("widget".into());
        svc.register_help(&obj, HelpLocation::new("M", "t.html"));
        svc.clear_help(&obj);
        assert!(svc.get_help_location(&obj).is_none());
    }

    #[test]
    fn test_exclude_from_help() {
        let mut svc = DefaultHelpService::new();
        let obj = TestObj("hidden".into());
        svc.exclude_from_help(&obj);
        assert!(svc.is_excluded_from_help(&obj));
    }

    #[test]
    fn test_not_excluded() {
        let svc = DefaultHelpService::new();
        let obj = TestObj("visible".into());
        assert!(!svc.is_excluded_from_help(&obj));
    }

    #[test]
    fn test_get_help_info_excluded() {
        let mut svc = DefaultHelpService::new();
        let obj = TestObj("x".into());
        svc.exclude_from_help(&obj);
        assert!(svc.get_help_info("x").contains("excluded"));
    }

    #[test]
    fn test_get_help_info_registered() {
        let mut svc = DefaultHelpService::new();
        let obj = TestObj("y".into());
        svc.register_help(&obj, HelpLocation::new("Mod", "t.html"));
        assert!(svc.get_help_info("y").contains("Mod/t.html"));
    }

    #[test]
    fn test_get_help_info_none() {
        let svc = DefaultHelpService::new();
        assert!(svc.get_help_info("unknown").contains("No help"));
    }
}
