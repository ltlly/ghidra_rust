//! The `HelpService` trait -- display help content by object, URL, or location.
//!
//! Ported from `help.HelpService`.

use crate::help_location::{DynamicHelpLocation, HelpLocation};

/// A dummy help-set file name used as a sentinel.
pub const DUMMY_HELP_SET_NAME: &str = "Dummy_HelpSet.hs";

/// Display Help content identified by an object, URL, or [`HelpLocation`].
///
/// Implementors provide the actual rendering mechanism (browser, embedded
/// viewer, etc.). [`DefaultHelpService`](crate::DefaultHelpService) is a
/// no-op fallback.
pub trait HelpService {
    /// Display the help content registered for `help_object`.
    ///
    /// If `info_only` is true, show diagnostic information about the help
    /// registration rather than the help UI itself.
    fn show_help_object(&self, help_object: &dyn HelpDescriptorObj, info_only: bool);

    /// Display the help page at the given URL.
    fn show_help_url(&self, url: &str);

    /// Display the help page at the given [`HelpLocation`].
    fn show_help_location(&self, location: &HelpLocation);

    /// Exclude `help_object` from help validation and registration.
    fn exclude_from_help(&mut self, help_object: &dyn HelpDescriptorObj);

    /// Returns `true` if `help_object` has been excluded.
    fn is_excluded_from_help(&self, help_object: &dyn HelpDescriptorObj) -> bool;

    /// Register a [`HelpLocation`] for `help_object`.
    fn register_help(&mut self, help_object: &dyn HelpDescriptorObj, location: HelpLocation);

    /// Register a dynamic help provider for `help_object`.
    fn register_dynamic_help(
        &mut self,
        help_object: &dyn HelpDescriptorObj,
        location: DynamicHelpLocation,
    );

    /// Remove the help registration for `help_object`.
    fn clear_help(&mut self, help_object: &dyn HelpDescriptorObj);

    /// Returns the registered [`HelpLocation`] for `object`, or `None`.
    fn get_help_location(&self, object: &dyn HelpDescriptorObj) -> Option<&HelpLocation>;

    /// Returns `true` if help content exists and the system has finished
    /// initializing.
    fn help_exists(&self) -> bool;

    /// Reload help content (e.g., after a theme change).
    fn reload(&mut self);
}

/// Object-safe helper: anything that can serve as a help object key.
///
/// In Java this was simply `Object`; in Rust we use a trait with an
/// identifier to allow `HashMap`-based registration.
pub trait HelpDescriptorObj {
    /// A stable identifier for this help object (e.g., its type name + name).
    fn help_object_id(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub;
    impl HelpDescriptorObj for Stub {
        fn help_object_id(&self) -> String {
            "stub".into()
        }
    }

    #[test]
    fn test_dummy_help_set_name() {
        assert_eq!(DUMMY_HELP_SET_NAME, "Dummy_HelpSet.hs");
    }

    #[test]
    fn test_help_descriptor_obj_id() {
        let s = Stub;
        assert_eq!(s.help_object_id(), "stub");
    }
}
