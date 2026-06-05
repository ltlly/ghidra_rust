//! DiscoverableGTheme: abstract base for built-in themes.
//!
//! Ported from `generic.theme.DiscoverableGTheme`.

use super::g_theme::GTheme;
use super::laf_type::LafType;

/// Prefix used in theme locators for discoverable themes.
pub const CLASS_PREFIX: &str = "Class:";

/// Trait for built-in themes that are discoverable at application startup.
pub trait DiscoverableGTheme {
    fn name(&self) -> &str;
    fn laf_type(&self) -> LafType;
    fn use_dark_defaults(&self) -> bool;
    fn theme_locater(&self) -> String {
        format!("{}{}", CLASS_PREFIX, std::any::type_name::<Self>())
    }
    fn is_read_only(&self) -> bool { true }
    fn to_g_theme(&self) -> GTheme {
        GTheme::with_laf(self.name(), self.laf_type())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTheme;
    impl DiscoverableGTheme for TestTheme {
        fn name(&self) -> &str { "Test Theme" }
        fn laf_type(&self) -> LafType { LafType::FlatLight }
        fn use_dark_defaults(&self) -> bool { false }
    }

    #[test]
    fn discoverable_theme_locater() {
        let t = TestTheme;
        assert!(t.theme_locater().starts_with(CLASS_PREFIX));
        assert!(t.is_read_only());
    }

    #[test]
    fn discoverable_to_g_theme() {
        let t = TestTheme;
        let gt = t.to_g_theme();
        assert_eq!(gt.name(), "Test Theme");
        assert_eq!(gt.look_and_feel(), LafType::FlatLight);
    }
}
