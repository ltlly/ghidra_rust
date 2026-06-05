//! FlatLight built-in theme.
//!
//! Ported from `generic.theme.builtin.FlatLightTheme`.

use crate::theme::discoverable_theme::DiscoverableGTheme;
use crate::theme::laf_type::LafType;

pub struct FlatLightTheme;

impl DiscoverableGTheme for FlatLightTheme {
    fn name(&self) -> &str { "Flat Light" }
    fn laf_type(&self) -> LafType { LafType::FlatLight }
    fn use_dark_defaults(&self) -> bool { false }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_light_properties() {
        let t = FlatLightTheme;
        assert_eq!(t.name(), "Flat Light");
        assert_eq!(t.laf_type(), LafType::FlatLight);
        assert!(!t.use_dark_defaults());
        assert!(t.is_read_only());
    }
}
