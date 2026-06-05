//! FlatDark built-in theme.
//!
//! Ported from `generic.theme.builtin.FlatDarkTheme`.

use crate::theme::discoverable_theme::DiscoverableGTheme;
use crate::theme::laf_type::LafType;

pub struct FlatDarkTheme;

impl DiscoverableGTheme for FlatDarkTheme {
    fn name(&self) -> &str { "Flat Dark" }
    fn laf_type(&self) -> LafType { LafType::FlatDark }
    fn use_dark_defaults(&self) -> bool { true }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flat_dark_properties() {
        let t = FlatDarkTheme;
        assert_eq!(t.name(), "Flat Dark");
        assert!(t.use_dark_defaults());
    }
}
