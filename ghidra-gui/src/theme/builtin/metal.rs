//! Metal built-in theme.
//!
//! Ported from `generic.theme.builtin.MetalTheme`.

use crate::theme::discoverable_theme::DiscoverableGTheme;
use crate::theme::laf_type::LafType;

pub struct MetalTheme;

impl DiscoverableGTheme for MetalTheme {
    fn name(&self) -> &str { "Metal" }
    fn laf_type(&self) -> LafType { LafType::Metal }
    fn use_dark_defaults(&self) -> bool { false }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metal_properties() {
        let t = MetalTheme;
        assert_eq!(t.name(), "Metal");
        assert_eq!(t.laf_type(), LafType::Metal);
    }
}
