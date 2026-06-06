//! Port of `TranslateIcon`.
use std::collections::HashMap;
/// Struct porting `TranslateIcon`.
#[derive(Debug, Clone)]
pub struct TranslateIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl TranslateIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for TranslateIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_translate_icon_new() { let _ = TranslateIcon::new(); }
}
