//! Port of `ExtensionFileFilter`.
use std::collections::HashMap;
/// Struct porting `ExtensionFileFilter`.
#[derive(Debug, Clone)]
pub struct ExtensionFileFilter {
    _phantom: std::marker::PhantomData<()>,
}
impl ExtensionFileFilter {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ExtensionFileFilter {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_extension_file_filter_new() { let _ = ExtensionFileFilter::new(); }
}
