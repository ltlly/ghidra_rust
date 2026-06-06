//! Port of `WrappedFile`.
use std::collections::HashMap;
/// Struct porting `WrappedFile`.
#[derive(Debug, Clone)]
pub struct WrappedFile {
    _phantom: std::marker::PhantomData<()>,
}
impl WrappedFile {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WrappedFile {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wrapped_file_new() { let _ = WrappedFile::new(); }
}
