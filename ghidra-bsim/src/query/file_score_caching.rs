//! Port of `FileScoreCaching`.
use std::collections::HashMap;
/// Struct porting `FileScoreCaching`.
#[derive(Debug, Clone)]
pub struct FileScoreCaching {
    _phantom: std::marker::PhantomData<()>,
}
impl FileScoreCaching {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FileScoreCaching {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_file_score_caching_new() { let _ = FileScoreCaching::new(); }
}
