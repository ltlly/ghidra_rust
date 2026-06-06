//! Port of `IterateRepository`.
use std::collections::HashMap;
/// Struct porting `IterateRepository`.
#[derive(Debug, Clone)]
pub struct IterateRepository {
    _phantom: std::marker::PhantomData<()>,
}
impl IterateRepository {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for IterateRepository {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_iterate_repository_new() { let _ = IterateRepository::new(); }
}
