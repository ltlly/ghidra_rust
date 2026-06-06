//! Port of `DefaultGraphDisplayOptions`.
use std::collections::HashMap;
/// Struct porting `DefaultGraphDisplayOptions`.
#[derive(Debug, Clone)]
pub struct DefaultGraphDisplayOptions {
    _phantom: std::marker::PhantomData<()>,
}
impl DefaultGraphDisplayOptions {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DefaultGraphDisplayOptions {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_graph_display_options_new() { let _ = DefaultGraphDisplayOptions::new(); }
}
