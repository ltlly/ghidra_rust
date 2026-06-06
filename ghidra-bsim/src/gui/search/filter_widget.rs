//! Port of `FilterWidget`.
use std::collections::HashMap;
/// Struct porting `FilterWidget`.
#[derive(Debug, Clone)]
pub struct FilterWidget {
    _phantom: std::marker::PhantomData<()>,
}
impl FilterWidget {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FilterWidget {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_filter_widget_new() { let _ = FilterWidget::new(); }
}
