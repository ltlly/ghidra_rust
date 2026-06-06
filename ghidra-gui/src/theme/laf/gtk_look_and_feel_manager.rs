//! Port of `GtkLookAndFeelManager`.
use std::collections::HashMap;
/// Struct porting `GtkLookAndFeelManager`.
#[derive(Debug, Clone)]
pub struct GtkLookAndFeelManager {
    _phantom: std::marker::PhantomData<()>,
}
impl GtkLookAndFeelManager {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for GtkLookAndFeelManager {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_gtk_look_and_feel_manager_new() { let _ = GtkLookAndFeelManager::new(); }
}
