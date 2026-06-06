//! Port of `CustomNimbusLookAndFeel`.
use std::collections::HashMap;
/// Struct porting `CustomNimbusLookAndFeel`.
#[derive(Debug, Clone)]
pub struct CustomNimbusLookAndFeel {
    _phantom: std::marker::PhantomData<()>,
}
impl CustomNimbusLookAndFeel {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CustomNimbusLookAndFeel {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_custom_nimbus_look_and_feel_new() { let _ = CustomNimbusLookAndFeel::new(); }
}
