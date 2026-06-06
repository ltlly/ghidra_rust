//! Port of `HeadlessBSimApplicationConfiguration`.
use std::collections::HashMap;
/// Struct porting `HeadlessBSimApplicationConfiguration`.
#[derive(Debug, Clone)]
pub struct HeadlessBSimApplicationConfiguration {
    _phantom: std::marker::PhantomData<()>,
}
impl HeadlessBSimApplicationConfiguration {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for HeadlessBSimApplicationConfiguration {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_headless_b_sim_application_configuration_new() { let _ = HeadlessBSimApplicationConfiguration::new(); }
}
