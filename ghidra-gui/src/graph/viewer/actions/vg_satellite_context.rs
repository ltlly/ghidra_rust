//! Port of `VgSatelliteContext`.
use std::collections::HashMap;
/// Struct porting `VgSatelliteContext`.
#[derive(Debug, Clone)]
pub struct VgSatelliteContext {
    _phantom: std::marker::PhantomData<()>,
}
impl VgSatelliteContext {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VgSatelliteContext {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vg_satellite_context_new() { let _ = VgSatelliteContext::new(); }
}
