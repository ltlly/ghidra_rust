//! Port of `VgSatelliteFeaturette`.
use std::collections::HashMap;
/// Struct porting `VgSatelliteFeaturette`.
#[derive(Debug, Clone)]
pub struct VgSatelliteFeaturette {
    _phantom: std::marker::PhantomData<()>,
}
impl VgSatelliteFeaturette {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VgSatelliteFeaturette {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vg_satellite_featurette_new() { let _ = VgSatelliteFeaturette::new(); }
}
