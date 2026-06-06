//! Port of `TarjanStronglyConnectedAlgorthm`.
use std::collections::HashMap;
/// Struct porting `TarjanStronglyConnectedAlgorthm`.
#[derive(Debug, Clone)]
pub struct TarjanStronglyConnectedAlgorthm {
    /// index.
    pub index: i32,
    /// low_link.
    pub low_link: i32,
}

impl TarjanStronglyConnectedAlgorthm {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for TarjanStronglyConnectedAlgorthm {
    fn default() -> Self {
        Self {
            index: 0,
            low_link: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_tarjan_strongly_connected_algorthm_new() { let _ = TarjanStronglyConnectedAlgorthm::new(); }
}
