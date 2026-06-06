//! Port of `ResponsePair`.
use std::collections::HashMap;
/// Struct porting `ResponsePair`.
#[derive(Debug, Clone)]
pub struct ResponsePair {
    /// average_sim.
    pub average_sim: f64,
    /// sim_std_dev.
    pub sim_std_dev: f64,
    /// average_sig.
    pub average_sig: f64,
    /// sig_std_dev.
    pub sig_std_dev: f64,
    /// scale.
    pub scale: f64,
    /// pair_count.
    pub pair_count: i32,
}

impl ResponsePair {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponsePair {
    fn default() -> Self {
        Self {
            average_sim: 0,
            sim_std_dev: 0,
            average_sig: 0,
            sig_std_dev: 0,
            scale: 0,
            pair_count: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_pair_new() { let _ = ResponsePair::new(); }
}
