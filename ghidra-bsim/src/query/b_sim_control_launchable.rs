//! Port of `BSimControlLaunchable`.
use std::collections::HashMap;
/// Struct porting `BSimControlLaunchable`.
#[derive(Debug, Clone)]
pub struct BSimControlLaunchable {
    /// cafile_option.
    pub cafile_option: String,
    /// auth_option.
    pub auth_option: String,
    /// dn_option.
    pub dn_option: String,
    /// port_option.
    pub port_option: String,
    /// user_option.
    pub user_option: String,
    /// cert_option.
    pub cert_option: String,
}

impl BSimControlLaunchable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for BSimControlLaunchable {
    fn default() -> Self {
        Self {
            cafile_option: String::new(),
            auth_option: String::new(),
            dn_option: String::new(),
            port_option: String::new(),
            user_option: String::new(),
            cert_option: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_control_launchable_new() { let _ = BSimControlLaunchable::new(); }
}
