//! Port of `Configuration`.
use std::collections::HashMap;
/// Struct porting `Configuration`.
#[derive(Debug, Clone)]
pub struct Configuration {
    /// info.
    pub info: String,
    /// k.
    pub k: i32,
    /// l.
    pub l: i32,
    /// weightfactory.
    pub weightfactory: String,
    /// idflookup.
    pub idflookup: String,
}

impl Configuration {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            info: String::new(),
            k: 0,
            l: 0,
            weightfactory: String::new(),
            idflookup: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_configuration_new() { let _ = Configuration::new(); }
}
