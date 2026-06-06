//! Port of `ResponseName`.
use std::collections::HashMap;
/// Struct porting `ResponseName`.
#[derive(Debug, Clone)]
pub struct ResponseName {
    /// manage.
    pub manage: String,
    /// uniqueexecutable.
    pub uniqueexecutable: bool,
    /// printselfsig.
    pub printselfsig: bool,
    /// printjustexe.
    pub printjustexe: bool,
}

impl ResponseName {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResponseName {
    fn default() -> Self {
        Self {
            manage: String::new(),
            uniqueexecutable: false,
            printselfsig: false,
            printjustexe: false,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_response_name_new() { let _ = ResponseName::new(); }
}
