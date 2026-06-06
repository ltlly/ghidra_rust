//! Port of `HTMLUtilities`.
use std::collections::HashMap;
/// Struct porting `HTMLUtilities`.
#[derive(Debug, Clone)]
pub struct HTMLUtilities {
    /// html.
    pub html: String,
    /// html_close.
    pub html_close: String,
    /// br.
    pub br: String,
    /// pre.
    pub pre: String,
    /// pre_close.
    pub pre_close: String,
    /// link_placeholder_open.
    pub link_placeholder_open: String,
}

impl HTMLUtilities {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for HTMLUtilities {
    fn default() -> Self {
        Self {
            html: String::new(),
            html_close: String::new(),
            br: String::new(),
            pre: String::new(),
            pre_close: String::new(),
            link_placeholder_open: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_html_utilities_new() { let _ = HTMLUtilities::new(); }
}
