//! Port of `BSimSearchDialog`.
use std::collections::HashMap;
/// Struct porting `BSimSearchDialog`.
#[derive(Debug, Clone)]
pub struct BSimSearchDialog {
    /// selected_functions.
    pub selected_functions: String,
}

impl BSimSearchDialog {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for BSimSearchDialog {
    fn default() -> Self {
        Self {
            selected_functions: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_search_dialog_new() { let _ = BSimSearchDialog::new(); }
}
