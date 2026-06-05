//! Reachability table model.
//!
//! Ported from Ghidra's reachability analysis classes.

use serde::{Deserialize, Serialize};

/// A reachable function entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReachableFunction {
    /// Function name.
    pub name: String,
    /// Function address.
    pub address: String,
    /// Call depth from the starting function.
    pub depth: usize,
    /// Whether the function is in a library.
    pub is_library: bool,
    /// Number of times this function is reachable through different paths.
    pub path_count: usize,
}

impl ReachableFunction {
    pub fn new(name: &str, address: &str, depth: usize) -> Self {
        Self { name: name.to_string(), address: address.to_string(), depth, is_library: false, path_count: 1 }
    }
}

/// Reachability analysis result model.
#[derive(Debug, Default)]
pub struct ReachabilityModel {
    functions: Vec<ReachableFunction>,
    start_address: Option<String>,
}

impl ReachabilityModel {
    pub fn new() -> Self { Self::default() }
    pub fn set_start(&mut self, address: &str) {
        self.start_address = Some(address.to_string());
    }
    pub fn add_reachable(&mut self, func: ReachableFunction) {
        self.functions.push(func);
    }
    pub fn functions(&self) -> &[ReachableFunction] { &self.functions }
    pub fn len(&self) -> usize { self.functions.len() }
    pub fn is_empty(&self) -> bool { self.functions.is_empty() }
    pub fn start_address(&self) -> Option<&str> { self.start_address.as_deref() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reachable_function() {
        let f = ReachableFunction::new("foo", "0x402000", 1);
        assert_eq!(f.name, "foo");
        assert_eq!(f.depth, 1);
    }

    #[test]
    fn test_reachability_model() {
        let mut model = ReachabilityModel::new();
        model.set_start("0x401000");
        model.add_reachable(ReachableFunction::new("main", "0x401000", 0));
        model.add_reachable(ReachableFunction::new("foo", "0x402000", 1));
        model.add_reachable(ReachableFunction::new("bar", "0x403000", 2));
        assert_eq!(model.len(), 3);
        assert_eq!(model.start_address(), Some("0x401000"));
    }
}
