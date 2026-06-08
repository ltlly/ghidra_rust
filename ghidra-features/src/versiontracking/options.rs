//! Options for version tracking correlators.

use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone)]
pub struct VtOptions {
    name: String,
    int_options: HashMap<String, i64>,
    bool_options: HashMap<String, bool>,
    string_options: HashMap<String, String>,
    double_options: HashMap<String, f64>,
    descriptions: HashMap<String, String>,
}

impl VtOptions {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), int_options: HashMap::new(), bool_options: HashMap::new(),
            string_options: HashMap::new(), double_options: HashMap::new(), descriptions: HashMap::new() }
    }
    pub fn name(&self) -> &str { &self.name }
    pub fn set_int(&mut self, key: impl Into<String>, value: i64) { self.int_options.insert(key.into(), value); }
    pub fn get_int(&self, key: &str, default: i64) -> i64 { self.int_options.get(key).copied().unwrap_or(default) }
    pub fn set_bool(&mut self, key: impl Into<String>, value: bool) { self.bool_options.insert(key.into(), value); }
    pub fn get_bool(&self, key: &str, default: bool) -> bool { self.bool_options.get(key).copied().unwrap_or(default) }
    pub fn set_string(&mut self, key: impl Into<String>, value: impl Into<String>) { self.string_options.insert(key.into(), value.into()); }
    pub fn get_string<'a>(&'a self, key: &str, default: &'a str) -> &'a str { self.string_options.get(key).map(|s| s.as_str()).unwrap_or(default) }
    pub fn set_double(&mut self, key: impl Into<String>, value: f64) { self.double_options.insert(key.into(), value); }
    pub fn get_double(&self, key: &str, default: f64) -> f64 { self.double_options.get(key).copied().unwrap_or(default) }
    pub fn register_option(&mut self, key: impl Into<String>, description: impl Into<String>) { self.descriptions.insert(key.into(), description.into()); }
    pub fn description<'a>(&'a self, key: &'a str) -> &'a str { self.descriptions.get(key).map(|s| s.as_str()).unwrap_or(key) }
    pub fn validate(&self) -> bool { true }
    pub fn copy(&self) -> Self { self.clone() }
}

impl fmt::Display for VtOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VtOptions({})", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vt_options_int() {
        let mut opts = VtOptions::new("Test");
        opts.set_int("min_size", 10);
        assert_eq!(opts.get_int("min_size", 0), 10);
        assert_eq!(opts.get_int("missing", 42), 42);
    }

    #[test]
    fn test_vt_options_copy() {
        let mut opts = VtOptions::new("Test");
        opts.set_int("x", 42);
        let copy = opts.copy();
        assert_eq!(copy.get_int("x", 0), 42);
    }
}
