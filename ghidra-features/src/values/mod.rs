//! Ghidra-specific values map for typed parameter storage.
//!
//! Ported from `ghidra.features.base.values`.
//!
//! Extends the generic values map with Ghidra-specific types such as
//! [`Address`], [`LanguageSpec`], program files, project files, and project folders.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// GhidraValuesMap
// ---------------------------------------------------------------------------

/// Central registry of named typed values used in Ghidra dialogs and scripts.
///
/// Each value has a name, type, and optional default.  The map supports
/// reading values from a property/string map and writing them back.
#[derive(Debug, Default)]
pub struct GhidraValuesMap {
    /// Internal storage: name -> boxed value.
    values: HashMap<String, Box<dyn GhidraValue>>,
}

impl GhidraValuesMap {
    /// Create an empty values map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Define a string value.
    pub fn define_string(&mut self, name: &str, default: Option<&str>) {
        let v = StringValue {
            name: name.to_string(),
            value: default.map(|s| s.to_string()),
        };
        self.values.insert(name.to_string(), Box::new(v));
    }

    /// Define an address value (stored as u64 offset).
    pub fn define_address(&mut self, name: &str, default: Option<u64>) {
        let v = AddressValue {
            name: name.to_string(),
            value: default,
        };
        self.values.insert(name.to_string(), Box::new(v));
    }

    /// Define a language/compiler-spec pair value.
    pub fn define_language(&mut self, name: &str, default: Option<LanguageSpec>) {
        let v = LanguageValue {
            name: name.to_string(),
            value: default,
        };
        self.values.insert(name.to_string(), Box::new(v));
    }

    /// Define a project folder path value.
    pub fn define_project_folder(&mut self, name: &str, default_path: Option<&str>) {
        let v = ProjectFolderValue {
            name: name.to_string(),
            path: default_path.map(|s| s.to_string()),
        };
        self.values.insert(name.to_string(), Box::new(v));
    }

    /// Define a project file path value.
    pub fn define_project_file(&mut self, name: &str, default_path: Option<&str>) {
        let v = ProjectFileValue {
            name: name.to_string(),
            path: default_path.map(|s| s.to_string()),
        };
        self.values.insert(name.to_string(), Box::new(v));
    }

    /// Define a program file path value.
    pub fn define_program(&mut self, name: &str, start_path: Option<&str>) {
        let v = ProgramFileValue {
            name: name.to_string(),
            start_path: start_path.map(|s| s.to_string()),
            program_path: None,
        };
        self.values.insert(name.to_string(), Box::new(v));
    }

    /// Get a string value by name.
    pub fn get_string(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|v| v.as_any().downcast_ref::<StringValue>())
            .and_then(|v| v.value.as_deref())
    }

    /// Set a string value.
    pub fn set_string(&mut self, name: &str, value: &str) -> bool {
        if let Some(v) = self.values.get_mut(name) {
            if let Some(sv) = v.as_any_mut().downcast_mut::<StringValue>() {
                sv.value = Some(value.to_string());
                return true;
            }
        }
        false
    }

    /// Get an address value by name.
    pub fn get_address(&self, name: &str) -> Option<u64> {
        self.values
            .get(name)
            .and_then(|v| v.as_any().downcast_ref::<AddressValue>())
            .and_then(|v| v.value)
    }

    /// Set an address value.
    pub fn set_address(&mut self, name: &str, addr: u64) -> bool {
        if let Some(v) = self.values.get_mut(name) {
            if let Some(av) = v.as_any_mut().downcast_mut::<AddressValue>() {
                av.value = Some(addr);
                return true;
            }
        }
        false
    }

    /// Get a language value by name.
    pub fn get_language(&self, name: &str) -> Option<&LanguageSpec> {
        self.values
            .get(name)
            .and_then(|v| v.as_any().downcast_ref::<LanguageValue>())
            .and_then(|v| v.value.as_ref())
    }

    /// Get a project folder path by name.
    pub fn get_project_folder(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|v| v.as_any().downcast_ref::<ProjectFolderValue>())
            .and_then(|v| v.path.as_deref())
    }

    /// Get a project file path by name.
    pub fn get_project_file(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|v| v.as_any().downcast_ref::<ProjectFileValue>())
            .and_then(|v| v.path.as_deref())
    }

    /// Get a program file path by name.
    pub fn get_program(&self, name: &str) -> Option<&str> {
        self.values
            .get(name)
            .and_then(|v| v.as_any().downcast_ref::<ProgramFileValue>())
            .and_then(|v| v.program_path.as_deref())
    }

    /// Number of defined values.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Get the list of all value names.
    pub fn names(&self) -> Vec<&str> {
        self.values.keys().map(|s| s.as_str()).collect()
    }

    /// Populate values from a string map (name -> value).
    pub fn load_from_map(&mut self, map: &HashMap<String, String>) {
        for (k, v) in map {
            if let Some(val) = self.values.get_mut(k) {
                val.set_from_string(v);
            }
        }
    }

    /// Dump all values to a string map.
    pub fn save_to_map(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for (k, v) in &self.values {
            if let Some(s) = v.to_string_value() {
                map.insert(k.clone(), s);
            }
        }
        map
    }
}

// ---------------------------------------------------------------------------
// GhidraValue trait
// ---------------------------------------------------------------------------

use std::any::Any;

/// Trait for a named, typed value in a [`GhidraValuesMap`].
pub trait GhidraValue: std::fmt::Debug + Send + Sync {
    /// The name of this value.
    fn name(&self) -> &str;

    /// Convert to string for serialization.
    fn to_string_value(&self) -> Option<String>;

    /// Load from a string (for deserialization).
    fn set_from_string(&mut self, s: &str);

    /// Downcast support.
    fn as_any(&self) -> &dyn Any;

    /// Mutable downcast support.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

// ---------------------------------------------------------------------------
// Concrete value types
// ---------------------------------------------------------------------------

/// A string value.
#[derive(Debug, Clone)]
pub struct StringValue {
    name: String,
    value: Option<String>,
}

impl GhidraValue for StringValue {
    fn name(&self) -> &str {
        &self.name
    }
    fn to_string_value(&self) -> Option<String> {
        self.value.clone()
    }
    fn set_from_string(&mut self, s: &str) {
        self.value = Some(s.to_string());
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// An address value (stored as u64 offset).
#[derive(Debug, Clone)]
pub struct AddressValue {
    name: String,
    value: Option<u64>,
}

impl GhidraValue for AddressValue {
    fn name(&self) -> &str {
        &self.name
    }
    fn to_string_value(&self) -> Option<String> {
        self.value.map(|v| format!("0x{v:x}"))
    }
    fn set_from_string(&mut self, s: &str) {
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            self.value = u64::from_str_radix(hex, 16).ok();
        } else {
            self.value = s.parse::<u64>().ok();
        }
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// A language/compiler-spec pair for architecture selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageSpec {
    /// Language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// Compiler spec ID (e.g., "default", "gcc").
    pub compiler_spec_id: String,
}

impl fmt::Display for LanguageSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.language_id, self.compiler_spec_id)
    }
}

/// A language/compiler-spec value.
#[derive(Debug, Clone)]
pub struct LanguageValue {
    name: String,
    value: Option<LanguageSpec>,
}

impl GhidraValue for LanguageValue {
    fn name(&self) -> &str {
        &self.name
    }
    fn to_string_value(&self) -> Option<String> {
        self.value.as_ref().map(|v| v.to_string())
    }
    fn set_from_string(&mut self, s: &str) {
        if let Some((lang, comp)) = s.rsplit_once(':') {
            self.value = Some(LanguageSpec {
                language_id: lang.to_string(),
                compiler_spec_id: comp.to_string(),
            });
        }
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// A project folder path value.
#[derive(Debug, Clone)]
pub struct ProjectFolderValue {
    name: String,
    path: Option<String>,
}

impl GhidraValue for ProjectFolderValue {
    fn name(&self) -> &str {
        &self.name
    }
    fn to_string_value(&self) -> Option<String> {
        self.path.clone()
    }
    fn set_from_string(&mut self, s: &str) {
        self.path = Some(s.to_string());
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// A project file path value.
#[derive(Debug, Clone)]
pub struct ProjectFileValue {
    name: String,
    path: Option<String>,
}

impl GhidraValue for ProjectFileValue {
    fn name(&self) -> &str {
        &self.name
    }
    fn to_string_value(&self) -> Option<String> {
        self.path.clone()
    }
    fn set_from_string(&mut self, s: &str) {
        self.path = Some(s.to_string());
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// A program file value with optional starting path.
#[derive(Debug, Clone)]
pub struct ProgramFileValue {
    name: String,
    start_path: Option<String>,
    program_path: Option<String>,
}

impl GhidraValue for ProgramFileValue {
    fn name(&self) -> &str {
        &self.name
    }
    fn to_string_value(&self) -> Option<String> {
        self.program_path.clone()
    }
    fn set_from_string(&mut self, s: &str) {
        self.program_path = Some(s.to_string());
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_map() {
        let map = GhidraValuesMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_string_value() {
        let mut map = GhidraValuesMap::new();
        map.define_string("name", Some("default"));
        assert_eq!(map.get_string("name"), Some("default"));
        map.set_string("name", "changed");
        assert_eq!(map.get_string("name"), Some("changed"));
    }

    #[test]
    fn test_address_value() {
        let mut map = GhidraValuesMap::new();
        map.define_address("entry", Some(0x400000));
        assert_eq!(map.get_address("entry"), Some(0x400000));
        map.set_address("entry", 0x800000);
        assert_eq!(map.get_address("entry"), Some(0x800000));
    }

    #[test]
    fn test_address_value_from_string() {
        let mut map = GhidraValuesMap::new();
        map.define_address("addr", None);
        let mut map2 = HashMap::new();
        map2.insert("addr".to_string(), "0xdeadbeef".to_string());
        map.load_from_map(&map2);
        assert_eq!(map.get_address("addr"), Some(0xdeadbeef));
    }

    #[test]
    fn test_language_value() {
        let mut map = GhidraValuesMap::new();
        let spec = LanguageSpec {
            language_id: "x86:LE:64:default".into(),
            compiler_spec_id: "default".into(),
        };
        map.define_language("lang", Some(spec.clone()));
        let retrieved = map.get_language("lang").unwrap();
        assert_eq!(retrieved.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_project_folder() {
        let mut map = GhidraValuesMap::new();
        map.define_project_folder("folder", Some("/project/src"));
        assert_eq!(map.get_project_folder("folder"), Some("/project/src"));
    }

    #[test]
    fn test_project_file() {
        let mut map = GhidraValuesMap::new();
        map.define_project_file("file", Some("/project/file.gzf"));
        assert_eq!(map.get_project_file("file"), Some("/project/file.gzf"));
    }

    #[test]
    fn test_program_value() {
        let mut map = GhidraValuesMap::new();
        map.define_program("prog", Some("/home/user/bins"));
        assert_eq!(map.get_program("prog"), None); // not set yet
    }

    #[test]
    fn test_save_load_roundtrip() {
        let mut map = GhidraValuesMap::new();
        map.define_string("a", Some("alpha"));
        map.define_string("b", Some("beta"));

        let saved = map.save_to_map();
        assert_eq!(saved.len(), 2);

        let mut map2 = GhidraValuesMap::new();
        map2.define_string("a", None);
        map2.define_string("b", None);
        map2.load_from_map(&saved);
        assert_eq!(map2.get_string("a"), Some("alpha"));
        assert_eq!(map2.get_string("b"), Some("beta"));
    }

    #[test]
    fn test_names() {
        let mut map = GhidraValuesMap::new();
        map.define_string("x", None);
        map.define_string("y", None);
        let names = map.names();
        assert!(names.contains(&"x"));
        assert!(names.contains(&"y"));
    }

    #[test]
    fn test_language_spec_display() {
        let spec = LanguageSpec {
            language_id: "ARM:LE:32:v8".into(),
            compiler_spec_id: "gcc".into(),
        };
        assert_eq!(spec.to_string(), "ARM:LE:32:v8:gcc");
    }
}
