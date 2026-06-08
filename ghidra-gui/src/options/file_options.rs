//! File-backed options persistence.
//!
//! Ports `ghidra.framework.options.FileOptions` which reads/writes options
//! to a JSON file.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::option::OptionEntry;
use super::option_value::OptionValue;

/// Options that are persisted to/from a JSON file.
///
/// Ported from Ghidra's `ghidra.framework.options.FileOptions`.
#[derive(Debug)]
pub struct FileOptions {
    /// Display name (derived from file name).
    name: String,
    /// The backing file path.
    file: Option<PathBuf>,
    /// Stored options.
    options: HashMap<String, OptionEntry>,
}

impl FileOptions {
    /// Create a new empty file options store (not yet associated with a file).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            file: None,
            options: HashMap::new(),
        }
    }

    /// Load options from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("options")
            .to_string();

        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read options file: {}", path.display()))?;

        let map: HashMap<String, serde_json::Value> = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse options file: {}", path.display()))?;

        let mut options = HashMap::new();
        for (key, value) in map {
            let opt_value = json_to_option_value(&value);
            let option_type = opt_value.option_type();
            let opt = OptionEntry::new_unregistered(&key, option_type, opt_value);
            options.insert(key, opt);
        }

        Ok(Self { name, file: Some(path.to_path_buf()), options })
    }

    /// Save options to the associated file (or a new file).
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("options")
            .to_string();
        self.file = Some(path.to_path_buf());
        self.save_to_file()
    }

    /// Save to the currently associated file.
    pub fn save_to_file(&self) -> Result<()> {
        let path = self.file.as_ref().context("No file associated")?;
        let mut map = serde_json::Map::new();
        for (key, opt) in &self.options {
            map.insert(key.clone(), option_value_to_json(opt.current_value()));
        }
        let json = serde_json::to_string_pretty(&map)?;
        fs::write(path, json)
            .with_context(|| format!("Failed to write options file: {}", path.display()))?;
        Ok(())
    }

    /// Get the file path.
    pub fn file(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    /// Get the name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get a reference to the stored options.
    pub fn options(&self) -> &HashMap<String, OptionEntry> {
        &self.options
    }

    /// Get a mutable reference to the stored options.
    pub fn options_mut(&mut self) -> &mut HashMap<String, OptionEntry> {
        &mut self.options
    }

    /// Put an option value.
    pub fn put(&mut self, key: &str, value: OptionValue) {
        let mut opt = OptionEntry::new_unregistered(key, value.option_type(), OptionValue::None);
        opt.set_current_value(value);
        self.options.insert(key.to_string(), opt);
    }

    /// Get an option value.
    pub fn get(&self, key: &str) -> Option<&OptionValue> {
        self.options.get(key).map(|o| o.current_value())
    }

    /// Copy all options into a new FileOptions.
    pub fn copy(&self) -> Self {
        let mut copy = FileOptions::new("copy");
        for (key, opt) in &self.options {
            copy.put(key, opt.current_value().clone());
        }
        copy
    }
}

fn json_to_option_value(value: &serde_json::Value) -> OptionValue {
    match value {
        serde_json::Value::Null => OptionValue::None,
        serde_json::Value::Bool(b) => OptionValue::Boolean(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                if i >= i32::MIN as i64 && i <= i32::MAX as i64 {
                    OptionValue::Int(i as i32)
                } else {
                    OptionValue::Long(i)
                }
            } else if let Some(f) = n.as_f64() {
                OptionValue::Double(f)
            } else {
                OptionValue::None
            }
        }
        serde_json::Value::String(s) => OptionValue::String(s.clone()),
        serde_json::Value::Array(arr) => {
            let bytes: Vec<u8> = arr
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect();
            OptionValue::ByteArray(bytes)
        }
        serde_json::Value::Object(obj) => {
            // Could be a custom option or a wrapped value
            if let Some(serde_json::Value::String(s)) = obj.get("type") {
                OptionValue::Custom(format!("{}:{}", s, serde_json::to_string(obj).unwrap_or_default()))
            } else {
                OptionValue::Custom(serde_json::to_string(obj).unwrap_or_default())
            }
        }
    }
}

fn option_value_to_json(value: &OptionValue) -> serde_json::Value {
    match value {
        OptionValue::None => serde_json::Value::Null,
        OptionValue::Boolean(b) => serde_json::Value::Bool(*b),
        OptionValue::Int(i) => serde_json::json!(*i),
        OptionValue::Long(l) => serde_json::json!(*l),
        OptionValue::Float(f) => serde_json::json!(*f as f64),
        OptionValue::Double(d) => serde_json::json!(*d),
        OptionValue::String(s) => serde_json::Value::String(s.clone()),
        OptionValue::ByteArray(bytes) => {
            serde_json::Value::Array(bytes.iter().map(|b| serde_json::json!(*b)).collect())
        }
        OptionValue::File(p) => serde_json::Value::String(p.display().to_string()),
        OptionValue::Color(c) => serde_json::Value::String(c.to_hex_string()),
        OptionValue::Font(f) => serde_json::Value::String(f.to_string()),
        OptionValue::KeyStroke(k) => serde_json::Value::String(k.to_string()),
        OptionValue::Date(d) => serde_json::Value::String(d.clone()),
        OptionValue::Custom(c) => serde_json::Value::String(c.clone()),
        OptionValue::Enum(e) => serde_json::Value::String(e.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_options_new() {
        let fo = FileOptions::new("test");
        assert_eq!(fo.name(), "test");
        assert!(fo.file().is_none());
    }

    #[test]
    fn test_file_options_put_get() {
        let mut fo = FileOptions::new("test");
        fo.put("key", OptionValue::Int(42));
        assert_eq!(fo.get("key"), Some(&OptionValue::Int(42)));
    }

    #[test]
    fn test_file_options_copy() {
        let mut fo = FileOptions::new("original");
        fo.put("a", OptionValue::Int(1));
        fo.put("b", OptionValue::String("hello".into()));
        let copy = fo.copy();
        assert_eq!(copy.get("a"), Some(&OptionValue::Int(1)));
        assert_eq!(copy.get("b"), Some(&OptionValue::String("hello".into())));
    }

    #[test]
    fn test_json_roundtrip() {
        let original = OptionValue::Int(42);
        let json = option_value_to_json(&original);
        let restored = json_to_option_value(&json);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_json_string_roundtrip() {
        let original = OptionValue::String("hello world".into());
        let json = option_value_to_json(&original);
        let restored = json_to_option_value(&json);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_json_bool_roundtrip() {
        let original = OptionValue::Boolean(true);
        let json = option_value_to_json(&original);
        let restored = json_to_option_value(&json);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_json_byte_array_roundtrip() {
        let original = OptionValue::ByteArray(vec![1, 2, 3, 255]);
        let json = option_value_to_json(&original);
        let restored = json_to_option_value(&json);
        assert_eq!(original, restored);
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("ghidra_gui_test_file_options");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("test_options.json");

        let mut fo = FileOptions::new("test");
        fo.put("count", OptionValue::Int(42));
        fo.put("name", OptionValue::String("test".into()));
        fo.put("flag", OptionValue::Boolean(true));
        fo.save(&path).unwrap();

        let loaded = FileOptions::load(&path).unwrap();
        assert_eq!(loaded.get("count"), Some(&OptionValue::Int(42)));
        assert_eq!(loaded.get("name"), Some(&OptionValue::String("test".into())));
        assert_eq!(loaded.get("flag"), Some(&OptionValue::Boolean(true)));

        let _ = fs::remove_file(&path);
    }
}
