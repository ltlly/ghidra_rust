//! Additional wrapped option types for the framework options system.
//!
//! Ports Ghidra's `ghidra.framework.options.WrappedActionTrigger`,
//! `WrappedCustomOption`, `WrappedDate`, `WrappedFile`, `WrappedKeyStroke`.

use std::path::PathBuf;

use super::action_trigger::ActionTrigger;
use super::option_type::OptionType;
use super::option_value::OptionValue;
use super::wrapped_option::WrappedOption;

// ============================================================================
// WrappedActionTrigger
// ============================================================================

/// Wrapper for an [`ActionTrigger`] that can be persisted as an option value.
///
/// Ported from `ghidra.framework.options.WrappedActionTrigger`.
#[derive(Debug, Clone)]
pub struct WrappedActionTrigger {
    trigger: ActionTrigger,
}

impl WrappedActionTrigger {
    /// Create a new wrapper around the given action trigger.
    pub fn new(trigger: ActionTrigger) -> Self {
        Self { trigger }
    }

    /// Get a reference to the inner action trigger.
    pub fn trigger(&self) -> &ActionTrigger {
        &self.trigger
    }

    /// Consume the wrapper and return the inner action trigger.
    pub fn into_trigger(self) -> ActionTrigger {
        self.trigger
    }
}

impl WrappedOption for WrappedActionTrigger {
    fn get_object(&self) -> OptionValue {
        // Serialize the action trigger to a string representation.
        let repr = format!("{}", self.trigger);
        OptionValue::String(repr)
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        for (key, val) in state {
            if key == "trigger" {
                if let OptionValue::String(s) = val {
                    if let Some(trigger) = ActionTrigger::parse(s) {
                        self.trigger = trigger;
                    }
                }
            }
        }
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        vec![(
            "trigger".to_string(),
            OptionValue::String(format!("{}", self.trigger)),
        )]
    }

    fn option_type(&self) -> OptionType {
        OptionType::ActionTrigger
    }
}

impl std::fmt::Display for WrappedActionTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrappedActionTrigger: {}", self.trigger)
    }
}

// ============================================================================
// WrappedDate
// ============================================================================

/// Wrapper for a date/time value that can be persisted as an option value.
///
/// Ported from `ghidra.framework.options.WrappedDate`.
#[derive(Debug, Clone)]
pub struct WrappedDate {
    /// The stored timestamp as milliseconds since the Unix epoch.
    timestamp_ms: i64,
}

impl WrappedDate {
    /// Create a new wrapped date from a timestamp in milliseconds.
    pub fn new(timestamp_ms: i64) -> Self {
        Self { timestamp_ms }
    }

    /// Create a wrapped date representing the current time.
    pub fn now() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            timestamp_ms: now.as_millis() as i64,
        }
    }

    /// Get the stored timestamp in milliseconds.
    pub fn timestamp_ms(&self) -> i64 {
        self.timestamp_ms
    }
}

impl WrappedOption for WrappedDate {
    fn get_object(&self) -> OptionValue {
        OptionValue::Long(self.timestamp_ms)
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        for (key, val) in state {
            if key == "date" {
                if let OptionValue::Long(ts) = val {
                    self.timestamp_ms = *ts;
                }
            }
        }
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        vec![("date".to_string(), OptionValue::Long(self.timestamp_ms))]
    }

    fn option_type(&self) -> OptionType {
        OptionType::DateType
    }
}

impl std::fmt::Display for WrappedDate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrappedDate: {}", self.timestamp_ms)
    }
}

// ============================================================================
// WrappedFile
// ============================================================================

/// Wrapper for a file path that can be persisted as an option value.
///
/// Ported from `ghidra.framework.options.WrappedFile`.
#[derive(Debug, Clone)]
pub struct WrappedFile {
    /// The file path.
    path: PathBuf,
}

impl WrappedFile {
    /// Create a new wrapped file from a path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Get the stored file path.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Consume the wrapper and return the path.
    pub fn into_path(self) -> PathBuf {
        self.path
    }
}

impl WrappedOption for WrappedFile {
    fn get_object(&self) -> OptionValue {
        OptionValue::String(self.path.to_string_lossy().to_string())
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        for (key, val) in state {
            if key == "file" {
                if let OptionValue::String(s) = val {
                    self.path = PathBuf::from(s);
                }
            }
        }
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        vec![(
            "file".to_string(),
            OptionValue::String(self.path.to_string_lossy().to_string()),
        )]
    }

    fn option_type(&self) -> OptionType {
        OptionType::FileType
    }
}

impl std::fmt::Display for WrappedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrappedFile: {}", self.path.display())
    }
}

// ============================================================================
// WrappedKeyStroke
// ============================================================================

/// Representation of a keyboard shortcut (key code + modifier mask).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyStroke {
    /// The virtual key code.
    pub key_code: u32,
    /// Modifier bitmask (Ctrl=1, Shift=2, Alt=4, Meta=8).
    pub modifiers: u32,
}

impl KeyStroke {
    /// Create a new keystroke.
    pub fn new(key_code: u32, modifiers: u32) -> Self {
        Self {
            key_code,
            modifiers,
        }
    }

    /// Whether the Ctrl modifier is set.
    pub fn ctrl(&self) -> bool {
        self.modifiers & 1 != 0
    }

    /// Whether the Shift modifier is set.
    pub fn shift(&self) -> bool {
        self.modifiers & 2 != 0
    }

    /// Whether the Alt modifier is set.
    pub fn alt(&self) -> bool {
        self.modifiers & 4 != 0
    }

    /// Whether the Meta modifier is set.
    pub fn meta(&self) -> bool {
        self.modifiers & 8 != 0
    }
}

impl std::fmt::Display for KeyStroke {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if self.ctrl() {
            parts.push("Ctrl");
        }
        if self.shift() {
            parts.push("Shift");
        }
        if self.alt() {
            parts.push("Alt");
        }
        if self.meta() {
            parts.push("Meta");
        }
        parts.push(&"key");
        write!(f, "{} (code={}, mods={})", parts.join("+"), self.key_code, self.modifiers)
    }
}

/// Wrapper for a [`KeyStroke`] that can be persisted as an option value.
///
/// Ported from `ghidra.framework.options.WrappedKeyStroke`.
#[derive(Debug, Clone)]
pub struct WrappedKeyStroke {
    keystroke: Option<KeyStroke>,
}

impl WrappedKeyStroke {
    /// Create a new wrapper around a keystroke.
    pub fn new(keystroke: KeyStroke) -> Self {
        Self {
            keystroke: Some(keystroke),
        }
    }

    /// Create a wrapper with no keystroke.
    pub fn empty() -> Self {
        Self { keystroke: None }
    }

    /// Get the inner keystroke, if any.
    pub fn keystroke(&self) -> Option<&KeyStroke> {
        self.keystroke.as_ref()
    }
}

impl WrappedOption for WrappedKeyStroke {
    fn get_object(&self) -> OptionValue {
        match &self.keystroke {
            Some(ks) => OptionValue::String(format!("{}+{}", ks.key_code, ks.modifiers)),
            None => OptionValue::String(String::new()),
        }
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        let mut key_code: u32 = 0;
        let mut modifiers: u32 = 0;
        let mut has_key = false;
        for (key, val) in state {
            match key.as_str() {
                "KeyCode" => {
                    if let OptionValue::Int(v) = val {
                        key_code = *v as u32;
                        has_key = true;
                    }
                }
                "Modifiers" => {
                    if let OptionValue::Int(v) = val {
                        modifiers = *v as u32;
                    }
                }
                _ => {}
            }
        }
        if has_key {
            self.keystroke = Some(KeyStroke::new(key_code, modifiers));
        }
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        match &self.keystroke {
            Some(ks) => vec![
                ("KeyCode".to_string(), OptionValue::Int(ks.key_code as i32)),
                ("Modifiers".to_string(), OptionValue::Int(ks.modifiers as i32)),
            ],
            None => Vec::new(),
        }
    }

    fn option_type(&self) -> OptionType {
        OptionType::KeyStrokeType
    }
}

impl std::fmt::Display for WrappedKeyStroke {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.keystroke {
            Some(ks) => write!(f, "WrappedKeyStroke: {}", ks),
            None => write!(f, "WrappedKeyStroke: (none)"),
        }
    }
}

// ============================================================================
// WrappedCustomOption
// ============================================================================

/// Trait for custom option values that can be serialized to/from key/value state.
///
/// Ported from `ghidra.framework.options.CustomOption`.
pub trait CustomOption: std::fmt::Debug {
    /// Read state from a key/value map.
    fn read_state(&mut self, state: &[(String, OptionValue)]);

    /// Write state into a key/value map.
    fn write_state(&self) -> Vec<(String, OptionValue)>;
}

/// Wrapper for a [`CustomOption`] that can be persisted as an option value.
///
/// Ported from `ghidra.framework.options.WrappedCustomOption`.
#[derive(Debug)]
pub struct WrappedCustomOption {
    /// The class name of the custom option implementation.
    class_name: String,
    /// The serialized state of the custom option.
    state: Vec<(String, OptionValue)>,
    /// Whether the custom option was deserialized successfully.
    valid: bool,
}

impl WrappedCustomOption {
    /// Create a new wrapper for a custom option.
    pub fn new(class_name: impl Into<String>) -> Self {
        Self {
            class_name: class_name.into(),
            state: Vec::new(),
            valid: true,
        }
    }

    /// Get the class name of the custom option.
    pub fn class_name(&self) -> &str {
        &self.class_name
    }

    /// Whether the custom option was deserialized successfully.
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    /// Get the stored state.
    pub fn state(&self) -> &[(String, OptionValue)] {
        &self.state
    }

    /// Set the stored state.
    pub fn set_state(&mut self, state: Vec<(String, OptionValue)>) {
        self.state = state;
    }
}

impl WrappedOption for WrappedCustomOption {
    fn get_object(&self) -> OptionValue {
        OptionValue::String(self.class_name.clone())
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        let mut class_name_found = false;
        let mut new_class = String::new();
        let mut data_state = Vec::new();

        for (key, val) in state {
            if key == "CUSTOM OPTION CLASS" {
                if let OptionValue::String(s) = val {
                    new_class = s.clone();
                    class_name_found = true;
                }
            } else {
                data_state.push((key.clone(), val.clone()));
            }
        }

        if class_name_found {
            self.class_name = new_class;
        }
        self.state = data_state;
        self.valid = true;
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        let mut result = vec![(
            "CUSTOM OPTION CLASS".to_string(),
            OptionValue::String(self.class_name.clone()),
        )];
        result.extend(self.state.clone());
        result
    }

    fn option_type(&self) -> OptionType {
        OptionType::CustomType
    }
}

impl std::fmt::Display for WrappedCustomOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WrappedCustomOption: class={}, valid={}, fields={}",
            self.class_name,
            self.valid,
            self.state.len()
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapped_date_new() {
        let d = WrappedDate::new(1_700_000_000_000);
        assert_eq!(d.timestamp_ms(), 1_700_000_000_000);
        assert_eq!(d.option_type(), OptionType::DateType);
    }

    #[test]
    fn test_wrapped_date_now() {
        let d = WrappedDate::now();
        assert!(d.timestamp_ms() > 0);
    }

    #[test]
    fn test_wrapped_date_roundtrip() {
        let d = WrappedDate::new(1234567890);
        let state = d.write_state();
        let mut d2 = WrappedDate::new(0);
        d2.read_state(&state);
        assert_eq!(d2.timestamp_ms(), 1234567890);
    }

    #[test]
    fn test_wrapped_file_new() {
        let f = WrappedFile::new("/tmp/test.txt");
        assert_eq!(f.path().to_str(), Some("/tmp/test.txt"));
        assert_eq!(f.option_type(), OptionType::FileType);
    }

    #[test]
    fn test_wrapped_file_roundtrip() {
        let f = WrappedFile::new("/home/user/data.bin");
        let state = f.write_state();
        let mut f2 = WrappedFile::new(".");
        f2.read_state(&state);
        assert_eq!(f2.path().to_str(), Some("/home/user/data.bin"));
    }

    #[test]
    fn test_keystroke_modifiers() {
        let ks = KeyStroke::new(65, 1 | 2); // Ctrl+Shift+A
        assert!(ks.ctrl());
        assert!(ks.shift());
        assert!(!ks.alt());
        assert!(!ks.meta());
    }

    #[test]
    fn test_wrapped_keystroke_roundtrip() {
        let ks = KeyStroke::new(70, 2); // Shift+F
        let w = WrappedKeyStroke::new(ks);
        assert_eq!(w.option_type(), OptionType::KeyStrokeType);

        let state = w.write_state();
        assert_eq!(state.len(), 2);

        let mut w2 = WrappedKeyStroke::empty();
        w2.read_state(&state);
        let ks2 = w2.keystroke().unwrap();
        assert_eq!(ks2.key_code, 70);
        assert_eq!(ks2.modifiers, 2);
    }

    #[test]
    fn test_wrapped_keystroke_empty() {
        let w = WrappedKeyStroke::empty();
        assert!(w.keystroke().is_none());
        assert!(w.write_state().is_empty());
    }

    #[test]
    fn test_wrapped_custom_option_basic() {
        let mut co = WrappedCustomOption::new("com.example.MyOption");
        assert!(co.is_valid());
        assert_eq!(co.class_name(), "com.example.MyOption");
        assert_eq!(co.option_type(), OptionType::CustomType);
    }

    #[test]
    fn test_wrapped_custom_option_roundtrip() {
        let mut co = WrappedCustomOption::new("com.example.MyOption");
        co.set_state(vec![
            ("width".to_string(), OptionValue::Int(800)),
            ("height".to_string(), OptionValue::Int(600)),
        ]);

        let state = co.write_state();
        // State should have "CUSTOM OPTION CLASS" + 2 data fields.
        assert_eq!(state.len(), 3);

        let mut co2 = WrappedCustomOption::new("");
        co2.read_state(&state);
        assert_eq!(co2.class_name(), "com.example.MyOption");
        assert_eq!(co2.state().len(), 2);
    }

    #[test]
    fn test_display_traits() {
        let d = WrappedDate::new(1000);
        assert!(format!("{}", d).contains("1000"));

        let f = WrappedFile::new("/tmp/a.txt");
        assert!(format!("{}", f).contains("a.txt"));

        let w = WrappedKeyStroke::new(KeyStroke::new(65, 1));
        assert!(format!("{}", w).contains("Ctrl"));
    }
}
