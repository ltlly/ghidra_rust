//! Extended TraceOptionsManager - trace metadata and configuration.
//!
//! Ported from Ghidra's `ghidra.trace.model.TraceOptionsManager` interface.
//! Manages trace-level options including name, creation date, base language,
//! platform, and executable path.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The base language/architecture of the trace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TraceLanguageId {
    /// The language ID string (e.g., "x86:LE:64:default").
    pub id: String,
}

impl TraceLanguageId {
    /// Create a new language ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    /// Get the architecture name from the language ID.
    ///
    /// For "x86:LE:64:default", returns "x86".
    pub fn architecture(&self) -> &str {
        self.id.split(':').next().unwrap_or(&self.id)
    }

    /// Get the endianness from the language ID.
    ///
    /// For "x86:LE:64:default", returns "LE".
    pub fn endianness(&self) -> Option<&str> {
        self.id.split(':').nth(1)
    }

    /// Get the bit size from the language ID.
    ///
    /// For "x86:LE:64:default", returns "64".
    pub fn bits(&self) -> Option<&str> {
        self.id.split(':').nth(2)
    }

    /// Get the variant from the language ID.
    ///
    /// For "x86:LE:64:default", returns "default".
    pub fn variant(&self) -> Option<&str> {
        self.id.split(':').nth(3)
    }
}

impl std::fmt::Display for TraceLanguageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// The compiler specification ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompilerSpecId {
    /// The compiler spec ID string.
    pub id: String,
}

impl CompilerSpecId {
    /// Create a new compiler spec ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    /// The default compiler spec.
    pub fn default_spec() -> Self {
        Self::new("default")
    }
}

impl std::fmt::Display for CompilerSpecId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

/// Extended options manager for a trace.
///
/// Manages metadata about the trace: its name, creation date, base
/// language/architecture, platform, and the path to the executable
/// being debugged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceOptionsManagerExt {
    /// The trace name.
    name: String,
    /// When the trace was created.
    creation_date: DateTime<Utc>,
    /// The base language ID.
    base_language_id: Option<TraceLanguageId>,
    /// The compiler spec ID.
    compiler_spec_id: Option<CompilerSpecId>,
    /// The platform name.
    platform: Option<String>,
    /// The executable path.
    executable_path: Option<String>,
    /// Generic key-value options.
    options: BTreeMap<String, String>,
}

impl Default for TraceOptionsManagerExt {
    fn default() -> Self {
        Self {
            name: String::new(),
            creation_date: Utc::now(),
            base_language_id: None,
            compiler_spec_id: None,
            platform: None,
            executable_path: None,
            options: BTreeMap::new(),
        }
    }
}

impl TraceOptionsManagerExt {
    /// Create a new options manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the trace name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the trace name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Get the creation date.
    pub fn creation_date(&self) -> DateTime<Utc> {
        self.creation_date
    }

    /// Get the base language ID.
    pub fn base_language_id(&self) -> Option<&TraceLanguageId> {
        self.base_language_id.as_ref()
    }

    /// Set the base language ID.
    pub fn set_base_language_id(&mut self, id: TraceLanguageId) {
        self.base_language_id = Some(id);
    }

    /// Get the compiler spec ID.
    pub fn compiler_spec_id(&self) -> Option<&CompilerSpecId> {
        self.compiler_spec_id.as_ref()
    }

    /// Set the compiler spec ID.
    pub fn set_compiler_spec_id(&mut self, id: CompilerSpecId) {
        self.compiler_spec_id = Some(id);
    }

    /// Get the platform name.
    pub fn platform(&self) -> Option<&str> {
        self.platform.as_deref()
    }

    /// Set the platform name.
    pub fn set_platform(&mut self, platform: impl Into<String>) {
        self.platform = Some(platform.into());
    }

    /// Get the executable path.
    pub fn executable_path(&self) -> Option<&str> {
        self.executable_path.as_deref()
    }

    /// Set the executable path.
    pub fn set_executable_path(&mut self, path: impl Into<String>) {
        self.executable_path = Some(path.into());
    }

    /// Get all options as a map.
    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.options
    }

    /// Set a generic option.
    pub fn set_option(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.options.insert(key.into(), value.into());
    }

    /// Get a generic option.
    pub fn get_option(&self, key: &str) -> Option<&str> {
        self.options.get(key).map(|s| s.as_str())
    }

    /// Remove a generic option.
    pub fn remove_option(&mut self, key: &str) -> Option<String> {
        self.options.remove(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_id() {
        let lang = TraceLanguageId::new("x86:LE:64:default");
        assert_eq!(lang.architecture(), "x86");
        assert_eq!(lang.endianness(), Some("LE"));
        assert_eq!(lang.bits(), Some("64"));
        assert_eq!(lang.variant(), Some("default"));
        assert_eq!(lang.to_string(), "x86:LE:64:default");
    }

    #[test]
    fn test_language_id_arm() {
        let lang = TraceLanguageId::new("ARM:LE:32:v8");
        assert_eq!(lang.architecture(), "ARM");
        assert_eq!(lang.endianness(), Some("LE"));
        assert_eq!(lang.bits(), Some("32"));
        assert_eq!(lang.variant(), Some("v8"));
    }

    #[test]
    fn test_compiler_spec_id() {
        let cs = CompilerSpecId::new("default");
        assert_eq!(cs.to_string(), "default");
        assert_eq!(cs, CompilerSpecId::default_spec());
    }

    #[test]
    fn test_options_manager_ext_basic() {
        let mut opts = TraceOptionsManagerExt::new();
        assert!(opts.name().is_empty());
        assert!(opts.base_language_id().is_none());

        opts.set_name("My Trace");
        assert_eq!(opts.name(), "My Trace");

        opts.set_base_language_id(TraceLanguageId::new("x86:LE:64:default"));
        assert!(opts.base_language_id().is_some());
        assert_eq!(
            opts.base_language_id().unwrap().architecture(),
            "x86"
        );
    }

    #[test]
    fn test_options_manager_ext_platform() {
        let mut opts = TraceOptionsManagerExt::new();
        assert!(opts.platform().is_none());

        opts.set_platform("windows-x86_64");
        assert_eq!(opts.platform(), Some("windows-x86_64"));
    }

    #[test]
    fn test_options_manager_ext_executable() {
        let mut opts = TraceOptionsManagerExt::new();
        assert!(opts.executable_path().is_none());

        opts.set_executable_path("/usr/bin/ls");
        assert_eq!(opts.executable_path(), Some("/usr/bin/ls"));
    }

    #[test]
    fn test_options_manager_ext_compiler_spec() {
        let mut opts = TraceOptionsManagerExt::new();
        assert!(opts.compiler_spec_id().is_none());

        opts.set_compiler_spec_id(CompilerSpecId::new("gcc"));
        assert_eq!(opts.compiler_spec_id().unwrap().to_string(), "gcc");
    }

    #[test]
    fn test_options_manager_ext_generic_options() {
        let mut opts = TraceOptionsManagerExt::new();
        opts.set_option("max-snaps", "1000");
        assert_eq!(opts.get_option("max-snaps"), Some("1000"));

        opts.set_option("key2", "val2");
        assert_eq!(opts.as_map().len(), 2);

        opts.remove_option("max-snaps");
        assert!(opts.get_option("max-snaps").is_none());
    }

    #[test]
    fn test_options_manager_ext_serde() {
        let mut opts = TraceOptionsManagerExt::new();
        opts.set_name("test");
        opts.set_base_language_id(TraceLanguageId::new("x86:LE:64:default"));

        let json = serde_json::to_string(&opts).unwrap();
        let back: TraceOptionsManagerExt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name(), "test");
    }
}
