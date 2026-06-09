//! Decompiler Plugin -- provides the decompiler panel.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.decompile` package.
//!
//! This module provides the decompiler plugin that produces a high-level C
//! interpretation of assembly functions. It manages the decompiler interface,
//! result caching, and user interactions.
//!
//! # Architecture
//!
//! ```text
//! DecompilePlugin
//!   ├── DecompilerProvider (display component)
//!   ├── DecompilerController (decompilation logic)
//!   ├── DecompileResultCache (result caching)
//!   └── DecompilerActions (user actions)
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::plugin::decompile::decompile_plugin::DecompilePlugin;
//!
//! let mut plugin = DecompilePlugin::new("Decompiler");
//! plugin.init();
//! assert_eq!(plugin.name(), "Decompiler");
//! ```

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// DecompileResult -- result of decompiling a function
// ---------------------------------------------------------------------------

/// The status of a decompilation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecompileStatus {
    /// Decompilation succeeded.
    Success,
    /// Decompilation failed.
    Failed,
    /// Decompilation was cancelled.
    Cancelled,
    /// Decompilation is in progress.
    InProgress,
}

impl fmt::Display for DecompileStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Success"),
            Self::Failed => write!(f, "Failed"),
            Self::Cancelled => write!(f, "Cancelled"),
            Self::InProgress => write!(f, "In Progress"),
        }
    }
}

/// A token in the decompiled output.
#[derive(Debug, Clone)]
pub struct DecompiledToken {
    /// The token text.
    pub text: String,
    /// The token type.
    pub token_type: DecompiledTokenType,
    /// The source address (if applicable).
    pub address: Option<String>,
}

/// The type of a decompiled token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecompiledTokenType {
    /// A keyword (if, while, return, etc.).
    Keyword,
    /// A type name (int, char, void, etc.).
    Type,
    /// A function name.
    Function,
    /// A variable name.
    Variable,
    /// A constant value.
    Constant,
    /// An operator (+, -, *, /, etc.).
    Operator,
    /// A comment.
    Comment,
    /// A whitespace.
    Whitespace,
    /// Other/unknown.
    Other,
}

/// The result of decompiling a function.
#[derive(Debug, Clone)]
pub struct DecompileResult {
    /// The function name.
    pub function_name: String,
    /// The function address.
    pub function_address: String,
    /// The decompiled C code.
    pub code: String,
    /// The tokens in the decompiled output.
    pub tokens: Vec<DecompiledToken>,
    /// The status of the decompilation.
    pub status: DecompileStatus,
    /// Error message (if failed).
    pub error: Option<String>,
    /// Decompilation time in milliseconds.
    pub time_ms: u64,
}

impl DecompileResult {
    /// Creates a successful decompile result.
    pub fn success(
        function_name: impl Into<String>,
        function_address: impl Into<String>,
        code: impl Into<String>,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            function_address: function_address.into(),
            code: code.into(),
            tokens: Vec::new(),
            status: DecompileStatus::Success,
            error: None,
            time_ms: 0,
        }
    }

    /// Creates a failed decompile result.
    pub fn failed(
        function_name: impl Into<String>,
        function_address: impl Into<String>,
        error: impl Into<String>,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            function_address: function_address.into(),
            code: String::new(),
            tokens: Vec::new(),
            status: DecompileStatus::Failed,
            error: Some(error.into()),
            time_ms: 0,
        }
    }

    /// Returns whether the decompilation was successful.
    pub fn is_success(&self) -> bool {
        self.status == DecompileStatus::Success
    }
}

// ---------------------------------------------------------------------------
// DecompileResultCache -- caches decompilation results
// ---------------------------------------------------------------------------

/// Caches decompilation results to avoid redundant decompilation.
#[derive(Debug)]
pub struct DecompileResultCache {
    /// Cached results by function address.
    cache: HashMap<String, DecompileResult>,
    /// Maximum cache size.
    max_size: usize,
}

impl DecompileResultCache {
    /// Creates a new cache with the given maximum size.
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_size,
        }
    }

    /// Inserts a result into the cache.
    pub fn insert(&mut self, result: DecompileResult) {
        if self.cache.len() >= self.max_size {
            // Remove the first entry (arbitrary eviction)
            if let Some(key) = self.cache.keys().next().cloned() {
                self.cache.remove(&key);
            }
        }
        self.cache.insert(result.function_address.clone(), result);
    }

    /// Returns a cached result for the given function address.
    pub fn get(&self, function_address: &str) -> Option<&DecompileResult> {
        self.cache.get(function_address)
    }

    /// Returns whether the cache contains a result for the given address.
    pub fn contains(&self, function_address: &str) -> bool {
        self.cache.contains_key(function_address)
    }

    /// Clears the cache.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Returns the current cache size.
    pub fn size(&self) -> usize {
        self.cache.len()
    }

    /// Returns the maximum cache size.
    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

impl Default for DecompileResultCache {
    fn default() -> Self {
        Self::new(100)
    }
}

// ---------------------------------------------------------------------------
// DecompilePlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The decompiler plugin.
///
/// Provides the decompiler panel that produces a high-level C interpretation
/// of assembly functions. Manages the decompiler interface, result caching,
/// and user interactions.
///
/// Ported from Ghidra's `DecompilePlugin` Java class.
#[derive(Debug)]
pub struct DecompilePlugin {
    /// The plugin name.
    name: String,
    /// The decompilation result cache.
    cache: DecompileResultCache,
    /// The current function address.
    current_function: Option<String>,
    /// Decompiler options.
    options: HashMap<String, DecompileOption>,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
}

/// A decompiler plugin option.
#[derive(Debug, Clone)]
pub enum DecompileOption {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i32),
    /// String option.
    String(String),
}

impl fmt::Display for DecompileOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
        }
    }
}

impl DecompilePlugin {
    /// Creates a new decompiler plugin.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            cache: DecompileResultCache::new(100),
            current_function: None,
            options: HashMap::new(),
            initialized: false,
            disposed: false,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initializes the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.cache.clear();
        self.current_function = None;
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Returns a reference to the result cache.
    pub fn cache(&self) -> &DecompileResultCache {
        &self.cache
    }

    /// Returns a mutable reference to the result cache.
    pub fn cache_mut(&mut self) -> &mut DecompileResultCache {
        &mut self.cache
    }

    /// Sets the current function to decompile.
    pub fn set_current_function(&mut self, address: Option<String>) {
        self.current_function = address;
    }

    /// Returns the current function address.
    pub fn current_function(&self) -> Option<&str> {
        self.current_function.as_deref()
    }

    /// Caches a decompile result.
    pub fn cache_result(&mut self, result: DecompileResult) {
        self.cache.insert(result);
    }

    /// Returns a cached result for the given function address.
    pub fn get_cached_result(&self, function_address: &str) -> Option<&DecompileResult> {
        self.cache.get(function_address)
    }

    /// Returns whether a cached result exists for the given address.
    pub fn has_cached_result(&self, function_address: &str) -> bool {
        self.cache.contains(function_address)
    }

    /// Clears the result cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Sets a plugin option.
    pub fn set_option(&mut self, key: impl Into<String>, value: DecompileOption) {
        self.options.insert(key.into(), value);
    }

    /// Gets a plugin option.
    pub fn get_option(&self, key: &str) -> Option<&DecompileOption> {
        self.options.get(key)
    }
}

impl Default for DecompilePlugin {
    fn default() -> Self {
        Self::new("DecompilePlugin")
    }
}

impl fmt::Display for DecompilePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecompilePlugin({}, cache_size={})",
            self.name,
            self.cache.size()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = DecompilePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert!(plugin.current_function().is_none());
    }

    #[test]
    fn test_decompile_result() {
        let result = DecompileResult::success("main", "0x401000", "int main() { return 0; }");
        assert!(result.is_success());
        assert_eq!(result.function_name, "main");
        assert_eq!(result.function_address, "0x401000");
    }

    #[test]
    fn test_result_cache() {
        let mut cache = DecompileResultCache::new(2);
        let result1 = DecompileResult::success("func1", "0x401000", "code1");
        let result2 = DecompileResult::success("func2", "0x402000", "code2");
        cache.insert(result1);
        cache.insert(result2);
        assert_eq!(cache.size(), 2);
        assert!(cache.contains("0x401000"));
        assert!(cache.contains("0x402000"));
    }

    #[test]
    fn test_plugin_cache() {
        let mut plugin = DecompilePlugin::new("TestPlugin");
        let result = DecompileResult::success("main", "0x401000", "int main() {}");
        plugin.cache_result(result);
        assert!(plugin.has_cached_result("0x401000"));
        let cached = plugin.get_cached_result("0x401000");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().function_name, "main");
    }

    #[test]
    fn test_init_dispose() {
        let mut plugin = DecompilePlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_decompile_status() {
        assert_eq!(DecompileStatus::Success.to_string(), "Success");
        assert_eq!(DecompileStatus::Failed.to_string(), "Failed");
        assert_eq!(DecompileStatus::Cancelled.to_string(), "Cancelled");
    }
}
