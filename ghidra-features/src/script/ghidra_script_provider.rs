//! GhidraScript provider system: discovering, loading, compiling, and
//! managing script types.
//!
//! Ported from Ghidra's `ghidra.app.script.GhidraScriptProvider` Java class
//! and related provider infrastructure (`JavaScriptProvider`,
//! `JythonScriptProvider`, etc.).
//!
//! A `GhidraScriptProvider` is responsible for:
//! - Providing the file extension it handles (`.java`, `.py`, `.js`, etc.)
//! - Creating new script files from templates
//! - Loading script instances from source files
//! - Providing comment syntax for the language
//! - Managing compilation and caching
//!
//! # Key Types
//!
//! - [`ScriptProvider`] -- abstract provider that discovers and manages a script type
//! - [`JavaSc riptProvider`] -- Java script provider (compiles `.java` files)
//! - [`PythonScriptProvider`] -- Python/Jython script provider (interprets `.py` files)
//! - [`ScriptProviderRegistry`] -- central registry of all known providers

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use super::ghidra_script::{GhidraScriptLoadException, ScriptLanguage};

// ---------------------------------------------------------------------------
// ScriptProvider -- abstract provider for a script language
// ---------------------------------------------------------------------------

/// Metadata about a script provider.
///
/// Ported from `ghidra.app.script.GhidraScriptProvider`.
#[derive(Debug, Clone)]
pub struct ScriptProvider {
    /// The language this provider supports.
    pub language: ScriptLanguage,
    /// File extensions this provider handles (e.g. `[".java"]`).
    pub extensions: Vec<String>,
    /// Human-readable description.
    pub description: String,
    /// The comment character(s) for this language (e.g. `"//"`, `"#"`).
    pub comment_character: String,
    /// Optional block comment opening pattern (e.g. `"/*"`).
    pub block_comment_start: Option<String>,
    /// Optional block comment closing pattern (e.g. `"*/"`).
    pub block_comment_end: Option<String>,
    /// Optional runtime environment name (for disambiguating providers
    /// that share the same extension).
    pub runtime_environment: Option<String>,
    /// Prefix for certification header body lines (if applicable).
    pub certification_body_prefix: Option<String>,
    /// Start of certification header (if applicable).
    pub certify_header_start: Option<String>,
    /// End of certification header (if applicable).
    pub certify_header_end: Option<String>,
    /// Provider priority (lower = higher priority when multiple providers
    /// match the same extension).
    pub priority: i32,
    /// Whether the provider is currently enabled.
    pub enabled: bool,
}

impl ScriptProvider {
    /// Create a new script provider.
    pub fn new(
        language: ScriptLanguage,
        extension: impl Into<String>,
        description: impl Into<String>,
        comment_character: impl Into<String>,
    ) -> Self {
        Self {
            language,
            extensions: vec![extension.into()],
            description: description.into(),
            comment_character: comment_character.into(),
            block_comment_start: None,
            block_comment_end: None,
            runtime_environment: None,
            certification_body_prefix: None,
            certify_header_start: None,
            certify_header_end: None,
            priority: 0,
            enabled: true,
        }
    }

    /// Add an additional file extension to this provider.
    pub fn with_extension(mut self, ext: impl Into<String>) -> Self {
        self.extensions.push(ext.into());
        self
    }

    /// Set block comment delimiters.
    pub fn with_block_comments(
        mut self,
        start: impl Into<String>,
        end: impl Into<String>,
    ) -> Self {
        self.block_comment_start = Some(start.into());
        self.block_comment_end = Some(end.into());
        self
    }

    /// Set the runtime environment name.
    pub fn with_runtime_environment(mut self, name: impl Into<String>) -> Self {
        self.runtime_environment = Some(name.into());
        self
    }

    /// Set the provider priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Check if this provider can handle a file with the given name.
    pub fn can_handle(&self, filename: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let lower = filename.to_lowercase();
        self.extensions.iter().any(|ext| lower.ends_with(ext))
    }

    /// Get the default (first) file extension.
    pub fn default_extension(&self) -> &str {
        self.extensions.first().map(|s| s.as_str()).unwrap_or("")
    }

    /// Generate a script header for a new script in the given category.
    pub fn write_header(&self, category: &str) -> String {
        let cat = if category.is_empty() { "_NEW_" } else { category };
        let mut out = String::new();

        out.push_str(&format!(
            "{}TODO write a description for this script\n",
            self.comment_character
        ));

        // Standard metadata tags
        let metadata_items = [
            "@author",
            "@category",
            "@keybinding",
            "@menupath",
            "@toolbar",
            "@description",
            "@runtime",
        ];

        for item in &metadata_items {
            out.push_str(&format!("{}{} ", self.comment_character, item));
            if *item == "@category" {
                out.push_str(cat);
            } else if *item == "@runtime" {
                if let Some(ref rt) = self.runtime_environment {
                    out.push_str(rt);
                }
            }
            out.push('\n');
        }

        out.push('\n');
        out
    }

    /// Generate a script body template.
    pub fn write_body(&self) -> String {
        format!("{}TODO Add User Code Here\n", self.comment_character)
    }

    /// Delete a script file managed by this provider.
    ///
    /// Returns `true` if the file was deleted or did not exist.
    pub fn delete_script(&self, path: &Path) -> bool {
        if !path.exists() {
            return true;
        }
        std::fs::remove_file(path).is_ok()
    }

    /// Read script source from a file path.
    pub fn read_source(&self, path: &Path) -> Result<String, ScriptProviderError> {
        std::fs::read_to_string(path).map_err(|e| ScriptProviderError::IoError {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
    }
}

impl fmt::Display for ScriptProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}

// ---------------------------------------------------------------------------
// Pre-built providers
// ---------------------------------------------------------------------------

impl ScriptProvider {
    /// Create a Java script provider.
    pub fn java() -> Self {
        Self::new(
            ScriptLanguage::Java,
            ".java",
            "Java Ghidra Script",
            "//",
        )
        .with_block_comments("/*", "*/")
    }

    /// Create a Python (Jython) script provider.
    pub fn python() -> Self {
        Self::new(
            ScriptLanguage::Python,
            ".py",
            "Python (Jython) Ghidra Script",
            "#",
        )
    }

    /// Create a JavaScript script provider.
    pub fn javascript() -> Self {
        Self::new(
            ScriptLanguage::JavaScript,
            ".js",
            "JavaScript Ghidra Script",
            "//",
        )
        .with_block_comments("/*", "*/")
    }

    /// Create a Groovy script provider.
    pub fn groovy() -> Self {
        Self::new(
            ScriptLanguage::Java, // Groovy runs on JVM
            ".groovy",
            "Groovy Ghidra Script",
            "//",
        )
        .with_block_comments("/*", "*/")
        .with_runtime_environment("Groovy")
    }
}

// ---------------------------------------------------------------------------
// ScriptProviderError
// ---------------------------------------------------------------------------

/// Errors from script provider operations.
#[derive(Debug, Clone)]
pub enum ScriptProviderError {
    /// I/O error reading or writing a script file.
    IoError {
        /// The file path that caused the error.
        path: PathBuf,
        /// The error message.
        message: String,
    },
    /// The script could not be loaded.
    LoadError(GhidraScriptLoadException),
    /// No provider found for the given file extension.
    NoProvider {
        /// The filename that had no matching provider.
        filename: String,
    },
    /// Compilation error.
    CompileError {
        /// The script that failed to compile.
        script_name: String,
        /// The compilation error message.
        message: String,
        /// Line number where the error occurred, if known.
        line: Option<u32>,
    },
}

impl fmt::Display for ScriptProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoError { path, message } => {
                write!(f, "I/O error for '{}': {}", path.display(), message)
            }
            Self::LoadError(e) => write!(f, "{}", e),
            Self::NoProvider { filename } => {
                write!(f, "No script provider found for '{}'", filename)
            }
            Self::CompileError {
                script_name,
                message,
                line,
            } => {
                if let Some(l) = line {
                    write!(
                        f,
                        "Compilation error in '{}' at line {}: {}",
                        script_name, l, message
                    )
                } else {
                    write!(
                        f,
                        "Compilation error in '{}': {}",
                        script_name, message
                    )
                }
            }
        }
    }
}

impl std::error::Error for ScriptProviderError {}

// ---------------------------------------------------------------------------
// ScriptProviderRegistry -- central registry of providers
// ---------------------------------------------------------------------------

/// Central registry of script providers.
///
/// Maintains a mapping from file extensions to providers and provides
/// lookup/discovery functionality.
///
/// Ported from the provider discovery mechanism in
/// `ghidra.app.script.GhidraScriptUtil`.
#[derive(Debug)]
pub struct ScriptProviderRegistry {
    /// Registered providers keyed by their primary extension.
    providers: HashMap<String, Arc<ScriptProvider>>,
    /// All providers in registration order.
    all_providers: Vec<Arc<ScriptProvider>>,
}

impl ScriptProviderRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            all_providers: Vec::new(),
        }
    }

    /// Create a registry pre-populated with the built-in providers.
    pub fn with_defaults() -> Self {
        let mut registry = Self::new();
        registry.register(ScriptProvider::java());
        registry.register(ScriptProvider::python());
        registry.register(ScriptProvider::javascript());
        registry.register(ScriptProvider::groovy());
        registry
    }

    /// Register a script provider.
    ///
    /// The provider is keyed by each of its file extensions.
    pub fn register(&mut self, provider: ScriptProvider) {
        let arc = Arc::new(provider);
        for ext in &arc.extensions {
            self.providers.insert(ext.clone(), Arc::clone(&arc));
        }
        self.all_providers.push(arc);
    }

    /// Find a provider for the given filename.
    pub fn find_provider(&self, filename: &str) -> Option<&ScriptProvider> {
        let lower = filename.to_lowercase();
        self.providers
            .values()
            .find(|p| p.enabled && p.extensions.iter().any(|ext| lower.ends_with(ext)))
            .map(|p| p.as_ref())
    }

    /// Find a provider by language.
    pub fn find_by_language(&self, language: ScriptLanguage) -> Option<&ScriptProvider> {
        self.all_providers
            .iter()
            .find(|p| p.language == language && p.enabled)
            .map(|p| p.as_ref())
    }

    /// Find a provider by runtime environment name.
    pub fn find_by_runtime(&self, runtime: &str) -> Option<&ScriptProvider> {
        self.all_providers
            .iter()
            .find(|p| {
                p.enabled && p.runtime_environment.as_deref() == Some(runtime)
            })
            .map(|p| p.as_ref())
    }

    /// Get all registered providers.
    pub fn all_providers(&self) -> &[Arc<ScriptProvider>] {
        &self.all_providers
    }

    /// Get all enabled providers sorted by priority.
    pub fn sorted_providers(&self) -> Vec<&ScriptProvider> {
        let mut providers: Vec<&ScriptProvider> = self
            .all_providers
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.as_ref())
            .collect();
        providers.sort_by_key(|p| p.priority);
        providers
    }

    /// Get all supported file extensions.
    pub fn supported_extensions(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a filename has a supported extension.
    pub fn is_supported(&self, filename: &str) -> bool {
        self.find_provider(filename).is_some()
    }

    /// Remove a provider by its primary extension.
    pub fn unregister(&mut self, extension: &str) -> Option<Arc<ScriptProvider>> {
        self.providers.remove(extension).map(|arc| {
            self.all_providers.retain(|p| !Arc::ptr_eq(p, &arc));
            arc
        })
    }

    /// Enable or disable a provider for a given extension.
    pub fn set_enabled(&mut self, extension: &str, enabled: bool) {
        // Note: because providers are Arc-wrapped, we cannot mutate in place.
        // In a full implementation, this would use interior mutability.
        // For now, this is a no-op placeholder.
        let _ = (extension, enabled);
    }

    /// Get the number of registered providers.
    pub fn len(&self) -> usize {
        self.all_providers.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.all_providers.is_empty()
    }
}

impl Default for ScriptProviderRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ---------------------------------------------------------------------------
// ScriptCompilationCache -- caches compiled script class files
// ---------------------------------------------------------------------------

/// Entry in the compilation cache.
#[derive(Debug, Clone)]
pub struct CompileCacheEntry {
    /// Path to the source file.
    pub source_path: PathBuf,
    /// Path to the compiled output (e.g. `.class` file).
    pub output_path: PathBuf,
    /// Source file modification time at compile time (epoch millis).
    pub source_modified: u64,
    /// Compilation timestamp (epoch millis).
    pub compiled_at: u64,
    /// Whether compilation succeeded.
    pub success: bool,
    /// Compilation error message, if any.
    pub error: Option<String>,
}

/// Caches script compilation results to avoid recompilation when
/// source files have not changed.
///
/// Ported from the compilation cache in `GhidraScriptUtil`.
#[derive(Debug)]
pub struct ScriptCompilationCache {
    /// Cache entries keyed by source path.
    entries: HashMap<PathBuf, CompileCacheEntry>,
    /// Maximum number of cache entries.
    max_entries: usize,
}

impl ScriptCompilationCache {
    /// Create a new compilation cache.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Check if a source file needs recompilation.
    pub fn needs_recompile(&self, source_path: &Path, current_modified: u64) -> bool {
        match self.entries.get(source_path) {
            Some(entry) => !entry.success || entry.source_modified < current_modified,
            None => true,
        }
    }

    /// Record a successful compilation.
    pub fn record_success(
        &mut self,
        source_path: PathBuf,
        output_path: PathBuf,
        source_modified: u64,
        compiled_at: u64,
    ) {
        self.evict_if_needed();
        self.entries.insert(
            source_path.clone(),
            CompileCacheEntry {
                source_path,
                output_path,
                source_modified,
                compiled_at,
                success: true,
                error: None,
            },
        );
    }

    /// Record a failed compilation.
    pub fn record_failure(
        &mut self,
        source_path: PathBuf,
        source_modified: u64,
        compiled_at: u64,
        error: String,
    ) {
        self.evict_if_needed();
        self.entries.insert(
            source_path.clone(),
            CompileCacheEntry {
                source_path,
                output_path: PathBuf::new(),
                source_modified,
                compiled_at,
                success: false,
                error: Some(error),
            },
        );
    }

    /// Get a cache entry.
    pub fn get(&self, source_path: &Path) -> Option<&CompileCacheEntry> {
        self.entries.get(source_path)
    }

    /// Invalidate a cache entry.
    pub fn invalidate(&mut self, source_path: &Path) {
        self.entries.remove(source_path);
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict oldest entries if over capacity.
    fn evict_if_needed(&mut self) {
        if self.entries.len() >= self.max_entries {
            // Remove the oldest successful entry by compiled_at timestamp.
            if let Some(oldest_key) = self
                .entries
                .iter()
                .filter(|(_, e)| e.success)
                .min_by_key(|(_, e)| e.compiled_at)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
    }
}

impl Default for ScriptCompilationCache {
    fn default() -> Self {
        Self::new(256)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_provider_creation() {
        let java = ScriptProvider::java();
        assert_eq!(java.language, ScriptLanguage::Java);
        assert_eq!(java.default_extension(), ".java");
        assert_eq!(java.comment_character, "//");
        assert!(java.block_comment_start.is_some());
        assert!(java.block_comment_end.is_some());
        assert!(java.enabled);
    }

    #[test]
    fn test_script_provider_python() {
        let python = ScriptProvider::python();
        assert_eq!(python.language, ScriptLanguage::Python);
        assert_eq!(python.default_extension(), ".py");
        assert_eq!(python.comment_character, "#");
        assert!(python.block_comment_start.is_none());
    }

    #[test]
    fn test_script_provider_javascript() {
        let js = ScriptProvider::javascript();
        assert_eq!(js.language, ScriptLanguage::JavaScript);
        assert_eq!(js.default_extension(), ".js");
    }

    #[test]
    fn test_script_provider_groovy() {
        let groovy = ScriptProvider::groovy();
        assert!(groovy.runtime_environment.is_some());
        assert_eq!(groovy.runtime_environment.as_deref(), Some("Groovy"));
    }

    #[test]
    fn test_provider_can_handle() {
        let java = ScriptProvider::java();
        assert!(java.can_handle("MyScript.java"));
        assert!(java.can_handle("MYSCRIPT.JAVA"));
        assert!(!java.can_handle("MyScript.py"));
        assert!(!java.can_handle("MyScript.txt"));
    }

    #[test]
    fn test_provider_disabled() {
        let mut java = ScriptProvider::java();
        java.enabled = false;
        assert!(!java.can_handle("test.java"));
    }

    #[test]
    fn test_provider_with_extension() {
        let provider = ScriptProvider::java().with_extension(".jsh");
        assert!(provider.can_handle("test.java"));
        assert!(provider.can_handle("test.jsh"));
        assert_eq!(provider.extensions.len(), 2);
    }

    #[test]
    fn test_provider_write_header() {
        let java = ScriptProvider::java();
        let header = java.write_header("Analysis");
        assert!(header.contains("//TODO write a description"));
        assert!(header.contains("//@category Analysis"));
        assert!(header.contains("//@author"));
    }

    #[test]
    fn test_provider_write_header_empty_category() {
        let java = ScriptProvider::java();
        let header = java.write_header("");
        assert!(header.contains("//@category _NEW_"));
    }

    #[test]
    fn test_provider_write_body() {
        let java = ScriptProvider::java();
        let body = java.write_body();
        assert!(body.contains("//TODO Add User Code Here"));
    }

    #[test]
    fn test_provider_display() {
        let java = ScriptProvider::java();
        assert_eq!(format!("{}", java), "Java Ghidra Script");
    }

    #[test]
    fn test_registry_creation() {
        let registry = ScriptProviderRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_with_defaults() {
        let registry = ScriptProviderRegistry::with_defaults();
        assert!(!registry.is_empty());
        assert!(registry.len() >= 4); // Java, Python, JavaScript, Groovy
    }

    #[test]
    fn test_registry_find_provider() {
        let registry = ScriptProviderRegistry::with_defaults();
        let java = registry.find_provider("test.java");
        assert!(java.is_some());
        assert_eq!(java.unwrap().language, ScriptLanguage::Java);

        let py = registry.find_provider("analyze.py");
        assert!(py.is_some());

        assert!(registry.find_provider("unknown.xyz").is_none());
    }

    #[test]
    fn test_registry_find_by_language() {
        let registry = ScriptProviderRegistry::with_defaults();
        let java = registry.find_by_language(ScriptLanguage::Java);
        assert!(java.is_some());

        let js = registry.find_by_language(ScriptLanguage::JavaScript);
        assert!(js.is_some());
    }

    #[test]
    fn test_registry_find_by_runtime() {
        let registry = ScriptProviderRegistry::with_defaults();
        let groovy = registry.find_by_runtime("Groovy");
        assert!(groovy.is_some());
        assert_eq!(groovy.unwrap().default_extension(), ".groovy");

        assert!(registry.find_by_runtime("NonExistent").is_none());
    }

    #[test]
    fn test_registry_supported_extensions() {
        let registry = ScriptProviderRegistry::with_defaults();
        let exts = registry.supported_extensions();
        assert!(exts.contains(&".java"));
        assert!(exts.contains(&".py"));
        assert!(exts.contains(&".js"));
        assert!(exts.contains(&".groovy"));
    }

    #[test]
    fn test_registry_is_supported() {
        let registry = ScriptProviderRegistry::with_defaults();
        assert!(registry.is_supported("test.java"));
        assert!(registry.is_supported("test.py"));
        assert!(!registry.is_supported("test.rb"));
    }

    #[test]
    fn test_registry_sorted_providers() {
        let mut registry = ScriptProviderRegistry::new();
        registry.register(ScriptProvider::java().with_priority(10));
        registry.register(ScriptProvider::python().with_priority(5));
        registry.register(ScriptProvider::javascript().with_priority(15));

        let sorted = registry.sorted_providers();
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].language, ScriptLanguage::Python); // lowest priority first
        assert_eq!(sorted[1].language, ScriptLanguage::Java);
        assert_eq!(sorted[2].language, ScriptLanguage::JavaScript);
    }

    #[test]
    fn test_provider_error_display() {
        let err = ScriptProviderError::NoProvider {
            filename: "test.rb".to_string(),
        };
        assert!(format!("{}", err).contains("test.rb"));

        let err = ScriptProviderError::CompileError {
            script_name: "bad.java".to_string(),
            message: "unexpected token".to_string(),
            line: Some(42),
        };
        let s = format!("{}", err);
        assert!(s.contains("bad.java"));
        assert!(s.contains("line 42"));
    }

    #[test]
    fn test_compilation_cache_basic() {
        let mut cache = ScriptCompilationCache::new(10);
        assert!(cache.is_empty());

        let src = PathBuf::from("/scripts/test.java");
        assert!(cache.needs_recompile(&src, 1000));

        cache.record_success(
            src.clone(),
            PathBuf::from("/compiled/test.class"),
            1000,
            2000,
        );
        assert_eq!(cache.len(), 1);
        assert!(!cache.needs_recompile(&src, 1000));
        assert!(!cache.needs_recompile(&src, 999));
        assert!(cache.needs_recompile(&src, 1001)); // newer source
    }

    #[test]
    fn test_compilation_cache_failure() {
        let mut cache = ScriptCompilationCache::new(10);
        let src = PathBuf::from("/scripts/bad.java");

        cache.record_failure(src.clone(), 1000, 2000, "syntax error".to_string());
        // Failed compilations always need recompile
        assert!(cache.needs_recompile(&src, 1000));
    }

    #[test]
    fn test_compilation_cache_eviction() {
        let mut cache = ScriptCompilationCache::new(2);

        cache.record_success(
            PathBuf::from("/a.java"),
            PathBuf::from("/a.class"),
            1000,
            2000,
        );
        cache.record_success(
            PathBuf::from("/b.java"),
            PathBuf::from("/b.class"),
            1000,
            3000,
        );
        assert_eq!(cache.len(), 2);

        // Adding a third should evict the oldest (a.java)
        cache.record_success(
            PathBuf::from("/c.java"),
            PathBuf::from("/c.class"),
            1000,
            4000,
        );
        assert_eq!(cache.len(), 2);
        assert!(cache.get(Path::new("/a.java")).is_none());
        assert!(cache.get(Path::new("/b.java")).is_some());
        assert!(cache.get(Path::new("/c.java")).is_some());
    }

    #[test]
    fn test_compilation_cache_invalidate() {
        let mut cache = ScriptCompilationCache::new(10);
        let src = PathBuf::from("/test.java");

        cache.record_success(src.clone(), PathBuf::from("/test.class"), 1000, 2000);
        assert!(!cache.needs_recompile(&src, 1000));

        cache.invalidate(&src);
        assert!(cache.needs_recompile(&src, 1000));
    }

    #[test]
    fn test_compilation_cache_clear() {
        let mut cache = ScriptCompilationCache::new(10);
        cache.record_success(
            PathBuf::from("/a.java"),
            PathBuf::from("/a.class"),
            1000,
            2000,
        );
        cache.record_success(
            PathBuf::from("/b.java"),
            PathBuf::from("/b.class"),
            1000,
            2000,
        );
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
    }
}
