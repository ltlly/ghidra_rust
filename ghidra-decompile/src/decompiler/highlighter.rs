//! Decompiler highlighter types.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompilerHighlighter` and related.

/// The highlighter interface passed to clients of the DecompilerHighlightService.
///
/// The expected workflow is: create the highlighter, clients request highlights
/// via `apply_highlights()`, clients clear highlights via `clear_highlights()`,
/// and the highlighter may be removed via `dispose()`.
pub trait DecompilerHighlighter: std::fmt::Debug {
    /// Apply the highlights to the decompiler view.
    fn apply_highlights(&self);

    /// Clear all highlights from the decompiler view.
    fn clear_highlights(&self);

    /// Dispose of this highlighter, cleaning up resources.
    fn dispose(&self);
}

/// A token highlight matcher that matches tokens by name.
#[derive(Debug, Clone)]
pub struct CTokenHighlightMatcher {
    /// The token name to match.
    pub token_name: String,
    /// Whether the match is case-sensitive.
    pub case_sensitive: bool,
}

impl CTokenHighlightMatcher {
    /// Create a new CTokenHighlightMatcher.
    pub fn new(token_name: &str, case_sensitive: bool) -> Self {
        Self {
            token_name: token_name.to_string(),
            case_sensitive,
        }
    }

    /// Check if a token text matches.
    pub fn matches(&self, text: &str) -> bool {
        if self.case_sensitive {
            text == self.token_name
        } else {
            text.eq_ignore_ascii_case(&self.token_name)
        }
    }
}

/// Color provider for token highlights.
#[derive(Debug, Clone)]
pub struct TokenHighlightColors {
    /// Color for keyword tokens.
    pub keyword: String,
    /// Color for comment tokens.
    pub comment: String,
    /// Color for type tokens.
    pub type_color: String,
    /// Color for function tokens.
    pub function: String,
    /// Color for variable tokens.
    pub variable: String,
    /// Color for constant tokens.
    pub constant: String,
    /// Color for parameter tokens.
    pub parameter: String,
    /// Color for global tokens.
    pub global: String,
    /// Color for default tokens.
    pub default: String,
    /// Color for error tokens.
    pub error: String,
    /// Color for special tokens.
    pub special: String,
}

impl Default for TokenHighlightColors {
    fn default() -> Self {
        Self {
            keyword: "#0000ff".to_string(),
            comment: "#808080".to_string(),
            type_color: "#800080".to_string(),
            function: "#0000ff".to_string(),
            variable: "#000000".to_string(),
            constant: "#008000".to_string(),
            parameter: "#804000".to_string(),
            global: "#008080".to_string(),
            default: "#000000".to_string(),
            error: "#ff0000".to_string(),
            special: "#8000ff".to_string(),
        }
    }
}

// ============================================================================
// CTokenHighlightMatcher (trait version)
// ============================================================================

/// Trait for matching Clang tokens that should be highlighted.
///
/// Ports Ghidra's `ghidra.app.decompiler.CTokenHighlightMatcher` interface.
///
/// The expected lifecycle is:
/// 1. `start(root)` -- called when a function is decompiled
/// 2. `get_token_highlight(token_text, syntax_type)` -- called for each token
/// 3. `end()` -- called when highlighting is complete
pub trait CTokenHighlightMatcherTrait: std::fmt::Debug + Send + Sync {
    /// Called at the beginning of a function decompilation.
    /// Default is a no-op.
    fn start(&mut self) {}

    /// Determine whether a token should be highlighted.
    /// Returns an optional highlight color (CSS color string).
    fn get_token_highlight(
        &self,
        token_text: &str,
        syntax_type: super::clang_node::SyntaxType,
    ) -> Option<String>;

    /// Called at the end of a function decompilation.
    /// Default is a no-op.
    fn end(&mut self) {}
}

/// A name-based token highlight matcher implementing the trait.
#[derive(Debug, Clone)]
pub struct NameBasedHighlightMatcher {
    /// The token name to match.
    pub token_name: String,
    /// The highlight color to apply.
    pub highlight_color: String,
    /// Whether the match is case-sensitive.
    pub case_sensitive: bool,
}

impl NameBasedHighlightMatcher {
    /// Create a new matcher.
    pub fn new(
        token_name: impl Into<String>,
        highlight_color: impl Into<String>,
        case_sensitive: bool,
    ) -> Self {
        Self {
            token_name: token_name.into(),
            highlight_color: highlight_color.into(),
            case_sensitive,
        }
    }
}

impl CTokenHighlightMatcherTrait for NameBasedHighlightMatcher {
    fn get_token_highlight(
        &self,
        token_text: &str,
        _syntax_type: super::clang_node::SyntaxType,
    ) -> Option<String> {
        let matches = if self.case_sensitive {
            token_text == self.token_name
        } else {
            token_text.eq_ignore_ascii_case(&self.token_name)
        };
        if matches {
            Some(self.highlight_color.clone())
        } else {
            None
        }
    }
}

/// A syntax-type-based token highlight matcher.
#[derive(Debug, Clone)]
pub struct SyntaxTypeHighlightMatcher {
    /// The syntax type to match.
    pub target_type: super::clang_node::SyntaxType,
    /// The highlight color to apply.
    pub highlight_color: String,
}

impl SyntaxTypeHighlightMatcher {
    /// Create a new matcher.
    pub fn new(
        target_type: super::clang_node::SyntaxType,
        highlight_color: impl Into<String>,
    ) -> Self {
        Self {
            target_type,
            highlight_color: highlight_color.into(),
        }
    }
}

impl CTokenHighlightMatcherTrait for SyntaxTypeHighlightMatcher {
    fn get_token_highlight(
        &self,
        _token_text: &str,
        syntax_type: super::clang_node::SyntaxType,
    ) -> Option<String> {
        if syntax_type == self.target_type {
            Some(self.highlight_color.clone())
        } else {
            None
        }
    }
}

// ============================================================================
// DecompilerHighlightService
// ============================================================================

/// Service for creating highlighters in the Decompiler UI.
///
/// Ports Ghidra's `ghidra.app.decompiler.DecompilerHighlightService` interface.
///
/// Clients create highlighters via this service.  Multiple highlighters may be
/// installed simultaneously.  Overlapping highlights will be blended.
pub trait DecompilerHighlightService: std::fmt::Debug + Send + Sync {
    /// Create a highlighter that applies to all decompiled functions.
    fn create_global_highlighter(
        &mut self,
        matcher: Box<dyn CTokenHighlightMatcherTrait>,
    ) -> HighlighterId;

    /// Create a highlighter scoped to a specific function (by entry address).
    fn create_function_highlighter(
        &mut self,
        function_address: u64,
        matcher: Box<dyn CTokenHighlightMatcherTrait>,
    ) -> HighlighterId;

    /// Create a named highlighter, replacing any existing highlighter with
    /// the same ID.  This is convenient for scripts that cannot hold on to
    /// highlighter references between executions.
    fn create_named_highlighter(
        &mut self,
        id: &str,
        matcher: Box<dyn CTokenHighlightMatcherTrait>,
    ) -> HighlighterId;

    /// Remove a highlighter by its ID.
    fn remove_highlighter(&mut self, id: HighlighterId);

    /// Remove all highlighters.
    fn clear_highlighters(&mut self);
}

/// Unique identifier for a decompiler highlighter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HighlighterId(pub u64);

// ============================================================================
// DecompilerMarginService
// ============================================================================

/// Service for adding custom margin areas to the Decompiler UI.
///
/// Ports Ghidra's `ghidra.app.decompiler.DecompilerMarginService` interface.
pub trait DecompilerMarginService: std::fmt::Debug + Send + Sync {
    /// Add a margin provider to the decompiler's primary window.
    fn add_margin_provider(&mut self, provider: Box<dyn DecompilerMarginProvider>);

    /// Remove a margin provider from the decompiler's primary window.
    fn remove_margin_provider(&mut self, provider_id: MarginProviderId);
}

/// Unique identifier for a margin provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MarginProviderId(pub u64);

/// Trait for a margin provider that renders content in the Decompiler margin.
///
/// A margin provider draws annotations (e.g. bookmarks, coverage bars,
/// breakpoint indicators) in the gutter area beside the decompiler output.
pub trait DecompilerMarginProvider: std::fmt::Debug + Send + Sync {
    /// The unique ID of this provider.
    fn id(&self) -> MarginProviderId;

    /// The preferred width of the margin in pixels.
    fn preferred_width(&self) -> f64 {
        20.0
    }

    /// Render the margin for a given line of decompiler output.
    ///
    /// Returns the height in pixels that was consumed, or 0 if nothing was rendered.
    fn paint_line(
        &self,
        line_number: usize,
        y: f64,
        width: f64,
        height: f64,
    ) -> f64;

    /// Called when the margin provider is no longer needed.
    fn dispose(&self) {}
}

// ============================================================================
// DecompileProcessFactory
// ============================================================================

/// Factory for creating decompiler process instances.
///
/// Ports Ghidra's `ghidra.app.decompiler.DecompileProcessFactory`.
///
/// Locates the native `decompile` binary and creates new process instances.
/// The factory caches the executable path after the first successful lookup.
#[derive(Debug)]
pub struct DecompileProcessFactory {
    /// Cached path to the native decompiler executable.
    exe_path: Option<String>,
}

impl DecompileProcessFactory {
    /// Create a new factory.
    pub fn new() -> Self {
        Self { exe_path: None }
    }

    /// Get or create a decompile process.
    ///
    /// The factory looks for the native `decompile` executable in the
    /// standard locations (next to the Rust binary, on `$PATH`, etc.)
    pub fn get(&mut self) -> Result<DecompileProcessHandle, String> {
        if self.exe_path.is_none() {
            self.exe_path = Some(self.find_exe_path()?);
        }
        let path = self.exe_path.as_ref().unwrap().clone();
        Ok(DecompileProcessHandle::new(path))
    }

    /// Release (dispose) a previously obtained decompile process.
    pub fn release(_handle: DecompileProcessHandle) {
        // Handle is dropped automatically; this is a hook for future cleanup.
    }

    /// Search for the native decompiler executable.
    fn find_exe_path(&self) -> Result<String, String> {
        // Try platform-specific names
        let names = if cfg!(target_os = "windows") {
            vec!["decompile.exe", "ghidraDecompiler.exe"]
        } else {
            vec!["decompile", "ghidraDecompiler"]
        };

        for name in &names {
            // Check next to the current executable
            if let Ok(exe_dir) = std::env::current_exe() {
                if let Some(dir) = exe_dir.parent() {
                    let candidate = dir.join(name);
                    if candidate.exists() {
                        return Ok(candidate.to_string_lossy().into_owned());
                    }
                }
            }

            // Check on PATH
            if let Ok(path) = std::env::var("PATH") {
                for dir in path.split(if cfg!(target_os = "windows") { ';' } else { ':' }) {
                    let candidate = std::path::Path::new(dir).join(name);
                    if candidate.exists() {
                        return Ok(candidate.to_string_lossy().into_owned());
                    }
                }
            }
        }

        Err(format!(
            "Could not find native decompiler executable ({:?}).  \
             Set the GHIDRA_INSTALL_DIR environment variable or ensure \
             'decompile' is on your PATH.",
            names
        ))
    }

    /// Clear the cached executable path.
    pub fn reset(&mut self) {
        self.exe_path = None;
    }
}

impl Default for DecompileProcessFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle to a decompiler process created by the factory.
#[derive(Debug)]
pub struct DecompileProcessHandle {
    /// Path to the native executable.
    pub exe_path: String,
    /// Whether this handle has been disposed.
    disposed: bool,
}

impl DecompileProcessHandle {
    /// Create a new process handle.
    pub fn new(exe_path: impl Into<String>) -> Self {
        Self {
            exe_path: exe_path.into(),
            disposed: false,
        }
    }

    /// The path to the native executable.
    pub fn executable_path(&self) -> &str {
        &self.exe_path
    }

    /// Whether this handle has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of this handle.
    pub fn dispose(&mut self) {
        self.disposed = true;
    }
}

impl Drop for DecompileProcessHandle {
    fn drop(&mut self) {
        self.dispose();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::clang_node::SyntaxType;

    #[test]
    fn test_ctoken_highlight_matcher_case_sensitive() {
        let matcher = CTokenHighlightMatcher::new("main", true);
        assert!(matcher.matches("main"));
        assert!(!matcher.matches("Main"));
        assert!(!matcher.matches("MAIN"));
    }

    #[test]
    fn test_ctoken_highlight_matcher_case_insensitive() {
        let matcher = CTokenHighlightMatcher::new("main", false);
        assert!(matcher.matches("main"));
        assert!(matcher.matches("Main"));
        assert!(matcher.matches("MAIN"));
    }

    #[test]
    fn test_token_highlight_colors_default() {
        let colors = TokenHighlightColors::default();
        assert!(!colors.keyword.is_empty());
        assert!(!colors.comment.is_empty());
        assert!(!colors.error.is_empty());
    }

    #[test]
    fn test_name_based_highlight_matcher() {
        let matcher = NameBasedHighlightMatcher::new("malloc", "#ff0000", true);
        assert_eq!(
            matcher.get_token_highlight("malloc", SyntaxType::Function),
            Some("#ff0000".to_string())
        );
        assert_eq!(
            matcher.get_token_highlight("free", SyntaxType::Function),
            None
        );
        assert_eq!(
            matcher.get_token_highlight("Malloc", SyntaxType::Function),
            None,
            "case sensitive should not match"
        );
    }

    #[test]
    fn test_name_based_highlight_matcher_case_insensitive() {
        let matcher = NameBasedHighlightMatcher::new("malloc", "#ff0000", false);
        assert_eq!(
            matcher.get_token_highlight("Malloc", SyntaxType::Function),
            Some("#ff0000".to_string())
        );
    }

    #[test]
    fn test_syntax_type_highlight_matcher() {
        let matcher = SyntaxTypeHighlightMatcher::new(SyntaxType::Keyword, "#0000ff");
        assert_eq!(
            matcher.get_token_highlight("if", SyntaxType::Keyword),
            Some("#0000ff".to_string())
        );
        assert_eq!(
            matcher.get_token_highlight("x", SyntaxType::Variable),
            None
        );
    }

    #[test]
    fn test_decompile_process_factory_new() {
        let factory = DecompileProcessFactory::new();
        assert!(factory.exe_path.is_none());
    }

    #[test]
    fn test_decompile_process_handle() {
        let handle = DecompileProcessHandle::new("/usr/bin/decompile");
        assert_eq!(handle.executable_path(), "/usr/bin/decompile");
        assert!(!handle.is_disposed());
    }

    #[test]
    fn test_decompile_process_handle_dispose() {
        let mut handle = DecompileProcessHandle::new("/usr/bin/decompile");
        handle.dispose();
        assert!(handle.is_disposed());
    }

    #[test]
    fn test_highlighter_id_equality() {
        let a = HighlighterId(1);
        let b = HighlighterId(1);
        let c = HighlighterId(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_margin_provider_id_equality() {
        let a = MarginProviderId(1);
        let b = MarginProviderId(1);
        assert_eq!(a, b);
    }
}
