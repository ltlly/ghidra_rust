//! Detailed script metadata parsing.
//!
//! Ported from `ghidra.app.script.ScriptInfo` (the detailed version that parses
//! script headers to extract metadata annotations).
//!
//! This module provides header parsing for `@author`, `@category`, `@keybinding`,
//! `@menupath`, `@toolbar`, and `@runtime` annotations found in script source files.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Script metadata annotation tags
// ---------------------------------------------------------------------------

/// The delimiter used in categories and menu paths.
pub const METADATA_DELIMITER: &str = ".";

/// `@author` tag.
pub const TAG_AUTHOR: &str = "@author";
/// `@category` tag.
pub const TAG_CATEGORY: &str = "@category";
/// `@keybinding` tag.
pub const TAG_KEYBINDING: &str = "@keybinding";
/// `@menupath` tag.
pub const TAG_MENUPATH: &str = "@menupath";
/// `@toolbar` tag.
pub const TAG_TOOLBAR: &str = "@toolbar";
/// `@runtime` tag.
pub const TAG_RUNTIME: &str = "@runtime";
/// `@importpackage` tag (not included in METADATA to avoid pre-populating).
pub const TAG_IMPORTPACKAGE: &str = "@importpackage";

/// All metadata tags that are written into new script templates.
pub const METADATA_TAGS: &[&str] = &[
    TAG_AUTHOR,
    TAG_CATEGORY,
    TAG_KEYBINDING,
    TAG_MENUPATH,
    TAG_TOOLBAR,
    TAG_RUNTIME,
];

// ---------------------------------------------------------------------------
// Runtime environment
// ---------------------------------------------------------------------------

/// Known runtime environments for scripts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptRuntime {
    /// Jython / Python scripts.
    Jython,
    /// Java source scripts.
    Java,
    /// Java compiled class scripts.
    JavaCompiled,
    /// Groovy scripts.
    Groovy,
    /// JavaScript scripts.
    JavaScript,
    /// Unknown / unsupported runtime.
    Unknown,
}

impl ScriptRuntime {
    /// Return the canonical runtime name (matches `@runtime` annotation values).
    pub fn name(&self) -> &str {
        match self {
            Self::Jython => "jython",
            Self::Java => "java",
            Self::JavaCompiled => "java-compiled",
            Self::Groovy => "groovy",
            Self::JavaScript => "javascript",
            Self::Unknown => "unknown",
        }
    }

    /// Infer the runtime from a file extension.
    pub fn from_extension(ext: &str) -> Self {
        match ext {
            "py" => Self::Jython,
            "java" => Self::Java,
            "class" => Self::JavaCompiled,
            "groovy" => Self::Groovy,
            "js" => Self::JavaScript,
            _ => Self::Unknown,
        }
    }

    /// Parse a runtime name from a `@runtime` annotation.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "jython" | "python" => Self::Jython,
            "java" => Self::Java,
            "java-compiled" => Self::JavaCompiled,
            "groovy" => Self::Groovy,
            "javascript" | "js" => Self::JavaScript,
            _ => Self::Unknown,
        }
    }

    /// The comment prefix used by this runtime.
    pub fn comment_prefix(&self) -> &str {
        match self {
            Self::Jython | Self::Groovy => "#",
            Self::Java | Self::JavaCompiled | Self::JavaScript => "//",
            Self::Unknown => "#",
        }
    }

    /// The certification header start marker (if any).
    pub fn certify_header_start(&self) -> Option<&str> {
        match self {
            Self::Java | Self::JavaCompiled => Some("/* ###"),
            _ => None,
        }
    }
}

impl fmt::Display for ScriptRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// ParsedScriptInfo -- detailed metadata from header parsing
// ---------------------------------------------------------------------------

/// Detailed script metadata parsed from source file headers.
///
/// Ported from `ghidra.app.script.ScriptInfo`.
#[derive(Debug, Clone)]
pub struct ParsedScriptInfo {
    /// Source file path.
    pub source_file: PathBuf,
    /// Script description (from comment header before `@` tags).
    pub description: String,
    /// Author name (`@author`).
    pub author: Option<String>,
    /// Category path segments (`@category`).
    pub category: Vec<String>,
    /// Key binding (`@keybinding`).
    pub key_binding: Option<String>,
    /// Menu path segments (`@menupath`).
    pub menu_path: Option<Vec<String>>,
    /// Toolbar icon path (`@toolbar`).
    pub toolbar: Option<String>,
    /// Import package (`@importpackage`).
    pub import_package: Option<String>,
    /// Runtime environment (`@runtime`).
    pub runtime: ScriptRuntime,
    /// Whether the script has compile errors.
    pub has_compile_errors: bool,
    /// Whether this is a duplicate script name.
    pub is_duplicate: bool,
    /// Additional raw annotations not in the standard set.
    pub extra_annotations: HashMap<String, String>,
    /// File modification time (Unix millis) at last parse.
    pub last_modified: u64,
}

impl ParsedScriptInfo {
    /// Create a new info for the given source file.
    pub fn new(source_file: PathBuf, runtime: ScriptRuntime) -> Self {
        Self {
            source_file,
            description: String::new(),
            author: None,
            category: Vec::new(),
            key_binding: None,
            menu_path: None,
            toolbar: None,
            import_package: None,
            runtime,
            has_compile_errors: false,
            is_duplicate: false,
            extra_annotations: HashMap::new(),
            last_modified: 0,
        }
    }

    /// The script file name (without directory).
    pub fn name(&self) -> &str {
        self.source_file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
    }

    /// The file extension.
    pub fn extension(&self) -> &str {
        self.source_file
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
    }

    /// Whether the script has an unsupported provider.
    pub fn has_unsupported_provider(&self) -> bool {
        self.runtime == ScriptRuntime::Unknown
    }

    /// The category as a dot-separated path.
    pub fn category_path(&self) -> String {
        self.category.join(METADATA_DELIMITER)
    }

    /// The menu path as a slash-separated string.
    pub fn menu_path_string(&self) -> String {
        self.menu_path
            .as_ref()
            .map(|p| p.join("/"))
            .unwrap_or_default()
    }

    /// Parse metadata from script source text.
    ///
    /// This parses comment headers looking for `@` annotations.
    pub fn parse_from_source(&mut self, source: &str) {
        let prefix = self.runtime.comment_prefix().to_string();
        let certify_start = self.runtime.certify_header_start().map(|s| s.to_string());

        let mut description_buf = String::new();
        let mut hit_at_sign = false;
        let mut in_certify_header = false;
        let mut in_block_comment = false;

        for line in source.lines() {
            let trimmed = line.trim();

            // Handle block comment start/end
            if self.runtime == ScriptRuntime::Java
                || self.runtime == ScriptRuntime::JavaCompiled
                || self.runtime == ScriptRuntime::JavaScript
            {
                if trimmed.starts_with("/*") {
                    if let Some(ref start) = certify_start {
                        if trimmed.starts_with(start.as_str()) {
                            in_certify_header = true;
                            continue;
                        }
                    }
                    in_block_comment = true;
                    continue;
                }
                if in_block_comment {
                    if trimmed.contains("*/") {
                        in_block_comment = false;
                    }
                    continue;
                }
                if in_certify_header {
                    if trimmed.contains("*/") {
                        in_certify_header = false;
                    }
                    continue;
                }
            }

            // Parse line comments
            if trimmed.starts_with(&prefix) {
                let content = trimmed[prefix.len()..].trim();

                if content.starts_with('@') {
                    hit_at_sign = true;
                    self.parse_annotation(content);
                } else if !hit_at_sign {
                    // Description text comes before any @ tags
                    if !content.is_empty() {
                        description_buf.push_str(content);
                        description_buf.push('\n');
                    }
                }
            } else if trimmed.is_empty() && !hit_at_sign {
                continue; // Allow blank lines between comment sections
            } else if !trimmed.is_empty() {
                break; // Non-comment, non-blank line ends the header
            }
        }

        if !description_buf.is_empty() {
            self.description = description_buf.trim().to_string();
        }
    }

    fn parse_annotation(&mut self, line: &str) {
        let (tag, value) = if let Some(pos) = line.find(char::is_whitespace) {
            (&line[..pos], line[pos..].trim())
        } else {
            (line, "")
        };

        match tag {
            TAG_AUTHOR => self.author = Some(value.to_string()),
            TAG_CATEGORY => {
                self.category = value
                    .split('.')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            TAG_KEYBINDING => self.key_binding = Some(value.to_string()),
            TAG_MENUPATH => {
                self.menu_path = Some(
                    value
                        .split('/')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
            }
            TAG_TOOLBAR => self.toolbar = Some(value.to_string()),
            TAG_RUNTIME => self.runtime = ScriptRuntime::parse(value),
            TAG_IMPORTPACKAGE => self.import_package = Some(value.to_string()),
            _ => {
                self.extra_annotations
                    .insert(tag.to_string(), value.to_string());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ScriptInfoManager
// ---------------------------------------------------------------------------

/// Manages script metadata for all known scripts.
///
/// Ported from `ghidra.app.script.GhidraScriptInfoManager`.
#[derive(Debug, Default)]
pub struct ScriptInfoManager {
    /// Metadata for all known scripts.
    infos: Vec<ParsedScriptInfo>,
}

impl ScriptInfoManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a script info.
    pub fn add(&mut self, info: ParsedScriptInfo) {
        self.infos.push(info);
    }

    /// Get the number of known scripts.
    pub fn len(&self) -> usize {
        self.infos.len()
    }

    /// Whether the manager is empty.
    pub fn is_empty(&self) -> bool {
        self.infos.is_empty()
    }

    /// Get a script info by index.
    pub fn get(&self, index: usize) -> Option<&ParsedScriptInfo> {
        self.infos.get(index)
    }

    /// Get all script infos.
    pub fn all(&self) -> &[ParsedScriptInfo] {
        &self.infos
    }

    /// Find a script by name.
    pub fn find_by_name(&self, name: &str) -> Option<&ParsedScriptInfo> {
        self.infos.iter().find(|i| i.name() == name)
    }

    /// Find scripts in a category.
    pub fn find_by_category(&self, category: &str) -> Vec<&ParsedScriptInfo> {
        self.infos
            .iter()
            .filter(|i| i.category_path() == category)
            .collect()
    }

    /// Remove a script by path.
    pub fn remove_by_path(&mut self, path: &Path) -> Option<ParsedScriptInfo> {
        if let Some(pos) = self.infos.iter().position(|i| i.source_file == path) {
            Some(self.infos.remove(pos))
        } else {
            None
        }
    }

    /// Mark duplicate script names.
    pub fn mark_duplicates(&mut self) {
        use std::collections::{HashMap, HashSet};
        // Count occurrences of each name.
        let mut counts: HashMap<String, usize> = HashMap::new();
        for info in &self.infos {
            *counts.entry(info.name().to_string()).or_insert(0) += 1;
        }
        // Collect names that appear more than once.
        let dup_names: HashSet<String> = counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(name, _)| name)
            .collect();
        // Mark all entries with duplicate names.
        for info in &mut self.infos {
            if dup_names.contains(info.name()) {
                info.is_duplicate = true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GhidraScriptConstants
// ---------------------------------------------------------------------------

/// Constants shared across the scripting subsystem.
///
/// Ported from `ghidra.app.script.GhidraScriptConstants`.
pub struct GhidraScriptConstants;

impl GhidraScriptConstants {
    /// System property that overrides the scripts source directory.
    pub const USER_SCRIPTS_DIR_PROPERTY: &'static str = "ghidra.user.scripts.dir";

    /// Default name for new scripts.
    pub const DEFAULT_SCRIPT_NAME: &'static str = "NewScript";
}

// ---------------------------------------------------------------------------
// GhidraScriptUnsupportedClassVersionError
// ---------------------------------------------------------------------------

/// Error raised when a compiled script class file targets a JVM version
/// newer than the running environment supports.
///
/// Ported from `ghidra.app.script.GhidraScriptUnsupportedClassVersionError`.
#[derive(Debug, Clone)]
pub struct UnsupportedClassVersionError {
    /// The script file path.
    pub script_path: PathBuf,
    /// The class file major version.
    pub class_version: u32,
    /// The maximum supported JVM major version.
    pub max_supported_version: u32,
}

impl fmt::Display for UnsupportedClassVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Script '{}' requires Java {} but only Java {} is supported",
            self.script_path.display(),
            self.class_version,
            self.max_supported_version
        )
    }
}

impl std::error::Error for UnsupportedClassVersionError {}

// ---------------------------------------------------------------------------
// GhidraScriptLoadException
// ---------------------------------------------------------------------------

/// Error loading or compiling a script.
#[derive(Debug, Clone)]
pub struct ScriptLoadError {
    /// The script path that failed to load.
    pub script_path: PathBuf,
    /// Human-readable error message.
    pub message: String,
    /// Optional underlying cause.
    pub cause: Option<String>,
}

impl fmt::Display for ScriptLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Failed to load script '{}': {}",
            self.script_path.display(),
            self.message
        )
    }
}

impl std::error::Error for ScriptLoadError {}

// ---------------------------------------------------------------------------
// ImproperUseException
// ---------------------------------------------------------------------------

/// Exception indicating the scripting API is being used incorrectly.
///
/// Ported from `ghidra.app.script.ImproperUseException`.
#[derive(Debug, Clone)]
pub struct ImproperUseException {
    /// Explanation of the improper use.
    pub message: String,
}

impl fmt::Display for ImproperUseException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Improper use: {}", self.message)
    }
}

impl std::error::Error for ImproperUseException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_runtime_from_extension() {
        assert_eq!(ScriptRuntime::from_extension("py"), ScriptRuntime::Jython);
        assert_eq!(ScriptRuntime::from_extension("java"), ScriptRuntime::Java);
        assert_eq!(ScriptRuntime::from_extension("groovy"), ScriptRuntime::Groovy);
        assert_eq!(ScriptRuntime::from_extension("js"), ScriptRuntime::JavaScript);
        assert_eq!(ScriptRuntime::from_extension("rb"), ScriptRuntime::Unknown);
    }

    #[test]
    fn test_script_runtime_parse() {
        assert_eq!(ScriptRuntime::parse("jython"), ScriptRuntime::Jython);
        assert_eq!(ScriptRuntime::parse("python"), ScriptRuntime::Jython);
        assert_eq!(ScriptRuntime::parse("JAVA"), ScriptRuntime::Java);
        assert_eq!(ScriptRuntime::parse("groovy"), ScriptRuntime::Groovy);
    }

    #[test]
    fn test_script_runtime_comment_prefix() {
        assert_eq!(ScriptRuntime::Jython.comment_prefix(), "#");
        assert_eq!(ScriptRuntime::Java.comment_prefix(), "//");
        assert_eq!(ScriptRuntime::Groovy.comment_prefix(), "#");
    }

    #[test]
    fn test_script_runtime_certify_header() {
        assert_eq!(
            ScriptRuntime::Java.certify_header_start(),
            Some("/* ###")
        );
        assert_eq!(ScriptRuntime::Jython.certify_header_start(), None);
    }

    #[test]
    fn test_parsed_script_info_basic() {
        let info = ParsedScriptInfo::new(
            PathBuf::from("/scripts/MyScript.py"),
            ScriptRuntime::Jython,
        );
        assert_eq!(info.name(), "MyScript");
        assert_eq!(info.extension(), "py");
        assert!(!info.has_unsupported_provider());
        assert_eq!(info.category_path(), "");
    }

    #[test]
    fn test_parse_from_source_python() {
        let source = "# This script does amazing things.\n\
                       # It can parse binary files.\n\
                       # @author John Doe\n\
                       # @category Analysis\n\
                       # @keybinding ctrl shift A\n\
                       # @menupath Analysis/My Tools/Amazing\n\
                       # @toolbar amazing.png\n\
                       import ghidra\n";
        let mut info = ParsedScriptInfo::new(
            PathBuf::from("/scripts/amazing.py"),
            ScriptRuntime::Jython,
        );
        info.parse_from_source(source);

        assert_eq!(info.description, "This script does amazing things.\nIt can parse binary files.");
        assert_eq!(info.author.as_deref(), Some("John Doe"));
        assert_eq!(info.category, vec!["Analysis"]);
        assert_eq!(info.key_binding.as_deref(), Some("ctrl shift A"));
        assert!(info.menu_path.is_some());
        assert_eq!(info.toolbar.as_deref(), Some("amazing.png"));
    }

    #[test]
    fn test_parse_from_source_java() {
        let source = r#"/* ###
 * IP: GHIDRA
 * Licensed under Apache 2.0
 */
// This is a Java script for data analysis.
// @author Jane Smith
// @category Data
import ghidra.program.model.listing.*;
public class MyScript extends GhidraScript { }
"#;
        let mut info = ParsedScriptInfo::new(
            PathBuf::from("/scripts/MyScript.java"),
            ScriptRuntime::Java,
        );
        info.parse_from_source(source);

        assert_eq!(info.author.as_deref(), Some("Jane Smith"));
        assert_eq!(info.category, vec!["Data"]);
        assert!(info.description.contains("Java script for data analysis"));
    }

    #[test]
    fn test_script_info_manager() {
        let mut mgr = ScriptInfoManager::new();
        assert!(mgr.is_empty());

        let info1 = ParsedScriptInfo::new(
            PathBuf::from("/scripts/a.py"),
            ScriptRuntime::Jython,
        );
        let mut info2 = ParsedScriptInfo::new(
            PathBuf::from("/scripts/b.py"),
            ScriptRuntime::Jython,
        );
        info2.category.push("Analysis".to_string());

        mgr.add(info1);
        mgr.add(info2);
        assert_eq!(mgr.len(), 2);

        let found = mgr.find_by_name("a");
        assert!(found.is_some());

        let analysis_scripts = mgr.find_by_category("Analysis");
        assert_eq!(analysis_scripts.len(), 1);
    }

    #[test]
    fn test_script_info_manager_duplicates() {
        let mut mgr = ScriptInfoManager::new();
        mgr.add(ParsedScriptInfo::new(
            PathBuf::from("/dir1/script.py"),
            ScriptRuntime::Jython,
        ));
        mgr.add(ParsedScriptInfo::new(
            PathBuf::from("/dir2/script.py"),
            ScriptRuntime::Jython,
        ));

        mgr.mark_duplicates();
        // Both should be marked as duplicate since they share the name "script"
        assert!(mgr.get(0).unwrap().is_duplicate);
        assert!(mgr.get(1).unwrap().is_duplicate);
    }

    #[test]
    fn test_category_path() {
        let mut info = ParsedScriptInfo::new(
            PathBuf::from("/s.py"),
            ScriptRuntime::Jython,
        );
        info.category = vec!["Analysis".to_string(), "DWARF".to_string()];
        assert_eq!(info.category_path(), "Analysis.DWARF");
    }

    #[test]
    fn test_menu_path_string() {
        let mut info = ParsedScriptInfo::new(
            PathBuf::from("/s.py"),
            ScriptRuntime::Jython,
        );
        info.menu_path = Some(vec![
            "Analysis".to_string(),
            "My Tools".to_string(),
            "Amazing".to_string(),
        ]);
        assert_eq!(info.menu_path_string(), "Analysis/My Tools/Amazing");
    }

    #[test]
    fn test_unsupported_class_version_error() {
        let err = UnsupportedClassVersionError {
            script_path: PathBuf::from("/scripts/NewScript.class"),
            class_version: 65,
            max_supported_version: 61,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("65"));
        assert!(msg.contains("61"));
    }

    #[test]
    fn test_script_load_error() {
        let err = ScriptLoadError {
            script_path: PathBuf::from("/scripts/bad.py"),
            message: "Syntax error".to_string(),
            cause: Some("unexpected token".to_string()),
        };
        assert!(format!("{}", err).contains("bad.py"));
    }

    #[test]
    fn test_improper_use_exception() {
        let err = ImproperUseException {
            message: "Cannot call getByte() on a non-initialized block".to_string(),
        };
        assert!(format!("{}", err).contains("getByte"));
    }

    #[test]
    fn test_metadata_tags() {
        assert_eq!(METADATA_TAGS.len(), 6);
        assert!(METADATA_TAGS.contains(&"@author"));
        assert!(METADATA_TAGS.contains(&"@category"));
        assert!(METADATA_TAGS.contains(&"@runtime"));
    }

    #[test]
    fn test_ghidra_script_constants() {
        assert_eq!(
            GhidraScriptConstants::USER_SCRIPTS_DIR_PROPERTY,
            "ghidra.user.scripts.dir"
        );
        assert_eq!(GhidraScriptConstants::DEFAULT_SCRIPT_NAME, "NewScript");
    }
}
