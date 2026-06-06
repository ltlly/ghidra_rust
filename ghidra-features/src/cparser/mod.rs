//! C source parser plugin for importing C header definitions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.cparser` package.
//!
//! Provides functionality to parse C source/header files and import
//! their type definitions (structs, unions, enums, typedefs, function
//! signatures) into a Ghidra program's data type manager.
//!
//! # Key Types
//!
//! - [`CParserPlugin`] -- Plugin providing the "Parse C Source" action
//! - [`CParserOptions`] -- Configuration for the C parser
//! - [`CParserTask`] -- Background task that performs parsing
//! - [`IncludePath`] -- Represents an include search path
//! - [`ParseResult`] -- Results of a C parsing operation
//! - [`ParsedType`] -- A data type parsed from C source

/// C parser plugin, task, include file finder, and parse dialog.
///
/// Ported from `ghidra.app.plugin.core.cparser.CParserPlugin`,
/// `CParserTask`, `IncludeFileFinder`, and `ParseDialog`.
pub mod plugin;

/// Include file finder and preprocessor argument builder.
///
/// Ported from `ghidra.app.plugin.core.cparser.IncludeFileFinder`
/// and preprocessor invocation logic.
pub mod task;

use std::collections::HashMap;
use std::path::PathBuf;

/// Default profile name for C parser options.
pub const DEFAULT_PROFILE: &str = "default";

/// Maximum include directory depth to prevent infinite recursion.
pub const MAX_INCLUDE_DEPTH: usize = 64;

/// Action name for the parse C source command.
pub const PARSE_ACTION_NAME: &str = "Parse C Source";

// ---------------------------------------------------------------------------
// Include path
// ---------------------------------------------------------------------------

/// Represents an include search path for the C parser.
///
/// Can be a system path (angle-bracket includes) or a user path
/// (quoted includes).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IncludePath {
    /// System include path (e.g., `/usr/include`).
    System(PathBuf),
    /// User/project include path.
    User(PathBuf),
}

impl IncludePath {
    /// Get the underlying path.
    pub fn path(&self) -> &PathBuf {
        match self {
            Self::System(p) | Self::User(p) => p,
        }
    }

    /// Whether this is a system include path.
    pub fn is_system(&self) -> bool {
        matches!(self, Self::System(_))
    }
}

// ---------------------------------------------------------------------------
// Parsed type
// ---------------------------------------------------------------------------

/// A data type parsed from C source code.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedType {
    /// A C struct definition.
    Struct {
        /// The struct name.
        name: String,
        /// Field names and their type names.
        fields: Vec<(String, String)>,
        /// Packed byte size, if known.
        size: Option<u64>,
    },
    /// A C union definition.
    Union {
        /// The union name.
        name: String,
        /// Member names and their type names.
        members: Vec<(String, String)>,
        /// Packed byte size, if known.
        size: Option<u64>,
    },
    /// A C enum definition.
    Enum {
        /// The enum name.
        name: String,
        /// Enum variant names to their integer values.
        variants: Vec<(String, i64)>,
        /// Whether this is a scoped enum (C++11 `enum class`).
        scoped: bool,
    },
    /// A C typedef.
    Typedef {
        /// The new type name.
        name: String,
        /// The aliased type name.
        aliased_type: String,
    },
    /// A function declaration/definition.
    Function {
        /// Function name.
        name: String,
        /// Return type name.
        return_type: String,
        /// Parameter names and types.
        parameters: Vec<(String, String)>,
        /// Whether the function is variadic.
        variadic: bool,
    },
}

impl ParsedType {
    /// Get the name of this parsed type.
    pub fn name(&self) -> &str {
        match self {
            Self::Struct { name, .. }
            | Self::Union { name, .. }
            | Self::Enum { name, .. }
            | Self::Typedef { name, .. }
            | Self::Function { name, .. } => name,
        }
    }

    /// Human-readable kind label.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Struct { .. } => "struct",
            Self::Union { .. } => "union",
            Self::Enum { .. } => "enum",
            Self::Typedef { .. } => "typedef",
            Self::Function { .. } => "function",
        }
    }
}

// ---------------------------------------------------------------------------
// C parser options
// ---------------------------------------------------------------------------

/// Options controlling the C parser behavior.
///
/// Ported from `ghidra.app.plugin.core.cparser.ParseDialog` options.
#[derive(Debug, Clone)]
pub struct CParserOptions {
    /// Include search paths.
    pub include_paths: Vec<IncludePath>,
    /// Preprocessor definitions (`NAME` or `NAME=VALUE`).
    pub defines: HashMap<String, Option<String>>,
    /// Whether to parse all data types or only explicitly requested ones.
    pub parse_all: bool,
    /// Whether to handle `#pragma pack` directives.
    pub handle_pragma_pack: bool,
    /// Whether to attempt to resolve unknown types.
    pub resolve_types: bool,
    /// The data organization (pointer size, alignment, etc.) to use.
    pub data_organization: Option<DataOrganization>,
    /// Profile name for persisting options.
    pub profile_name: String,
}

/// Simplified data organization settings for the C parser.
#[derive(Debug, Clone)]
pub struct DataOrganization {
    /// Size of a pointer in bytes.
    pub pointer_size: u8,
    /// Default alignment for structs.
    pub default_alignment: u8,
    /// Whether to use big-endian byte order.
    pub big_endian: bool,
    /// Whether `char` is signed by default.
    pub char_signed: bool,
}

impl Default for DataOrganization {
    fn default() -> Self {
        Self {
            pointer_size: 8,
            default_alignment: 8,
            big_endian: false,
            char_signed: true,
        }
    }
}

impl Default for CParserOptions {
    fn default() -> Self {
        Self {
            include_paths: Vec::new(),
            defines: HashMap::new(),
            parse_all: true,
            handle_pragma_pack: true,
            resolve_types: true,
            data_organization: None,
            profile_name: DEFAULT_PROFILE.to_string(),
        }
    }
}

impl CParserOptions {
    /// Add a preprocessor define.
    pub fn add_define(&mut self, name: impl Into<String>, value: Option<String>) {
        self.defines.insert(name.into(), value);
    }

    /// Add a system include path.
    pub fn add_system_include(&mut self, path: impl Into<PathBuf>) {
        self.include_paths
            .push(IncludePath::System(path.into()));
    }

    /// Add a user include path.
    pub fn add_user_include(&mut self, path: impl Into<PathBuf>) {
        self.include_paths
            .push(IncludePath::User(path.into()));
    }

    /// Get the command-line preprocessor arguments for these options.
    pub fn preprocessor_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for inc in &self.include_paths {
            args.push("-I".to_string());
            args.push(inc.path().to_string_lossy().to_string());
        }
        for (name, value) in &self.defines {
            args.push("-D".to_string());
            match value {
                Some(v) => args.push(format!("{}={}", name, v)),
                None => args.push(name.clone()),
            }
        }
        args
    }
}

// ---------------------------------------------------------------------------
// Parse result
// ---------------------------------------------------------------------------

/// Result of a C source parsing operation.
#[derive(Debug, Clone)]
pub struct ParseResult {
    /// Successfully parsed types.
    pub types: Vec<ParsedType>,
    /// Warning messages generated during parsing.
    pub warnings: Vec<ParseMessage>,
    /// Error messages generated during parsing.
    pub errors: Vec<ParseMessage>,
    /// Total number of lines parsed.
    pub lines_parsed: usize,
}

impl Default for ParseResult {
    fn default() -> Self {
        Self {
            types: Vec::new(),
            warnings: Vec::new(),
            errors: Vec::new(),
            lines_parsed: 0,
        }
    }
}

impl ParseResult {
    /// Whether the parse completed without errors.
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }

    /// Number of types successfully parsed.
    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    /// Get all parsed types of a specific kind.
    pub fn types_of_kind(&self, kind: &str) -> Vec<&ParsedType> {
        self.types.iter().filter(|t| t.kind() == kind).collect()
    }
}

/// A diagnostic message from the C parser.
#[derive(Debug, Clone)]
pub struct ParseMessage {
    /// Source file path, if known.
    pub file: Option<String>,
    /// Line number (1-based), if known.
    pub line: Option<usize>,
    /// Column number (1-based), if known.
    pub column: Option<usize>,
    /// The message text.
    pub message: String,
}

impl ParseMessage {
    /// Create a new parse message with just text.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            file: None,
            line: None,
            column: None,
            message: message.into(),
        }
    }

    /// Create a parse message with location info.
    pub fn with_location(
        message: impl Into<String>,
        file: impl Into<String>,
        line: usize,
        column: usize,
    ) -> Self {
        Self {
            file: Some(file.into()),
            line: Some(line),
            column: Some(column),
            message: message.into(),
        }
    }

    /// Format as a user-facing string.
    pub fn format(&self) -> String {
        match (&self.file, self.line, self.column) {
            (Some(f), Some(l), Some(c)) => format!("{}:{}:{}: {}", f, l, c, self.message),
            (Some(f), Some(l), None) => format!("{}:{}: {}", f, l, self.message),
            _ => self.message.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// C parser task
// ---------------------------------------------------------------------------

/// Background task that parses C source files and imports their types.
///
/// Ported from `ghidra.app.plugin.core.cparser.CParserTask`.
#[derive(Debug)]
pub struct CParserTask {
    /// Source files to parse.
    pub source_files: Vec<PathBuf>,
    /// Parser options.
    pub options: CParserOptions,
    /// Result of the parse (populated after execution).
    result: Option<ParseResult>,
}

impl CParserTask {
    /// Create a new C parser task.
    pub fn new(source_files: Vec<PathBuf>, options: CParserOptions) -> Self {
        Self {
            source_files,
            options,
            result: None,
        }
    }

    /// Get the parse result, if available.
    pub fn result(&self) -> Option<&ParseResult> {
        self.result.as_ref()
    }

    /// Execute the parsing task.
    ///
    /// Returns the parse result. In a full implementation, this would
    /// invoke a C preprocessor and parse the translation unit.
    pub fn execute(&mut self) -> ParseResult {
        let result = ParseResult::default();
        self.result = Some(result.clone());
        result
    }
}

// ---------------------------------------------------------------------------
// C parser plugin
// ---------------------------------------------------------------------------

/// Plugin providing the "Parse C Source" action.
///
/// Ported from `ghidra.app.plugin.core.cparser.CParserPlugin`.
#[derive(Debug)]
pub struct CParserPlugin {
    /// Current parser options.
    options: CParserOptions,
    /// Source file finder paths.
    search_paths: Vec<PathBuf>,
}

impl CParserPlugin {
    /// Create a new C parser plugin.
    pub fn new() -> Self {
        Self {
            options: CParserOptions::default(),
            search_paths: Vec::new(),
        }
    }

    /// Get the current parser options.
    pub fn options(&self) -> &CParserOptions {
        &self.options
    }

    /// Get a mutable reference to the parser options.
    pub fn options_mut(&mut self) -> &mut CParserOptions {
        &mut self.options
    }

    /// Set the search paths for finding include files.
    pub fn set_search_paths(&mut self, paths: Vec<PathBuf>) {
        self.search_paths = paths;
    }

    /// Get the search paths.
    pub fn search_paths(&self) -> &[PathBuf] {
        &self.search_paths
    }
}

impl Default for CParserPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_include_path_variants() {
        let sys = IncludePath::System(PathBuf::from("/usr/include"));
        assert!(sys.is_system());
        assert_eq!(sys.path(), &PathBuf::from("/usr/include"));

        let user = IncludePath::User(PathBuf::from("./include"));
        assert!(!user.is_system());
    }

    #[test]
    fn test_parsed_type_names() {
        let s = ParsedType::Struct {
            name: "my_struct".into(),
            fields: vec![("x".into(), "int".into())],
            size: Some(4),
        };
        assert_eq!(s.name(), "my_struct");
        assert_eq!(s.kind(), "struct");

        let e = ParsedType::Enum {
            name: "color".into(),
            variants: vec![("RED".into(), 0), ("GREEN".into(), 1)],
            scoped: false,
        };
        assert_eq!(e.kind(), "enum");
    }

    #[test]
    fn test_c_parser_options_default() {
        let opts = CParserOptions::default();
        assert!(opts.parse_all);
        assert!(opts.handle_pragma_pack);
        assert!(opts.resolve_types);
        assert_eq!(opts.profile_name, "default");
    }

    #[test]
    fn test_c_parser_options_add_define() {
        let mut opts = CParserOptions::default();
        opts.add_define("DEBUG", None);
        opts.add_define("VERSION", Some("2.0".into()));
        assert_eq!(opts.defines.len(), 2);
        assert_eq!(opts.defines["DEBUG"], None);
        assert_eq!(opts.defines["VERSION"], Some("2.0".into()));
    }

    #[test]
    fn test_preprocessor_args() {
        let mut opts = CParserOptions::default();
        opts.add_system_include("/usr/include");
        opts.add_user_include("./my_include");
        opts.add_define("DEBUG", None);

        let args = opts.preprocessor_args();
        assert!(args.contains(&"-I".to_string()));
        assert!(args.contains(&"/usr/include".to_string()));
        assert!(args.contains(&"-D".to_string()));
        assert!(args.contains(&"DEBUG".to_string()));
    }

    #[test]
    fn test_parse_result_success() {
        let mut result = ParseResult::default();
        assert!(result.is_success());
        assert_eq!(result.type_count(), 0);

        result.types.push(ParsedType::Typedef {
            name: "u32".into(),
            aliased_type: "unsigned int".into(),
        });
        assert_eq!(result.type_count(), 1);
    }

    #[test]
    fn test_parse_result_types_of_kind() {
        let mut result = ParseResult::default();
        result.types.push(ParsedType::Struct {
            name: "A".into(),
            fields: vec![],
            size: None,
        });
        result.types.push(ParsedType::Typedef {
            name: "B".into(),
            aliased_type: "int".into(),
        });
        result.types.push(ParsedType::Struct {
            name: "C".into(),
            fields: vec![],
            size: None,
        });

        assert_eq!(result.types_of_kind("struct").len(), 2);
        assert_eq!(result.types_of_kind("typedef").len(), 1);
        assert_eq!(result.types_of_kind("enum").len(), 0);
    }

    #[test]
    fn test_parse_message_format() {
        let msg = ParseMessage::new("unexpected token");
        assert_eq!(msg.format(), "unexpected token");

        let msg = ParseMessage::with_location("syntax error", "test.h", 42, 10);
        assert_eq!(msg.format(), "test.h:42:10: syntax error");
    }

    #[test]
    fn test_c_parser_task_lifecycle() {
        let mut task = CParserTask::new(
            vec![PathBuf::from("test.h")],
            CParserOptions::default(),
        );
        assert!(task.result().is_none());

        let result = task.execute();
        assert!(result.is_success());
        assert!(task.result().is_some());
    }

    #[test]
    fn test_c_parser_plugin() {
        let mut plugin = CParserPlugin::new();
        assert_eq!(plugin.options().profile_name, "default");

        plugin.set_search_paths(vec![PathBuf::from("/usr/include")]);
        assert_eq!(plugin.search_paths().len(), 1);
    }

    #[test]
    fn test_data_organization_default() {
        let org = DataOrganization::default();
        assert_eq!(org.pointer_size, 8);
        assert!(!org.big_endian);
        assert!(org.char_signed);
    }
}

// ---------------------------------------------------------------------------
// IncludeFileFinder -- locate header files for #include directives
// ---------------------------------------------------------------------------

/// Searches for include files across configured search paths.
///
/// Ported from `ghidra.app.plugin.core.cparser.IncludeFileFinder`.
///
/// Resolves `#include <file>` (system) and `#include "file"` (user) directives
/// by searching through the configured include paths.
#[derive(Debug)]
pub struct IncludeFileFinder {
    /// System include paths (searched for angle-bracket includes).
    system_paths: Vec<PathBuf>,
    /// User include paths (searched for quoted includes).
    user_paths: Vec<PathBuf>,
    /// Cache of resolved files: include name -> full path.
    cache: HashMap<String, Option<PathBuf>>,
}

impl IncludeFileFinder {
    /// Create a new finder with the given search paths.
    pub fn new(system_paths: Vec<PathBuf>, user_paths: Vec<PathBuf>) -> Self {
        Self {
            system_paths,
            user_paths,
            cache: HashMap::new(),
        }
    }

    /// Create a finder from parser options.
    pub fn from_options(options: &CParserOptions) -> Self {
        let mut system_paths = Vec::new();
        let mut user_paths = Vec::new();
        for inc in &options.include_paths {
            match inc {
                IncludePath::System(p) => system_paths.push(p.clone()),
                IncludePath::User(p) => user_paths.push(p.clone()),
            }
        }
        Self::new(system_paths, user_paths)
    }

    /// Find a system include file (`#include <file>`).
    ///
    /// Searches system paths first, then user paths as fallback.
    pub fn find_system(&mut self, filename: &str) -> Option<PathBuf> {
        self.find_internal(filename, true)
    }

    /// Find a user include file (`#include "file"`).
    ///
    /// Searches user paths first (relative to the including file's directory),
    /// then system paths as fallback.
    pub fn find_user(&mut self, filename: &str) -> Option<PathBuf> {
        self.find_internal(filename, false)
    }

    /// Find an include file, checking the cache first.
    fn find_internal(&mut self, filename: &str, is_system: bool) -> Option<PathBuf> {
        if let Some(cached) = self.cache.get(filename) {
            return cached.clone();
        }

        let result = if is_system {
            self.search_paths(filename, &self.system_paths.clone())
                .or_else(|| self.search_paths(filename, &self.user_paths.clone()))
        } else {
            self.search_paths(filename, &self.user_paths.clone())
                .or_else(|| self.search_paths(filename, &self.system_paths.clone()))
        };

        self.cache.insert(filename.to_string(), result.clone());
        result
    }

    /// Search a list of directories for a file.
    fn search_paths(&self, filename: &str, paths: &[PathBuf]) -> Option<PathBuf> {
        for dir in paths {
            let candidate = dir.join(filename);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }

    /// Clear the resolution cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get the number of cached entries.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Add a system path at runtime.
    pub fn add_system_path(&mut self, path: PathBuf) {
        self.system_paths.push(path);
    }

    /// Add a user path at runtime.
    pub fn add_user_path(&mut self, path: PathBuf) {
        self.user_paths.push(path);
    }

    /// Get all system paths.
    pub fn system_paths(&self) -> &[PathBuf] {
        &self.system_paths
    }

    /// Get all user paths.
    pub fn user_paths(&self) -> &[PathBuf] {
        &self.user_paths
    }
}

// ---------------------------------------------------------------------------
// CPreprocessorArgs -- structured preprocessor arguments
// ---------------------------------------------------------------------------

/// Structured representation of C preprocessor arguments.
///
/// Ported from the argument-building logic in `CParserPlugin.parse()`.
#[derive(Debug, Clone)]
pub struct CPreprocessorArgs {
    /// Source files to parse.
    pub source_files: Vec<PathBuf>,
    /// Include paths.
    pub include_paths: Vec<IncludePath>,
    /// Preprocessor definitions.
    pub defines: HashMap<String, Option<String>>,
    /// Additional raw arguments.
    pub extra_args: Vec<String>,
    /// Target language ID (e.g., "x86:LE:64:default").
    pub language_id: Option<String>,
    /// Target compiler spec ID (e.g., "default").
    pub compiler_spec_id: Option<String>,
    /// Output data file path (for parsing to a saved database).
    pub output_file: Option<PathBuf>,
}

impl CPreprocessorArgs {
    /// Build args from parser options and source files.
    pub fn from_options(source_files: Vec<PathBuf>, options: &CParserOptions) -> Self {
        Self {
            source_files,
            include_paths: options.include_paths.clone(),
            defines: options.defines.clone(),
            extra_args: Vec::new(),
            language_id: None,
            compiler_spec_id: None,
            output_file: None,
        }
    }

    /// Convert to command-line argument strings.
    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for path in &self.include_paths {
            args.push("-I".to_string());
            args.push(path.path().to_string_lossy().to_string());
        }
        for (name, value) in &self.defines {
            args.push("-D".to_string());
            match value {
                Some(v) => args.push(format!("{}={}", name, v)),
                None => args.push(name.clone()),
            }
        }
        args.extend(self.extra_args.clone());
        args
    }
}

// ===========================================================================
// Tests for IncludeFileFinder and CPreprocessorArgs
// ===========================================================================

#[cfg(test)]
mod finder_tests {
    use super::*;

    #[test]
    fn test_include_file_finder_from_options() {
        let mut opts = CParserOptions::default();
        opts.add_system_include("/usr/include");
        opts.add_user_include("./local");
        let finder = IncludeFileFinder::from_options(&opts);
        assert_eq!(finder.system_paths().len(), 1);
        assert_eq!(finder.user_paths().len(), 1);
    }

    #[test]
    fn test_include_file_finder_cache() {
        let finder = IncludeFileFinder::new(vec![], vec![]);
        assert_eq!(finder.cache_size(), 0);
    }

    #[test]
    fn test_include_file_finder_not_found() {
        let mut finder = IncludeFileFinder::new(vec![], vec![]);
        assert!(finder.find_system("nonexistent.h").is_none());
        assert!(finder.find_user("nonexistent.h").is_none());
    }

    #[test]
    fn test_include_file_finder_add_paths() {
        let mut finder = IncludeFileFinder::new(vec![], vec![]);
        finder.add_system_path(PathBuf::from("/usr/include"));
        finder.add_user_path(PathBuf::from("./local"));
        assert_eq!(finder.system_paths().len(), 1);
        assert_eq!(finder.user_paths().len(), 1);
    }

    #[test]
    fn test_include_file_finder_clear_cache() {
        let mut finder = IncludeFileFinder::new(vec![], vec![]);
        finder.find_system("test.h"); // cached miss
        assert_eq!(finder.cache_size(), 1);
        finder.clear_cache();
        assert_eq!(finder.cache_size(), 0);
    }

    #[test]
    fn test_c_preprocessor_args_from_options() {
        let mut opts = CParserOptions::default();
        opts.add_system_include("/usr/include");
        opts.add_define("DEBUG", None);
        let args = CPreprocessorArgs::from_options(vec![PathBuf::from("test.h")], &opts);
        assert_eq!(args.source_files.len(), 1);
        let cli_args = args.to_args();
        assert!(cli_args.contains(&"-I".to_string()));
        assert!(cli_args.contains(&"/usr/include".to_string()));
        assert!(cli_args.contains(&"-D".to_string()));
        assert!(cli_args.contains(&"DEBUG".to_string()));
    }

    #[test]
    fn test_c_preprocessor_args_with_value_define() {
        let mut opts = CParserOptions::default();
        opts.add_define("VERSION", Some("2.0".into()));
        let args = CPreprocessorArgs::from_options(vec![], &opts);
        let cli_args = args.to_args();
        assert!(cli_args.contains(&"VERSION=2.0".to_string()));
    }
}
