//! Include file finder and preprocessor arguments -- ported from Ghidra's cparser package.
//!
//! Ported from:
//! - `ghidra.app.plugin.core.cparser.IncludeFileFinder`
//! - Preprocessor invocation logic

use std::collections::HashMap;
use std::path::PathBuf;

use super::{CParserOptions, IncludePath};

// ---------------------------------------------------------------------------
// IncludeFileFinder -- finds include files in search paths
// ---------------------------------------------------------------------------

/// Finds include files in configured search paths.
///
/// Ported from `ghidra.app.plugin.core.cparser.IncludeFileFinder`.
///
/// Searches system include directories and user include directories
/// for header files, with caching of results.
#[derive(Debug)]
pub struct IncludeFileFinder {
    /// System include paths (e.g., /usr/include).
    system_paths: Vec<PathBuf>,
    /// User include paths.
    user_paths: Vec<PathBuf>,
    /// Cache of resolved paths. Key = filename, value = full path.
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
        let mut system = Vec::new();
        let mut user = Vec::new();
        for p in &options.include_paths {
            match p {
                IncludePath::System(path) => system.push(path.clone()),
                IncludePath::User(path) => user.push(path.clone()),
            }
        }
        Self::new(system, user)
    }

    /// Add a system include path.
    pub fn add_system_path(&mut self, path: PathBuf) {
        if !self.system_paths.contains(&path) {
            self.system_paths.push(path);
        }
    }

    /// Add a user include path.
    pub fn add_user_path(&mut self, path: PathBuf) {
        if !self.user_paths.contains(&path) {
            self.user_paths.push(path);
        }
    }

    /// Find a file in system include paths.
    pub fn find_system(&mut self, filename: &str) -> Option<PathBuf> {
        if let Some(cached) = self.cache.get(filename) {
            return cached.clone();
        }
        let result = self.search_paths(&self.system_paths, filename);
        self.cache.insert(filename.to_string(), result.clone());
        result
    }

    /// Find a file in user include paths.
    pub fn find_user(&mut self, filename: &str) -> Option<PathBuf> {
        let key = format!("user:{}", filename);
        if let Some(cached) = self.cache.get(&key) {
            return cached.clone();
        }
        let result = self.search_paths(&self.user_paths, filename);
        self.cache.insert(key, result.clone());
        result
    }

    /// Find a file checking user paths first, then system paths.
    pub fn find(&mut self, filename: &str) -> Option<PathBuf> {
        if let Some(path) = self.find_user(filename) {
            return Some(path);
        }
        self.find_system(filename)
    }

    /// Search a set of paths for a filename.
    fn search_paths(&self, paths: &[PathBuf], filename: &str) -> Option<PathBuf> {
        for dir in paths {
            let full = dir.join(filename);
            if full.exists() {
                return Some(full);
            }
        }
        None
    }

    /// Get the system include paths.
    pub fn system_paths(&self) -> &[PathBuf] {
        &self.system_paths
    }

    /// Get the user include paths.
    pub fn user_paths(&self) -> &[PathBuf] {
        &self.user_paths
    }

    /// Get the cache size (number of lookups cached).
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    /// Clear the lookup cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
}

// ---------------------------------------------------------------------------
// CPreprocessorArgs -- arguments for the C preprocessor
// ---------------------------------------------------------------------------

/// Arguments for invoking the C preprocessor.
///
/// Ported from the preprocessor invocation logic in the cparser package.
#[derive(Debug, Clone)]
pub struct CPreprocessorArgs {
    /// Source files to process.
    pub source_files: Vec<PathBuf>,
    /// Include directories (-I).
    pub include_dirs: Vec<PathBuf>,
    /// Preprocessor defines (-D).
    pub defines: Vec<(String, Option<String>)>,
    /// Undefines (-U).
    pub undefines: Vec<String>,
    /// Additional flags.
    pub extra_flags: Vec<String>,
}

impl CPreprocessorArgs {
    /// Create args from parser options.
    pub fn from_options(source_files: Vec<PathBuf>, options: &CParserOptions) -> Self {
        let include_dirs: Vec<PathBuf> = options
            .include_paths
            .iter()
            .map(|p| p.path().clone())
            .collect();
        let defines: Vec<(String, Option<String>)> = options
            .defines
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Self {
            source_files,
            include_dirs,
            defines,
            undefines: Vec::new(),
            extra_flags: Vec::new(),
        }
    }

    /// Convert to command-line argument strings.
    pub fn to_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        for dir in &self.include_dirs {
            args.push("-I".into());
            args.push(dir.to_string_lossy().into_owned());
        }
        for (name, value) in &self.defines {
            args.push("-D".into());
            match value {
                Some(v) => args.push(format!("{}={}", name, v)),
                None => args.push(name.clone()),
            }
        }
        for undef in &self.undefines {
            args.push("-U".into());
            args.push(undef.clone());
        }
        for flag in &self.extra_flags {
            args.push(flag.clone());
        }
        for file in &self.source_files {
            args.push(file.to_string_lossy().into_owned());
        }
        args
    }
}

// ---------------------------------------------------------------------------
// CParserTaskResult -- enhanced parse task result
// ---------------------------------------------------------------------------

/// Enhanced result of a C parser task.
///
/// Extends the basic [`super::ParseResult`] with more detailed metrics
/// matching Ghidra's `CParserTask` reporting.
#[derive(Debug, Clone)]
pub struct CParserTaskResult {
    /// Number of data types parsed.
    pub types_parsed: usize,
    /// Number of functions parsed.
    pub functions_parsed: usize,
    /// Number of errors.
    pub error_count: usize,
    /// Number of warnings.
    pub warning_count: usize,
    /// The parse messages.
    pub messages: Vec<String>,
    /// Whether the parse was successful.
    pub successful: bool,
}

impl CParserTaskResult {
    /// Create a successful result.
    pub fn success(types_parsed: usize, functions_parsed: usize) -> Self {
        Self {
            types_parsed,
            functions_parsed,
            error_count: 0,
            warning_count: 0,
            messages: Vec::new(),
            successful: true,
        }
    }

    /// Create a failed result.
    pub fn failure(error_count: usize, messages: Vec<String>) -> Self {
        Self {
            types_parsed: 0,
            functions_parsed: 0,
            error_count,
            warning_count: 0,
            messages,
            successful: false,
        }
    }

    /// Summary message.
    pub fn summary(&self) -> String {
        if self.successful {
            format!(
                "Parsed {} data types and {} functions.",
                self.types_parsed, self.functions_parsed
            )
        } else {
            format!(
                "Parse failed with {} errors. {}",
                self.error_count,
                self.messages.join("; ")
            )
        }
    }

    /// Whether there were any warnings.
    pub fn has_warnings(&self) -> bool {
        self.warning_count > 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_include_file_finder() {
        let finder = IncludeFileFinder::new(vec![], vec![]);
        assert_eq!(finder.system_paths().len(), 0);
        assert_eq!(finder.user_paths().len(), 0);
        assert_eq!(finder.cache_size(), 0);
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
    fn test_include_file_finder_not_found() {
        let mut finder = IncludeFileFinder::new(vec![], vec![]);
        assert!(finder.find_system("nonexistent.h").is_none());
        assert!(finder.find_user("nonexistent.h").is_none());
        assert_eq!(finder.cache_size(), 2);
    }

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
    fn test_include_file_finder_clear_cache() {
        let mut finder = IncludeFileFinder::new(vec![], vec![]);
        finder.find_system("test.h");
        assert_eq!(finder.cache_size(), 1);
        finder.clear_cache();
        assert_eq!(finder.cache_size(), 0);
    }

    #[test]
    fn test_c_preprocessor_args() {
        let mut opts = CParserOptions::default();
        opts.add_system_include("/usr/include");
        opts.add_define("DEBUG", None);
        let args = CPreprocessorArgs::from_options(vec![PathBuf::from("test.h")], &opts);
        let cli_args = args.to_args();
        assert!(cli_args.contains(&"-I".to_string()));
        assert!(cli_args.contains(&"/usr/include".to_string()));
        assert!(cli_args.contains(&"-D".to_string()));
        assert!(cli_args.contains(&"DEBUG".to_string()));
        assert!(cli_args.contains(&"test.h".to_string()));
    }

    #[test]
    fn test_c_preprocessor_args_with_value() {
        let mut opts = CParserOptions::default();
        opts.add_define("VERSION", Some("2.0".into()));
        let args = CPreprocessorArgs::from_options(vec![], &opts);
        let cli_args = args.to_args();
        assert!(cli_args.contains(&"VERSION=2.0".to_string()));
    }

    #[test]
    fn test_cparser_task_result_success() {
        let result = CParserTaskResult::success(10, 3);
        assert!(result.successful);
        assert!(result.summary().contains("10 data types"));
        assert!(!result.has_warnings());
    }

    #[test]
    fn test_cparser_task_result_failure() {
        let result = CParserTaskResult::failure(2, vec!["err1".into(), "err2".into()]);
        assert!(!result.successful);
        assert!(result.summary().contains("2 errors"));
    }
}
