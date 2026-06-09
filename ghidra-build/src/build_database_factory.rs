//! Factory for creating a [`BuildDatabase`] from a Ghidra installation tree.
//!
//! Port of Ghidra's language-loading infrastructure, which combines the
//! `SleighLanguageProvider` resource discovery with the `DefaultLanguageService`
//! singleton registry.
//!
//! The [`BuildDatabaseFactory`] scans a Ghidra installation directory for `.ldefs`
//! files (language definitions), loads them via
//! [`LanguageSpecFactory`](super::language_spec_factory::LanguageSpecFactory),
//! and populates a [`BuildDatabase`](super::build_database::BuildDatabase).
//!
//! # Example
///
/// ```no_run
/// use std::path::Path;
/// use ghidra_build::build_database_factory::BuildDatabaseFactory;
///
/// let factory = BuildDatabaseFactory::new();
/// let db = factory.load_from_install_dir(Path::new("/opt/ghidra")).unwrap();
/// println!("Loaded {} languages", db.language_count());
/// ```

use std::path::{Path, PathBuf};

use super::build_database::BuildDatabase;
use super::language_spec_factory::{LanguageSpecError, LanguageSpecFactory};

// ============================================================================
// Error types
// ============================================================================

/// Errors that can occur when building the database.
#[derive(Debug, thiserror::Error)]
pub enum BuildDatabaseError {
    /// The specified directory does not exist.
    #[error("Directory does not exist: {0}")]
    DirectoryNotFound(PathBuf),

    /// The specified path is not a directory.
    #[error("Not a directory: {0}")]
    NotADirectory(PathBuf),

    /// No `.ldefs` files were found.
    #[error("No .ldefs files found in {0}")]
    NoLdefsFiles(PathBuf),

    /// Error loading a language spec file.
    #[error("Error loading language spec: {0}")]
    LanguageSpec(#[from] LanguageSpecError),
}

// ============================================================================
// BuildDatabaseFactory
// ============================================================================

/// Factory for creating [`BuildDatabase`] instances from file system paths.
///
/// This factory handles the discovery and loading of Ghidra's language
/// definition files (`.ldefs`). It supports loading from:
///
/// - A full Ghidra installation directory (scans the `Processors/` subtree)
/// - A specific directory containing `.ldefs` files
/// - Individual `.ldefs` files
///
/// # Ghidra Installation Layout
///
/// In a Ghidra installation, language definitions are located under:
/// ```text
/// Ghidra/
///   Processors/
///     x86/
///       data/
///         languages/
///           x86.ldefs
///           x86.sla
///           x86.pspec
///           default.cspec
///           windows.cspec
///     ARM/
///       data/
///         languages/
///           arm.ldefs
///           ...
/// ```
///
/// The factory can also work in a development environment where the source
/// tree has a different layout.
#[derive(Debug, Default)]
pub struct BuildDatabaseFactory {
    /// Additional directories to search for `.ldefs` files.
    extra_dirs: Vec<PathBuf>,
    /// Whether to search recursively in directories.
    recursive: bool,
}

impl BuildDatabaseFactory {
    /// Create a new factory with default settings.
    pub fn new() -> Self {
        Self {
            extra_dirs: Vec::new(),
            recursive: true,
        }
    }

    /// Add an extra directory to search for `.ldefs` files.
    ///
    /// These directories are searched in addition to the standard Ghidra
    /// installation paths.
    pub fn add_directory(&mut self, dir: PathBuf) -> &mut Self {
        self.extra_dirs.push(dir);
        self
    }

    /// Set whether to search directories recursively.
    ///
    /// Default is `true`. When set to `false`, only top-level `.ldefs` files
    /// in each directory are loaded.
    pub fn set_recursive(&mut self, recursive: bool) -> &mut Self {
        self.recursive = recursive;
        self
    }

    /// Load a build database from a Ghidra installation directory.
    ///
    /// This searches for `.ldefs` files in the standard Ghidra layout:
    /// - `{install_dir}/Processors/**/languages/*.ldefs`
    /// - `{install_dir}/Ghidra/Processors/**/languages/*.ldefs`
    ///
    /// For development environments (detected by the presence of `build.gradle`
    /// or `pom.xml`), it also searches the source tree directly.
    pub fn load_from_install_dir(&self, install_dir: &Path) -> Result<BuildDatabase, BuildDatabaseError> {
        if !install_dir.exists() {
            return Err(BuildDatabaseError::DirectoryNotFound(
                install_dir.to_path_buf(),
            ));
        }
        if !install_dir.is_dir() {
            return Err(BuildDatabaseError::NotADirectory(
                install_dir.to_path_buf(),
            ));
        }

        let mut spec_factory = LanguageSpecFactory::new();
        let mut found_any = false;

        // Standard Ghidra installation layout
        let processors_dir = install_dir.join("Ghidra").join("Processors");
        if processors_dir.is_dir() {
            if self.recursive {
                spec_factory.load_from_directory_recursive(&processors_dir)?;
            } else {
                spec_factory.load_from_directory(&processors_dir)?;
            }
            if !spec_factory.is_empty() {
                found_any = true;
            }
        }

        // Also check {install_dir}/Processors (non-standard or alternate layout)
        let alt_processors = install_dir.join("Processors");
        if alt_processors.is_dir() && alt_processors != processors_dir {
            if self.recursive {
                spec_factory.load_from_directory_recursive(&alt_processors)?;
            } else {
                spec_factory.load_from_directory(&alt_processors)?;
            }
            if !spec_factory.is_empty() {
                found_any = true;
            }
        }

        // Check extra directories
        for dir in &self.extra_dirs {
            if dir.is_dir() {
                if self.recursive {
                    spec_factory.load_from_directory_recursive(dir)?;
                } else {
                    spec_factory.load_from_directory(dir)?;
                }
                if !spec_factory.is_empty() {
                    found_any = true;
                }
            }
        }

        if !found_any {
            return Err(BuildDatabaseError::NoLdefsFiles(install_dir.to_path_buf()));
        }

        let mut db = BuildDatabase::new();
        for spec in spec_factory.into_language_specs() {
            db.add_language_spec(spec);
        }

        Ok(db)
    }

    /// Load a build database from a specific directory containing `.ldefs` files.
    pub fn load_from_directory(&self, dir: &Path) -> Result<BuildDatabase, BuildDatabaseError> {
        if !dir.exists() {
            return Err(BuildDatabaseError::DirectoryNotFound(dir.to_path_buf()));
        }
        if !dir.is_dir() {
            return Err(BuildDatabaseError::NotADirectory(dir.to_path_buf()));
        }

        let mut spec_factory = LanguageSpecFactory::new();
        if self.recursive {
            spec_factory.load_from_directory_recursive(dir)?;
        } else {
            spec_factory.load_from_directory(dir)?;
        }

        if spec_factory.is_empty() {
            return Err(BuildDatabaseError::NoLdefsFiles(dir.to_path_buf()));
        }

        let mut db = BuildDatabase::new();
        for spec in spec_factory.into_language_specs() {
            db.add_language_spec(spec);
        }

        Ok(db)
    }

    /// Load a build database from a single `.ldefs` file.
    pub fn load_from_file(&self, path: &Path) -> Result<BuildDatabase, BuildDatabaseError> {
        let mut spec_factory = LanguageSpecFactory::new();
        spec_factory.load_from_file(path)?;

        let mut db = BuildDatabase::new();
        for spec in spec_factory.into_language_specs() {
            db.add_language_spec(spec);
        }

        Ok(db)
    }

    /// Load a build database from XML content in memory.
    ///
    /// Useful for testing or when the `.ldefs` content is already available
    /// as a string (e.g., from a bundled resource or network fetch).
    pub fn load_from_str(&self, content: &str, source_name: &str) -> Result<BuildDatabase, BuildDatabaseError> {
        let mut spec_factory = LanguageSpecFactory::new();
        spec_factory.load_from_str(content, Path::new(source_name))?;

        let mut db = BuildDatabase::new();
        for spec in spec_factory.into_language_specs() {
            db.add_language_spec(spec);
        }

        Ok(db)
    }

    /// Build a database from multiple sources.
    ///
    /// Loads from all provided paths (files and directories) and merges
    /// them into a single database. Paths are processed in order; if the
    /// same language ID appears in multiple sources, the last one wins.
    pub fn load_from_paths(&self, paths: &[&Path]) -> Result<BuildDatabase, BuildDatabaseError> {
        let mut spec_factory = LanguageSpecFactory::new();

        for &path in paths {
            if path.is_dir() {
                if self.recursive {
                    spec_factory.load_from_directory_recursive(path)?;
                } else {
                    spec_factory.load_from_directory(path)?;
                }
            } else if path.is_file() {
                spec_factory.load_from_file(path)?;
            }
        }

        let mut db = BuildDatabase::new();
        for spec in spec_factory.into_language_specs() {
            db.add_language_spec(spec);
        }

        Ok(db)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_LDEFS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
  <language id="x86:LE:64:default" processor="x86" endian="LE" size="64"
            variant="default" version="1.0"
            slafile="x86.sla" processorspec="x86.pspec">
    <description>x86 64-bit little-endian</description>
    <compiler id="default" name="default" spec="default.cspec"/>
  </language>
  <language id="x86:LE:32:default" processor="x86" endian="LE" size="32"
            variant="default" version="1.0"
            slafile="x86.sla" processorspec="x86.pspec">
    <description>x86 32-bit little-endian</description>
    <compiler id="default" name="default" spec="default.cspec"/>
  </language>
  <language id="ARM:LE:32:v7" processor="ARM" endian="LE" size="32"
            variant="v7" version="1.0"
            slafile="arm.sla" processorspec="arm.pspec">
    <description>ARM 32-bit little-endian v7</description>
    <compiler id="default" name="default" spec="default.cspec"/>
  </language>
</language_definitions>"#;

    #[test]
    fn test_factory_new() {
        let factory = BuildDatabaseFactory::new();
        assert!(factory.recursive);
        assert!(factory.extra_dirs.is_empty());
    }

    #[test]
    fn test_factory_set_recursive() {
        let mut factory = BuildDatabaseFactory::new();
        factory.set_recursive(false);
        assert!(!factory.recursive);
    }

    #[test]
    fn test_factory_load_from_str() {
        let factory = BuildDatabaseFactory::new();
        let db = factory.load_from_str(SAMPLE_LDEFS, "test.ldefs").unwrap();
        assert_eq!(db.language_count(), 3);
        assert!(db.contains_language("x86:LE:64:default"));
        assert!(db.contains_language("x86:LE:32:default"));
        assert!(db.contains_language("ARM:LE:32:v7"));
    }

    #[test]
    fn test_factory_load_from_str_processors() {
        let factory = BuildDatabaseFactory::new();
        let db = factory.load_from_str(SAMPLE_LDEFS, "test.ldefs").unwrap();
        assert_eq!(db.processor_count(), 2);
        assert!(db.get_processor("x86").is_some());
        assert!(db.get_processor("ARM").is_some());
    }

    #[test]
    fn test_factory_load_from_str_default_language() {
        let factory = BuildDatabaseFactory::new();
        let db = factory.load_from_str(SAMPLE_LDEFS, "test.ldefs").unwrap();
        let default_x86 = db.get_default_language("x86").unwrap();
        assert_eq!(default_x86.variant, "default");
        assert!(!default_x86.deprecated);
    }

    #[test]
    fn test_factory_load_from_str_empty() {
        let factory = BuildDatabaseFactory::new();
        let result = factory.load_from_str("", "empty.ldefs");
        assert!(result.is_err());
    }

    #[test]
    fn test_factory_load_from_nonexistent_dir() {
        let factory = BuildDatabaseFactory::new();
        let result = factory.load_from_directory(Path::new("/nonexistent/path"));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BuildDatabaseError::DirectoryNotFound(_)
        ));
    }

    #[test]
    fn test_factory_load_from_nonexistent_install_dir() {
        let factory = BuildDatabaseFactory::new();
        let result = factory.load_from_install_dir(Path::new("/nonexistent/ghidra"));
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BuildDatabaseError::DirectoryNotFound(_)
        ));
    }

    #[test]
    fn test_factory_add_directory() {
        let mut factory = BuildDatabaseFactory::new();
        factory.add_directory(PathBuf::from("/extra/dir"));
        assert_eq!(factory.extra_dirs.len(), 1);
    }

    #[test]
    fn test_factory_load_from_file() {
        use std::fs;
        use tempfile::NamedTempFile;

        let tmp = NamedTempFile::new().unwrap();
        fs::write(tmp.path(), SAMPLE_LDEFS).unwrap();

        let factory = BuildDatabaseFactory::new();
        let db = factory.load_from_file(tmp.path()).unwrap();
        assert_eq!(db.language_count(), 3);
    }

    #[test]
    fn test_factory_load_from_paths() {
        use std::fs;
        use tempfile::NamedTempFile;

        let tmp1 = NamedTempFile::new().unwrap();
        let ldefs1 = r#"<?xml version="1.0"?>
<language_definitions>
  <language id="x86:LE:64:default" processor="x86" endian="LE" size="64"
            variant="default" version="1" slafile="x.sla" processorspec="x.pspec">
    <description>x86</description>
    <compiler id="default" name="default" spec="d.cspec"/>
  </language>
</language_definitions>"#;
        fs::write(tmp1.path(), ldefs1).unwrap();

        let tmp2 = NamedTempFile::new().unwrap();
        let ldefs2 = r#"<?xml version="1.0"?>
<language_definitions>
  <language id="ARM:LE:32:v7" processor="ARM" endian="LE" size="32"
            variant="v7" version="1" slafile="a.sla" processorspec="a.pspec">
    <description>ARM</description>
    <compiler id="default" name="default" spec="d.cspec"/>
  </language>
</language_definitions>"#;
        fs::write(tmp2.path(), ldefs2).unwrap();

        let factory = BuildDatabaseFactory::new();
        let db = factory
            .load_from_paths(&[tmp1.path(), tmp2.path()])
            .unwrap();
        assert_eq!(db.language_count(), 2);
        assert!(db.contains_language("x86:LE:64:default"));
        assert!(db.contains_language("ARM:LE:32:v7"));
    }

    #[test]
    fn test_factory_load_from_paths_with_dir() {
        use std::fs;
        use tempfile::TempDir;

        let dir = TempDir::new().unwrap();
        let ldefs = r#"<?xml version="1.0"?>
<language_definitions>
  <language id="TEST:LE:32:default" processor="TEST" endian="LE" size="32"
            variant="default" version="1" slafile="t.sla" processorspec="t.pspec">
    <description>Test</description>
    <compiler id="default" name="default" spec="d.cspec"/>
  </language>
</language_definitions>"#;
        fs::write(dir.path().join("test.ldefs"), ldefs).unwrap();

        let factory = BuildDatabaseFactory::new();
        let db = factory.load_from_paths(&[dir.path()]).unwrap();
        assert_eq!(db.language_count(), 1);
    }

    #[test]
    fn test_error_display() {
        let err = BuildDatabaseError::DirectoryNotFound(PathBuf::from("/test"));
        assert!(format!("{}", err).contains("/test"));

        let err = BuildDatabaseError::NotADirectory(PathBuf::from("/test/file"));
        assert!(format!("{}", err).contains("Not a directory"));

        let err = BuildDatabaseError::NoLdefsFiles(PathBuf::from("/test"));
        assert!(format!("{}", err).contains("No .ldefs files"));
    }

    #[test]
    fn test_error_from_language_spec_error() {
        let inner = LanguageSpecError::Parse {
            path: PathBuf::from("test.ldefs"),
            message: "bad XML".to_string(),
        };
        let err: BuildDatabaseError = inner.into();
        assert!(format!("{}", err).contains("bad XML"));
    }

    #[test]
    fn test_full_workflow() {
        let factory = BuildDatabaseFactory::new();
        let db = factory.load_from_str(SAMPLE_LDEFS, "test.ldefs").unwrap();

        // Verify all languages loaded
        assert_eq!(db.language_count(), 3);
        assert_eq!(db.processor_count(), 2);

        // Verify x86 languages
        let x86_specs = db.get_languages_for_processor("x86");
        assert_eq!(x86_specs.len(), 2);

        // Verify ARM language
        let arm_specs = db.get_languages_for_processor("ARM");
        assert_eq!(arm_specs.len(), 1);
        assert_eq!(arm_specs[0].description, "ARM 32-bit little-endian v7");

        // Verify default language selection
        let default = db.get_default_language("x86").unwrap();
        assert_eq!(default.id.size, 64); // prefers 64-bit default

        // Verify compiler specs
        let cs = db.get_compiler_spec("x86:LE:64:default", &crate::language_spec::CompilerSpecID::new("default"));
        assert!(cs.is_some());
    }
}
