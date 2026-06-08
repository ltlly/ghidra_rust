//! Swift demangler configuration options.
//!
//! Ported from Ghidra's `SwiftDemanglerOptions.java`.

use std::path::{Path, PathBuf};

/// Prefix added to labels with incomplete demangling.
pub const INCOMPLETE_PREFIX: &str = "$";

/// Prefix added to labels with unsupported demangling.
pub const UNSUPPORTED_PREFIX: &str = "$$";

/// Options controlling Swift demangling behavior.
///
/// Configures how the demangler processes Swift symbols, including
/// paths to the Swift toolchain and label formatting preferences.
#[derive(Debug, Clone, Default)]
pub struct SwiftDemanglerOptions {
    /// Path to the Swift toolchain binary directory.
    ///
    /// If `None`, the system `PATH` is used to locate `swift-demangle`
    /// or `swift`.
    swift_dir: Option<PathBuf>,

    /// Whether to prefix incomplete demangled labels with [`INCOMPLETE_PREFIX`].
    use_incomplete_prefix: bool,

    /// Whether to prefix unsupported demangled labels with [`UNSUPPORTED_PREFIX`].
    use_unsupported_prefix: bool,
}

impl SwiftDemanglerOptions {
    /// Create new options with default settings.
    pub fn new() -> Self {
        Self {
            swift_dir: None,
            use_incomplete_prefix: true,
            use_unsupported_prefix: true,
        }
    }

    /// Get the Swift toolchain directory, if set.
    pub fn swift_dir(&self) -> Option<&Path> {
        self.swift_dir.as_deref()
    }

    /// Set the Swift toolchain directory.
    ///
    /// If the Swift binaries are already on `PATH`, this can be `None`.
    pub fn set_swift_dir(&mut self, dir: Option<PathBuf>) {
        self.swift_dir = dir;
    }

    /// Get the prefix for incomplete demangled labels.
    ///
    /// Returns [`INCOMPLETE_PREFIX`] if enabled, empty string otherwise.
    pub fn incomplete_prefix(&self) -> &str {
        if self.use_incomplete_prefix {
            INCOMPLETE_PREFIX
        } else {
            ""
        }
    }

    /// Set whether to use an incomplete prefix on labels.
    pub fn set_incomplete_prefix(&mut self, enabled: bool) {
        self.use_incomplete_prefix = enabled;
    }

    /// Get the prefix for unsupported demangled labels.
    ///
    /// Returns [`UNSUPPORTED_PREFIX`] if enabled, empty string otherwise.
    pub fn unsupported_prefix(&self) -> &str {
        if self.use_unsupported_prefix {
            UNSUPPORTED_PREFIX
        } else {
            ""
        }
    }

    /// Set whether to use an unsupported prefix on labels.
    pub fn set_unsupported_prefix(&mut self, enabled: bool) {
        self.use_unsupported_prefix = enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = SwiftDemanglerOptions::new();
        assert!(opts.swift_dir().is_none());
        assert!(opts.use_incomplete_prefix);
        assert!(opts.use_unsupported_prefix);
        assert_eq!(opts.incomplete_prefix(), "$");
        assert_eq!(opts.unsupported_prefix(), "$$");
    }

    #[test]
    fn test_disabled_prefixes() {
        let mut opts = SwiftDemanglerOptions::new();
        opts.set_incomplete_prefix(false);
        opts.set_unsupported_prefix(false);
        assert_eq!(opts.incomplete_prefix(), "");
        assert_eq!(opts.unsupported_prefix(), "");
    }

    #[test]
    fn test_set_swift_dir() {
        let mut opts = SwiftDemanglerOptions::new();
        assert!(opts.swift_dir().is_none());

        opts.set_swift_dir(Some(PathBuf::from("/usr/bin")));
        assert_eq!(opts.swift_dir(), Some(Path::new("/usr/bin")));

        opts.set_swift_dir(None);
        assert!(opts.swift_dir().is_none());
    }

    #[test]
    fn test_mixed_prefix_settings() {
        let mut opts = SwiftDemanglerOptions::new();
        opts.set_incomplete_prefix(true);
        opts.set_unsupported_prefix(false);
        assert_eq!(opts.incomplete_prefix(), "$");
        assert_eq!(opts.unsupported_prefix(), "");
    }

    #[test]
    fn test_clone() {
        let mut opts = SwiftDemanglerOptions::new();
        opts.set_swift_dir(Some(PathBuf::from("/opt/swift")));
        let cloned = opts.clone();
        assert_eq!(cloned.swift_dir(), Some(Path::new("/opt/swift")));
    }
}
