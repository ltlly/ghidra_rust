//! Filesystem-specific error types.
//!
//! Provides [`FileSystemException`] as a structured error type for filesystem
//! operations, and re-exports convenience error constructors from
//! `crate::filesystem::store`.
//!
//! In the Java Ghidra codebase, `FileSystemException` is a checked exception.
//! In Rust, we model it as a structured enum that can be converted to/from
//! the crate-level [`GhidraError`].

use std::fmt;
use std::path::PathBuf;

use crate::error::GhidraError;

// Re-export store error constructors.
pub use crate::filesystem::store::{
    duplicate_file_error, exclusive_checkout_error, file_in_use_error,
    folder_not_empty_error, invalid_name_error, lock_error, not_found_error,
    read_only_error,
};

// ============================================================================
// FileSystemException
// ============================================================================

/// A structured error type for filesystem store operations.
///
/// This is analogous to the Java `FileSystemException` and provides
/// fine-grained error categorization for store-level filesystem operations.
///
/// Each variant maps to one or more [`GhidraError`] variants for
/// interoperability with the rest of the crate.
#[derive(Debug)]
pub enum FileSystemException {
    /// A file or folder was not found.
    NotFound {
        /// Path or name that was not found.
        path: String,
    },

    /// A file or folder already exists at the target location.
    AlreadyExists {
        /// Path that already exists.
        path: String,
    },

    /// The file system is read-only and the operation is not permitted.
    ReadOnly,

    /// A lock could not be acquired.
    LockError {
        /// Description of the lock failure.
        message: String,
        /// The resource that was being locked.
        resource: Option<String>,
    },

    /// A file is currently in use by another operation.
    FileInUse {
        /// The path of the file in use.
        path: String,
        /// The user or operation holding the file.
        holder: Option<String>,
    },

    /// An exclusive checkout prevents the operation.
    ExclusiveCheckout {
        /// Description of the conflict.
        message: String,
    },

    /// A folder is not empty and cannot be deleted.
    FolderNotEmpty {
        /// The path of the non-empty folder.
        path: String,
    },

    /// An invalid item name was provided.
    InvalidName {
        /// The invalid name.
        name: String,
        /// Reason the name is invalid.
        reason: String,
    },

    /// A duplicate file exists.
    DuplicateFile {
        /// The path of the duplicate.
        path: String,
    },

    /// An I/O error occurred.
    IoError {
        /// The I/O error.
        source: std::io::Error,
        /// The path involved, if known.
        path: Option<PathBuf>,
    },

    /// The operation is not supported by this filesystem.
    NotSupported {
        /// Description of the unsupported operation.
        message: String,
    },

    /// An invalid or corrupt state was encountered.
    InvalidState {
        /// Description of the invalid state.
        message: String,
    },

    /// A catch-all for other errors.
    Other {
        /// The error message.
        message: String,
    },
}

impl FileSystemException {
    /// Create a NotFound exception.
    pub fn not_found(path: impl Into<String>) -> Self {
        FileSystemException::NotFound { path: path.into() }
    }

    /// Create an AlreadyExists exception.
    pub fn already_exists(path: impl Into<String>) -> Self {
        FileSystemException::AlreadyExists { path: path.into() }
    }

    /// Create a ReadOnly exception.
    pub fn read_only() -> Self {
        FileSystemException::ReadOnly
    }

    /// Create a LockError exception.
    pub fn lock_error(
        message: impl Into<String>,
        resource: Option<impl Into<String>>,
    ) -> Self {
        FileSystemException::LockError {
            message: message.into(),
            resource: resource.map(|r| r.into()),
        }
    }

    /// Create a FileInUse exception.
    pub fn file_in_use(
        path: impl Into<String>,
        holder: Option<impl Into<String>>,
    ) -> Self {
        FileSystemException::FileInUse {
            path: path.into(),
            holder: holder.map(|h| h.into()),
        }
    }

    /// Create an ExclusiveCheckout exception.
    pub fn exclusive_checkout(message: impl Into<String>) -> Self {
        FileSystemException::ExclusiveCheckout {
            message: message.into(),
        }
    }

    /// Create a FolderNotEmpty exception.
    pub fn folder_not_empty(path: impl Into<String>) -> Self {
        FileSystemException::FolderNotEmpty { path: path.into() }
    }

    /// Create an InvalidName exception.
    pub fn invalid_name(name: impl Into<String>, reason: impl Into<String>) -> Self {
        FileSystemException::InvalidName {
            name: name.into(),
            reason: reason.into(),
        }
    }

    /// Create a DuplicateFile exception.
    pub fn duplicate_file(path: impl Into<String>) -> Self {
        FileSystemException::DuplicateFile { path: path.into() }
    }

    /// Create a NotSupported exception.
    pub fn not_supported(message: impl Into<String>) -> Self {
        FileSystemException::NotSupported {
            message: message.into(),
        }
    }

    /// Create an InvalidState exception.
    pub fn invalid_state(message: impl Into<String>) -> Self {
        FileSystemException::InvalidState {
            message: message.into(),
        }
    }

    /// Create an Other exception.
    pub fn other(message: impl Into<String>) -> Self {
        FileSystemException::Other {
            message: message.into(),
        }
    }

    /// Returns true if this error is recoverable (retry might succeed).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            FileSystemException::LockError { .. } | FileSystemException::FileInUse { .. }
        )
    }

    /// Returns true if this error indicates a not-found condition.
    pub fn is_not_found(&self) -> bool {
        matches!(self, FileSystemException::NotFound { .. })
    }
}

impl fmt::Display for FileSystemException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileSystemException::NotFound { path } => {
                write!(f, "Not found: {}", path)
            }
            FileSystemException::AlreadyExists { path } => {
                write!(f, "Already exists: {}", path)
            }
            FileSystemException::ReadOnly => {
                write!(f, "File system is read-only")
            }
            FileSystemException::LockError { message, resource } => {
                if let Some(res) = resource {
                    write!(f, "Lock error on '{}': {}", res, message)
                } else {
                    write!(f, "Lock error: {}", message)
                }
            }
            FileSystemException::FileInUse { path, holder } => {
                if let Some(h) = holder {
                    write!(f, "File in use: {} (held by {})", path, h)
                } else {
                    write!(f, "File in use: {}", path)
                }
            }
            FileSystemException::ExclusiveCheckout { message } => {
                write!(f, "Exclusive checkout: {}", message)
            }
            FileSystemException::FolderNotEmpty { path } => {
                write!(f, "Folder not empty: {}", path)
            }
            FileSystemException::InvalidName { name, reason } => {
                write!(f, "Invalid name '{}': {}", name, reason)
            }
            FileSystemException::DuplicateFile { path } => {
                write!(f, "Duplicate file: {}", path)
            }
            FileSystemException::IoError { source, path } => {
                if let Some(p) = path {
                    write!(f, "I/O error at '{}': {}", p.display(), source)
                } else {
                    write!(f, "I/O error: {}", source)
                }
            }
            FileSystemException::NotSupported { message } => {
                write!(f, "Not supported: {}", message)
            }
            FileSystemException::InvalidState { message } => {
                write!(f, "Invalid state: {}", message)
            }
            FileSystemException::Other { message } => {
                write!(f, "Filesystem error: {}", message)
            }
        }
    }
}

impl std::error::Error for FileSystemException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FileSystemException::IoError { source, .. } => Some(source),
            _ => None,
        }
    }
}

// ============================================================================
// Conversions
// ============================================================================

impl From<std::io::Error> for FileSystemException {
    fn from(e: std::io::Error) -> Self {
        FileSystemException::IoError {
            source: e,
            path: None,
        }
    }
}

impl From<FileSystemException> for GhidraError {
    fn from(e: FileSystemException) -> Self {
        match e {
            FileSystemException::NotFound { path } => GhidraError::NotFound(path),
            FileSystemException::AlreadyExists { path } => {
                GhidraError::InvalidData(format!("Already exists: {}", path))
            }
            FileSystemException::ReadOnly => {
                GhidraError::InvalidState("File system is read-only".into())
            }
            FileSystemException::LockError { message, .. } => {
                GhidraError::InvalidState(format!("Lock error: {}", message))
            }
            FileSystemException::FileInUse { path, .. } => {
                GhidraError::InvalidState(format!("File in use: {}", path))
            }
            FileSystemException::ExclusiveCheckout { message } => {
                GhidraError::InvalidState(format!("Exclusive checkout: {}", message))
            }
            FileSystemException::FolderNotEmpty { path } => {
                GhidraError::InvalidData(format!("Folder not empty: {}", path))
            }
            FileSystemException::InvalidName { name, reason } => {
                GhidraError::InvalidData(format!("Invalid name '{}': {}", name, reason))
            }
            FileSystemException::DuplicateFile { path } => {
                GhidraError::InvalidData(format!("Duplicate file: {}", path))
            }
            FileSystemException::IoError { source, .. } => GhidraError::IoError(source),
            FileSystemException::NotSupported { message } => GhidraError::NotSupported(message),
            FileSystemException::InvalidState { message } => GhidraError::InvalidState(message),
            FileSystemException::Other { message } => {
                GhidraError::Other(anyhow::anyhow!(message))
            }
        }
    }
}

impl From<GhidraError> for FileSystemException {
    fn from(e: GhidraError) -> Self {
        match e {
            GhidraError::NotFound(msg) => FileSystemException::NotFound { path: msg },
            GhidraError::IoError(e) => FileSystemException::IoError {
                source: e,
                path: None,
            },
            GhidraError::InvalidState(msg) => {
                if msg.contains("Lock error") {
                    FileSystemException::LockError {
                        message: msg,
                        resource: None,
                    }
                } else if msg.contains("File in use") {
                    FileSystemException::FileInUse {
                        path: msg,
                        holder: None,
                    }
                } else if msg.contains("read-only") {
                    FileSystemException::ReadOnly
                } else {
                    FileSystemException::InvalidState { message: msg }
                }
            }
            GhidraError::InvalidData(msg) => {
                if msg.contains("Already exists") {
                    FileSystemException::AlreadyExists { path: msg }
                } else if msg.contains("Folder not empty") {
                    FileSystemException::FolderNotEmpty { path: msg }
                } else if msg.contains("Duplicate file") {
                    FileSystemException::DuplicateFile { path: msg }
                } else {
                    FileSystemException::Other { message: msg }
                }
            }
            GhidraError::NotSupported(msg) => {
                FileSystemException::NotSupported { message: msg }
            }
            other => FileSystemException::Other {
                message: format!("{}", other),
            },
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_found_display() {
        let e = FileSystemException::not_found("/path/to/missing");
        assert_eq!(format!("{}", e), "Not found: /path/to/missing");
        assert!(e.is_not_found());
        assert!(!e.is_recoverable());
    }

    #[test]
    fn test_already_exists_display() {
        let e = FileSystemException::already_exists("/tmp/existing");
        assert_eq!(format!("{}", e), "Already exists: /tmp/existing");
    }

    #[test]
    fn test_read_only_display() {
        let e = FileSystemException::read_only();
        assert_eq!(format!("{}", e), "File system is read-only");
    }

    #[test]
    fn test_lock_error_with_resource() {
        let e = FileSystemException::lock_error("timeout", Some("resource-a"));
        let msg = format!("{}", e);
        assert!(msg.contains("resource-a"));
        assert!(msg.contains("timeout"));
        assert!(e.is_recoverable());
    }

    #[test]
    fn test_lock_error_without_resource() {
        let e = FileSystemException::lock_error("deadlock", None as Option<&str>);
        let msg = format!("{}", e);
        assert!(msg.contains("deadlock"));
        assert!(e.is_recoverable());
    }

    #[test]
    fn test_file_in_use() {
        let e = FileSystemException::file_in_use("/data/file.db", Some("alice"));
        let msg = format!("{}", e);
        assert!(msg.contains("file.db"));
        assert!(msg.contains("alice"));
        assert!(e.is_recoverable());
    }

    #[test]
    fn test_exclusive_checkout() {
        let e = FileSystemException::exclusive_checkout("held by bob");
        assert!(format!("{}", e).contains("held by bob"));
    }

    #[test]
    fn test_folder_not_empty() {
        let e = FileSystemException::folder_not_empty("/projects/data");
        assert!(format!("{}", e).contains("/projects/data"));
    }

    #[test]
    fn test_invalid_name() {
        let e = FileSystemException::invalid_name("bad/name", "contains slash");
        let msg = format!("{}", e);
        assert!(msg.contains("bad/name"));
        assert!(msg.contains("contains slash"));
    }

    #[test]
    fn test_io_error_from_std() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let fs_err = FileSystemException::from(io_err);
        assert!(format!("{}", fs_err).contains("denied"));
    }

    #[test]
    fn test_conversion_to_ghidra_error() {
        let fs_err = FileSystemException::not_found("/test");
        let gh_err: GhidraError = fs_err.into();
        assert!(matches!(gh_err, GhidraError::NotFound(_)));
    }

    #[test]
    fn test_conversion_from_ghidra_error() {
        let gh_err = GhidraError::NotFound("test".into());
        let fs_err = FileSystemException::from(gh_err);
        assert!(fs_err.is_not_found());
    }

    #[test]
    fn test_io_error_roundtrip() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let fs_err = FileSystemException::IoError {
            source: io_err,
            path: Some(PathBuf::from("/some/path")),
        };
        let gh_err: GhidraError = fs_err.into();
        assert!(matches!(gh_err, GhidraError::IoError(_)));
    }

    #[test]
    fn test_error_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "inner");
        let fs_err = FileSystemException::IoError {
            source: io_err,
            path: None,
        };
        assert!(fs_err.source().is_some());

        let fs_err2 = FileSystemException::not_found("test");
        assert!(fs_err2.source().is_none());
    }

    #[test]
    fn test_not_supported() {
        let e = FileSystemException::not_supported("versioning");
        assert!(format!("{}", e).contains("versioning"));
    }

    #[test]
    fn test_invalid_state() {
        let e = FileSystemException::invalid_state("corrupt");
        assert!(format!("{}", e).contains("corrupt"));
    }

    #[test]
    fn test_other() {
        let e = FileSystemException::other("something went wrong");
        assert!(format!("{}", e).contains("something went wrong"));
    }

    #[test]
    fn test_convenience_constructors_from_store() {
        let e = lock_error("test lock");
        assert!(format!("{}", e).contains("Lock error"));

        let e = read_only_error();
        assert!(format!("{}", e).contains("read-only"));

        let e = duplicate_file_error("test.txt");
        assert!(format!("{}", e).contains("Duplicate file"));

        let e = folder_not_empty_error("/my/folder");
        assert!(format!("{}", e).contains("Folder not empty"));

        let e = invalid_name_error("bad*name");
        assert!(format!("{}", e).contains("Invalid name"));

        let e = file_in_use_error("locked.db");
        assert!(format!("{}", e).contains("File in use"));

        let e = not_found_error("missing.txt");
        assert!(format!("{}", e).contains("missing.txt"));
    }
}
