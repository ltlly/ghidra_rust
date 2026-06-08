//! Go language support types ported from Ghidra's
//! `ghidra.app.util.bin.format.golang` package.
//!
//! Provides types for parsing and representing Go binary metadata:
//! - [`GoVer`] -- Go version number (major.minor.patch) with wildcard support
//! - [`GoVerRange`] -- contiguous range of Go versions
//! - Constants for calling conventions, category paths, and parameter names

pub mod go_constants;
pub mod go_ver;
pub mod go_ver_range;

// Re-export key types for convenience
pub use go_constants::*;
pub use go_ver::{GoVer, GOLANG_VERSION_PROPERTY_NAME};
pub use go_ver_range::GoVerRange;
