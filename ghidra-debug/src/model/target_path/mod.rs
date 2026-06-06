//! Target object path types ported from ghidra.trace.model.target.path.
//!
//! Provides KeyPath (immutable path of keys), PathFilter (trait for path
//! matching), PathPattern (single-path filter), and PathMatcher (union filter).

pub mod key_path;
pub mod path_filter;
pub mod path_matcher;
pub mod path_pattern;

pub use key_path::KeyPath;
pub use path_filter::{Align, PathFilter};
pub use path_matcher::PathMatcher;
pub use path_pattern::PathPattern;
