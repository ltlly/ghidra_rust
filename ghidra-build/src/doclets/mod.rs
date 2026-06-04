//! Javadoc doclet tools for generating Python type stubs and JSON documentation.
//!
//! Port of Ghidra's `ghidra.doclets` package.
//!
//! The original Java code uses the `jdk.javadoc.doclet` API which is inherently
//! Java-specific. This Rust port models the output formats (Python `.pyi` stubs
//! and JSON documentation) and the data transformations, rather than the
//! Javadoc parser internals.

pub mod json_doclet;
pub mod python_type_stub;
pub mod rst_table;

pub use json_doclet::*;
pub use python_type_stub::*;
pub use rst_table::*;
