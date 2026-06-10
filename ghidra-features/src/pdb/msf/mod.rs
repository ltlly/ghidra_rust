//! MSF (Multi-Stream Format) container module.
//!
//! This module provides the low-level MSF container implementation used
//! by the PDB parser. It defines:
//!
//! - [`msf_file`] -- MSF header, directory, and container types.
//! - [`msf_stream`] -- Stream abstraction and well-known stream indices.

pub mod msf_file;
pub mod msf_stream;

// Re-export key types for convenience.
pub use msf_file::{MsfContainer, MsfHeader, MsfVersion, MsfDirectoryEntry, MsfContainerError};
pub use msf_stream::{MsfStream, MsfStreamInfo};
