//! Function Identification (FID) database and matching.
//!
//! Ported from Ghidra's `FunctionID` feature.
//!
//! Provides:
//!
//! - **FidDB**: A SQLite-backed database of function signatures (hashes,
//!   names, library metadata).
//! - **Function hashing**: Multiple hash families (e.g., full body hash,
//!   trimmed hash, instruction-only hash) for robust function matching.
//! - **FidService**: High-level service for querying, populating, and
//!   matching FID databases.
//! - **Match scoring**: Confidence scoring for function identification
//!   matches.

#![allow(ambiguous_glob_reexports)]

pub mod fid_db;
pub mod fid_hasher;
pub mod fid_service;
pub mod fid_file;
pub mod fid_match;

pub use fid_db::*;
pub use fid_hasher::{FidHasher, HashFamily, HashMatch};
pub use fid_service::*;
pub use fid_file::*;
pub use fid_match::{FidMatchScore, FidSearchResult, MatchNameAnalysis, NameVersions, Location};
