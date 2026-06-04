//! iOS / Apple-specific file format parsers.
//!
//! Ported from Ghidra's `ghidra.file.formats.ios` package.
//!
//! Covers: DMG, HFS, DyldCache, IMG2/IMG3/IMG4, B-tree structures,
//! iBootIM, IPSW, decmpfs, prelink, and other Apple platform formats.

pub mod dmg;
pub mod dyld_cache;

// Re-exports
pub use dmg::DmgHeader;
pub use dyld_cache::DyldCacheHeader;
