//! iOS / Apple-specific file format parsers.
//!
//! Ported from Ghidra's `ghidra.file.formats.ios` package.
//!
//! Covers: DMG, HFS, DyldCache, IMG2/IMG3/IMG4, B-tree structures,
//! iBootIM, IPSW, decmpfs, prelink, and other Apple platform formats.

pub mod dmg;
pub mod dyld_cache;
pub mod dyld_cache_header;
pub mod dyld_cache_image;
pub mod dyld_cache_slide_info;

// Re-exports
pub use dmg::DmgHeader;
pub use dyld_cache::DyldCacheHeader;
pub use dyld_cache_header::{
    DyldCacheAccelerateInfo, DyldCacheLocalSymbolsEntry, DyldCacheMappingAndSlideInfo,
    DyldCacheMappingInfo, DyldCacheRangeEntry,
};
pub use dyld_cache_image::{
    DyldCacheAcceleratorDof, DyldCacheAcceleratorInitializer, DyldCacheImageInfo,
    DyldCacheImageInfoExtra, DyldCacheImageTextInfo,
};
pub use dyld_cache_slide_info::{
    DyldCacheSlideInfo, DyldCacheSlideInfo1, DyldCacheSlideInfo2, DyldCacheSlideInfo3,
    DyldCacheSlideInfo4, DyldCacheSlideInfo5, DyldFixup,
};
