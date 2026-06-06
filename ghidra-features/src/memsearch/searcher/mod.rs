//! Memory search engine -- the core search infrastructure.
//!
//! Ported from `ghidra.features.base.memsearch.searcher`.
//!
//! - [`MemorySearcher`] -- searches bytes from a byte source using a [`ByteMatcher`]
//! - [`MemoryMatch`] -- a single search hit
//! - [`AlignmentFilter`] -- filters results by address alignment
//! - [`CodeUnitFilter`] -- filters results by code unit type

mod memory_match;
mod memory_searcher;
mod alignment_filter;
mod code_unit_filter;

pub use memory_match::MemoryMatch;
pub use memory_searcher::MemorySearcher;
pub use alignment_filter::AlignmentFilter;
pub use code_unit_filter::CodeUnitFilter;
