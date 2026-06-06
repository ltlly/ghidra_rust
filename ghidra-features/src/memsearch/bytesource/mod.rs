//! Byte sources for memory search -- ported from
//! `ghidra.features.base.memsearch.bytesource`.
//!
//! Provides abstractions for reading bytes from program memory and defining
//! searchable memory regions.

mod addressable;
mod empty;
mod program_source;
mod search_region;

pub use addressable::AddressableByteSource;
pub use empty::EmptyByteSource;
pub use program_source::ProgramByteSource;
pub use search_region::{SearchRegion, ProgramSearchRegion};
