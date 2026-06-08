//! Binary I/O utilities ported from Ghidra's `ghidra.app.util.bin` and
//! `ghidra.app.util.bin.format` packages.
//!
//! Provides core types for reading and writing binary data:
//! - [`ByteProvider`] trait -- random-access byte source
//! - [`MutableByteProvider`] trait -- read-write byte source
//! - [`BinaryReader`] -- endian-aware binary reader with cursor
//! - [`BinaryWriter`] -- endian-aware binary writer (maps to Java `Writeable`)
//! - [`MemoryLoadable`] -- marker trait for memory-loadable binary sections
//! - [`StructConverter`] -- trait for converting structs to Ghidra DataType
//! - [`RelocationException`] -- error for relocation processing
//! - [`InvalidDataException`] -- error for invalid data encountered during parsing
//! - [`InputStreamByteProvider`] -- forward-only stream-based byte source
//! - [`RangeMappedByteProvider`] -- sparse range-mapped concatenation of sub-ranges
//! - [`FaultTolerantInputStream`] -- I/O error suppression with zero-fill fallback
//! - [`GhidraRandomAccessFile`] -- buffered random-access file with double-buffering
//! - [`MemBufferByteProvider`] -- byte provider backed by an in-memory buffer
//! - [`ByteProviderInputStream`] -- `Read` adapter over a `ByteProvider`
//! - LEB128 variable-length integer encoding/decoding
//! - Utility functions for checksums, hashing, and bit manipulation

pub mod analysis_command;
pub mod binary_reader;
pub mod binary_writer;
pub mod byte_provider;
pub mod byte_provider_stream;
pub mod coff;
pub mod coff_analysis;
pub mod dwarf;
pub mod elf;
pub mod elf_analysis;
pub mod fault_tolerant_stream;
pub mod golang;
pub mod leb128;
pub mod macho_analysis;
pub mod mem_buffer_provider;
pub mod mz;
pub mod ne;
pub mod padded_stream;
pub mod pe;
pub mod pe_analysis;
pub mod random_access_file;
pub mod range_mapped_provider;
pub mod stream_provider;
pub mod struct_converter_util;
pub mod types;
pub mod ubi;
pub mod unixaout;
pub mod unlimited_byte_provider_wrapper;
pub mod util;
pub mod xcoff;
pub mod lx;
pub mod som;

// Re-export key types for convenience
pub use binary_reader::BinaryReader;
pub use binary_writer::{BinaryWritable, BinaryWriter};
pub use byte_provider::{
    AccessMode, ByteArrayConverter, ByteArrayProvider, ByteProvider, ByteProviderWrapper,
    EmptyByteProvider, FileByteProvider, MutableByteProvider, SynchronizedByteProvider,
};
pub use leb128::{LEB128Info, LEB128};
pub use types::{
    DataTypeDescription, InvalidDataException, MemoryLoadable, RelocationException,
    StructConverter,
};
pub use fault_tolerant_stream::FaultTolerantInputStream;
pub use ne::{
    InformationBlock as NeInformationBlock, NewExecutable, Segment as NeSegment,
    SegmentRelocation as NeSegmentRelocation, SegmentTable as NeSegmentTable,
    WindowsHeader as NeWindowsHeader,
};
pub use ubi::{FatArch, FatHeader, UbiException};
pub use range_mapped_provider::RangeMappedByteProvider;
pub use stream_provider::InputStreamByteProvider;
pub use padded_stream::PaddedByteProvider;
pub use struct_converter_util::{FieldDescriptor, ReflectableStruct, StructConverterUtil, StructDescriptor};
pub use unlimited_byte_provider_wrapper::UnlimitedByteProviderWrapper;
pub use util::{bytes_to_hex, crc32, hex_to_bytes, md5, sha256};
pub use random_access_file::GhidraRandomAccessFile;
pub use mem_buffer_provider::{BorrowedMemBufferProvider, MemBufferByteProvider};
pub use byte_provider_stream::{
    ByteProviderInputStream, ClosingByteProviderStream, OwnedByteProviderStream,
};
pub use coff_analysis::CoffAnalysisCommand;
pub use macho_analysis::MachoAnalysisCommand;
pub use pe_analysis::PeAnalysisCommand;
pub use xcoff::{
    XCoffArchiveHeader, XCoffArchiveMemberHeader, XCoffException, XCoffFileHeader,
    XCoffOptionalHeader, XCoffSectionHeader, XCoffSymbol,
};
pub use dwarf::{DwarfChildren, DwarfEncoding, DwarfException};
pub use golang::{GoVer, GoVerRange, GOLANG_CATEGORYPATH};
pub use som::{
    read_next_aux_header, SomAuxHeader, SomCompilationUnit, SomConstants, SomDltEntry,
    SomDynamicLoaderHeader, SomDynamicRelocation, SomException, SomExecAuxHeader, SomExportEntry,
    SomExportEntryExt, SomHeader, SomImportEntry, SomLinkerFootprintAuxHeader, SomModuleEntry,
    SomPltEntry, SomProductSpecificsAuxHeader, SomShlibListEntry, SomSpace, SomSubspace,
    SomSymbol, SomSysClock, SomUnknownAuxHeader, SomAuxId,
};
