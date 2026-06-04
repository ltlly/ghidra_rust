//! Binary I/O utilities ported from Ghidra's `ghidra.app.util.bin` and
//! `ghidra.app.util.bin.format` packages.
//!
//! Provides core types for reading and writing binary data:
//! - [`ByteProvider`] trait -- random-access byte source
//! - [`BinaryReader`] -- endian-aware binary reader with cursor
//! - [`BinaryWriter`] -- endian-aware binary writer (maps to Java `Writeable`)
//! - [`MemoryLoadable`] -- marker trait for memory-loadable binary sections
//! - [`StructConverter`] -- trait for converting structs to Ghidra DataType
//! - [`RelocationException`] -- error for relocation processing
//! - [`InvalidDataException`] -- error for invalid data encountered during parsing
//! - LEB128 variable-length integer encoding/decoding

use std::fmt;
use std::io::{self, Read, Write};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// ByteProvider trait
// ---------------------------------------------------------------------------

/// A generic random-access byte provider.
///
/// Ported from `ghidra.app.util.bin.ByteProvider`. This is the fundamental
/// abstraction for accessing binary data in Ghidra -- all format parsers
/// read data through this trait.
pub trait ByteProvider: Send + Sync {
    /// Returns the name of this byte provider (e.g., filename).
    fn name(&self) -> Option<&str>;

    /// Returns the absolute path to this byte provider, if file-backed.
    fn absolute_path(&self) -> Option<&str>;

    /// Returns the length of the byte provider in bytes.
    fn length(&self) -> u64;

    /// Returns true if the provider is empty.
    fn is_empty(&self) -> bool {
        self.length() == 0
    }

    /// Returns true if the given index is valid.
    fn is_valid_index(&self, index: u64) -> bool {
        index < self.length()
    }

    /// Read a single byte at the given index.
    fn read_u8(&self, index: u64) -> io::Result<u8>;

    /// Read multiple bytes starting at the given index.
    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Read a slice of bytes starting at index with the given length.
    fn read_slice(&self, index: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.read_bytes(index, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Close and release resources.
    fn close(&self) {}
}

// ---------------------------------------------------------------------------
// ByteProvider implementations
// ---------------------------------------------------------------------------

/// An in-memory byte provider backed by a `Vec<u8>`.
///
/// Ported from `ghidra.app.util.bin.ByteArrayProvider`.
pub struct ByteArrayProvider {
    name: Option<String>,
    path: Option<PathBuf>,
    data: Vec<u8>,
}

impl ByteArrayProvider {
    /// Create a new byte array provider.
    pub fn new(name: Option<String>, data: Vec<u8>) -> Self {
        Self {
            name,
            path: None,
            data,
        }
    }

    /// Create with a file path.
    pub fn with_path(name: Option<String>, path: PathBuf, data: Vec<u8>) -> Self {
        Self {
            name,
            path: Some(path),
            data,
        }
    }

    /// Get a reference to the underlying data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl ByteProvider for ByteArrayProvider {
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn absolute_path(&self) -> Option<&str> {
        self.path.as_ref().and_then(|p| p.to_str())
    }

    fn length(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_u8(&self, index: u64) -> io::Result<u8> {
        let idx = index as usize;
        if idx >= self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("index {} out of range (len={})", index, self.data.len()),
            ));
        }
        Ok(self.data[idx])
    }

    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        let idx = index as usize;
        if idx >= self.data.len() {
            return Ok(0);
        }
        let available = self.data.len() - idx;
        let to_read = buf.len().min(available);
        buf[..to_read].copy_from_slice(&self.data[idx..idx + to_read]);
        Ok(to_read)
    }
}

/// An empty byte provider that contains no data.
///
/// Ported from `ghidra.app.util.bin.EmptyByteProvider`.
pub struct EmptyByteProvider;

impl ByteProvider for EmptyByteProvider {
    fn name(&self) -> Option<&str> {
        None
    }
    fn absolute_path(&self) -> Option<&str> {
        None
    }
    fn length(&self) -> u64 {
        0
    }
    fn read_u8(&self, _index: u64) -> io::Result<u8> {
        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty provider"))
    }
    fn read_bytes(&self, _index: u64, _buf: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

/// A wrapper that adds a view/window over a portion of another ByteProvider.
///
/// Ported from `ghidra.app.util.bin.ByteProviderWrapper`.
pub struct ByteProviderWrapper {
    inner: Box<dyn ByteProvider>,
    offset: u64,
    length: u64,
}

impl ByteProviderWrapper {
    /// Create a new wrapper over a subrange.
    pub fn new(inner: Box<dyn ByteProvider>, offset: u64, length: u64) -> Self {
        let actual_len = length.min(inner.length().saturating_sub(offset));
        Self {
            inner,
            offset,
            length: actual_len,
        }
    }
}

impl ByteProvider for ByteProviderWrapper {
    fn name(&self) -> Option<&str> {
        self.inner.name()
    }
    fn absolute_path(&self) -> Option<&str> {
        self.inner.absolute_path()
    }
    fn length(&self) -> u64 {
        self.length
    }
    fn read_u8(&self, index: u64) -> io::Result<u8> {
        if index >= self.length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "index out of range",
            ));
        }
        self.inner.read_u8(self.offset + index)
    }
    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        if index >= self.length {
            return Ok(0);
        }
        let available = self.length - index;
        let to_read = buf.len().min(available as usize);
        self.inner.read_bytes(self.offset + index, &mut buf[..to_read])
    }
}

// ---------------------------------------------------------------------------
// BinaryReader
// ---------------------------------------------------------------------------

/// Endian-aware binary reader with an internal cursor.
///
/// Ported from `ghidra.app.util.bin.BinaryReader`. Reads data from a
/// `ByteProvider` in either big-endian or little-endian byte order.
pub struct BinaryReader {
    provider: Box<dyn ByteProvider>,
    is_little_endian: bool,
    index: u64,
}

impl BinaryReader {
    /// Size constants matching Java's `BinaryReader`.
    pub const SIZEOF_BYTE: usize = 1;
    pub const SIZEOF_SHORT: usize = 2;
    pub const SIZEOF_INT: usize = 4;
    pub const SIZEOF_LONG: usize = 8;

    /// Create a new reader.
    pub fn new(provider: Box<dyn ByteProvider>, is_little_endian: bool) -> Self {
        Self {
            provider,
            is_little_endian,
            index: 0,
        }
    }

    /// Create a reader from a byte slice.
    pub fn from_bytes(data: &[u8], is_little_endian: bool) -> Self {
        Self::new(
            Box::new(ByteArrayProvider::new(None, data.to_vec())),
            is_little_endian,
        )
    }

    /// Get the underlying byte provider.
    pub fn provider(&self) -> &dyn ByteProvider {
        self.provider.as_ref()
    }

    /// Get the current cursor position.
    pub fn cursor(&self) -> u64 {
        self.index
    }

    /// Set the cursor position.
    pub fn set_cursor(&mut self, index: u64) {
        self.index = index;
    }

    /// Advance the cursor by the given offset.
    pub fn advance(&mut self, offset: u64) {
        self.index += offset;
    }

    /// Get the total length of the underlying provider.
    pub fn length(&self) -> u64 {
        self.provider.length()
    }

    /// Returns true if the reader is little-endian.
    pub fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    /// Get the number of remaining bytes from cursor to end.
    pub fn remaining(&self) -> u64 {
        self.provider.length().saturating_sub(self.index)
    }

    // --- Read primitives at cursor (advancing) ---

    /// Read a u8 at cursor and advance by 1.
    pub fn read_next_u8(&mut self) -> io::Result<u8> {
        let val = self.provider.read_u8(self.index)?;
        self.index += 1;
        Ok(val)
    }

    /// Read a i8 at cursor and advance by 1.
    pub fn read_next_i8(&mut self) -> io::Result<i8> {
        Ok(self.read_next_u8()? as i8)
    }

    /// Read a u16 at cursor and advance by 2.
    pub fn read_next_u16(&mut self) -> io::Result<u16> {
        let mut buf = [0u8; 2];
        self.read_exact_at_cursor(&mut buf)?;
        Ok(if self.is_little_endian {
            u16::from_le_bytes(buf)
        } else {
            u16::from_be_bytes(buf)
        })
    }

    /// Read a i16 at cursor and advance by 2.
    pub fn read_next_i16(&mut self) -> io::Result<i16> {
        Ok(self.read_next_u16()? as i16)
    }

    /// Read a u32 at cursor and advance by 4.
    pub fn read_next_u32(&mut self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact_at_cursor(&mut buf)?;
        Ok(if self.is_little_endian {
            u32::from_le_bytes(buf)
        } else {
            u32::from_be_bytes(buf)
        })
    }

    /// Read a i32 at cursor and advance by 4.
    pub fn read_next_i32(&mut self) -> io::Result<i32> {
        Ok(self.read_next_u32()? as i32)
    }

    /// Read a u64 at cursor and advance by 8.
    pub fn read_next_u64(&mut self) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact_at_cursor(&mut buf)?;
        Ok(if self.is_little_endian {
            u64::from_le_bytes(buf)
        } else {
            u64::from_be_bytes(buf)
        })
    }

    /// Read a i64 at cursor and advance by 8.
    pub fn read_next_i64(&mut self) -> io::Result<i64> {
        Ok(self.read_next_u64()? as i64)
    }

    /// Read a f32 at cursor and advance by 4.
    pub fn read_next_f32(&mut self) -> io::Result<f32> {
        Ok(f32::from_bits(self.read_next_u32()?))
    }

    /// Read a f64 at cursor and advance by 8.
    pub fn read_next_f64(&mut self) -> io::Result<f64> {
        Ok(f64::from_bits(self.read_next_u64()?))
    }

    /// Read `len` bytes at cursor and advance.
    pub fn read_next_bytes(&mut self, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.read_exact_at_cursor(&mut buf)?;
        Ok(buf)
    }

    /// Read a null-terminated ASCII string at cursor and advance past the null.
    pub fn read_next_cstring(&mut self) -> io::Result<String> {
        let mut bytes = Vec::new();
        loop {
            let b = self.read_next_u8()?;
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Read a fixed-length ASCII string at cursor (padded with nulls) and advance.
    pub fn read_next_fixed_string(&mut self, len: usize) -> io::Result<String> {
        let bytes = self.read_next_bytes(len)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
    }

    // --- Read primitives at arbitrary index (non-advancing) ---

    /// Read a u8 at the given index without moving the cursor.
    pub fn read_u8_at(&self, index: u64) -> io::Result<u8> {
        self.provider.read_u8(index)
    }

    /// Read a u16 at the given index without moving the cursor.
    pub fn read_u16_at(&self, index: u64) -> io::Result<u16> {
        let mut buf = [0u8; 2];
        self.provider.read_bytes(index, &mut buf)?;
        Ok(if self.is_little_endian {
            u16::from_le_bytes(buf)
        } else {
            u16::from_be_bytes(buf)
        })
    }

    /// Read a u32 at the given index without moving the cursor.
    pub fn read_u32_at(&self, index: u64) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.provider.read_bytes(index, &mut buf)?;
        Ok(if self.is_little_endian {
            u32::from_le_bytes(buf)
        } else {
            u32::from_be_bytes(buf)
        })
    }

    /// Read a u64 at the given index without moving the cursor.
    pub fn read_u64_at(&self, index: u64) -> io::Result<u64> {
        let mut buf = [0u8; 8];
        self.provider.read_bytes(index, &mut buf)?;
        Ok(if self.is_little_endian {
            u64::from_le_bytes(buf)
        } else {
            u64::from_be_bytes(buf)
        })
    }

    /// Read bytes at the given index without moving the cursor.
    pub fn read_bytes_at(&self, index: u64, len: usize) -> io::Result<Vec<u8>> {
        self.provider.read_slice(index, len)
    }

    // --- Convenience methods matching Java BinaryReader ---

    /// Read a u32 at the given index in the specified endianness.
    pub fn read_u32_at_endian(index: u64, provider: &dyn ByteProvider, le: bool) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        provider.read_bytes(index, &mut buf)?;
        Ok(if le {
            u32::from_le_bytes(buf)
        } else {
            u32::from_be_bytes(buf)
        })
    }

    /// Create a new reader with a different endianness sharing the same provider.
    ///
    /// NOTE: The returned reader has its own cursor starting at 0.
    pub fn as_other_endian(&self, is_little_endian: bool) -> io::Result<BinaryReader> {
        // We need to clone the provider data; the simplest approach is to
        // read all bytes. For large providers, callers should use slices.
        let data = self.provider.read_slice(0, self.provider.length() as usize)?;
        Ok(BinaryReader::from_bytes(&data, is_little_endian))
    }

    // Private helper
    fn read_exact_at_cursor(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let n = self.provider.read_bytes(self.index, buf)?;
        if n < buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "expected {} bytes at offset {}, got {}",
                    buf.len(),
                    self.index,
                    n
                ),
            ));
        }
        self.index += buf.len() as u64;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BinaryWriter (maps to Writeable)
// ---------------------------------------------------------------------------

/// Endian-aware binary writer.
///
/// Ported from Ghidra's `Writeable` interface and `DataConverter` pattern.
pub struct BinaryWriter {
    output: Vec<u8>,
    is_little_endian: bool,
}

impl BinaryWriter {
    /// Create a new writer with the given endianness.
    pub fn new(is_little_endian: bool) -> Self {
        Self {
            output: Vec::new(),
            is_little_endian,
        }
    }

    /// Create a writer with a pre-allocated capacity.
    pub fn with_capacity(capacity: usize, is_little_endian: bool) -> Self {
        Self {
            output: Vec::with_capacity(capacity),
            is_little_endian,
        }
    }

    /// Returns true if the writer is little-endian.
    pub fn is_little_endian(&self) -> bool {
        self.is_little_endian
    }

    /// Get the current write position (length of output).
    pub fn position(&self) -> u64 {
        self.output.len() as u64
    }

    /// Write a u8.
    pub fn write_u8(&mut self, val: u8) {
        self.output.push(val);
    }

    /// Write a u16.
    pub fn write_u16(&mut self, val: u16) {
        let bytes = if self.is_little_endian {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        self.output.extend_from_slice(&bytes);
    }

    /// Write a u32.
    pub fn write_u32(&mut self, val: u32) {
        let bytes = if self.is_little_endian {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        self.output.extend_from_slice(&bytes);
    }

    /// Write a u64.
    pub fn write_u64(&mut self, val: u64) {
        let bytes = if self.is_little_endian {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        self.output.extend_from_slice(&bytes);
    }

    /// Write raw bytes.
    pub fn write_bytes(&mut self, data: &[u8]) {
        self.output.extend_from_slice(data);
    }

    /// Write a null-terminated C string.
    pub fn write_cstring(&mut self, s: &str) {
        self.output.extend_from_slice(s.as_bytes());
        self.output.push(0);
    }

    /// Pad the output with zeros to reach the given alignment.
    pub fn align(&mut self, alignment: usize) {
        let current = self.output.len();
        let padding = (alignment - (current % alignment)) % alignment;
        self.output.extend(std::iter::repeat_n(0u8, padding));
    }

    /// Consume the writer and return the output bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.output
    }

    /// Get a reference to the output bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.output
    }
}

/// Trait for types that can write themselves to a binary format.
///
/// Ported from `ghidra.app.util.bin.format.Writeable`.
pub trait BinaryWritable {
    /// Write this object using the given writer.
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()>;
}

// ---------------------------------------------------------------------------
// MemoryLoadable trait
// ---------------------------------------------------------------------------

/// Marker interface for a memory-loadable portion of a binary file.
///
/// Ported from `ghidra.app.util.bin.format.MemoryLoadable`. Sections that
/// implement this can be loaded into a program's memory model.
pub trait MemoryLoadable: Send + Sync {
    /// Returns the file offset of this loadable section.
    fn file_offset(&self) -> u64;

    /// Returns the in-memory size of this loadable section.
    fn memory_size(&self) -> u64;

    /// Returns the file data size (may differ from memory size if BSS-like).
    fn file_size(&self) -> u64;

    /// Returns the target virtual address for this section.
    fn virtual_address(&self) -> u64;

    /// Returns true if this section requires filtered/decompressed input
    /// rather than a direct memory-mapped load.
    fn has_filtered_load(&self) -> bool {
        false
    }

    /// Returns true if this section is initialized (has data in the file).
    fn is_initialized(&self) -> bool {
        self.file_size() > 0
    }

    /// Returns the section name, if any.
    fn section_name(&self) -> Option<&str> {
        None
    }

    /// Returns the raw data bytes for this section.
    fn raw_data(&self) -> io::Result<Vec<u8>>;

    /// Returns true if the section has read permission.
    fn is_readable(&self) -> bool {
        true
    }

    /// Returns true if the section has write permission.
    fn is_writable(&self) -> bool {
        false
    }

    /// Returns true if the section has execute permission.
    fn is_executable(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// RelocationException
// ---------------------------------------------------------------------------

/// Error type for relocation processing.
///
/// Ported from `ghidra.app.util.bin.format.RelocationException`.
#[derive(Debug)]
pub struct RelocationException(pub String);

impl fmt::Display for RelocationException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Relocation error: {}", self.0)
    }
}

impl std::error::Error for RelocationException {}

// ---------------------------------------------------------------------------
// InvalidDataException
// ---------------------------------------------------------------------------

/// Error for invalid data encountered during binary parsing.
///
/// Ported from `ghidra.app.util.bin.InvalidDataException`.
#[derive(Debug)]
pub struct InvalidDataException {
    pub message: String,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl InvalidDataException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for InvalidDataException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid data: {}", self.message)
    }
}

impl std::error::Error for InvalidDataException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

// ---------------------------------------------------------------------------
// StructConverter trait
// ---------------------------------------------------------------------------

/// Allows a struct to create a Ghidra DataType equivalent.
///
/// Ported from `ghidra.app.util.bin.StructConverter`. Implementations
/// return a `DataTypeDescription` that represents the struct's layout.
pub trait StructConverter {
    /// Convert this struct to a data type description.
    fn to_data_type(&self) -> DataTypeDescription;
}

/// Description of a Ghidra data type for struct conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataTypeDescription {
    /// A single byte.
    Byte,
    /// A 16-bit word.
    Word,
    /// A 32-bit double word.
    DWord,
    /// A 64-bit quad word.
    QWord,
    /// An ASCII character.
    Ascii,
    /// A string (null-terminated).
    String,
    /// A UTF-8 string.
    Utf8,
    /// A UTF-16 string.
    Utf16,
    /// A pointer.
    Pointer,
    /// Void.
    Void,
    /// A 32-bit image base offset.
    Ibo32,
    /// A 64-bit image base offset.
    Ibo64,
    /// An array of elements.
    Array {
        /// Element type.
        element: Box<DataTypeDescription>,
        /// Number of elements.
        count: usize,
    },
    /// A struct with named fields.
    Struct {
        /// Struct name.
        name: String,
        /// Ordered list of (field_name, field_type).
        fields: Vec<(String, DataTypeDescription)>,
    },
    /// A pointer to another type.
    PointerTo(Box<DataTypeDescription>),
    /// Undefined/unknown type with a byte length.
    Undefined(usize),
}

impl fmt::Display for DataTypeDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataTypeDescription::Byte => write!(f, "byte"),
            DataTypeDescription::Word => write!(f, "word"),
            DataTypeDescription::DWord => write!(f, "dword"),
            DataTypeDescription::QWord => write!(f, "qword"),
            DataTypeDescription::Ascii => write!(f, "char"),
            DataTypeDescription::String => write!(f, "string"),
            DataTypeDescription::Utf8 => write!(f, "string_utf8"),
            DataTypeDescription::Utf16 => write!(f, "unicode"),
            DataTypeDescription::Pointer => write!(f, "pointer"),
            DataTypeDescription::Void => write!(f, "void"),
            DataTypeDescription::Ibo32 => write!(f, "ibo32"),
            DataTypeDescription::Ibo64 => write!(f, "ibo64"),
            DataTypeDescription::Array { element, count } => {
                write!(f, "{}[{}]", element, count)
            }
            DataTypeDescription::Struct { name, .. } => write!(f, "struct {}", name),
            DataTypeDescription::PointerTo(inner) => write!(f, "{} *", inner),
            DataTypeDescription::Undefined(n) => write!(f, "undefined{}", n),
        }
    }
}

// ---------------------------------------------------------------------------
// LEB128 encoding/decoding
// ---------------------------------------------------------------------------

/// Decoded LEB128 value with its byte length.
///
/// Ported from `ghidra.app.util.bin.LEB128Info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LEB128Info {
    /// The decoded value.
    pub value: u64,
    /// The number of bytes consumed to decode.
    pub length: usize,
}

/// LEB128 (Little Endian Base 128) variable-length integer encoding.
///
/// Ported from Ghidra's LEB128 utilities. This encoding is used in DWARF
/// debug info, WebAssembly, and many other formats.
pub struct LEB128;

impl LEB128 {
    /// Decode an unsigned LEB128 value from the given bytes.
    pub fn read_unsigned(data: &[u8]) -> io::Result<LEB128Info> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        let mut bytes_read: usize = 0;

        for &byte in data {
            bytes_read += 1;
            let low_bits = (byte & 0x7F) as u64;
            result |= low_bits << shift;
            if byte & 0x80 == 0 {
                return Ok(LEB128Info {
                    value: result,
                    length: bytes_read,
                });
            }
            shift += 7;
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ULEB128 too large",
                ));
            }
        }

        Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated ULEB128",
        ))
    }

    /// Decode a signed LEB128 value from the given bytes.
    pub fn read_signed(data: &[u8]) -> io::Result<(i64, usize)> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        let mut bytes_read: usize = 0;
        let mut byte: u8 = 0;

        for &b in data {
            byte = b;
            bytes_read += 1;
            let low_bits = (byte & 0x7F) as i64;
            result |= low_bits << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SLEB128 too large",
                ));
            }
        }

        // Sign extend if the high bit of the last byte is set
        if shift < 64 && (byte & 0x40) != 0 {
            result |= -(1i64 << shift);
        }

        Ok((result, bytes_read))
    }

    /// Encode an unsigned value as ULEB128.
    pub fn write_unsigned(mut value: u64) -> Vec<u8> {
        let mut result = Vec::new();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            result.push(byte);
            if value == 0 {
                break;
            }
        }
        result
    }

    /// Encode a signed value as SLEB128.
    pub fn write_signed(mut value: i64) -> Vec<u8> {
        let mut result = Vec::new();
        loop {
            let mut byte = (value & 0x7F) as u8;
            value >>= 7;
            if (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0) {
                result.push(byte);
                break;
            }
            byte |= 0x80;
            result.push(byte);
        }
        result
    }

    /// Read an unsigned LEB128 from a BinaryReader, advancing the cursor.
    pub fn read_unsigned_from_reader(reader: &mut BinaryReader) -> io::Result<LEB128Info> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        let mut bytes_read: usize = 0;

        loop {
            let byte = reader.read_next_u8()?;
            bytes_read += 1;
            let low_bits = (byte & 0x7F) as u64;
            result |= low_bits << shift;
            if byte & 0x80 == 0 {
                return Ok(LEB128Info {
                    value: result,
                    length: bytes_read,
                });
            }
            shift += 7;
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ULEB128 too large",
                ));
            }
        }
    }

    /// Read a signed LEB128 from a BinaryReader, advancing the cursor.
    pub fn read_signed_from_reader(reader: &mut BinaryReader) -> io::Result<(i64, usize)> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        let mut bytes_read: usize = 0;
        let mut byte: u8 = 0;

        loop {
            byte = reader.read_next_u8()?;
            bytes_read += 1;
            let low_bits = (byte & 0x7F) as i64;
            result |= low_bits << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SLEB128 too large",
                ));
            }
        }

        // Sign extend
        if shift < 64 && (byte & 0x40) != 0 {
            result |= -(1i64 << shift);
        }

        Ok((result, bytes_read))
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Read all bytes from a reader into a `Vec<u8>`.
pub fn read_all(reader: &mut BinaryReader) -> io::Result<Vec<u8>> {
    let len = reader.remaining() as usize;
    reader.read_next_bytes(len)
}

/// Compute a CRC32 checksum of the given data.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Compute an MD5 hash of the given data (returns 16 bytes).
pub fn md5(data: &[u8]) -> [u8; 16] {
    use md5::Digest;
    let result = md5::Md5::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

/// Compute a SHA-256 hash of the given data (returns 32 bytes).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let result = sha2::Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Byte array to hex string.
pub fn bytes_to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_array_provider() {
        let provider = ByteArrayProvider::new(Some("test".into()), vec![1, 2, 3, 4, 5]);
        assert_eq!(provider.length(), 5);
        assert_eq!(provider.name(), Some("test"));
        assert!(provider.is_valid_index(4));
        assert!(!provider.is_valid_index(5));
        assert_eq!(provider.read_u8(2).unwrap(), 3);

        let mut buf = [0u8; 3];
        let n = provider.read_bytes(1, &mut buf).unwrap();
        assert_eq!(n, 3);
        assert_eq!(buf, [2, 3, 4]);
    }

    #[test]
    fn test_empty_byte_provider() {
        let provider = EmptyByteProvider;
        assert_eq!(provider.length(), 0);
        assert!(provider.is_empty());
        assert!(!provider.is_valid_index(0));
    }

    #[test]
    fn test_byte_provider_wrapper() {
        let inner = ByteArrayProvider::new(None, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let wrapper = ByteProviderWrapper::new(Box::new(inner), 3, 5);
        assert_eq!(wrapper.length(), 5);
        assert_eq!(wrapper.read_u8(0).unwrap(), 3);
        assert_eq!(wrapper.read_u8(4).unwrap(), 7);
    }

    #[test]
    fn test_binary_reader_le() {
        let data = vec![0x78, 0x56, 0x34, 0x12];
        let mut reader = BinaryReader::from_bytes(&data, true);
        assert_eq!(reader.read_next_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_binary_reader_be() {
        let data = vec![0x12, 0x34, 0x56, 0x78];
        let mut reader = BinaryReader::from_bytes(&data, false);
        assert_eq!(reader.read_next_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_binary_reader_cursor() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut reader = BinaryReader::from_bytes(&data, true);
        assert_eq!(reader.cursor(), 0);
        let val = reader.read_next_u16().unwrap();
        assert_eq!(val, 0x0201);
        assert_eq!(reader.cursor(), 2);
        reader.set_cursor(4);
        let val = reader.read_next_u32().unwrap();
        assert_eq!(val, 0x08070605);
    }

    #[test]
    fn test_binary_reader_at() {
        let data = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
        let reader = BinaryReader::from_bytes(&data, false);
        assert_eq!(reader.read_u16_at(0).unwrap(), 0xAABB);
        assert_eq!(reader.read_u32_at(2).unwrap(), 0xCCDDEEFF);
        assert_eq!(reader.cursor(), 0); // cursor unchanged
    }

    #[test]
    fn test_binary_reader_string() {
        let data = b"hello\0world\0";
        let mut reader = BinaryReader::from_bytes(data, true);
        assert_eq!(reader.read_next_cstring().unwrap(), "hello");
        assert_eq!(reader.read_next_cstring().unwrap(), "world");
    }

    #[test]
    fn test_binary_reader_fixed_string() {
        let data = b"hello\0\0\0";
        let mut reader = BinaryReader::from_bytes(data, true);
        assert_eq!(reader.read_next_fixed_string(8).unwrap(), "hello");
    }

    #[test]
    fn test_binary_reader_remaining() {
        let data = vec![0u8; 10];
        let mut reader = BinaryReader::from_bytes(&data, true);
        assert_eq!(reader.remaining(), 10);
        reader.advance(3);
        assert_eq!(reader.remaining(), 7);
    }

    #[test]
    fn test_binary_writer() {
        let mut writer = BinaryWriter::new(true);
        writer.write_u8(0x01);
        writer.write_u16(0x0203);
        writer.write_u32(0x04050607);
        let data = writer.into_vec();
        assert_eq!(data, vec![0x01, 0x03, 0x02, 0x07, 0x06, 0x05, 0x04]);
    }

    #[test]
    fn test_binary_writer_be() {
        let mut writer = BinaryWriter::new(false);
        writer.write_u16(0x0203);
        writer.write_u32(0x04050607);
        let data = writer.into_vec();
        assert_eq!(data, vec![0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    }

    #[test]
    fn test_binary_writer_align() {
        let mut writer = BinaryWriter::new(true);
        writer.write_u8(0xAA);
        writer.write_u8(0xBB);
        writer.align(4);
        assert_eq!(writer.position(), 4);
        assert_eq!(writer.as_slice(), &[0xAA, 0xBB, 0x00, 0x00]);
    }

    #[test]
    fn test_binary_writer_cstring() {
        let mut writer = BinaryWriter::new(true);
        writer.write_cstring("test");
        assert_eq!(writer.as_slice(), b"test\0");
    }

    #[test]
    fn test_leb128_unsigned() {
        // 624485 encodes as 0xE5, 0x8E, 0x26
        let encoded = LEB128::write_unsigned(624485);
        assert_eq!(encoded, vec![0xE5, 0x8E, 0x26]);

        let decoded = LEB128::read_unsigned(&encoded).unwrap();
        assert_eq!(decoded.value, 624485);
        assert_eq!(decoded.length, 3);
    }

    #[test]
    fn test_leb128_signed() {
        // -123456 encodes as ...
        let encoded = LEB128::write_signed(-123456);
        let (decoded, len) = LEB128::read_signed(&encoded).unwrap();
        assert_eq!(decoded, -123456);
        assert_eq!(len, encoded.len());
    }

    #[test]
    fn test_leb128_small_values() {
        // Single byte values
        assert_eq!(LEB128::write_unsigned(0), vec![0x00]);
        assert_eq!(LEB128::write_unsigned(127), vec![0x7F]);
        assert_eq!(LEB128::write_unsigned(128), vec![0x80, 0x01]);

        assert_eq!(LEB128::read_unsigned(&[0x00]).unwrap().value, 0);
        assert_eq!(LEB128::read_unsigned(&[0x7F]).unwrap().value, 127);
        assert_eq!(LEB128::read_unsigned(&[0x80, 0x01]).unwrap().value, 128);
    }

    #[test]
    fn test_leb128_reader() {
        let data = LEB128::write_unsigned(1000);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let info = LEB128::read_unsigned_from_reader(&mut reader).unwrap();
        assert_eq!(info.value, 1000);
        assert_eq!(reader.cursor(), info.length as u64);
    }

    #[test]
    fn test_leb128_signed_reader() {
        let data = LEB128::write_signed(-1000);
        let mut reader = BinaryReader::from_bytes(&data, true);
        let (value, len) = LEB128::read_signed_from_reader(&mut reader).unwrap();
        assert_eq!(value, -1000);
        assert_eq!(reader.cursor(), len as u64);
    }

    #[test]
    fn test_relocation_exception() {
        let e = RelocationException("bad relocation".into());
        assert!(e.to_string().contains("bad relocation"));
    }

    #[test]
    fn test_invalid_data_exception() {
        use std::error::Error;
        let e = InvalidDataException::new("bad header");
        assert!(e.to_string().contains("bad header"));
        assert!(e.source().is_none());

        let inner = io::Error::new(io::ErrorKind::InvalidData, "inner");
        let e2 = InvalidDataException::with_source("outer", inner);
        assert!(e2.source().is_some());
    }

    #[test]
    fn test_data_type_description() {
        assert_eq!(DataTypeDescription::Byte.to_string(), "byte");
        assert_eq!(DataTypeDescription::DWord.to_string(), "dword");
        assert_eq!(
            DataTypeDescription::Array {
                element: Box::new(DataTypeDescription::Byte),
                count: 16
            }
            .to_string(),
            "byte[16]"
        );
        assert_eq!(
            DataTypeDescription::Struct {
                name: "Elf64_Ehdr".into(),
                fields: vec![]
            }
            .to_string(),
            "struct Elf64_Ehdr"
        );
    }

    #[test]
    fn test_crc32() {
        let data = b"123456789";
        let checksum = crc32(data);
        assert_eq!(checksum, 0xCBF43926);
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0x01, 0xAB, 0xFF]), "01abff");
    }

    #[test]
    fn test_reader_f32_f64() {
        let val_f32: f32 = 3.14;
        let bytes_f32 = val_f32.to_bits().to_le_bytes();
        let mut reader = BinaryReader::from_bytes(&bytes_f32, true);
        let decoded = reader.read_next_f32().unwrap();
        assert!((decoded - val_f32).abs() < f32::EPSILON);

        let val_f64: f64 = 2.718281828;
        let bytes_f64 = val_f64.to_bits().to_le_bytes();
        let mut reader = BinaryReader::from_bytes(&bytes_f64, true);
        let decoded = reader.read_next_f64().unwrap();
        assert!((decoded - val_f64).abs() < f64::EPSILON);
    }
}
