//! Binary I/O primitives (ported from `ghidra.app.util.bin`).
//!
//! This module provides:
//! - [`ByteProvider`] / [`MutableByteProvider`] -- random-access byte traits
//! - [`ByteArrayProvider`] -- in-memory byte-provider implementation
//! - [`FileByteProvider`] -- file-backed byte-provider implementation
//! - [`BinaryReader`] -- endian-aware structured reader
//! - [`Lep128Info`] -- LEB128 encoding/decoding with metadata
//! - [`FaultTolerantInputStream`] -- I/O that swallows errors

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ===================================================================
// Errors
// ===================================================================

/// Errors that can occur during binary I/O operations.
#[derive(Debug, Error)]
pub enum BinError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Attempted to read beyond the end of the provider.
    #[error("index {index} out of range [0..{length})")]
    OutOfRange {
        /// The requested index.
        index: u64,
        /// The total length.
        length: u64,
    },
    /// Invalid data encountered.
    #[error("invalid data: {0}")]
    InvalidData(String),
    /// LEB128 overflow.
    #[error("LEB128 value overflow: {0}")]
    Leb128Overflow(String),
}

/// Result alias for binary I/O operations.
pub type BinResult<T> = Result<T, BinError>;

// ===================================================================
// ByteProvider  (ghidra.app.util.bin.ByteProvider)
// ===================================================================

/// Trait for a generic random-access byte provider.
///
/// This is the Rust equivalent of the Java `ByteProvider` interface.
/// Implementations provide read-only access to a contiguous sequence of bytes
/// identified by their file-system name and optional path.
pub trait ByteProvider: Send + Sync {
    /// Returns the name of this provider (e.g. file name).
    fn name(&self) -> Option<&str>;

    /// Returns the absolute path to the underlying data, if any.
    fn absolute_path(&self) -> Option<&str>;

    /// Returns the total number of bytes.
    fn length(&self) -> u64;

    /// Returns `true` if this provider contains zero bytes.
    fn is_empty(&self) -> bool {
        self.length() == 0
    }

    /// Returns `true` if the given index is valid (i.e., `< length()`).
    fn is_valid_index(&self, index: u64) -> bool {
        index < self.length()
    }

    /// Read a single byte at the given index.
    fn read_byte(&self, index: u64) -> BinResult<u8>;

    /// Read `count` bytes starting at `index` into a newly allocated `Vec`.
    fn read_bytes(&self, index: u64, count: u64) -> BinResult<Vec<u8>> {
        let end = index.checked_add(count).ok_or(BinError::OutOfRange {
            index,
            length: count,
        })?;
        if end > self.length() {
            return Err(BinError::OutOfRange {
                index: end - 1,
                length: self.length(),
            });
        }
        let mut buf = vec![0u8; count as usize];
        for i in 0..count as usize {
            buf[i] = self.read_byte(index + i as u64)?;
        }
        Ok(buf)
    }

    /// Read exactly `buf.len()` bytes starting at `index` into `buf`.
    fn read_into(&self, index: u64, buf: &mut [u8]) -> BinResult<()> {
        let count = buf.len() as u64;
        let end = index.checked_add(count).ok_or(BinError::OutOfRange {
            index,
            length: count,
        })?;
        if end > self.length() {
            return Err(BinError::OutOfRange {
                index: end - 1,
                length: self.length(),
            });
        }
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = self.read_byte(index + i as u64)?;
        }
        Ok(())
    }
}

// ===================================================================
// MutableByteProvider  (ghidra.app.util.bin.MutableByteProvider)
// ===================================================================

/// Extension of [`ByteProvider`] that supports mutation.
pub trait MutableByteProvider: ByteProvider {
    /// Write a single byte at the given index.
    fn write_byte(&mut self, index: u64, value: u8) -> BinResult<()>;

    /// Write multiple bytes starting at the given index.
    fn write_bytes(&mut self, index: u64, values: &[u8]) -> BinResult<()> {
        for (i, &v) in values.iter().enumerate() {
            self.write_byte(index + i as u64, v)?;
        }
        Ok(())
    }
}

// ===================================================================
// ByteArrayProvider  (ghidra.app.util.bin.ByteArrayProvider)
// ===================================================================

/// In-memory byte provider backed by a `Vec<u8>`.
///
/// This is the Rust equivalent of the Java `ByteArrayProvider`.
#[derive(Debug, Clone)]
pub struct ByteArrayProvider {
    bytes: Vec<u8>,
    name: Option<String>,
}

impl ByteArrayProvider {
    /// Create a new provider from a byte vector.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes, name: None }
    }

    /// Create a new provider with a name.
    pub fn with_name(bytes: Vec<u8>, name: impl Into<String>) -> Self {
        Self {
            bytes,
            name: Some(name.into()),
        }
    }

    /// Consume the provider and return the underlying bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Get a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ByteProvider for ByteArrayProvider {
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn absolute_path(&self) -> Option<&str> {
        None
    }

    fn length(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_byte(&self, index: u64) -> BinResult<u8> {
        self.bytes
            .get(index as usize)
            .copied()
            .ok_or(BinError::OutOfRange {
                index,
                length: self.bytes.len() as u64,
            })
    }

    fn read_bytes(&self, index: u64, count: u64) -> BinResult<Vec<u8>> {
        let start = index as usize;
        let end = start.checked_add(count as usize).ok_or(BinError::OutOfRange {
            index,
            length: count,
        })?;
        if end > self.bytes.len() {
            return Err(BinError::OutOfRange {
                index: end as u64 - 1,
                length: self.bytes.len() as u64,
            });
        }
        Ok(self.bytes[start..end].to_vec())
    }

    fn read_into(&self, index: u64, buf: &mut [u8]) -> BinResult<()> {
        let start = index as usize;
        let end = start + buf.len();
        if end > self.bytes.len() {
            return Err(BinError::OutOfRange {
                index: end as u64 - 1,
                length: self.bytes.len() as u64,
            });
        }
        buf.copy_from_slice(&self.bytes[start..end]);
        Ok(())
    }
}

impl MutableByteProvider for ByteArrayProvider {
    fn write_byte(&mut self, index: u64, value: u8) -> BinResult<()> {
        let idx = index as usize;
        if idx >= self.bytes.len() {
            return Err(BinError::OutOfRange {
                index,
                length: self.bytes.len() as u64,
            });
        }
        self.bytes[idx] = value;
        Ok(())
    }

    fn write_bytes(&mut self, index: u64, values: &[u8]) -> BinResult<()> {
        let start = index as usize;
        let end = start + values.len();
        if end > self.bytes.len() {
            return Err(BinError::OutOfRange {
                index: end as u64 - 1,
                length: self.bytes.len() as u64,
            });
        }
        self.bytes[start..end].copy_from_slice(values);
        Ok(())
    }
}

// ===================================================================
// FileByteProvider  (ghidra.app.util.bin.FileByteProvider)
// ===================================================================

/// File-backed byte provider.
///
/// Reads are forwarded to the underlying file via pread-style semantics
/// (seek + read for each call).  For high-throughput workloads consider
/// memory-mapping via [`MmapByteProvider`].
#[derive(Debug)]
pub struct FileByteProvider {
    path: PathBuf,
    file: std::sync::Mutex<File>,
    len: u64,
}

impl FileByteProvider {
    /// Open a file read-only.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path,
            file: std::sync::Mutex::new(file),
            len,
        })
    }

    /// Open a file read-write.
    pub fn open_rw(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::options().read(true).write(true).open(&path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            path,
            file: std::sync::Mutex::new(file),
            len,
        })
    }
}

impl ByteProvider for FileByteProvider {
    fn name(&self) -> Option<&str> {
        self.path.file_name().and_then(|n| n.to_str())
    }

    fn absolute_path(&self) -> Option<&str> {
        self.path.to_str()
    }

    fn length(&self) -> u64 {
        self.len
    }

    fn read_byte(&self, index: u64) -> BinResult<u8> {
        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(index))?;
        let mut buf = [0u8; 1];
        file.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_bytes(&self, index: u64, count: u64) -> BinResult<Vec<u8>> {
        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(index))?;
        let mut buf = vec![0u8; count as usize];
        file.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn read_into(&self, index: u64, buf: &mut [u8]) -> BinResult<()> {
        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(index))?;
        file.read_exact(buf)?;
        Ok(())
    }
}

/// Mutable extension for `FileByteProvider` (requires opening with `open_rw`).
impl MutableByteProvider for FileByteProvider {
    fn write_byte(&mut self, index: u64, value: u8) -> BinResult<()> {
        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(index))?;
        file.write_all(&[value])?;
        Ok(())
    }

    fn write_bytes(&mut self, index: u64, values: &[u8]) -> BinResult<()> {
        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(index))?;
        file.write_all(values)?;
        Ok(())
    }
}

// ===================================================================
// EmptyByteProvider
// ===================================================================

/// An empty byte provider with length 0.
#[derive(Debug, Clone, Copy)]
pub struct EmptyByteProvider;

impl ByteProvider for EmptyByteProvider {
    fn name(&self) -> Option<&str> {
        Some("empty")
    }

    fn absolute_path(&self) -> Option<&str> {
        None
    }

    fn length(&self) -> u64 {
        0
    }

    fn read_byte(&self, index: u64) -> BinResult<u8> {
        Err(BinError::OutOfRange { index, length: 0 })
    }
}

/// Shared empty byte provider singleton.
pub static EMPTY_BYTE_PROVIDER: EmptyByteProvider = EmptyByteProvider;

// ===================================================================
// FaultTolerantInputStream  (ghidra.app.util.bin.FaultTolerantInputStream)
// ===================================================================

/// An `io::Read` wrapper that substitutes a default byte on I/O errors
/// instead of propagating them.
#[derive(Debug)]
pub struct FaultTolerantInputStream<R: Read> {
    inner: R,
    default_byte: u8,
}

impl<R: Read> FaultTolerantInputStream<R> {
    /// Wrap a reader with the given default byte for error recovery.
    pub fn new(inner: R, default_byte: u8) -> Self {
        Self { inner, default_byte }
    }
}

impl<R: Read> Read for FaultTolerantInputStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Ok(n) => Ok(n),
            Err(_) => {
                // On error, fill with default and report as many bytes as requested
                for b in buf.iter_mut() {
                    *b = self.default_byte;
                }
                Ok(buf.len())
            }
        }
    }
}

// ===================================================================
// ByteArrayConverter  (ghidra.app.util.bin.ByteArrayConverter)
// ===================================================================

/// Trait for types that can be converted to/from byte arrays.
pub trait ByteArrayConverter: Sized {
    /// Convert to a byte vector.
    fn to_byte_vec(&self) -> Vec<u8>;

    /// Attempt to construct from a byte slice.
    fn from_byte_slice(bytes: &[u8]) -> BinResult<Self>;
}

impl ByteArrayConverter for u16 {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }

    fn from_byte_slice(bytes: &[u8]) -> BinResult<Self> {
        if bytes.len() < 2 {
            return Err(BinError::InvalidData("need 2 bytes for u16".into()));
        }
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
}

impl ByteArrayConverter for u32 {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }

    fn from_byte_slice(bytes: &[u8]) -> BinResult<Self> {
        if bytes.len() < 4 {
            return Err(BinError::InvalidData("need 4 bytes for u32".into()));
        }
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

impl ByteArrayConverter for u64 {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }

    fn from_byte_slice(bytes: &[u8]) -> BinResult<Self> {
        if bytes.len() < 8 {
            return Err(BinError::InvalidData("need 8 bytes for u64".into()));
        }
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

// ===================================================================
// LEB128  (ghidra.app.util.bin.LEB128Info)
// ===================================================================

/// Result of reading a LEB128-encoded value along with position metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leb128Info {
    /// The offset in the source stream where the LEB128 value started.
    pub offset: u64,
    /// The decoded integer value.
    pub value: u64,
    /// Number of bytes consumed to decode the value.
    pub byte_length: usize,
    /// Whether the value was encoded as signed.
    pub signed: bool,
}

impl Leb128Info {
    /// Read an unsigned LEB128 from a `BinaryReader`.
    pub fn unsigned(reader: &mut BinaryReader<'_>) -> BinResult<Self> {
        Self::read_value(reader, false)
    }

    /// Read a signed LEB128 from a `BinaryReader`.
    pub fn signed(reader: &mut BinaryReader<'_>) -> BinResult<Self> {
        Self::read_value(reader, true)
    }

    fn read_value(reader: &mut BinaryReader<'_>, is_signed: bool) -> BinResult<Self> {
        let offset = reader.position();
        let value = if is_signed {
            read_leb128_signed(reader)?
        } else {
            read_leb128_unsigned(reader)?
        };
        let byte_length = (reader.position() - offset) as usize;
        Ok(Self {
            offset,
            value: value as u64,
            byte_length,
            signed: is_signed,
        })
    }

    /// Return the value as `u32`, or error if it does not fit.
    pub fn as_u32(&self) -> BinResult<u32> {
        if self.value > u32::MAX as u64 {
            return Err(BinError::Leb128Overflow(format!(
                "value {} exceeds u32 range",
                self.value
            )));
        }
        Ok(self.value as u32)
    }

    /// Return the value as `i32`, or error if it does not fit.
    pub fn as_i32(&self) -> BinResult<i32> {
        if self.signed {
            let v = self.value as i64;
            if v < i32::MIN as i64 || v > i32::MAX as i64 {
                return Err(BinError::Leb128Overflow(format!(
                    "value {} exceeds i32 range",
                    v
                )));
            }
            Ok(v as i32)
        } else {
            if self.value > i32::MAX as u64 {
                return Err(BinError::Leb128Overflow(format!(
                    "value {} exceeds i32 range",
                    self.value
                )));
            }
            Ok(self.value as i32)
        }
    }

    /// Return the value as `u64`.
    pub fn as_u64(&self) -> u64 {
        self.value
    }

    /// Return the value as `i64` (signed interpretation).
    pub fn as_i64(&self) -> i64 {
        self.value as i64
    }
}

/// Read an unsigned LEB128 value from a byte source.
fn read_leb128_unsigned(reader: &mut BinaryReader<'_>) -> BinResult<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    loop {
        let byte = reader.read_byte()?;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(BinError::Leb128Overflow(
                "unsigned LEB128 exceeds 64 bits".into(),
            ));
        }
    }
    Ok(result)
}

/// Read a signed LEB128 value from a byte source.
fn read_leb128_signed(reader: &mut BinaryReader<'_>) -> BinResult<u64> {
    let mut result: i64 = 0;
    let mut shift = 0;
    let mut byte;
    loop {
        byte = reader.read_byte()?;
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
        if shift >= 64 {
            return Err(BinError::Leb128Overflow(
                "signed LEB128 exceeds 64 bits".into(),
            ));
        }
    }
    // sign-extend
    if shift < 64 && (byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }
    Ok(result as u64)
}

// ===================================================================
// BinaryReader  (ghidra.app.util.bin.BinaryReader)
// ===================================================================

/// Endian-aware structured binary reader.
///
/// Wraps a `ByteProvider` and maintains a current read position (pointer).
/// All read methods advance the pointer by the appropriate number of bytes.
///
/// # Example
///
/// ```rust
/// use ghidra_app::util::bin::{BinaryReader, ByteProvider, ByteArrayProvider, Endian};
///
/// let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
/// let provider = ByteArrayProvider::new(data);
/// let mut reader = BinaryReader::new(&provider, Endian::Little);
/// let v = reader.read_u32().unwrap();
/// assert_eq!(v, 0x04030201);
/// ```
pub struct BinaryReader<'a> {
    provider: &'a dyn ByteProvider,
    pointer: u64,
    endian: Endian,
}

/// Endianness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endian {
    /// Little-endian byte order.
    Little,
    /// Big-endian byte order.
    Big,
}

impl Endian {
    /// Return `true` if big-endian.
    pub fn is_big_endian(self) -> bool {
        self == Self::Big
    }
}

impl<'a> BinaryReader<'a> {
    /// Create a new reader starting at position 0.
    pub fn new(provider: &'a dyn ByteProvider, endian: Endian) -> Self {
        Self {
            provider,
            pointer: 0,
            endian,
        }
    }

    /// Create a reader starting at a specific offset.
    pub fn with_offset(
        provider: &'a dyn ByteProvider,
        endian: Endian,
        offset: u64,
    ) -> Self {
        Self {
            provider,
            pointer: offset,
            endian,
        }
    }

    /// Return the current read position.
    pub fn position(&self) -> u64 {
        self.pointer
    }

    /// Set the read position.
    pub fn set_position(&mut self, pos: u64) {
        self.pointer = pos;
    }

    /// Advance the pointer by `n` bytes.
    pub fn skip(&mut self, n: u64) {
        self.pointer += n;
    }

    /// Return the endianness.
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// Return the total length of the underlying provider.
    pub fn length(&self) -> u64 {
        self.provider.length()
    }

    /// Return `true` if the pointer is at or past the end.
    pub fn is_eof(&self) -> bool {
        self.pointer >= self.provider.length()
    }

    /// Return remaining bytes from current position.
    pub fn remaining(&self) -> u64 {
        self.provider.length().saturating_sub(self.pointer)
    }

    /// Read a single byte and advance by 1.
    pub fn read_byte(&mut self) -> BinResult<u8> {
        let v = self.provider.read_byte(self.pointer)?;
        self.pointer += 1;
        Ok(v)
    }

    /// Read `n` bytes and advance by `n`.
    pub fn read_bytes(&mut self, n: u64) -> BinResult<Vec<u8>> {
        let v = self.provider.read_bytes(self.pointer, n)?;
        self.pointer += n;
        Ok(v)
    }

    /// Read into a pre-allocated slice and advance.
    pub fn read_into(&mut self, buf: &mut [u8]) -> BinResult<()> {
        self.provider.read_into(self.pointer, buf)?;
        self.pointer += buf.len() as u64;
        Ok(())
    }

    /// Read a `u8` (1 byte).
    pub fn read_u8(&mut self) -> BinResult<u8> {
        self.read_byte()
    }

    /// Read a `i8` (1 byte).
    pub fn read_i8(&mut self) -> BinResult<i8> {
        Ok(self.read_byte()? as i8)
    }

    /// Read a `u16` (2 bytes) in the configured endianness.
    pub fn read_u16(&mut self) -> BinResult<u16> {
        let bytes = self.read_bytes(2)?;
        let arr = [bytes[0], bytes[1]];
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(arr),
            Endian::Big => u16::from_be_bytes(arr),
        })
    }

    /// Read a `i16` (2 bytes) in the configured endianness.
    pub fn read_i16(&mut self) -> BinResult<i16> {
        let bytes = self.read_bytes(2)?;
        let arr = [bytes[0], bytes[1]];
        Ok(match self.endian {
            Endian::Little => i16::from_le_bytes(arr),
            Endian::Big => i16::from_be_bytes(arr),
        })
    }

    /// Read a `u32` (4 bytes) in the configured endianness.
    pub fn read_u32(&mut self) -> BinResult<u32> {
        let bytes = self.read_bytes(4)?;
        let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(arr),
            Endian::Big => u32::from_be_bytes(arr),
        })
    }

    /// Read a `i32` (4 bytes) in the configured endianness.
    pub fn read_i32(&mut self) -> BinResult<i32> {
        let bytes = self.read_bytes(4)?;
        let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(match self.endian {
            Endian::Little => i32::from_le_bytes(arr),
            Endian::Big => i32::from_be_bytes(arr),
        })
    }

    /// Read a `u64` (8 bytes) in the configured endianness.
    pub fn read_u64(&mut self) -> BinResult<u64> {
        let bytes = self.read_bytes(8)?;
        let arr = [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]];
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(arr),
            Endian::Big => u64::from_be_bytes(arr),
        })
    }

    /// Read a `i64` (8 bytes) in the configured endianness.
    pub fn read_i64(&mut self) -> BinResult<i64> {
        let bytes = self.read_bytes(8)?;
        let arr = [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]];
        Ok(match self.endian {
            Endian::Little => i64::from_le_bytes(arr),
            Endian::Big => i64::from_be_bytes(arr),
        })
    }

    /// Read a `f32` (4 bytes) in the configured endianness.
    pub fn read_f32(&mut self) -> BinResult<f32> {
        let bits = self.read_u32()?;
        Ok(f32::from_bits(bits))
    }

    /// Read a `f64` (8 bytes) in the configured endianness.
    pub fn read_f64(&mut self) -> BinResult<f64> {
        let bits = self.read_u64()?;
        Ok(f64::from_bits(bits))
    }

    /// Read a null-terminated UTF-8 string.
    pub fn read_cstring(&mut self) -> BinResult<String> {
        let mut bytes = Vec::new();
        loop {
            let b = self.read_byte()?;
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        String::from_utf8(bytes).map_err(|e| BinError::InvalidData(e.to_string()))
    }

    /// Read a null-terminated string with a maximum length.
    pub fn read_cstring_max(&mut self, max_len: u64) -> BinResult<String> {
        let start = self.pointer;
        let mut bytes = Vec::new();
        for _ in 0..max_len {
            let b = self.read_byte()?;
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        // Skip remaining bytes to maintain position
        let consumed = self.pointer - start;
        if consumed < max_len {
            self.skip(max_len - consumed);
        }
        String::from_utf8(bytes).map_err(|e| BinError::InvalidData(e.to_string()))
    }

    /// Read a fixed-length string (padded with nulls).
    pub fn read_fixed_string(&mut self, len: u64) -> BinResult<String> {
        let bytes = self.read_bytes(len)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end])
            .into_owned()
            .pipe(Ok)
    }

    /// Read an unsigned LEB128 value.
    pub fn read_uleb128(&mut self) -> BinResult<Leb128Info> {
        Leb128Info::unsigned(self)
    }

    /// Read a signed LEB128 value.
    pub fn read_sleb128(&mut self) -> BinResult<Leb128Info> {
        Leb128Info::signed(self)
    }

    /// Peek at the next byte without advancing the pointer.
    pub fn peek_byte(&self) -> BinResult<u8> {
        self.provider.read_byte(self.pointer)
    }

    /// Peek at the next `n` bytes without advancing.
    pub fn peek_bytes(&self, n: u64) -> BinResult<Vec<u8>> {
        self.provider.read_bytes(self.pointer, n)
    }

    /// Read a `u32` in a specified endianness (overrides reader default).
    pub fn read_u32_endian(&mut self, endian: Endian) -> BinResult<u32> {
        let bytes = self.read_bytes(4)?;
        let arr = [bytes[0], bytes[1], bytes[2], bytes[3]];
        Ok(match endian {
            Endian::Little => u32::from_le_bytes(arr),
            Endian::Big => u32::from_be_bytes(arr),
        })
    }

    /// Read a `u16` in a specified endianness (overrides reader default).
    pub fn read_u16_endian(&mut self, endian: Endian) -> BinResult<u16> {
        let bytes = self.read_bytes(2)?;
        let arr = [bytes[0], bytes[1]];
        Ok(match endian {
            Endian::Little => u16::from_le_bytes(arr),
            Endian::Big => u16::from_be_bytes(arr),
        })
    }

    /// Return a reference to the underlying provider.
    pub fn provider(&self) -> &dyn ByteProvider {
        self.provider
    }

    /// Check that at least `n` bytes remain, returning `Ok(())` or error.
    pub fn ensure_remaining(&self, n: u64) -> BinResult<()> {
        if self.remaining() < n {
            Err(BinError::OutOfRange {
                index: self.pointer + n,
                length: self.provider.length(),
            })
        } else {
            Ok(())
        }
    }
}

/// Extension trait to allow `.pipe(|x| expr)` chains.
trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}
impl<T> Pipe for T {}

// ===================================================================
// GhidraRandomAccessFile  (ghidra.app.util.bin.GhidraRandomAccessFile)
// ===================================================================

/// A thin wrapper around a `File` that provides `Read + Write + Seek`.
///
/// This mirrors the Java `GhidraRandomAccessFile` which provided
/// `readFully`, `seek`, and `write` to byte-level file access.
#[derive(Debug)]
pub struct GhidraRandomAccessFile {
    file: File,
}

impl GhidraRandomAccessFile {
    /// Open a file in read-write mode, creating it if it doesn't exist.
    pub fn open_rw(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            file: File::options()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?,
        })
    }

    /// Open a file in read-only mode.
    pub fn open_ro(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            file: File::open(path)?,
        })
    }

    /// Read `buf.len()` bytes exactly.
    pub fn read_fully(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.file.read_exact(buf)
    }

    /// Seek to an absolute position.
    pub fn seek(&mut self, pos: u64) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(pos))?;
        Ok(())
    }

    /// Get current position.
    pub fn position(&mut self) -> io::Result<u64> {
        self.file.stream_position()
    }

    /// Get file length.
    pub fn length(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}

impl Read for GhidraRandomAccessFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

impl Write for GhidraRandomAccessFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for GhidraRandomAccessFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}

// ===================================================================
// InputStreamByteProvider  (ghidra.app.util.bin.InputStreamByteProvider)
// ===================================================================

/// A byte provider that reads from an `io::Read` into memory on demand.
///
/// This is primarily useful for converting a stream into a seekable
/// byte array.
#[derive(Debug)]
pub struct InputStreamByteProvider {
    data: Vec<u8>,
    name: Option<String>,
}

impl InputStreamByteProvider {
    /// Consume a reader, buffering all data into memory.
    pub fn from_reader(mut reader: impl Read, name: Option<String>) -> io::Result<Self> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        Ok(Self { data, name })
    }

    /// Consume a reader with an expected size hint.
    pub fn from_reader_with_size(
        mut reader: impl Read,
        name: Option<String>,
        expected_size: usize,
    ) -> io::Result<Self> {
        let mut data = Vec::with_capacity(expected_size);
        reader.read_to_end(&mut data)?;
        Ok(Self { data, name })
    }
}

impl ByteProvider for InputStreamByteProvider {
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn absolute_path(&self) -> Option<&str> {
        None
    }

    fn length(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_byte(&self, index: u64) -> BinResult<u8> {
        self.data
            .get(index as usize)
            .copied()
            .ok_or(BinError::OutOfRange {
                index,
                length: self.data.len() as u64,
            })
    }

    fn read_bytes(&self, index: u64, count: u64) -> BinResult<Vec<u8>> {
        let start = index as usize;
        let end = start + count as usize;
        if end > self.data.len() {
            return Err(BinError::OutOfRange {
                index: end as u64 - 1,
                length: self.data.len() as u64,
            });
        }
        Ok(self.data[start..end].to_vec())
    }

    fn read_into(&self, index: u64, buf: &mut [u8]) -> BinResult<()> {
        let start = index as usize;
        let end = start + buf.len();
        if end > self.data.len() {
            return Err(BinError::OutOfRange {
                index: end as u64 - 1,
                length: self.data.len() as u64,
            });
        }
        buf.copy_from_slice(&self.data[start..end]);
        Ok(())
    }
}

// ===================================================================
// MemoryMutableByteProvider
// ===================================================================

/// A mutable byte provider backed by a growable memory buffer.
///
/// Unlike `ByteArrayProvider`, this allows writing beyond the current
/// length by extending the buffer.
#[derive(Debug, Clone)]
pub struct MemoryMutableByteProvider {
    data: Vec<u8>,
    name: Option<String>,
}

impl MemoryMutableByteProvider {
    /// Create a new empty provider.
    pub fn new(name: Option<String>) -> Self {
        Self {
            data: Vec::new(),
            name,
        }
    }

    /// Create a new provider with pre-allocated capacity.
    pub fn with_capacity(capacity: usize, name: Option<String>) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            name,
        }
    }

    /// Resize the internal buffer.
    pub fn resize(&mut self, new_len: usize) {
        self.data.resize(new_len, 0);
    }
}

impl ByteProvider for MemoryMutableByteProvider {
    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn absolute_path(&self) -> Option<&str> {
        None
    }

    fn length(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_byte(&self, index: u64) -> BinResult<u8> {
        self.data
            .get(index as usize)
            .copied()
            .ok_or(BinError::OutOfRange {
                index,
                length: self.data.len() as u64,
            })
    }

    fn read_bytes(&self, index: u64, count: u64) -> BinResult<Vec<u8>> {
        let start = index as usize;
        let end = start + count as usize;
        if end > self.data.len() {
            return Err(BinError::OutOfRange {
                index: end as u64 - 1,
                length: self.data.len() as u64,
            });
        }
        Ok(self.data[start..end].to_vec())
    }

    fn read_into(&self, index: u64, buf: &mut [u8]) -> BinResult<()> {
        let start = index as usize;
        let end = start + buf.len();
        if end > self.data.len() {
            return Err(BinError::OutOfRange {
                index: end as u64 - 1,
                length: self.data.len() as u64,
            });
        }
        buf.copy_from_slice(&self.data[start..end]);
        Ok(())
    }
}

impl MutableByteProvider for MemoryMutableByteProvider {
    fn write_byte(&mut self, index: u64, value: u8) -> BinResult<()> {
        let idx = index as usize;
        if idx >= self.data.len() {
            self.data.resize(idx + 1, 0);
        }
        self.data[idx] = value;
        Ok(())
    }

    fn write_bytes(&mut self, index: u64, values: &[u8]) -> BinResult<()> {
        let start = index as usize;
        let end = start + values.len();
        if end > self.data.len() {
            self.data.resize(end, 0);
        }
        self.data[start..end].copy_from_slice(values);
        Ok(())
    }
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_provider() -> ByteArrayProvider {
        ByteArrayProvider::with_name(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08], "test")
    }

    #[test]
    fn byte_array_provider_basics() {
        let p = make_test_provider();
        assert_eq!(p.name(), Some("test"));
        assert_eq!(p.length(), 8);
        assert!(!p.is_empty());
        assert!(p.is_valid_index(7));
        assert!(!p.is_valid_index(8));
        assert_eq!(p.read_byte(0).unwrap(), 0x01);
        assert_eq!(p.read_byte(7).unwrap(), 0x08);
        assert!(p.read_byte(8).is_err());
    }

    #[test]
    fn byte_array_provider_read_bytes() {
        let p = make_test_provider();
        let bytes = p.read_bytes(2, 4).unwrap();
        assert_eq!(bytes, vec![0x03, 0x04, 0x05, 0x06]);
        assert!(p.read_bytes(6, 4).is_err());
    }

    #[test]
    fn byte_array_provider_read_into() {
        let p = make_test_provider();
        let mut buf = [0u8; 4];
        p.read_into(0, &mut buf).unwrap();
        assert_eq!(buf, [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn mutable_byte_array_provider() {
        let mut p = make_test_provider();
        p.write_byte(0, 0xFF).unwrap();
        assert_eq!(p.read_byte(0).unwrap(), 0xFF);
        p.write_bytes(2, &[0xAA, 0xBB]).unwrap();
        assert_eq!(p.read_byte(2).unwrap(), 0xAA);
        assert_eq!(p.read_byte(3).unwrap(), 0xBB);
    }

    #[test]
    fn binary_reader_little_endian() {
        let p = ByteArrayProvider::new(vec![0x78, 0x56, 0x34, 0x12]);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        assert_eq!(reader.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn binary_reader_big_endian() {
        let p = ByteArrayProvider::new(vec![0x12, 0x34, 0x56, 0x78]);
        let mut reader = BinaryReader::new(&p, Endian::Big);
        assert_eq!(reader.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn binary_reader_u16_i16() {
        let p = ByteArrayProvider::new(vec![0xFF, 0x7F, 0x00, 0x80]);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        assert_eq!(reader.read_u16().unwrap(), 0x7FFF);
        assert_eq!(reader.read_i16().unwrap(), i16::MIN);
    }

    #[test]
    fn binary_reader_u64_le() {
        let p = ByteArrayProvider::new(vec![0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        assert_eq!(reader.read_u64().unwrap(), 0x0102030405060708);
    }

    #[test]
    fn binary_reader_f32() {
        let p = ByteArrayProvider::new(f32::to_le_bytes(3.14).to_vec());
        let mut reader = BinaryReader::new(&p, Endian::Little);
        assert!((reader.read_f32().unwrap() - 3.14).abs() < 1e-5);
    }

    #[test]
    fn binary_reader_f64() {
        let p = ByteArrayProvider::new(f64::to_le_bytes(2.718281828).to_vec());
        let mut reader = BinaryReader::new(&p, Endian::Little);
        assert!((reader.read_f64().unwrap() - 2.718281828).abs() < 1e-9);
    }

    #[test]
    fn binary_reader_cstring() {
        let data = b"hello\x00world\x00".to_vec();
        let p = ByteArrayProvider::new(data);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        assert_eq!(reader.read_cstring().unwrap(), "hello");
        assert_eq!(reader.read_cstring().unwrap(), "world");
    }

    #[test]
    fn binary_reader_cstring_max() {
        let data = b"abcdef\x00gh".to_vec();
        let p = ByteArrayProvider::new(data);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        assert_eq!(reader.read_cstring_max(8).unwrap(), "abcdef");
        // Should have advanced 8 bytes total
        assert_eq!(reader.position(), 8);
    }

    #[test]
    fn binary_reader_position_and_skip() {
        let p = make_test_provider();
        let mut reader = BinaryReader::new(&p, Endian::Little);
        assert_eq!(reader.position(), 0);
        reader.skip(3);
        assert_eq!(reader.position(), 3);
        assert_eq!(reader.read_byte().unwrap(), 0x04);
        reader.set_position(0);
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn binary_reader_eof() {
        let p = ByteArrayProvider::new(vec![0x01, 0x02]);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        assert!(!reader.is_eof());
        reader.read_u16().unwrap();
        assert!(reader.is_eof());
        assert!(reader.read_byte().is_err());
    }

    #[test]
    fn binary_reader_peek() {
        let p = ByteArrayProvider::new(vec![0xAB, 0xCD]);
        let reader = BinaryReader::new(&p, Endian::Little);
        assert_eq!(reader.peek_byte().unwrap(), 0xAB);
        assert_eq!(reader.position(), 0); // not advanced
        assert_eq!(reader.peek_bytes(2).unwrap(), vec![0xAB, 0xCD]);
    }

    #[test]
    fn leb128_unsigned() {
        // 624485 encodes to 0xE5, 0x8E, 0x26
        let data = vec![0xE5, 0x8E, 0x26];
        let p = ByteArrayProvider::new(data);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        let info = reader.read_uleb128().unwrap();
        assert_eq!(info.value, 624485);
        assert_eq!(info.byte_length, 3);
        assert!(!info.signed);
        assert_eq!(info.offset, 0);
    }

    #[test]
    fn leb128_signed() {
        // -123456 encodes to 0xC0, 0xBB, 0x78
        let data = vec![0xC0, 0xBB, 0x78];
        let p = ByteArrayProvider::new(data);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        let info = reader.read_sleb128().unwrap();
        assert_eq!(info.as_i64(), -123456);
        assert_eq!(info.byte_length, 3);
        assert!(info.signed);
    }

    #[test]
    fn leb128_small_values() {
        // 0 encodes to 0x00
        let data = vec![0x00];
        let p = ByteArrayProvider::new(data);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        let info = reader.read_uleb128().unwrap();
        assert_eq!(info.value, 0);
        assert_eq!(info.byte_length, 1);
    }

    #[test]
    fn leb128_as_u32() {
        let info = Leb128Info {
            offset: 0,
            value: 100,
            byte_length: 1,
            signed: false,
        };
        assert_eq!(info.as_u32().unwrap(), 100);

        let big = Leb128Info {
            offset: 0,
            value: u32::MAX as u64 + 1,
            byte_length: 5,
            signed: false,
        };
        assert!(big.as_u32().is_err());
    }

    #[test]
    fn empty_byte_provider() {
        assert_eq!(EMPTY_BYTE_PROVIDER.length(), 0);
        assert!(EMPTY_BYTE_PROVIDER.is_empty());
        assert!(!EMPTY_BYTE_PROVIDER.is_valid_index(0));
        assert!(EMPTY_BYTE_PROVIDER.read_byte(0).is_err());
    }

    #[test]
    fn mutable_memory_provider_grows() {
        let mut p = MemoryMutableByteProvider::new(None);
        assert_eq!(p.length(), 0);
        p.write_byte(5, 0xFF).unwrap();
        assert_eq!(p.length(), 6);
        assert_eq!(p.read_byte(5).unwrap(), 0xFF);
        assert_eq!(p.read_byte(0).unwrap(), 0x00);
    }

    #[test]
    fn mutable_memory_provider_write_bytes() {
        let mut p = MemoryMutableByteProvider::new(None);
        p.write_bytes(0, &[1, 2, 3, 4]).unwrap();
        assert_eq!(p.length(), 4);
        assert_eq!(p.read_bytes(0, 4).unwrap(), vec![1, 2, 3, 4]);
        p.write_bytes(2, &[0xAA, 0xBB]).unwrap();
        assert_eq!(p.read_byte(2).unwrap(), 0xAA);
        assert_eq!(p.read_byte(3).unwrap(), 0xBB);
    }

    #[test]
    fn input_stream_byte_provider() {
        let data = vec![10, 20, 30, 40];
        let reader = std::io::Cursor::new(data);
        let provider = InputStreamByteProvider::from_reader(reader, Some("test".into())).unwrap();
        assert_eq!(provider.length(), 4);
        assert_eq!(provider.name(), Some("test"));
        assert_eq!(provider.read_byte(0).unwrap(), 10);
        assert_eq!(provider.read_byte(3).unwrap(), 40);
    }

    #[test]
    fn endian_display() {
        assert!(Endian::Big.is_big_endian());
        assert!(!Endian::Little.is_big_endian());
    }

    #[test]
    fn binary_reader_with_offset() {
        let p = ByteArrayProvider::new(vec![0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF]);
        let mut reader = BinaryReader::with_offset(&p, Endian::Little, 4);
        assert_eq!(reader.read_u32().unwrap(), 0xEFBEADDE);
    }

    #[test]
    fn binary_reader_read_u32_endian_override() {
        let p = ByteArrayProvider::new(vec![0x12, 0x34, 0x56, 0x78]);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        // Read as big-endian despite default being little
        assert_eq!(reader.read_u32_endian(Endian::Big).unwrap(), 0x12345678);
    }

    #[test]
    fn binary_reader_ensure_remaining() {
        let p = ByteArrayProvider::new(vec![0, 1, 2, 3]);
        let reader = BinaryReader::new(&p, Endian::Little);
        assert!(reader.ensure_remaining(4).is_ok());
        assert!(reader.ensure_remaining(5).is_err());
    }

    #[test]
    fn byte_array_converter_roundtrip() {
        let v: u32 = 0xDEADBEEF;
        let bytes = v.to_byte_vec();
        assert_eq!(u32::from_byte_slice(&bytes).unwrap(), v);

        let v: u64 = 0x0102030405060708;
        let bytes = v.to_byte_vec();
        assert_eq!(u64::from_byte_slice(&bytes).unwrap(), v);
    }

    #[test]
    fn fault_tolerant_input_stream() {
        // Normal read works fine
        let data = vec![1, 2, 3];
        let ft = FaultTolerantInputStream::new(std::io::Cursor::new(data), 0xFF);
        let mut output = vec![0u8; 3];
        let mut reader = ft;
        Read::read(&mut reader, &mut output).unwrap();
        assert_eq!(output, vec![1, 2, 3]);
    }

    #[test]
    fn binary_reader_fixed_string() {
        let data = b"hello\x00\x00\x00".to_vec();
        let p = ByteArrayProvider::new(data);
        let mut reader = BinaryReader::new(&p, Endian::Little);
        assert_eq!(reader.read_fixed_string(8).unwrap(), "hello");
    }
}
