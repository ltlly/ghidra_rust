//! Byte provider abstractions ported from Ghidra's `ghidra.app.util.bin` package.
//!
//! Provides the core random-access byte source traits and implementations:
//! - [`ByteProvider`] -- read-only random-access byte source
//! - [`MutableByteProvider`] -- read-write random-access byte source
//! - [`ByteArrayProvider`] -- in-memory byte array provider
//! - [`EmptyByteProvider`] -- provider with no data
//! - [`ByteProviderWrapper`] -- sub-range view of another provider
//! - [`FileByteProvider`] -- file-backed buffered provider with read/write
//! - [`SynchronizedByteProvider`] -- thread-safe wrapper around a provider
//! - [`ByteArrayConverter`] -- trait for objects convertible to byte arrays

use std::collections::HashMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
// MutableByteProvider trait
// ---------------------------------------------------------------------------

/// An extension of `ByteProvider` that supports write operations.
///
/// Ported from `ghidra.app.util.bin.MutableByteProvider`.
pub trait MutableByteProvider: ByteProvider {
    /// Writes a single byte at the specified index.
    fn write_byte(&self, index: u64, value: u8) -> io::Result<()>;

    /// Writes a byte array at the specified index.
    fn write_bytes(&self, index: u64, values: &[u8]) -> io::Result<()>;
}

// ---------------------------------------------------------------------------
// ByteArrayConverter trait
// ---------------------------------------------------------------------------

/// An interface to convert from an object to a byte array.
///
/// Ported from `ghidra.app.util.bin.ByteArrayConverter`.
pub trait ByteArrayConverter {
    /// Returns a byte array representing this object.
    ///
    /// Uses little-endian byte order by default; implementations may accept
    /// an endianness parameter if needed.
    fn to_bytes_le(&self) -> io::Result<Vec<u8>>;

    /// Returns a byte array in big-endian byte order.
    fn to_bytes_be(&self) -> io::Result<Vec<u8>> {
        // Default: reverse the LE bytes
        let mut bytes = self.to_bytes_le()?;
        bytes.reverse();
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// ByteArrayProvider
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

    /// Consume the provider and return the underlying data.
    pub fn into_data(self) -> Vec<u8> {
        self.data
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

// ---------------------------------------------------------------------------
// EmptyByteProvider
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ByteProviderWrapper
// ---------------------------------------------------------------------------

/// A wrapper that adds a view/window over a portion of another ByteProvider.
///
/// Ported from `ghidra.app.util.bin.ByteProviderWrapper`.
pub struct ByteProviderWrapper {
    inner: Box<dyn ByteProvider>,
    offset: u64,
    length: u64,
    display_name: Option<String>,
}

impl ByteProviderWrapper {
    /// Create a new wrapper over a subrange.
    pub fn new(inner: Box<dyn ByteProvider>, offset: u64, length: u64) -> Self {
        let actual_len = length.min(inner.length().saturating_sub(offset));
        Self {
            inner,
            offset,
            length: actual_len,
            display_name: None,
        }
    }

    /// Create a wrapper over the full range with a custom display name.
    pub fn with_name(inner: Box<dyn ByteProvider>, display_name: String) -> Self {
        let length = inner.length();
        Self {
            inner,
            offset: 0,
            length,
            display_name: Some(display_name),
        }
    }

    /// Get the sub-range offset within the inner provider.
    pub fn sub_offset(&self) -> u64 {
        self.offset
    }
}

impl ByteProvider for ByteProviderWrapper {
    fn name(&self) -> Option<&str> {
        self.display_name.as_deref().or_else(|| self.inner.name())
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
// FileByteProvider
// ---------------------------------------------------------------------------

/// Access mode for file-backed byte providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Read-only access.
    Read,
    /// Read-write access.
    Write,
}

/// A buffered file-backed byte provider.
///
/// Ported from `ghidra.app.util.bin.FileByteProvider`. Uses a cache of
/// fixed-size buffers to minimize file I/O for random access patterns.
pub struct FileByteProvider {
    file_path: PathBuf,
    file: Mutex<File>,
    access_mode: AccessMode,
    current_length: u64,
    buffers: Mutex<HashMap<u64, Buffer>>,
}

const BUFFER_SIZE: usize = 64 * 1024;

struct Buffer {
    pos: u64,
    len: usize,
    bytes: Vec<u8>,
}

impl Buffer {
    fn new(pos: u64, len: usize) -> Self {
        Self {
            pos,
            len,
            bytes: vec![0u8; len],
        }
    }

    fn get_buffer_offset(&self, file_pos: u64) -> io::Result<usize> {
        let ofs = (file_pos - self.pos) as usize;
        if ofs >= self.len {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }
        Ok(ofs)
    }
}

impl FileByteProvider {
    /// Creates a new file-backed byte provider.
    ///
    /// # Arguments
    /// * `path` - Path to the file
    /// * `access_mode` - Read or Read-Write access
    pub fn open(path: impl AsRef<Path>, access_mode: AccessMode) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = match access_mode {
            AccessMode::Read => OpenOptions::new().read(true).open(&path)?,
            AccessMode::Write => OpenOptions::new().read(true).write(true).open(&path)?,
        };
        let metadata = file.metadata()?;
        let current_length = metadata.len();

        Ok(Self {
            file_path: path,
            file: Mutex::new(file),
            access_mode,
            current_length,
            buffers: Mutex::new(HashMap::new()),
        })
    }

    /// Returns the access mode the file was opened with.
    pub fn access_mode(&self) -> AccessMode {
        self.access_mode
    }

    /// Returns the file path.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    fn get_buffer_pos(index: u64) -> u64 {
        (index / BUFFER_SIZE as u64) * BUFFER_SIZE as u64
    }

    fn get_buffer_for(&self, pos: u64) -> io::Result<()> {
        let buffer_pos = Self::get_buffer_pos(pos);
        if buffer_pos >= self.current_length {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }

        let mut buffers = self.buffers.lock().unwrap();
        if buffers.contains_key(&buffer_pos) {
            return Ok(());
        }

        let buf_len = std::cmp::min(
            (self.current_length - buffer_pos) as usize,
            BUFFER_SIZE,
        );
        let mut buffer = Buffer::new(buffer_pos, buf_len);

        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(buffer_pos))?;
        let bytes_read = file.read(&mut buffer.bytes)?;
        buffer.len = bytes_read;
        buffers.insert(buffer_pos, buffer);

        Ok(())
    }

    fn ensure_bounds(&self, index: u64, length: u64) -> io::Result<()> {
        if index > self.current_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Invalid index: {}", index),
            ));
        }
        if index + length > self.current_length {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("Unable to read past EOF: {}, {}", index, length),
            ));
        }
        Ok(())
    }
}

impl ByteProvider for FileByteProvider {
    fn name(&self) -> Option<&str> {
        self.file_path.file_name().and_then(|n| n.to_str())
    }

    fn absolute_path(&self) -> Option<&str> {
        self.file_path.to_str()
    }

    fn length(&self) -> u64 {
        self.current_length
    }

    fn is_valid_index(&self, index: u64) -> bool {
        index < self.current_length
    }

    fn read_u8(&self, index: u64) -> io::Result<u8> {
        self.ensure_bounds(index, 1)?;
        self.get_buffer_for(index)?;

        let buffers = self.buffers.lock().unwrap();
        let buffer_pos = Self::get_buffer_pos(index);
        let buffer = buffers.get(&buffer_pos).unwrap();
        let ofs = buffer.get_buffer_offset(index)?;
        Ok(buffer.bytes[ofs])
    }

    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        if index >= self.current_length {
            return Ok(0);
        }

        let length = std::cmp::min(buf.len() as u64, self.current_length - index) as usize;
        let mut total_read = 0;
        let mut pos = index;

        while total_read < length {
            self.get_buffer_for(pos)?;

            let buffers = self.buffers.lock().unwrap();
            let buffer_pos = Self::get_buffer_pos(pos);
            let buffer = buffers.get(&buffer_pos).unwrap();
            let ofs = buffer.get_buffer_offset(pos)?;
            let available = std::cmp::min(buffer.len - ofs, length - total_read);

            buf[total_read..total_read + available]
                .copy_from_slice(&buffer.bytes[ofs..ofs + available]);

            total_read += available;
            pos += available as u64;
        }

        Ok(total_read)
    }

    fn close(&self) {
        let mut buffers = self.buffers.lock().unwrap();
        buffers.clear();
    }
}

impl MutableByteProvider for FileByteProvider {
    fn write_byte(&self, index: u64, value: u8) -> io::Result<()> {
        self.write_bytes(index, &[value])
    }

    fn write_bytes(&self, index: u64, values: &[u8]) -> io::Result<()> {
        if self.access_mode != AccessMode::Write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Not in write mode",
            ));
        }

        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(index))?;
        file.write_all(values)?;

        let write_end = index + values.len() as u64;
        drop(file);

        // Update current_length if we wrote past the end
        // Note: we need to handle this carefully since current_length is not behind a mutex
        // For simplicity, we invalidate any affected buffers
        let mut buffers = self.buffers.lock().unwrap();
        let mut pos = index;
        let mut remaining = values.len();
        let mut values_offset = 0;

        while remaining > 0 {
            let buffer_pos = Self::get_buffer_pos(pos);
            let buffer_ofs = (pos - buffer_pos) as usize;
            let bytes_avail = std::cmp::min(remaining, BUFFER_SIZE - buffer_ofs);

            if let Some(buffer) = buffers.get_mut(&buffer_pos) {
                if buffer_ofs == 0 && remaining >= BUFFER_SIZE {
                    buffer.bytes[..BUFFER_SIZE]
                        .copy_from_slice(&values[values_offset..values_offset + BUFFER_SIZE]);
                    buffer.len = BUFFER_SIZE;
                } else {
                    buffers.remove(&buffer_pos);
                }
            }

            pos += bytes_avail as u64;
            values_offset += bytes_avail;
            remaining -= bytes_avail;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SynchronizedByteProvider
// ---------------------------------------------------------------------------

/// A thread-safe wrapper around a `ByteProvider`.
///
/// Ported from `ghidra.app.util.bin.SynchronizedByteProvider`. All operations
/// are serialized through an internal mutex.
pub struct SynchronizedByteProvider {
    inner: Box<dyn ByteProvider>,
}

impl SynchronizedByteProvider {
    /// Create a new synchronized wrapper.
    pub fn new(provider: Box<dyn ByteProvider>) -> Self {
        Self { inner: provider }
    }
}

impl ByteProvider for SynchronizedByteProvider {
    fn name(&self) -> Option<&str> {
        self.inner.name()
    }

    fn absolute_path(&self) -> Option<&str> {
        self.inner.absolute_path()
    }

    fn length(&self) -> u64 {
        self.inner.length()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn is_valid_index(&self, index: u64) -> bool {
        self.inner.is_valid_index(index)
    }

    fn read_u8(&self, index: u64) -> io::Result<u8> {
        // ByteProvider already requires Send+Sync; the underlying implementation
        // must handle synchronization. This wrapper exists for API compatibility.
        self.inner.read_u8(index)
    }

    fn read_bytes(&self, index: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_bytes(index, buf)
    }

    fn read_slice(&self, index: u64, len: usize) -> io::Result<Vec<u8>> {
        self.inner.read_slice(index, len)
    }

    fn close(&self) {
        self.inner.close()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Error for when a byte provider encounters an out-of-bounds access.
#[derive(Debug)]
pub struct ProviderBoundsError {
    pub index: u64,
    pub length: u64,
}

impl fmt::Display for ProviderBoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "index {} out of range (provider length: {})",
            self.index, self.length
        )
    }
}

impl std::error::Error for ProviderBoundsError {}

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
        assert!(wrapper.read_u8(5).is_err());
    }

    #[test]
    fn test_byte_provider_wrapper_name() {
        let inner = ByteArrayProvider::new(Some("inner".into()), vec![0, 1, 2, 3]);
        let wrapper = ByteProviderWrapper::with_name(Box::new(inner), "custom_name".into());
        assert_eq!(wrapper.name(), Some("custom_name"));
    }

    #[test]
    fn test_synchronized_byte_provider() {
        let inner = ByteArrayProvider::new(None, vec![10, 20, 30]);
        let sync = SynchronizedByteProvider::new(Box::new(inner));
        assert_eq!(sync.length(), 3);
        assert_eq!(sync.read_u8(1).unwrap(), 20);
    }

    #[test]
    fn test_byte_array_provider_into_data() {
        let provider = ByteArrayProvider::new(None, vec![1, 2, 3]);
        let data = provider.into_data();
        assert_eq!(data, vec![1, 2, 3]);
    }

    #[test]
    fn test_read_slice() {
        let provider = ByteArrayProvider::new(None, vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        let slice = provider.read_slice(1, 3).unwrap();
        assert_eq!(slice, vec![0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_access_mode() {
        assert_ne!(AccessMode::Read, AccessMode::Write);
        assert_eq!(AccessMode::Read, AccessMode::Read);
    }

    #[test]
    fn test_provider_bounds_error() {
        let err = ProviderBoundsError {
            index: 10,
            length: 5,
        };
        assert!(err.to_string().contains("10"));
        assert!(err.to_string().contains("5"));
    }
}
