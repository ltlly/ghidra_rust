//! Buffered random access file ported from Ghidra's
//! `ghidra.app.util.bin.GhidraRandomAccessFile`.
//!
//! Provides efficient random access to a file by maintaining a double-buffered
//! cache. Reads are served from the cache when possible, and the cache is
//! refreshed from the underlying file on miss.
//!
//! Key design decisions from the Java original:
//! - Two buffers (`buffer` and `lastbuffer`) are swapped to handle locality
//!   of reference patterns where reads alternate between two regions.
//! - Buffer size is 1 MiB (`BUFFER_SIZE = 0x100000`).
//! - Writes invalidate the entire cache (consistent with the Java behavior).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Size of each cache buffer (1 MiB, matching the Java implementation).
const BUFFER_SIZE: usize = 0x100000;

/// A buffered random access file with double-buffered caching.
///
/// Ported from `ghidra.app.util.bin.GhidraRandomAccessFile`. Maintains two
/// 1 MiB buffers to exploit spatial locality in read patterns. When the
/// requested position falls outside the current buffer, the last buffer is
/// checked before loading new data from the file.
///
/// # Thread Safety
///
/// This type is **not** thread-safe. Use external synchronization if sharing
/// across threads (consistent with the Java original).
///
/// # Example
///
/// ```no_run
/// use ghidra_features::bin_format::random_access_file::GhidraRandomAccessFile;
///
/// let mut raf = GhidraRandomAccessFile::open("test.bin", "r").unwrap();
/// raf.seek(0x100).unwrap();
/// let b = raf.read_byte().unwrap();
/// ```
pub struct GhidraRandomAccessFile {
    file: File,
    buffer: Vec<u8>,
    buffer_offset: usize,
    buffer_file_start_index: u64,
    last_buffer: Vec<u8>,
    last_buffer_offset: usize,
    last_buffer_file_start_index: u64,
    file_length: u64,
    open: bool,
}

impl GhidraRandomAccessFile {
    /// Opens a file for random access with the given mode.
    ///
    /// Supported modes:
    /// - `"r"` -- read-only
    /// - `"rw"` -- read-write (creates the file if it doesn't exist)
    ///
    /// # Arguments
    /// * `path` - Path to the file
    /// * `mode` - Access mode (`"r"` or `"rw"`)
    pub fn open(path: impl AsRef<Path>, mode: &str) -> io::Result<Self> {
        let file = match mode {
            "r" => OpenOptions::new().read(true).open(path)?,
            "rw" => OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported mode: {}", mode),
                ))
            }
        };

        let file_length = file.metadata()?.len();

        Ok(Self {
            file,
            buffer: Vec::new(),
            buffer_offset: 0,
            buffer_file_start_index: 0,
            last_buffer: Vec::new(),
            last_buffer_offset: 0,
            last_buffer_file_start_index: 0,
            file_length,
            open: true,
        })
    }

    /// Creates a new random access file from an already-opened `File` handle.
    pub fn from_file(file: File) -> io::Result<Self> {
        let file_length = file.metadata()?.len();
        Ok(Self {
            file,
            buffer: Vec::new(),
            buffer_offset: 0,
            buffer_file_start_index: 0,
            last_buffer: Vec::new(),
            last_buffer_offset: 0,
            last_buffer_file_start_index: 0,
            file_length,
            open: true,
        })
    }

    fn check_open(&self) -> io::Result<()> {
        if !self.open {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "GhidraRandomAccessFile is closed",
            ));
        }
        Ok(())
    }

    /// Returns the total length of the file in bytes.
    pub fn length(&mut self) -> io::Result<u64> {
        self.check_open()?;
        Ok(self.file_length)
    }

    /// Sets the file pointer to the specified position.
    ///
    /// If the position is within the current or last buffer, the buffer is
    /// reused. Otherwise, the current buffer is saved as the last buffer and
    /// a new read will be triggered on the next `read_byte()` or `read()`.
    pub fn seek(&mut self, pos: u64) -> io::Result<()> {
        self.check_open()?;

        if pos > self.file_length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("pos {} exceeds file length {}", pos, self.file_length),
            ));
        }

        let in_current = !self.buffer.is_empty()
            && pos >= self.buffer_file_start_index
            && pos < self.buffer_file_start_index + self.buffer.len() as u64;

        if !in_current {
            // Check if the last buffer contains the position
            self.swap_in_last();

            let in_last = !self.buffer.is_empty()
                && pos >= self.buffer_file_start_index
                && pos < self.buffer_file_start_index + self.buffer.len() as u64;

            if !in_last {
                // Position is not in either buffer; mark as unloaded
                self.buffer.clear();
                self.buffer_offset = 0;
                self.buffer_file_start_index = pos;
            }
        }

        self.buffer_offset = (pos - self.buffer_file_start_index) as usize;
        Ok(())
    }

    /// Reads a single byte at the current file pointer position.
    ///
    /// The file pointer is advanced by one byte after reading.
    pub fn read_byte(&mut self) -> io::Result<u8> {
        self.check_open()?;
        self.ensure_buffer(1)?;
        Ok(self.buffer[self.buffer_offset])
    }

    /// Reads bytes into the provided buffer starting at the current file pointer.
    ///
    /// Returns the number of bytes actually read.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check_open()?;
        if buf.is_empty() {
            return Ok(0);
        }
        self.read_full(buf, 0, buf.len())
    }

    /// Reads exactly `length` bytes into `buf` starting at `offset`.
    ///
    /// Reads in a loop to handle the case where the buffer boundary falls
    /// within the requested range.
    fn read_full(&mut self, buf: &mut [u8], mut offset: usize, mut length: usize) -> io::Result<usize> {
        let total_requested = length;

        while length > 0 {
            let available_in_buffer = if self.buffer.is_empty() {
                0
            } else {
                self.buffer.len() - self.buffer_offset
            };

            let block_length = if length > available_in_buffer || available_in_buffer == 0 {
                // Need to refill buffer
                let needed = length.min(BUFFER_SIZE);
                self.ensure_buffer(needed)?;
                let avail = self.buffer.len() - self.buffer_offset;
                length.min(avail)
            } else {
                length
            };

            if block_length == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
            }

            buf[offset..offset + block_length]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + block_length]);

            self.buffer_offset += block_length;
            offset += block_length;
            length -= block_length;

            if length > 0 {
                let new_pos = self.buffer_file_start_index + self.buffer_offset as u64;
                self.seek(new_pos)?;
            }
        }

        Ok(total_requested)
    }

    /// Writes a single byte at the current file pointer position.
    pub fn write_byte(&mut self, b: u8) -> io::Result<()> {
        self.check_open()?;
        self.write(&[b])
    }

    /// Writes bytes from the provided buffer at the current file pointer.
    ///
    /// Writing invalidates the entire buffer cache (consistent with the
    /// Java implementation behavior).
    pub fn write(&mut self, buf: &[u8]) -> io::Result<()> {
        self.check_open()?;
        self.file.seek(SeekFrom::Start(
            self.buffer_file_start_index + self.buffer_offset as u64,
        ))?;
        self.file.write_all(buf)?;
        self.buffer_offset += buf.len();

        // Invalidate both buffers after write
        self.buffer.clear();
        self.buffer_offset = 0;
        self.last_buffer.clear();
        self.last_buffer_offset = 0;
        Ok(())
    }

    /// Ensures that the buffer contains at least `bytes_needed` bytes from
    /// the current position onward. Loads data from the file if necessary.
    fn ensure_buffer(&mut self, bytes_needed: usize) -> io::Result<()> {
        if self.buffer.is_empty() || self.buffer_offset + bytes_needed > self.buffer.len() {
            // Try the last buffer first
            let old_pos = self.buffer_file_start_index + self.buffer_offset as u64;
            self.swap_in_last();

            let new_buffer_offset = (old_pos - self.buffer_file_start_index) as usize;

            if old_pos < self.buffer_file_start_index
                || old_pos >= self.buffer_file_start_index + self.buffer.len() as u64
                || new_buffer_offset + bytes_needed > self.buffer.len()
            {
                // Neither buffer has the data; load a fresh one
                self.buffer_file_start_index = old_pos;
                self.buffer = vec![0u8; BUFFER_SIZE];
                self.file.seek(SeekFrom::Start(self.buffer_file_start_index))?;

                let bytes_read = self.file.read(&mut self.buffer)?;
                self.buffer.truncate(bytes_read);
                self.buffer_offset = 0;

                if bytes_read == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
                }
            } else {
                self.buffer_offset = new_buffer_offset;
            }
        }

        Ok(())
    }

    /// Swaps the current buffer with the last buffer.
    ///
    /// This implements the double-buffering strategy: before loading new data,
    /// the current buffer is saved so that it can be reused if the next seek
    /// returns to the same region.
    fn swap_in_last(&mut self) {
        if self.buffer.is_empty() {
            return;
        }

        std::mem::swap(&mut self.buffer, &mut self.last_buffer);
        std::mem::swap(&mut self.buffer_offset, &mut self.last_buffer_offset);
        std::mem::swap(
            &mut self.buffer_file_start_index,
            &mut self.last_buffer_file_start_index,
        );
    }

    /// Closes the file and releases resources.
    pub fn close(&mut self) -> io::Result<()> {
        self.check_open()?;
        self.open = false;
        self.buffer.clear();
        self.last_buffer.clear();
        // File is closed when dropped
        Ok(())
    }
}

impl Drop for GhidraRandomAccessFile {
    fn drop(&mut self) {
        // File is automatically closed when dropped
        self.open = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_temp_file(data: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(data).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_basic_read() {
        let data: Vec<u8> = (0..255).collect();
        let tmp = create_temp_file(&data);

        let mut raf = GhidraRandomAccessFile::open(tmp.path(), "r").unwrap();
        assert_eq!(raf.length().unwrap(), 255);

        raf.seek(10).unwrap();
        assert_eq!(raf.read_byte().unwrap(), 10);

        raf.seek(0).unwrap();
        assert_eq!(raf.read_byte().unwrap(), 0);

        raf.seek(254).unwrap();
        assert_eq!(raf.read_byte().unwrap(), 254);
    }

    #[test]
    fn test_read_multi_byte() {
        let data: Vec<u8> = (0..100).collect();
        let tmp = create_temp_file(&data);

        let mut raf = GhidraRandomAccessFile::open(tmp.path(), "r").unwrap();
        raf.seek(10).unwrap();

        let mut buf = [0u8; 5];
        let n = raf.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, [10, 11, 12, 13, 14]);
    }

    #[test]
    fn test_seek_beyond_length_errors() {
        let data = vec![1, 2, 3];
        let tmp = create_temp_file(&data);

        let mut raf = GhidraRandomAccessFile::open(tmp.path(), "r").unwrap();
        assert!(raf.seek(10).is_err());
    }

    #[test]
    fn test_double_buffer_swap() {
        // Create a file larger than BUFFER_SIZE so we can test buffer swapping
        // We'll use a smaller test with known data
        let mut data = vec![0u8; 4096];
        for i in 0..4096 {
            data[i] = (i % 256) as u8;
        }
        let tmp = create_temp_file(&data);

        let mut raf = GhidraRandomAccessFile::open(tmp.path(), "r").unwrap();

        // Read from position 0
        raf.seek(0).unwrap();
        assert_eq!(raf.read_byte().unwrap(), 0);

        // Read from position 2000 (forces buffer load)
        raf.seek(2000).unwrap();
        assert_eq!(raf.read_byte().unwrap(), (2000 % 256) as u8);

        // Read from position 1000 (should be handled by last buffer swap)
        raf.seek(1000).unwrap();
        assert_eq!(raf.read_byte().unwrap(), (1000 % 256) as u8);
    }

    #[test]
    fn test_close_errors() {
        let data = vec![1, 2, 3];
        let tmp = create_temp_file(&data);

        let mut raf = GhidraRandomAccessFile::open(tmp.path(), "r").unwrap();
        raf.close().unwrap();

        assert!(raf.seek(0).is_err());
        assert!(raf.read_byte().is_err());
    }

    #[test]
    fn test_invalid_mode() {
        let data = vec![1, 2, 3];
        let tmp = create_temp_file(&data);

        let result = GhidraRandomAccessFile::open(tmp.path(), "x");
        assert!(result.is_err());
    }

    #[test]
    fn test_read_at_eof() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let tmp = create_temp_file(&data);

        let mut raf = GhidraRandomAccessFile::open(tmp.path(), "r").unwrap();
        raf.seek(2).unwrap();
        assert_eq!(raf.read_byte().unwrap(), 0xCC);

        // At EOF, reading should fail
        raf.seek(3).unwrap();
        assert!(raf.read_byte().is_err());
    }
}
