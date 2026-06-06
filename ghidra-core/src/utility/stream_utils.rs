//! Stream/IO utilities: BoundedInputStream, HashingOutputStream,
//! MonitoredOutputStream, and NullOutputStream.
//!
//! Port of `ghidra.util` stream types.

use std::io::{self, Read, Write};

/// A bounded input stream that limits the number of bytes read.
///
/// Port of `ghidra.util.BoundedInputStream`.
pub struct BoundedInputStream<R: Read> {
    inner: R,
    remaining: u64,
}

impl<R: Read> BoundedInputStream<R> {
    /// Create a new bounded stream wrapping the inner reader.
    pub fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            remaining: limit,
        }
    }

    /// Get the remaining bytes that can be read.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}

impl<R: Read> Read for BoundedInputStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let max = buf.len().min(self.remaining as usize);
        let n = self.inner.read(&mut buf[..max])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// An output stream that computes an MD5 hash of all bytes written.
///
/// Port of `ghidra.util.HashingOutputStream`.
pub struct HashingOutputStream<W: Write> {
    inner: W,
    bytes: Vec<u8>,
}

impl<W: Write> HashingOutputStream<W> {
    /// Create a new hashing stream.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            bytes: Vec::new(),
        }
    }

    /// Compute the MD5 hash of all bytes written so far.
    pub fn md5_hash(&self) -> String {
        use md5::Digest;
        let mut hasher = md5::Md5::new();
        hasher.update(&self.bytes);
        format!("{:x}", hasher.finalize())
    }

    /// Get the total bytes written.
    pub fn bytes_written(&self) -> usize {
        self.bytes.len()
    }

    /// Get the underlying writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for HashingOutputStream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A callback invoked on each write, for monitoring progress.
///
/// Port of `ghidra.util.MonitoredOutputStream`.
pub struct MonitoredOutputStream<W: Write> {
    inner: W,
    bytes_written: u64,
    callback: Option<Box<dyn FnMut(u64) + Send>>,
}

impl<W: Write> MonitoredOutputStream<W> {
    /// Create a new monitored stream.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
            callback: None,
        }
    }

    /// Create with a progress callback.
    pub fn with_callback(inner: W, callback: impl FnMut(u64) + Send + 'static) -> Self {
        Self {
            inner,
            bytes_written: 0,
            callback: Some(Box::new(callback)),
        }
    }

    /// Get the total bytes written.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

impl<W: Write> Write for MonitoredOutputStream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n as u64;
        if let Some(ref mut cb) = self.callback {
            cb(self.bytes_written);
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// An output stream that discards all data (like /dev/null).
///
/// Port of `ghidra.util.NullOutputStream`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullOutputStream {
    bytes_written: u64,
}

impl NullOutputStream {
    /// Create a new null output stream.
    pub fn new() -> Self {
        Self { bytes_written: 0 }
    }

    /// Get the total bytes "written".
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

impl Write for NullOutputStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes_written += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_bounded_input_stream() {
        let data = b"Hello, World!";
        let cursor = Cursor::new(data);
        let mut stream = BoundedInputStream::new(cursor, 5);
        let mut buf = [0u8; 20];
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], b"Hello");
        assert_eq!(stream.remaining(), 0);
        // Next read should return 0
        let n = stream.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_hashing_output_stream() {
        let mut buf = Vec::new();
        {
            let mut stream = HashingOutputStream::new(&mut buf);
            stream.write_all(b"hello").unwrap();
            assert_eq!(stream.bytes_written(), 5);
        }
    }

    #[test]
    fn test_monitored_output_stream() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::Arc;

        let total = Arc::new(AtomicU64::new(0));
        let t = total.clone();
        let mut stream = MonitoredOutputStream::with_callback(Vec::new(), move |n| {
            t.store(n, Ordering::Relaxed);
        });
        stream.write_all(b"test data").unwrap();
        assert_eq!(stream.bytes_written(), 9);
        assert_eq!(total.load(Ordering::Relaxed), 9);
    }

    #[test]
    fn test_null_output_stream() {
        let mut stream = NullOutputStream::new();
        stream.write_all(b"hello").unwrap();
        stream.write_all(b" world").unwrap();
        assert_eq!(stream.bytes_written(), 11);
    }
}
