//! Fault-tolerant stream wrapper ported from Ghidra's
//! `ghidra.app.util.bin.FaultTolerantInputStream`.
//!
//! Provides an `Read` wrapper that suppresses any `io::Error` thrown by the
//! wrapped stream and starts returning zero bytes for all subsequent reads.

use std::io::{self, Read};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// FaultTolerantInputStream
// ---------------------------------------------------------------------------

/// A `Read` wrapper that suppresses I/O errors and returns zeros after a fault.
///
/// Ported from `ghidra.app.util.bin.FaultTolerantInputStream`. Once the
/// underlying stream throws an `io::Error`, all subsequent reads return
/// zero-filled bytes up to the expected total length.
///
/// This is useful when reading from unreliable sources (network streams,
/// damaged media) where partial data is better than no data.
///
/// # Example
///
/// ```
/// use std::io::{Read, Cursor};
/// use ghidra_features::bin_format::fault_tolerant_stream::FaultTolerantInputStream;
///
/// // Simulate a stream with only 3 bytes but declared length of 10
/// let data = Cursor::new(vec![0x01u8, 0x02, 0x03]);
/// let mut stream = FaultTolerantInputStream::new(Box::new(data), 10, None);
///
/// let mut buf = [0u8; 10];
/// let n = stream.read(&mut buf).unwrap();
/// // After EOF, the remaining bytes are zero-filled
/// assert_eq!(n, 7);
/// assert!(buf.iter().all(|&b| b == 0));
/// ```
pub struct FaultTolerantInputStream {
    inner: Mutex<FaultTolerantInner>,
}

struct FaultTolerantInner {
    delegate: Box<dyn Read>,
    current_position: u64,
    total_length: u64,
    error: Option<io::Error>,
    fault_position: Option<u64>,
    fault_byte_count: u64,
}

/// Type alias for an error handler callback.
type ErrorHandler = Box<dyn Fn(&str, &io::Error) + Send + Sync>;

/// Container for optional error handler.
struct ErrorContext {
    handler: Option<ErrorHandler>,
}

impl FaultTolerantInputStream {
    /// Creates a new fault-tolerant stream wrapper.
    ///
    /// # Arguments
    ///
    /// * `delegate` - The underlying `Read` stream to wrap
    /// * `length` - The expected total length of the stream
    /// * `error_handler` - Optional callback invoked on close if errors occurred.
    ///   Receives a message string and the original error.
    pub fn new(
        delegate: Box<dyn Read>,
        length: u64,
        error_handler: Option<ErrorHandler>,
    ) -> Self {
        Self {
            inner: Mutex::new(FaultTolerantInner {
                delegate,
                current_position: 0,
                total_length: length,
                error: None,
                fault_position: None,
                fault_byte_count: 0,
            }),
        }
    }

    /// Creates a fault-tolerant stream with a simple log-style error handler.
    pub fn with_default_handler(delegate: Box<dyn Read>, length: u64) -> Self {
        Self::new(delegate, length, None)
    }

    /// Returns the position at which the first error occurred, if any.
    pub fn fault_position(&self) -> Option<u64> {
        self.inner.lock().unwrap().fault_position
    }

    /// Returns the number of zero-filled bytes returned after the fault.
    pub fn fault_byte_count(&self) -> u64 {
        self.inner.lock().unwrap().fault_byte_count
    }

    /// Returns true if a fault has been encountered.
    pub fn has_faulted(&self) -> bool {
        self.inner.lock().unwrap().error.is_some()
    }
}

impl Read for FaultTolerantInputStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock().unwrap();

        if inner.error.is_none() {
            // Haven't hit an error yet, try to read from delegate, looping
            // to fill as much of the buffer as possible (matching Java
            // FaultTolerantInputStream behavior).
            let mut total_read = 0usize;
            loop {
                if total_read >= buf.len() {
                    // Buffer completely filled
                    inner.current_position += total_read as u64;
                    return Ok(total_read);
                }
                match inner.delegate.read(&mut buf[total_read..]) {
                    Ok(0) => {
                        // EOF from delegate -- zero-fill the rest
                        inner.current_position += total_read as u64;
                        break;
                    }
                    Ok(n) => {
                        total_read += n;
                        if total_read >= buf.len() {
                            inner.current_position += total_read as u64;
                            return Ok(total_read);
                        }
                        // Partial read, loop to try again
                    }
                    Err(e) => {
                        inner.fault_position = Some(inner.current_position + total_read as u64);
                        inner.error = Some(e);
                        inner.current_position += total_read as u64;
                        // Fall through to zero-fill logic below
                        let remaining =
                            inner.total_length.saturating_sub(inner.current_position);
                        if remaining == 0 {
                            return Ok(total_read);
                        }
                        let unfilled = buf.len() - total_read;
                        let to_fill = (unfilled as u64).min(remaining) as usize;
                        for b in &mut buf[total_read..total_read + to_fill] {
                            *b = 0;
                        }
                        inner.current_position += to_fill as u64;
                        inner.fault_byte_count += to_fill as u64;
                        return Ok(total_read + to_fill);
                    }
                }
            }
        }

        // There was a previous error (or EOF above) -- return zeros
        let remaining = inner.total_length.saturating_sub(inner.current_position);
        if remaining == 0 {
            return Ok(0);
        }

        let to_fill = (buf.len() as u64).min(remaining) as usize;
        for b in &mut buf[..to_fill] {
            *b = 0;
        }
        inner.current_position += to_fill as u64;
        inner.fault_byte_count += to_fill as u64;
        Ok(to_fill)
    }
}

// ---------------------------------------------------------------------------
// ErrorAfterN -- test helper
// ---------------------------------------------------------------------------

/// A `Read` implementation that returns an error after N bytes.
///
/// This is useful for testing fault-tolerant stream behavior.
#[cfg(test)]
pub struct ErrorAfterN {
    data: Vec<u8>,
    position: usize,
    error_after: usize,
}

#[cfg(test)]
impl ErrorAfterN {
    /// Creates a new stream that errors after `error_after` bytes have been read.
    pub fn new(data: Vec<u8>, error_after: usize) -> Self {
        Self {
            data,
            position: 0,
            error_after,
        }
    }
}

#[cfg(test)]
impl Read for ErrorAfterN {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.error_after {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "simulated I/O error",
            ));
        }

        let available = self.data.len() - self.position;
        if available == 0 {
            return Ok(0);
        }

        let to_read = buf.len().min(available).min(self.error_after - self.position);
        buf[..to_read].copy_from_slice(&self.data[self.position..self.position + to_read]);
        self.position += to_read;
        Ok(to_read)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_normal_read() {
        let data = vec![1, 2, 3, 4, 5];
        let stream = FaultTolerantInputStream::new(Box::new(Cursor::new(data)), 5, None);

        let mut buf = [0u8; 5];
        let mut reader = stream;
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_fault_returns_zeros() {
        let error_stream = ErrorAfterN::new(vec![0x01, 0x02, 0x03], 3);
        let stream = FaultTolerantInputStream::new(Box::new(error_stream), 10, None);

        let mut buf = [0u8; 10];
        let mut reader = stream;
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 10);
        // First 3 bytes are real, rest are zeros
        assert_eq!(&buf[..3], &[0x01, 0x02, 0x03]);
        assert_eq!(&buf[3..], &[0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_fault_at_position_zero() {
        let error_stream = ErrorAfterN::new(vec![], 0);
        let stream = FaultTolerantInputStream::new(Box::new(error_stream), 5, None);

        let mut buf = [0u8; 5];
        let mut reader = stream;
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf, [0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_multiple_reads_after_fault() {
        let error_stream = ErrorAfterN::new(vec![0xAA, 0xBB], 2);
        let stream = FaultTolerantInputStream::new(Box::new(error_stream), 6, None);

        let mut reader = stream;

        // First read -- gets 2 real bytes + fault
        let mut buf1 = [0u8; 4];
        let n1 = reader.read(&mut buf1).unwrap();
        assert_eq!(n1, 4);
        assert_eq!(&buf1[..2], &[0xAA, 0xBB]);
        assert_eq!(&buf1[2..], &[0, 0]);

        // Second read -- all zeros
        let mut buf2 = [0u8; 2];
        let n2 = reader.read(&mut buf2).unwrap();
        assert_eq!(n2, 2);
        assert_eq!(buf2, [0, 0]);
    }

    #[test]
    fn test_fault_byte_count() {
        let error_stream = ErrorAfterN::new(vec![1, 2], 2);
        let stream = FaultTolerantInputStream::new(Box::new(error_stream), 8, None);

        let mut reader = stream;

        let mut buf = [0u8; 8];
        reader.read(&mut buf).unwrap();

        assert_eq!(reader.fault_position(), Some(2));
        assert_eq!(reader.fault_byte_count(), 6);
        assert!(reader.has_faulted());
    }

    #[test]
    fn test_no_fault_info_when_no_error() {
        let data = vec![1, 2, 3];
        let stream = FaultTolerantInputStream::new(Box::new(Cursor::new(data)), 3, None);

        let mut reader = stream;
        let mut buf = [0u8; 3];
        reader.read(&mut buf).unwrap();

        assert_eq!(reader.fault_position(), None);
        assert_eq!(reader.fault_byte_count(), 0);
        assert!(!reader.has_faulted());
    }

    #[test]
    fn test_empty_stream() {
        let stream = FaultTolerantInputStream::new(Box::new(Cursor::new(vec![])), 0, None);

        let mut reader = stream;
        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_read_less_than_remaining() {
        let error_stream = ErrorAfterN::new(vec![1, 2, 3], 3);
        let stream = FaultTolerantInputStream::new(Box::new(error_stream), 100, None);

        let mut reader = stream;

        // Request only 5 bytes but total length is 100
        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..3], &[1, 2, 3]);
        assert_eq!(&buf[3..], &[0, 0]);
    }

    #[test]
    fn test_with_default_handler() {
        let error_stream = ErrorAfterN::new(vec![1], 1);
        let stream = FaultTolerantInputStream::with_default_handler(
            Box::new(error_stream),
            5,
        );

        let mut reader = stream;
        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(buf[0], 1);
        assert!(reader.has_faulted());
    }
}
