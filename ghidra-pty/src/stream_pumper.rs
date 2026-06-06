//! `StreamPumper` -- pumps data from one stream to another.
//!
//! Ported from `ghidra.pty.StreamPumper`. Continuously reads from an input
//! stream and writes to an output stream, typically running in a separate
//! thread.

use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// Pumps data from a reader to a writer in a background thread.
///
/// Ported from `ghidra.pty.StreamPumper`. Once started, data is continuously
/// read from the input and written to the output until EOF or the pumper is
/// stopped.
pub struct StreamPumper {
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<io::Result<u64>>>,
}

impl StreamPumper {
    /// Create and start a new stream pumper.
    ///
    /// The pumper reads from `reader` and writes to `writer` in a background
    /// thread. Returns the pumper handle.
    pub fn start(
        mut reader: impl Read + Send + 'static,
        mut writer: impl Write + Send + 'static,
    ) -> Self {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let flag = stop_flag.clone();

        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut total: u64 = 0;

            while !flag.load(Ordering::Relaxed) {
                match reader.read(&mut buf) {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        writer.write_all(&buf[..n])?;
                        total += n as u64;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }

            let _ = writer.flush();
            Ok(total)
        });

        Self {
            stop_flag,
            handle: Some(handle),
        }
    }

    /// Signal the pumper to stop.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    /// Wait for the pumper thread to finish and return the total bytes
    /// transferred.
    pub fn join(&mut self) -> io::Result<u64> {
        if let Some(handle) = self.handle.take() {
            match handle.join() {
                Ok(result) => result,
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Pumper thread panicked",
                )),
            }
        } else {
            Ok(0)
        }
    }

    /// Returns `true` if the pumper has been signaled to stop.
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Relaxed)
    }
}

impl Drop for StreamPumper {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_stream_pumper_basic() {
        let input = Cursor::new(b"hello world".to_vec());
        let output: Vec<u8> = Vec::new();

        let mut pumper = StreamPumper::start(input, output);
        let bytes = pumper.join().unwrap();
        assert_eq!(bytes, 11);
    }

    #[test]
    fn test_stream_pumper_empty() {
        let input = Cursor::new(Vec::new());
        let output: Vec<u8> = Vec::new();

        let mut pumper = StreamPumper::start(input, output);
        let bytes = pumper.join().unwrap();
        assert_eq!(bytes, 0);
    }

    #[test]
    fn test_stream_pumper_stop() {
        // Use a slow reader that won't EOF quickly
        struct SlowReader;
        impl Read for SlowReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                std::thread::sleep(std::time::Duration::from_millis(100));
                buf[0] = 0;
                Ok(1)
            }
        }

        let pumper = StreamPumper::start(SlowReader, Vec::new());
        assert!(!pumper.is_stopped());
        pumper.stop();
        assert!(pumper.is_stopped());
    }
}
