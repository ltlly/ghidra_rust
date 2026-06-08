//! Decompiler process -- Rust port of
//! `ghidra.app.decompiler.DecompileProcess`.
//!
//! Manages communication with a single external decompiler process.
//! The process controls decompilation for a single program.  The process
//! is initiated by the [`register_program`] method.  If the process is
//! ready, the [`status_good`] flag will be `true`.  This flag must be
//! checked via [`is_ready`] prior to invoking any of the public methods.
//!
//! # Protocol
//!
//! The decompiler uses a burst-based binary protocol over stdin/stdout.
//! Each message is delimited by special 4-byte marker sequences:
//!
//! | Marker             | Bytes            | Purpose                         |
//! |--------------------|------------------|---------------------------------|
//! | `COMMAND_START`    | `[0,0,1,2]`     | Begin command to decompiler     |
//! | `COMMAND_END`      | `[0,0,1,3]`     | End command to decompiler       |
//! | `QR_START`         | `[0,0,1,8]`     | Begin query response to decomp. |
//! | `QR_END`           | `[0,0,1,9]`     | End query response to decomp.   |
//! | `STRING_START`     | `[0,0,1,14]`    | Begin string payload            |
//! | `STRING_END`       | `[0,0,1,15]`    | End string payload              |
//! | `EXCEPTION_START`  | `[0,0,1,10]`    | Begin exception from decompiler |
//! | `EXCEPTION_END`    | `[0,0,1,11]`    | End exception from decompiler   |
//! | `BYTE_START`       | `[0,0,1,12]`    | Begin byte payload              |
//! | `BYTE_END`         | `[0,0,1,13]`    | End byte payload                |
//!
//! # Architecture
//!
//! ```text
//! DecompileProcess
//!   ├── exe_path: PathBuf                    (path to decompiler executable)
//!   ├── native_process: Option<Child>        (the OS process handle)
//!   ├── status_good: bool                    (true while process is alive)
//!   ├── dispose_state: DisposeState
//!   ├── arch_id: i32                         (registered architecture id)
//!   ├── max_result_size_mb: usize            (upper bound on result size)
//!   └── program_source: Option<String>       (program name for error reports)
//! ```

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::decompile_exception::DecompileException;

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

/// Begin a command sent to the decompiler.
const COMMAND_START: [u8; 4] = [0, 0, 1, 2];
/// End a command sent to the decompiler.
const COMMAND_END: [u8; 4] = [0, 0, 1, 3];
/// Begin a query response sent back to the decompiler.
const QR_START: [u8; 4] = [0, 0, 1, 8];
/// End a query response sent back to the decompiler.
const QR_END: [u8; 4] = [0, 0, 1, 9];
/// Begin an exception message.
const EXCEPTION_START: [u8; 4] = [0, 0, 1, 10];
/// End an exception message.
const EXCEPTION_END: [u8; 4] = [0, 0, 1, 11];
/// Begin a byte payload.
const BYTE_START: [u8; 4] = [0, 0, 1, 12];
/// End a byte payload.
const BYTE_END: [u8; 4] = [0, 0, 1, 13];
/// Begin a string payload.
const STRING_START: [u8; 4] = [0, 0, 1, 14];
/// End a string payload.
const STRING_END: [u8; 4] = [0, 0, 1, 15];

// ---------------------------------------------------------------------------
// DisposeState
// ---------------------------------------------------------------------------

/// How the decompiler process was (or was not) disposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisposeState {
    /// Process was/is not disposed.
    NotDisposed,
    /// A timeout occurred.
    DisposedOnTimeout,
    /// The process was cancelled.
    DisposedOnCancel,
    /// The executable failed to start.
    DisposedOnStartupFailure,
}

// ---------------------------------------------------------------------------
// DecompileProcess
// ---------------------------------------------------------------------------

/// Manages communication with a single decompiler subprocess.
///
/// The process is started by calling [`DecompileProcess::register_program`].
/// Commands are sent via the various `send_command*` methods.  The process
/// can be shut down via [`DecompileProcess::dispose`] or by dropping it.
pub struct DecompileProcess {
    /// Path to the decompiler executable.
    exe_path: PathBuf,
    /// The OS process handle (None if not started or already disposed).
    native_process: Option<Child>,
    /// `true` while the decompiler process is running and responsive.
    status_good: bool,
    /// How the process was (or was not) disposed.
    dispose_state: DisposeState,
    /// Architecture id returned by `registerProgram`.
    arch_id: i32,
    /// Maximum result size in megabytes.
    max_result_size_mb: usize,
    /// Program name for error reporting.
    program_source: Option<String>,
    /// Accumulated response bytes from the last command.
    response_buffer: Vec<u8>,
    /// Accumulated exception/error bytes from the last command.
    exception_buffer: Vec<u8>,
    /// Native message from the decompiler (status/info).
    native_message: Option<String>,
}

impl DecompileProcess {
    /// Create a new decompiler process manager for the given executable path.
    ///
    /// The process is NOT started until [`register_program`] is called.
    pub fn new(exe_path: impl Into<PathBuf>) -> Self {
        Self {
            exe_path: exe_path.into(),
            native_process: None,
            status_good: false,
            dispose_state: DisposeState::NotDisposed,
            arch_id: -1,
            max_result_size_mb: 50,
            program_source: None,
            response_buffer: Vec::new(),
            exception_buffer: Vec::new(),
            native_message: None,
        }
    }

    /// Returns `true` if the decompiler process is running and responsive.
    pub fn is_ready(&self) -> bool {
        self.status_good && self.dispose_state == DisposeState::NotDisposed
    }

    /// Returns the current dispose state.
    pub fn get_dispose_state(&self) -> DisposeState {
        self.dispose_state
    }

    /// Returns the architecture id assigned by `registerProgram`.
    pub fn arch_id(&self) -> i32 {
        self.arch_id
    }

    /// Returns the native message from the last command, if any.
    pub fn native_message(&self) -> Option<&str> {
        self.native_message.as_deref()
    }

    /// Set an upper limit on the amount of data that can be sent back by the
    /// decompiler in response to a single command.
    pub fn set_max_result_size(&mut self, max_result_size_mb: usize) {
        self.max_result_size_mb = max_result_size_mb;
    }

    // ------------------------------------------------------------------
    // Process lifecycle
    // ------------------------------------------------------------------

    /// Start the decompiler subprocess.
    ///
    /// Returns `Ok(())` if the process started successfully, or an
    /// `io::Error` if the executable could not be launched.
    fn setup(&mut self) -> io::Result<()> {
        if self.dispose_state != DisposeState::NotDisposed {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Decompiler has been disposed",
            ));
        }

        // If a previous process exists (from a failed attempt), kill it.
        if let Some(mut prev) = self.native_process.take() {
            let _ = prev.kill();
        }

        if self.exe_path.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Could not find decompiler executable",
            ));
        }

        let child = Command::new(&self.exe_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();

        match child {
            Ok(mut proc) => {
                // Give process a moment to start and check if it died immediately.
                std::thread::sleep(Duration::from_millis(200));

                let alive = {
                    match proc.try_wait() {
                        Ok(Some(status)) => {
                            // Process exited already.
                            let _stderr = proc.stderr.take();
                            false
                        }
                        Ok(None) => true,
                        Err(_) => false,
                    }
                };

                if alive {
                    self.status_good = true;
                    self.native_process = Some(proc);
                    Ok(())
                } else {
                    self.dispose_state = DisposeState::DisposedOnStartupFailure;
                    let _ = proc.kill();
                    Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Decompiler process failed to launch (see log for details)",
                    ))
                }
            }
            Err(e) => {
                self.dispose_state = DisposeState::DisposedOnStartupFailure;
                Err(e)
            }
        }
    }

    /// Shut down the decompiler process.
    ///
    /// This is safe to call multiple times.  After disposal, the process
    /// cannot be restarted -- create a new [`DecompileProcess`] instead.
    pub fn dispose(&mut self) {
        if self.dispose_state != DisposeState::NotDisposed {
            return;
        }
        self.dispose_state = DisposeState::DisposedOnCancel;
        self.status_good = false;

        if let Some(mut proc) = self.native_process.take() {
            let _ = proc.kill();
            let _ = proc.wait();
        }
    }

    // ------------------------------------------------------------------
    // Low-level I/O helpers
    // ------------------------------------------------------------------

    /// Write raw bytes to the decompiler's stdin.
    fn write_bytes(&mut self, data: &[u8]) -> io::Result<()> {
        let proc = self
            .native_process
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "No decompiler process"))?;
        let stdin = proc
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "No stdin"))?;
        stdin.write_all(data)?;
        Ok(())
    }

    /// Write a single byte to the decompiler's stdin.
    fn write_byte(&mut self, b: u8) -> io::Result<()> {
        self.write_bytes(&[b])
    }

    /// Write a length-prefixed string to the decompiler.
    fn write_string(&mut self, s: &str) -> io::Result<()> {
        self.write_bytes(&STRING_START)?;
        self.write_bytes(s.as_bytes())?;
        self.write_bytes(&STRING_END)?;
        Ok(())
    }

    /// Read a burst delimiter from stdout and return the burst type byte.
    ///
    /// The protocol uses 0x00 bytes as padding, 0x01 as a burst marker,
    /// and the byte following the marker is the burst type.
    fn read_to_burst(&mut self) -> io::Result<u8> {
        let proc = self
            .native_process
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "No decompiler process"))?;
        let stdout = proc
            .stdout
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "No stdout"))?;

        let mut buf = [0u8; 1];
        // Skip non-zero bytes (data bytes).
        loop {
            stdout.read_exact(&mut buf)?;
            if buf[0] == 0 {
                break;
            }
        }
        // Skip zero bytes until we hit a 1 (burst marker).
        loop {
            stdout.read_exact(&mut buf)?;
            if buf[0] != 0 {
                break;
            }
        }
        if buf[0] == 1 {
            // Read the burst type.
            stdout.read_exact(&mut buf)?;
            Ok(buf[0])
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Decompiler process died",
            ))
        }
    }

    /// Read until the decompiler sends a response burst.
    fn read_to_response(&mut self) -> Result<(), DecompileException> {
        // Flush stdin so the decompiler has all its input.
        if let Some(proc) = self.native_process.as_mut() {
            if let Some(stdin) = proc.stdin.as_mut() {
                let _ = stdin.flush();
            }
        }

        loop {
            let burst_type = self.read_to_burst().map_err(|e| {
                DecompileException::process(format!("I/O error: {}", e))
            })?;

            // Odd burst types are intermediate; even types are terminal.
            if burst_type & 1 == 0 {
                if burst_type == 10 {
                    // Exception from decompiler.
                    return Err(DecompileException::process(
                        "Exception from decompiler during response",
                    ));
                }
                if burst_type == 6 {
                    return Ok(());
                }
                return Err(DecompileException::alignment(
                    "Ghidra/decompiler alignment error",
                ));
            }
            // Odd type -- continue reading.
        }
    }

    /// Read a string payload from the decompiler.
    fn read_string_payload(&mut self) -> io::Result<Vec<u8>> {
        let proc = self
            .native_process
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "No decompiler process"))?;
        let stdout = proc
            .stdout
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "No stdout"))?;

        let mut result = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = stdout.read(&mut buf)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Decompiler process died",
                ));
            }
            // Check for string_end marker in the bytes we just read.
            for &b in &buf[..n] {
                if b == 0 {
                    // Possible marker -- push and let caller handle.
                    result.push(b);
                } else if b == 1 {
                    // Possible burst marker.
                    result.push(b);
                } else {
                    result.push(b);
                }
            }
            // Simplified: in a real implementation, we'd parse the burst
            // protocol here.  For now, accumulate and return.
            if result.len() >= 4096 {
                break;
            }
        }
        Ok(result)
    }

    // ------------------------------------------------------------------
    // High-level command interface
    // ------------------------------------------------------------------

    /// Initialize the decompiler for a particular platform.
    ///
    /// This must be called before any other command.  It starts the
    /// decompiler subprocess and sends the `registerProgram` command.
    ///
    /// # Arguments
    /// * `program_source` -- name of the program (for error messages).
    /// * `pspec_xml` -- `.pspec` XML string.
    /// * `cspec_xml` -- `.cspec` XML string.
    /// * `tspec_xml` -- translator spec XML string.
    /// * `core_types_xml` -- core data-types XML string.
    ///
    /// # Returns
    /// The architecture id assigned by the decompiler.
    pub fn register_program(
        &mut self,
        program_source: impl Into<String>,
        pspec_xml: &str,
        cspec_xml: &str,
        tspec_xml: &str,
        core_types_xml: &str,
    ) -> Result<i32, DecompileException> {
        self.program_source = Some(program_source.into());
        self.setup().map_err(|e| DecompileException::process(e.to_string()))?;

        self.write_bytes(&COMMAND_START)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string("registerProgram")
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(pspec_xml)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(cspec_xml)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(tspec_xml)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(core_types_xml)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_bytes(&COMMAND_END)
            .map_err(|e| DecompileException::process(e.to_string()))?;

        // Read response (simplified -- real implementation parses the
        // full burst protocol).
        let response = self.read_command_response()?;

        let arch_id: i32 = response
            .trim()
            .parse()
            .map_err(|_| DecompileException::process("Invalid arch id in response"))?;

        self.arch_id = arch_id;
        Ok(arch_id)
    }

    /// Free decompiler resources and deregister the program.
    ///
    /// Returns `Ok(1)` if a program was actively deregistered, `Ok(0)`
    /// otherwise.  After this call the process is no longer usable.
    pub fn deregister_program(&mut self) -> Result<i32, DecompileException> {
        if !self.status_good {
            return Err(DecompileException::process(
                "deregisterProgram called on bad process",
            ));
        }
        self.status_good = false;

        self.write_bytes(&COMMAND_START)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string("deregisterProgram")
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(&self.arch_id.to_string())
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_bytes(&COMMAND_END)
            .map_err(|e| DecompileException::process(e.to_string()))?;

        let response = self.read_command_response()?;
        let result: i32 = response
            .trim()
            .parse()
            .map_err(|_| DecompileException::process("Invalid deregister response"))?;

        self.program_source = None;
        Ok(result)
    }

    /// Send a single command to the decompiler with no extra parameters.
    ///
    /// # Arguments
    /// * `command` -- the command name (e.g. `"decompile"`).
    ///
    /// # Returns
    /// The response string from the decompiler.
    pub fn send_command(&mut self, command: &str) -> Result<String, DecompileException> {
        if !self.status_good {
            return Err(DecompileException::process(format!(
                "{} called on bad process",
                command
            )));
        }

        self.write_bytes(&COMMAND_START)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(command)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(&self.arch_id.to_string())
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_bytes(&COMMAND_END)
            .map_err(|e| DecompileException::process(e.to_string()))?;

        self.read_command_response()
    }

    /// Send a command with a timeout.
    ///
    /// If `timeout_secs` is 0, no timeout is applied.
    ///
    /// # Arguments
    /// * `command` -- the command name.
    /// * `timeout_secs` -- timeout in seconds (0 = no timeout).
    /// * `param` -- the encoded parameter string.
    ///
    /// # Returns
    /// The response string from the decompiler.
    pub fn send_command_timeout(
        &mut self,
        command: &str,
        timeout_secs: u64,
        param: &str,
    ) -> Result<String, DecompileException> {
        if !self.status_good {
            return Err(DecompileException::process(format!(
                "{} called on bad process",
                command
            )));
        }

        let start = Instant::now();

        self.write_bytes(&COMMAND_START)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(command)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(&self.arch_id.to_string())
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(param)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_bytes(&COMMAND_END)
            .map_err(|e| DecompileException::process(e.to_string()))?;

        // Read with timeout check.
        let result = self.read_command_response();

        if timeout_secs > 0 && start.elapsed() > Duration::from_secs(timeout_secs) {
            self.dispose();
            self.dispose_state = DisposeState::DisposedOnTimeout;
            return Err(DecompileException::timeout());
        }

        result
    }

    /// Send a command with two string parameters.
    pub fn send_command_2_params(
        &mut self,
        command: &str,
        param1: &str,
        param2: &str,
    ) -> Result<String, DecompileException> {
        if !self.status_good {
            return Err(DecompileException::process(format!(
                "{} called on bad process",
                command
            )));
        }

        self.write_bytes(&COMMAND_START)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(command)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(&self.arch_id.to_string())
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(param1)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(param2)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_bytes(&COMMAND_END)
            .map_err(|e| DecompileException::process(e.to_string()))?;

        self.read_command_response()
    }

    /// Send a command with one string parameter.
    pub fn send_command_1_param(
        &mut self,
        command: &str,
        param1: &str,
    ) -> Result<String, DecompileException> {
        if !self.status_good {
            return Err(DecompileException::process(format!(
                "{} called on bad process",
                command
            )));
        }

        self.write_bytes(&COMMAND_START)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(command)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(&self.arch_id.to_string())
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_string(param1)
            .map_err(|e| DecompileException::process(e.to_string()))?;
        self.write_bytes(&COMMAND_END)
            .map_err(|e| DecompileException::process(e.to_string()))?;

        self.read_command_response()
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Read a complete command response from the decompiler.
    ///
    /// This is a simplified version that reads until the response
    /// terminator.  The full implementation would handle query callbacks,
    /// byte payloads, and exception forwarding.
    fn read_command_response(&mut self) -> Result<String, DecompileException> {
        // In the full implementation, this would parse the burst protocol,
        // handle type=4 (query callback), type=10 (exception),
        // type=14/15 (string payload), type=16/17 (native message),
        // and type=7 (end of response).
        //
        // For this port, we implement the core read loop.
        self.response_buffer.clear();
        self.exception_buffer.clear();
        self.native_message = None;

        // Flush stdin.
        if let Some(proc) = self.native_process.as_mut() {
            if let Some(stdin) = proc.stdin.as_mut() {
                let _ = stdin.flush();
            }
        }

        // Read response bursts.
        let mut response_started = false;
        let mut native_started = false;

        loop {
            let burst_type = self.read_to_burst().map_err(|e| {
                self.status_good = false;
                DecompileException::process(format!("Decompiler process died: {}", e))
            })?;

            match burst_type {
                7 => {
                    // End of response.
                    break;
                }
                4 => {
                    // Query callback from decompiler -- not handled in this
                    // simplified port.  A full implementation would dispatch
                    // to the DecompileCallback.
                    return Err(DecompileException::process(
                        "Query callback not supported in this port",
                    ));
                }
                6 => {
                    // Response continuation.
                    continue;
                }
                10 => {
                    // Exception from decompiler.
                    return Err(DecompileException::process(
                        "Exception from decompiler",
                    ));
                }
                14 => {
                    // Start of main decompiler output (string payload).
                    response_started = true;
                    native_started = false;
                    continue;
                }
                15 => {
                    // End of main decompiler output.
                    response_started = false;
                    continue;
                }
                16 => {
                    // Start of native message.
                    native_started = true;
                    response_started = false;
                    continue;
                }
                17 => {
                    // End of native message.
                    native_started = false;
                    continue;
                }
                _ => {
                    // Data byte -- accumulate into appropriate buffer.
                    if response_started {
                        self.response_buffer.push(burst_type);
                    } else if native_started {
                        self.exception_buffer.push(burst_type);
                    }
                }
            }
        }

        if !self.exception_buffer.is_empty() {
            self.native_message = Some(
                String::from_utf8_lossy(&self.exception_buffer).to_string(),
            );
        }

        Ok(String::from_utf8_lossy(&self.response_buffer).to_string())
    }
}

impl Drop for DecompileProcess {
    fn drop(&mut self) {
        self.dispose();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let proc = DecompileProcess::new("/usr/bin/decompiler");
        assert!(!proc.is_ready());
        assert_eq!(proc.get_dispose_state(), DisposeState::NotDisposed);
        assert_eq!(proc.arch_id(), -1);
        assert!(proc.native_message().is_none());
    }

    #[test]
    fn test_dispose() {
        let mut proc = DecompileProcess::new("/usr/bin/decompiler");
        assert_eq!(proc.get_dispose_state(), DisposeState::NotDisposed);

        proc.dispose();
        assert!(!proc.is_ready());
        assert_eq!(proc.get_dispose_state(), DisposeState::DisposedOnCancel);
    }

    #[test]
    fn test_dispose_idempotent() {
        let mut proc = DecompileProcess::new("/usr/bin/decompiler");
        proc.dispose();
        proc.dispose(); // should not panic
        assert_eq!(proc.get_dispose_state(), DisposeState::DisposedOnCancel);
    }

    #[test]
    fn test_set_max_result_size() {
        let mut proc = DecompileProcess::new("/usr/bin/decompiler");
        proc.set_max_result_size(100);
        assert_eq!(proc.max_result_size_mb, 100);
    }

    #[test]
    fn test_send_command_on_bad_process() {
        let mut proc = DecompileProcess::new("/usr/bin/decompiler");
        // Not started -- should fail.
        let result = proc.send_command("decompile");
        assert!(result.is_err());
    }

    #[test]
    fn test_register_program_bad_exe() {
        let mut proc = DecompileProcess::new("/nonexistent/decompiler");
        let result = proc.register_program("test_prog", "", "", "", "");
        assert!(result.is_err());
        assert_eq!(
            proc.get_dispose_state(),
            DisposeState::DisposedOnStartupFailure
        );
    }

    #[test]
    fn test_protocol_constants() {
        // Verify the marker sequences match the Java constants.
        assert_eq!(COMMAND_START, [0, 0, 1, 2]);
        assert_eq!(COMMAND_END, [0, 0, 1, 3]);
        assert_eq!(QR_START, [0, 0, 1, 8]);
        assert_eq!(QR_END, [0, 0, 1, 9]);
        assert_eq!(EXCEPTION_START, [0, 0, 1, 10]);
        assert_eq!(EXCEPTION_END, [0, 0, 1, 11]);
        assert_eq!(BYTE_START, [0, 0, 1, 12]);
        assert_eq!(BYTE_END, [0, 0, 1, 13]);
        assert_eq!(STRING_START, [0, 0, 1, 14]);
        assert_eq!(STRING_END, [0, 0, 1, 15]);
    }
}
