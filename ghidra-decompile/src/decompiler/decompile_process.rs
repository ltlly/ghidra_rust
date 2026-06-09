//! DecompileProcess: communication with the native decompiler process.
//!
//! Port of Ghidra's `ghidra.app.decompiler.DecompileProcess`.

use std::fmt;

/// How the decompiler process was (or was not) disposed.
///
/// Mirrors `DecompileProcess.DisposeState` in Ghidra Java.
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

impl Default for DisposeState {
    fn default() -> Self {
        Self::NotDisposed
    }
}

impl fmt::Display for DisposeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDisposed => write!(f, "not disposed"),
            Self::DisposedOnTimeout => write!(f, "timeout"),
            Self::DisposedOnCancel => write!(f, "cancelled"),
            Self::DisposedOnStartupFailure => write!(f, "startup failure"),
        }
    }
}

/// Status of the decompiler process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStatus {
    /// The process is not started.
    NotStarted,
    /// The process is running and ready for commands.
    Ready,
    /// The process has an error.
    Error,
    /// The process has been disposed.
    Disposed,
}

impl Default for ProcessStatus {
    fn default() -> Self {
        Self::NotStarted
    }
}

/// Communicates with a single native decompiler process.
///
/// The process controls decompilation for a single Program.  It is
/// initiated by the `register_program` method.  If the process is
/// ready, `is_ready()` will return true.  If the process isn't ready,
/// the only way to recover is by reissuing the `register_program` call.
///
/// In this Rust port, the native communication is modeled as an abstract
/// interface.  Actual pipe/process management would be implemented in
/// a platform-specific backend.
#[derive(Debug)]
pub struct DecompileProcess {
    /// Path to the decompiler executable.
    exe_path: String,
    /// Architecture id assigned by the native process.
    arch_id: Option<i32>,
    /// Program source name.
    program_source: Option<String>,
    /// Current process status.
    status: ProcessStatus,
    /// How the process was disposed.
    dispose_state: DisposeState,
}

impl DecompileProcess {
    /// Create a new DecompileProcess for the given executable path.
    pub fn new(exe_path: &str) -> Self {
        Self {
            exe_path: exe_path.to_string(),
            arch_id: None,
            program_source: None,
            status: ProcessStatus::NotStarted,
            dispose_state: DisposeState::NotDisposed,
        }
    }

    /// Whether the process is ready to accept commands.
    pub fn is_ready(&self) -> bool {
        self.status == ProcessStatus::Ready
    }

    /// Get the current process status.
    pub fn status(&self) -> ProcessStatus {
        self.status
    }

    /// Get the dispose state.
    pub fn dispose_state(&self) -> DisposeState {
        self.dispose_state
    }

    /// Get the executable path.
    pub fn exe_path(&self) -> &str {
        &self.exe_path
    }

    /// Get the architecture id.
    pub fn arch_id(&self) -> Option<i32> {
        self.arch_id
    }

    /// Register a program with the decompiler process.
    ///
    /// In the real Ghidra, this sends the processor spec, compiler spec,
    /// translator spec, and core types XML to the native decompiler process
    /// and receives back an architecture id.
    pub fn register_program(
        &mut self,
        program_name: &str,
        _pspec_xml: &str,
        _cspec_xml: &str,
        _tspec_xml: &str,
        _core_types_xml: &str,
    ) -> Result<(), DecompileProcessError> {
        if self.dispose_state != DisposeState::NotDisposed {
            return Err(DecompileProcessError::Disposed);
        }
        self.program_source = Some(program_name.to_string());
        // In a real implementation, this would start the native process
        // and send the registration command over the pipe.
        self.arch_id = Some(0);
        self.status = ProcessStatus::Ready;
        Ok(())
    }

    /// Deregister the current program and free decompiler resources.
    pub fn deregister_program(&mut self) -> Result<i32, DecompileProcessError> {
        if self.status != ProcessStatus::Ready {
            return Err(DecompileProcessError::NotReady);
        }
        let result = if self.arch_id.is_some() { 1 } else { 0 };
        self.status = ProcessStatus::Disposed;
        self.dispose_state = DisposeState::DisposedOnCancel;
        Ok(result)
    }

    /// Send a command with no parameters.
    pub fn send_command(
        &mut self,
        command: &str,
        _response: &mut Vec<u8>,
    ) -> Result<(), DecompileProcessError> {
        if self.status != ProcessStatus::Ready {
            return Err(DecompileProcessError::NotReady);
        }
        // In a real implementation, this would write to the process pipe
        let _ = command;
        Ok(())
    }

    /// Send a command with one parameter.
    pub fn send_command_1param(
        &mut self,
        command: &str,
        _param: &[u8],
        _response: &mut Vec<u8>,
    ) -> Result<(), DecompileProcessError> {
        if self.status != ProcessStatus::Ready {
            return Err(DecompileProcessError::NotReady);
        }
        let _ = command;
        Ok(())
    }

    /// Send a command with two parameters.
    ///
    /// Corresponds to Ghidra's `sendCommand2Params` used for action toggles.
    pub fn send_command_2params(
        &mut self,
        command: &str,
        _param1: &str,
        _param2: &str,
        _response: &mut Vec<u8>,
    ) -> Result<(), DecompileProcessError> {
        if self.status != ProcessStatus::Ready {
            return Err(DecompileProcessError::NotReady);
        }
        let _ = command;
        Ok(())
    }

    /// Send a command with timeout.
    pub fn send_command_timeout(
        &mut self,
        command: &str,
        _timeout_secs: u32,
        _query: &[u8],
        _response: &mut Vec<u8>,
    ) -> Result<(), DecompileProcessError> {
        if self.status != ProcessStatus::Ready {
            return Err(DecompileProcessError::NotReady);
        }
        let _ = command;
        Ok(())
    }

    /// Dispose of the process.
    pub fn dispose(&mut self) {
        if self.dispose_state != DisposeState::NotDisposed {
            return;
        }
        self.dispose_state = DisposeState::DisposedOnCancel;
        self.status = ProcessStatus::Disposed;
    }
}

/// Errors that can occur when communicating with the decompiler process.
#[derive(Debug, Clone)]
pub enum DecompileProcessError {
    /// The process has been disposed.
    Disposed,
    /// The process is not ready (not started or errored).
    NotReady,
    /// An I/O error communicating with the process.
    IoError(String),
    /// A timeout occurred.
    Timeout,
    /// The process crashed.
    ProcessCrash(String),
}

impl fmt::Display for DecompileProcessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disposed => write!(f, "decompiler process has been disposed"),
            Self::NotReady => write!(f, "decompiler process is not ready"),
            Self::IoError(msg) => write!(f, "I/O error: {}", msg),
            Self::Timeout => write!(f, "decompiler process timed out"),
            Self::ProcessCrash(msg) => write!(f, "decompiler process crashed: {}", msg),
        }
    }
}

impl std::error::Error for DecompileProcessError {}

/// Factory for creating DecompileProcess instances.
///
/// Port of Ghidra's `DecompileProcessFactory`.
pub struct DecompileProcessFactory;

impl DecompileProcessFactory {
    /// Default executable name on Unix.
    const EXEC_NAME: &'static str = "decompile";
    /// Default executable name on Windows.
    const WIN_EXEC_NAME: &'static str = "decompile.exe";

    /// Get the default executable name for the current platform.
    pub fn default_exe_name() -> &'static str {
        if cfg!(target_os = "windows") {
            Self::WIN_EXEC_NAME
        } else {
            Self::EXEC_NAME
        }
    }

    /// Create a new DecompileProcess using the default executable path.
    pub fn get(exe_path: &str) -> DecompileProcess {
        DecompileProcess::new(exe_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_new() {
        let p = DecompileProcess::new("/usr/bin/decompile");
        assert!(!p.is_ready());
        assert_eq!(p.status(), ProcessStatus::NotStarted);
        assert_eq!(p.dispose_state(), DisposeState::NotDisposed);
    }

    #[test]
    fn test_register_program() {
        let mut p = DecompileProcess::new("/usr/bin/decompile");
        p.register_program("test.elf", "", "", "", "").unwrap();
        assert!(p.is_ready());
        assert_eq!(p.arch_id(), Some(0));
    }

    #[test]
    fn test_register_disposed_fails() {
        let mut p = DecompileProcess::new("/usr/bin/decompile");
        p.dispose();
        assert!(p.register_program("test.elf", "", "", "", "").is_err());
    }

    #[test]
    fn test_deregister() {
        let mut p = DecompileProcess::new("/usr/bin/decompile");
        p.register_program("test.elf", "", "", "", "").unwrap();
        let result = p.deregister_program().unwrap();
        assert_eq!(result, 1);
        assert!(!p.is_ready());
    }

    #[test]
    fn test_send_command_not_ready() {
        let mut p = DecompileProcess::new("/usr/bin/decompile");
        let mut resp = Vec::new();
        assert!(p.send_command("flush", &mut resp).is_err());
    }

    #[test]
    fn test_dispose() {
        let mut p = DecompileProcess::new("/usr/bin/decompile");
        p.register_program("test.elf", "", "", "", "").unwrap();
        p.dispose();
        assert_eq!(p.dispose_state(), DisposeState::DisposedOnCancel);
        assert!(!p.is_ready());
        // Double dispose is safe
        p.dispose();
    }

    #[test]
    fn test_dispose_state_display() {
        assert_eq!(format!("{}", DisposeState::NotDisposed), "not disposed");
        assert_eq!(format!("{}", DisposeState::DisposedOnTimeout), "timeout");
        assert_eq!(format!("{}", DisposeState::DisposedOnCancel), "cancelled");
        assert_eq!(
            format!("{}", DisposeState::DisposedOnStartupFailure),
            "startup failure"
        );
    }

    #[test]
    fn test_factory() {
        let p = DecompileProcessFactory::get("/usr/bin/decompile");
        assert_eq!(p.exe_path(), "/usr/bin/decompile");
    }

    #[test]
    fn test_default_exe_name() {
        let name = DecompileProcessFactory::default_exe_name();
        if cfg!(target_os = "windows") {
            assert_eq!(name, "decompile.exe");
        } else {
            assert_eq!(name, "decompile");
        }
    }
}
