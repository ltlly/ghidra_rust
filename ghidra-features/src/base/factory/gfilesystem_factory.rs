//! GFileSystem factory and probe interfaces.
//!
//! Ported from `ghidra.formats.gfilesystem.factory` -- the interfaces
//! that filesystem implementations use to register themselves and to
//! advertise how they should be probed for compatibility.
//!
//! # Architecture
//!
//! The Ghidra virtual filesystem framework uses a *factory + probe*
//! pattern:
//!
//! 1. **Probing** -- before opening a file as a filesystem, the
//!    framework asks each registered [`GFileSystemProbe`] whether it
//!    can handle the file.  Two probe strategies exist:
//!    - [`GFileSystemProbeBytesOnly`] -- inspects only the first N
//!      bytes (fast, preferred).
//!    - [`GFileSystemProbeByteProvider`] -- receives a full
//!      [`ByteProvider`] (slower, for complex formats).
//!
//! 2. **Creation** -- once a match is found, the corresponding
//!    [`GFileSystemFactory`] creates the filesystem instance.
//!    - [`GFileSystemFactoryByteProvider`] -- creates a filesystem
//!      from a `ByteProvider`.
//!
//! 3. **Ignore** -- [`GFileSystemFactoryIgnore`] is a marker that tells
//!    the factory manager to skip registration.
//!
//! # Key Traits / Types
//!
//! - [`GFileSystemFactory`] -- base marker trait for all FS factories
//! - [`GFileSystemProbe`] -- base marker trait for all FS probes
//! - [`GFileSystemProbeBytesOnly`] -- bytes-only probe strategy
//! - [`GFileSystemProbeByteProvider`] -- ByteProvider probe strategy
//! - [`GFileSystemFactoryByteProvider`] -- factory that creates from ByteProvider
//! - [`GFileSystemFactoryIgnore`] -- marker to skip registration

use std::fmt;
use std::io;

use crate::gfilesystem::{Fsrl, FsrlRoot};

// ---------------------------------------------------------------------------
// ByteProvider -- minimal trait for seekable byte access
// ---------------------------------------------------------------------------

/// A provider of bytes from a file or stream.
///
/// Simplified port of `ghidra.app.util.bin.ByteProvider`.
pub trait ByteProvider: Send + Sync + fmt::Debug {
    /// The FSRL of the file this provider wraps.
    fn fsrl(&self) -> &Fsrl;

    /// Total number of bytes available.
    fn length(&self) -> u64;

    /// Read a single byte at `offset`.
    fn read_byte(&self, offset: u64) -> io::Result<u8>;

    /// Read `len` bytes starting at `offset`.
    fn read_bytes(&self, offset: u64, len: u64) -> io::Result<Vec<u8>>;

    /// Read the first `n` bytes (convenience for probing).
    fn read_start_bytes(&self, n: usize) -> io::Result<Vec<u8>> {
        let available = self.length().min(n as u64);
        self.read_bytes(0, available)
    }
}

// ---------------------------------------------------------------------------
// TaskMonitor -- minimal cancellation / progress trait
// ---------------------------------------------------------------------------

/// A monitor for long-running operations that supports cancellation
/// and progress reporting.
///
/// Simplified port of `ghidra.util.task.TaskMonitor`.
pub trait TaskMonitor: Send + Sync {
    /// Returns `true` if the user has requested cancellation.
    fn is_cancelled(&self) -> bool;

    /// Sets the maximum progress value.
    fn set_maximum(&self, max: u64);

    /// Sets the current progress value.
    fn set_progress(&self, value: u64);

    /// Increments progress by `delta`.
    fn increment_progress(&self, delta: u64);

    /// Sets the progress message.
    fn set_message(&self, msg: &str);

    /// Checks cancellation and returns an error if cancelled.
    fn check_cancelled(&self) -> io::Result<()> {
        if self.is_cancelled() {
            Err(io::Error::new(io::ErrorKind::Interrupted, "Operation cancelled"))
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// FileSystemService -- minimal trait for FS-level operations
// ---------------------------------------------------------------------------

/// The file system service that manages open filesystems.
///
/// Simplified port of `ghidra.formats.gfilesystem.FileSystemService`.
pub trait FileSystemService: Send + Sync + fmt::Debug {
    /// Returns the name of the service.
    fn service_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// GFileSystemFactory -- base marker trait
// ---------------------------------------------------------------------------

/// An empty marker trait that is the common base for all filesystem
/// factory interfaces.
///
/// Filesystem implementations register a factory so the framework can
/// create new instances on demand.
///
/// Ported from `ghidra.formats.gfilesystem.factory.GFileSystemFactory`.
pub trait GFileSystemFactory: Send + Sync + fmt::Debug {
    /// The filesystem type this factory creates (e.g. "zip", "tar", "cpio").
    fn fs_type(&self) -> &str;

    /// Human-readable description of this filesystem type.
    fn description(&self) -> &str;
}

// ---------------------------------------------------------------------------
// GFileSystemProbe -- base marker trait for probes
// ---------------------------------------------------------------------------

/// An empty marker trait that is the common base for all filesystem
/// probe interfaces.
///
/// See [`GFileSystemProbeBytesOnly`] and [`GFileSystemProbeByteProvider`]
/// for the real probe strategies.
///
/// Ported from `ghidra.formats.gfilesystem.factory.GFileSystemProbe`.
pub trait GFileSystemProbe: Send + Sync + fmt::Debug {
    /// The filesystem type this probe tests for.
    fn fs_type(&self) -> &str;
}

// ---------------------------------------------------------------------------
// GFileSystemProbeBytesOnly -- fast header-based probing
// ---------------------------------------------------------------------------

/// A probe that can determine filesystem compatibility by inspecting
/// only the first few bytes of a file.
///
/// This probe strategy is preferred when possible because it is fast
/// and does not require opening the entire file.
///
/// Ported from `ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly`.
pub trait GFileSystemProbeBytesOnly: GFileSystemProbe {
    /// Maximum allowed value for [`bytes_required`].
    const MAX_BYTES_REQUIRED: usize = 64 * 1024;

    /// The minimum number of bytes this probe needs to inspect.
    ///
    /// Must be <= [`MAX_BYTES_REQUIRED`].
    fn bytes_required(&self) -> usize;

    /// Tests whether the given start bytes indicate that the file is
    /// of the type this probe handles.
    ///
    /// # Parameters
    ///
    /// * `container_fsrl` -- the FSRL of the file being probed.
    /// * `start_bytes` -- the first `bytes_required()` bytes of the file.
    ///
    /// # Returns
    ///
    /// `true` if this filesystem can handle the file.
    fn probe_start_bytes(&self, container_fsrl: &Fsrl, start_bytes: &[u8]) -> bool;
}

// ---------------------------------------------------------------------------
// GFileSystemProbeByteProvider -- full-content probing
// ---------------------------------------------------------------------------

/// A probe that inspects a [`ByteProvider`] to determine whether a
/// file is of a supported filesystem type.
///
/// This is the slower probe strategy, used when the bytes-only probe
/// is not sufficient.
///
/// Ported from `ghidra.formats.gfilesystem.factory.GFileSystemProbeByteProvider`.
pub trait GFileSystemProbeByteProvider: GFileSystemProbe {
    /// Probes the given byte provider.
    ///
    /// Implementations must NOT close the byte provider.
    ///
    /// # Parameters
    ///
    /// * `byte_provider` -- the file contents to inspect.
    /// * `fs_service` -- the file system service.
    /// * `monitor` -- progress/cancellation monitor.
    ///
    /// # Returns
    ///
    /// `true` if this filesystem can handle the file.
    fn probe(
        &self,
        byte_provider: &dyn ByteProvider,
        fs_service: &dyn FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<bool>;
}

// ---------------------------------------------------------------------------
// GFileSystemFactoryByteProvider -- create FS from ByteProvider
// ---------------------------------------------------------------------------

/// A factory that creates [`GFileSystem`](crate::gfilesystem::GFileSystem)
/// instances from a [`ByteProvider`].
///
/// Ported from `ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider`.
pub trait GFileSystemFactoryByteProvider: GFileSystemFactory {
    /// Creates a new filesystem instance from the given byte provider.
    ///
    /// # Parameters
    ///
    /// * `target_fsrl` -- the FSRL root for the new filesystem.
    /// * `byte_provider` -- the file contents. The factory takes
    ///   ownership and is responsible for closing it.
    /// * `fs_service` -- the file system service.
    /// * `monitor` -- progress/cancellation monitor.
    ///
    /// # Returns
    ///
    /// A boxed trait object for the newly created filesystem.
    fn create(
        &self,
        target_fsrl: &FsrlRoot,
        byte_provider: Box<dyn ByteProvider>,
        fs_service: &dyn FileSystemService,
        monitor: &dyn TaskMonitor,
    ) -> io::Result<Box<dyn crate::gfilesystem::GFileSystem>>;
}

// ---------------------------------------------------------------------------
// GFileSystemFactoryIgnore -- marker to skip registration
// ---------------------------------------------------------------------------

/// A marker type that tells the factory manager to NOT register this
/// filesystem.
///
/// Some filesystem base classes provide the factory interface but
/// should not be registered directly (they are abstract or only used
/// as building blocks).
///
/// Ported from `ghidra.formats.gfilesystem.factory.GFileSystemFactoryIgnore`.
#[derive(Debug)]
pub struct GFileSystemFactoryIgnore {
    fs_type: String,
}

impl GFileSystemFactoryIgnore {
    /// Creates a new ignore marker for the given filesystem type.
    pub fn new(fs_type: impl Into<String>) -> Self {
        Self {
            fs_type: fs_type.into(),
        }
    }

    /// The filesystem type to ignore.
    pub fn ignored_fs_type(&self) -> &str {
        &self.fs_type
    }
}

impl GFileSystemFactory for GFileSystemFactoryIgnore {
    fn fs_type(&self) -> &str {
        &self.fs_type
    }

    fn description(&self) -> &str {
        "Ignored filesystem factory (marker)"
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Mock types ---

    #[derive(Debug)]
    struct MockByteProvider {
        data: Vec<u8>,
        fsrl: Fsrl,
    }

    impl MockByteProvider {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                fsrl: Fsrl::new(FsrlRoot::local(), Some("/test.bin".into()), None),
            }
        }
    }

    impl ByteProvider for MockByteProvider {
        fn fsrl(&self) -> &Fsrl {
            &self.fsrl
        }
        fn length(&self) -> u64 {
            self.data.len() as u64
        }
        fn read_byte(&self, offset: u64) -> io::Result<u8> {
            self.data
                .get(offset as usize)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "out of bounds"))
        }
        fn read_bytes(&self, offset: u64, len: u64) -> io::Result<Vec<u8>> {
            let start = offset as usize;
            let end = (start + len as usize).min(self.data.len());
            if start > self.data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "out of bounds",
                ));
            }
            Ok(self.data[start..end].to_vec())
        }
    }

    #[derive(Debug)]
    struct MockMonitor {
        cancelled: bool,
    }

    impl MockMonitor {
        fn new() -> Self {
            Self { cancelled: false }
        }
    }

    impl TaskMonitor for MockMonitor {
        fn is_cancelled(&self) -> bool {
            self.cancelled
        }
        fn set_maximum(&self, _max: u64) {}
        fn set_progress(&self, _value: u64) {}
        fn increment_progress(&self, _delta: u64) {}
        fn set_message(&self, _msg: &str) {}
    }

    #[derive(Debug)]
    struct MockFsService;

    impl FileSystemService for MockFsService {
        fn service_name(&self) -> &str {
            "MockFileSystemService"
        }
    }

    // --- ByteProvider ---

    #[test]
    fn test_byte_provider_read() {
        let bp = MockByteProvider::new(vec![0x7F, b'E', b'L', b'F', 0x02]);
        assert_eq!(bp.length(), 5);
        assert_eq!(bp.read_byte(0).unwrap(), 0x7F);
        assert_eq!(bp.read_byte(3).unwrap(), b'F');
        assert!(bp.read_byte(10).is_err());
    }

    #[test]
    fn test_byte_provider_read_bytes() {
        let bp = MockByteProvider::new(vec![1, 2, 3, 4, 5]);
        let data = bp.read_bytes(1, 3).unwrap();
        assert_eq!(data, vec![2, 3, 4]);
    }

    #[test]
    fn test_byte_provider_read_start_bytes() {
        let bp = MockByteProvider::new(vec![0x50, 0x4B, 0x03, 0x04, 0x99]);
        let start = bp.read_start_bytes(4).unwrap();
        assert_eq!(start, vec![0x50, 0x4B, 0x03, 0x04]);
    }

    #[test]
    fn test_byte_provider_fsrl() {
        let bp = MockByteProvider::new(vec![0, 1, 2]);
        assert_eq!(bp.fsrl().path(), Some("/test.bin"));
    }

    // --- TaskMonitor ---

    #[test]
    fn test_task_monitor_not_cancelled() {
        let monitor = MockMonitor::new();
        assert!(!monitor.is_cancelled());
        assert!(monitor.check_cancelled().is_ok());
    }

    // --- GFileSystemFactoryIgnore ---

    #[test]
    fn test_ignore_factory() {
        let ignore = GFileSystemFactoryIgnore::new("raw");
        assert_eq!(ignore.fs_type(), "raw");
        assert_eq!(ignore.ignored_fs_type(), "raw");
        assert!(ignore.description().contains("Ignored"));
    }

    // --- Mock probe implementation ---

    #[derive(Debug)]
    struct ZipProbe;

    impl GFileSystemProbe for ZipProbe {
        fn fs_type(&self) -> &str {
            "zip"
        }
    }

    impl GFileSystemProbeBytesOnly for ZipProbe {
        fn bytes_required(&self) -> usize {
            4
        }

        fn probe_start_bytes(&self, _fsrl: &Fsrl, start_bytes: &[u8]) -> bool {
            start_bytes.len() >= 4
                && start_bytes[0] == 0x50
                && start_bytes[1] == 0x4B
                && start_bytes[2] == 0x03
                && start_bytes[3] == 0x04
        }
    }

    #[test]
    fn test_bytes_only_probe_positive() {
        let probe = ZipProbe;
        let fsrl = Fsrl::new(FsrlRoot::local(), Some("/test.zip".into()), None);
        assert!(probe.probe_start_bytes(&fsrl, &[0x50, 0x4B, 0x03, 0x04]));
    }

    #[test]
    fn test_bytes_only_probe_negative() {
        let probe = ZipProbe;
        let fsrl = Fsrl::new(FsrlRoot::local(), Some("/test.bin".into()), None);
        assert!(!probe.probe_start_bytes(&fsrl, &[0x7F, b'E', b'L', b'F']));
    }

    #[test]
    fn test_bytes_only_probe_too_short() {
        let probe = ZipProbe;
        let fsrl = Fsrl::new(FsrlRoot::local(), Some("/tiny".into()), None);
        assert!(!probe.probe_start_bytes(&fsrl, &[0x50, 0x4B]));
    }

    #[test]
    fn test_probe_fs_type() {
        let probe = ZipProbe;
        assert_eq!(probe.fs_type(), "zip");
    }

    // --- Mock ByteProvider probe ---

    #[derive(Debug)]
    struct ElfProbe;

    impl GFileSystemProbe for ElfProbe {
        fn fs_type(&self) -> &str {
            "elf"
        }
    }

    impl GFileSystemProbeByteProvider for ElfProbe {
        fn probe(
            &self,
            byte_provider: &dyn ByteProvider,
            _fs_service: &dyn FileSystemService,
            monitor: &dyn TaskMonitor,
        ) -> io::Result<bool> {
            monitor.check_cancelled()?;
            if byte_provider.length() < 4 {
                return Ok(false);
            }
            let magic = byte_provider.read_bytes(0, 4)?;
            Ok(magic == vec![0x7F, b'E', b'L', b'F'])
        }
    }

    #[test]
    fn test_byte_provider_probe_positive() {
        let probe = ElfProbe;
        let bp = MockByteProvider::new(vec![0x7F, b'E', b'L', b'F', 0x02]);
        let fs = MockFsService;
        let monitor = MockMonitor::new();
        assert!(probe.probe(&bp, &fs, &monitor).unwrap());
    }

    #[test]
    fn test_byte_provider_probe_negative() {
        let probe = ElfProbe;
        let bp = MockByteProvider::new(vec![0x50, 0x4B, 0x03, 0x04]);
        let fs = MockFsService;
        let monitor = MockMonitor::new();
        assert!(!probe.probe(&bp, &fs, &monitor).unwrap());
    }

    #[test]
    fn test_byte_provider_probe_too_short() {
        let probe = ElfProbe;
        let bp = MockByteProvider::new(vec![0x7F]);
        let fs = MockFsService;
        let monitor = MockMonitor::new();
        assert!(!probe.probe(&bp, &fs, &monitor).unwrap());
    }
}
