//! Ghidra Pty -- Cross-platform pseudo-terminal support.
//!
//! Ports Ghidra's `Framework/Pty` Java package into Rust. Provides:
//!
//! - **`Pty`**: A pseudo-terminal with parent and child ends.
//! - **`PtyFactory`**: Trait for opening pseudo-terminals.
//! - **`PtySession`**: Handle to a session leader (typically a child process).
//! - **`PtyParent` / `PtyChild`**: Endpoints with I/O streams.
//! - Platform-specific implementations for Linux, macOS, and Windows.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │             PtyFactory (trait)                │
//! │  openpty(cols, rows) -> Pty                  │
//! └──────────────────────────────────────────────┘
//!     │             │              │
//!     ▼             ▼              ▼
//! ┌─────────┐  ┌──────────┐  ┌──────────┐
//! │  Linux   │  │  macOS   │  │ Windows  │
//! │  Pty     │  │  Pty     │  │ ConPTY   │
//! └─────────┘  └──────────┘  └──────────┘
//! ```

pub mod pty;
pub mod pty_child;
pub mod pty_endpoint;
pub mod pty_factory;
pub mod pty_parent;
pub mod pty_session;
pub mod shell_utils;
pub mod stream_pumper;

#[cfg(unix)]
pub mod unix;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(windows)]
pub mod windows;

// Re-export key types
pub use pty::Pty;
pub use pty_child::PtyChild;
pub use pty_endpoint::PtyEndpoint;
pub use pty_factory::PtyFactory;
pub use pty_parent::PtyParent;
pub use pty_session::PtySession;
pub use shell_utils::ShellUtils;
pub use stream_pumper::StreamPumper;
