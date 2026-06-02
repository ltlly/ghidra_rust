//! Ghidra Rust - Application library.
//!
//! This crate provides the shared application logic for the Ghidra Rust
//! reverse-engineering platform, including:
//!
//! - **loader** -- Load binaries (ELF, PE, Mach-O, raw) into a [`Program`].
//! - **exporter** -- Export analysis results to C, JSON, HTML, CSV, SQLite,
//!   IDA Python scripts, Ghidra projects, and binary patches.
//! - **server** -- Headless HTTP REST API built on axum + tokio for
//!   automated analysis sessions.
//!
//! # Example usage from `main.rs`
//!
//! ```ignore
//! let program = ghidra_app::load_program(Path::new("target.exe"), 0x400000, None)?;
//! ghidra_app::analyze_program(&program, 60)?;
//! ghidra_app::export_decompiled(&program, Path::new("output.c"))?;
//! ```

pub mod loader;
pub mod exporter;
pub mod server;

use ghidra_core::program::Program;
use std::net::SocketAddr;
use std::path::Path;

// ---------------------------------------------------------------------------
// Re-exports: loader
// ---------------------------------------------------------------------------

pub use loader::{analyze_program, export_decompiled, load_program, FileFormat};

// ---------------------------------------------------------------------------
// Convenience wrappers: exporter
// ---------------------------------------------------------------------------

/// Export decompiled C code for a program to a file.
///
/// Convenience wrapper around [`exporter::ExportManager::export_c`].
pub fn export_c(program: &Program, output: &Path) -> std::io::Result<()> {
    exporter::ExportManager::new().export_c(program, output)
}

/// Export a program's full analysis data as a structured JSON file.
///
/// Convenience wrapper around [`exporter::ExportManager::export_json`].
pub fn export_json(program: &Program, output: &Path) -> std::io::Result<()> {
    exporter::ExportManager::new().export_json(program, output)
}

/// Export a C header file with type definitions and function prototypes.
///
/// Convenience wrapper around [`exporter::ExportManager::export_header`].
pub fn export_header(program: &Program, output: &Path) -> std::io::Result<()> {
    exporter::ExportManager::new().export_header(program, output)
}

/// Export an interactive HTML analysis report.
///
/// Convenience wrapper around [`exporter::ExportManager::export_html`].
pub fn export_html(program: &Program, output: &Path) -> std::io::Result<()> {
    exporter::ExportManager::new().export_html(program, output)
}

/// Export disassembly listing as CSV.
///
/// Convenience wrapper around [`exporter::ExportManager::export_csv`].
pub fn export_csv(program: &Program, output: &Path) -> std::io::Result<()> {
    exporter::ExportManager::new().export_csv(program, output)
}

/// Export all analysis data into a SQLite database.
///
/// Convenience wrapper around [`exporter::ExportManager::export_sqlite`].
pub fn export_sqlite(program: &Program, output: &Path) -> std::io::Result<()> {
    exporter::ExportManager::new().export_sqlite(program, output)
}

/// Export as a Ghidra-compatible project directory.
///
/// Convenience wrapper around [`exporter::ExportManager::export_ghidra_project`].
pub fn export_ghidra_project(program: &Program, output: &Path) -> std::io::Result<()> {
    exporter::ExportManager::new().export_ghidra_project(program, output)
}

/// Export an IDA Python annotation script.
///
/// Convenience wrapper around [`exporter::ExportManager::export_ida_python`].
pub fn export_ida_python(program: &Program, output: &Path) -> std::io::Result<()> {
    exporter::ExportManager::new().export_ida_python(program, output)
}

/// Apply binary patches and write the result.
///
/// Convenience wrapper around [`exporter::ExportManager::export_binary_patch`].
pub fn export_binary_patch(
    program: &Program,
    patches: &[exporter::BinaryPatch],
    output: &Path,
) -> std::io::Result<()> {
    exporter::ExportManager::new().export_binary_patch(program, patches, output)
}

/// Build a [`exporter::JsonExport`] payload from a program.
///
/// Convenience wrapper around [`exporter::ExportManager::build_json_export`].
pub fn build_json_export(program: &Program) -> exporter::JsonExport {
    exporter::ExportManager::new().build_json_export(program)
}

// ---------------------------------------------------------------------------
// Convenience wrappers: server
// ---------------------------------------------------------------------------

/// Start the headless HTTP REST API server on the given port.
///
/// Binds to `127.0.0.1:{port}` and serves the full API surface:
/// session management, binary loading, analysis, disassembly, decompilation,
/// symbol listing, cross-references, and search.
///
/// # Example
///
/// ```ignore
/// tokio::runtime::Runtime::new()?.block_on(async {
///     ghidra_app::serve(8080).await
/// })?;
/// ```
pub async fn serve(port: u16) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("127.0.0.1:{}", port)
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid port {}: {}", port, e))?;
    server::run_server(addr).await
}

/// Start the headless server on a specific `SocketAddr`.
///
/// Delegates directly to [`server::run_server`].
pub async fn serve_on_addr(addr: SocketAddr) -> anyhow::Result<()> {
    server::run_server(addr).await
}
