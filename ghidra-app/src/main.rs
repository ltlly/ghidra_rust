//! Ghidra Rust - Software Reverse Engineering Framework
//!
//! Entry point for the `ghidra-server` binary.  Provides three modes:
//!
//! | Mode      | Command      | Description                                     |
//! |-----------|-------------|-------------------------------------------------|
//! | Analyze   | `analyze`    | Headless binary analysis and export             |
//! | GUI       | `gui` (default) | Interactive egui-based graphical interface   |
//! | Serve     | `serve`      | Headless HTTP REST API server                   |
//!
//! # Quick start
//!
//! ```text
//! ghidra-server analyze /path/to/binary -o output.c
//! ghidra-server gui --file /path/to/binary
//! ghidra-server serve --port 8080
//! ghidra-server --file /path/to/binary            # defaults to GUI
//! ```

use clap::{Parser, Subcommand};
use log::{error, info};
use std::net::SocketAddr;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "ghidra-rs")]
#[command(
    about = "Ghidra Rust - Software Reverse Engineering Framework",
    long_about = "Ghidra Rust is a software reverse engineering platform inspired \
                  by the NSA's Ghidra SRE framework.  It supports loading ELF, PE, \
                  Mach-O, and raw binaries for disassembly, decompilation, and \
                  automated analysis."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Binary file to analyze
    #[arg(short, long, help = "Path to the binary file to load")]
    file: Option<PathBuf>,

    /// Project directory
    #[arg(
        short,
        long,
        default_value = "./ghidra_projects",
        help = "Directory for Ghidra project files"
    )]
    project_dir: PathBuf,

    /// Architecture override (e.g. "x86:LE:64", "ARM:LE:32:v8")
    #[arg(
        long,
        help = "Override auto-detected architecture (required for raw binaries)"
    )]
    arch: Option<String>,

    /// Base address for raw binaries (hex or decimal)
    #[arg(
        long,
        default_value = "0x0",
        help = "Image base address for raw binary loading"
    )]
    base_address: String,

    /// Run without GUI (headless mode)
    #[arg(long, help = "Force headless mode for all operations")]
    headless: bool,

    /// Analysis timeout in seconds
    #[arg(
        long,
        default_value = "300",
        help = "Maximum time (seconds) to spend on analysis"
    )]
    timeout: u64,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a binary file in headless mode and optionally export results
    Analyze {
        /// Path to the binary file to analyze
        file: PathBuf,

        /// Output file for decompiled code (optional)
        #[arg(short, long, help = "Export decompiled C code to this file")]
        output: Option<PathBuf>,

        /// Output format: c, json, html, csv, sqlite
        #[arg(long, default_value = "c", help = "Export format for output")]
        format: String,
    },

    /// Run with the egui-based graphical interface (default)
    Gui {
        /// Optional file to open on startup
        #[arg(short, long, help = "Binary file to load at startup")]
        file: Option<PathBuf>,
    },

    /// Start a headless HTTP REST API server for automated analysis
    Serve {
        /// Port to listen on
        #[arg(
            short,
            long,
            default_value = "8080",
            help = "TCP port for the HTTP server"
        )]
        port: u16,

        /// Host address to bind to
        #[arg(
            long,
            default_value = "127.0.0.1",
            help = "Host address to bind the server to"
        )]
        host: String,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    // Initialise logging before anything else.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    if let Err(e) = run() {
        error!("Fatal error: {:#}", e);
        // Also print the full error chain for diagnosis.
        for cause in e.chain().skip(1) {
            error!("  caused by: {}", cause);
        }
        std::process::exit(1);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Extract shared options before the match consumes parts of `cli`.
    let base = parse_hex_or_decimal(&cli.base_address)
        .map_err(|e| anyhow::anyhow!("Invalid base address '{}': {}", cli.base_address, e))?;
    let arch = cli.arch.clone();
    let timeout = cli.timeout;
    let file_arg = cli.file.clone();

    // If no subcommand is given, default to GUI with the file flag forwarded.
    let command = cli
        .command
        .unwrap_or(Commands::Gui { file: file_arg.clone() });

    match command {
        // ---- Analyze mode ----
        Commands::Analyze {
            file,
            output,
            format,
        } => {
            info!("Loading: {:?}", file);
            let program = ghidra_app::load_program(&file, base, arch.as_deref())?;
            info!(
                "Loaded '{}' at base 0x{:x} ({} memory blocks, {} symbols)",
                program.name,
                program.image_base.offset,
                program.memory_blocks.len(),
                program.symbol_table.len()
            );

            info!("Analyzing (timeout: {}s)...", timeout);
            ghidra_app::analyze_program(&program, timeout)?;

            match output {
                Some(out) => {
                    export_in_format(&program, &out, &format)?;
                    info!("Export written to {}", out.display());
                }
                None => {
                    info!("Analysis complete (no output file specified).");
                }
            }
            info!("Done.");
        }

        // ---- GUI mode ----
        Commands::Gui { file: gui_file } => {
            let file_to_open = gui_file.or(file_arg);

            let options = eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size([1400.0, 900.0])
                    .with_title("Ghidra Rust"),
                ..Default::default()
            };

            info!("Launching GUI...");
            eframe::run_native(
                "Ghidra Rust",
                options,
                Box::new(move |_cc| {
                    let mut app = ghidra_gui::GhidraApp::new();

                    // Pre-load a file if one was given on the command line.
                    if let Some(ref f) = file_to_open {
                        match ghidra_app::load_program(f, base, arch.as_deref()) {
                            Ok(program) => {
                                app.load_program(program);
                            }
                            Err(e) => {
                                log::error!(
                                    "Failed to auto-load '{}': {}",
                                    f.display(),
                                    e
                                );
                            }
                        }
                    }

                    Ok(Box::new(app))
                }),
            )
            .map_err(|e| anyhow::anyhow!("GUI error: {}", e))?;
        }

        // ---- Headless server mode ----
        Commands::Serve { port, host } => {
            info!("Starting headless server on {}:{}", host, port);
            let addr: SocketAddr = format!("{}:{}", host, port)
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid server address '{}:{}': {}", host, port, e))?;

            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async { ghidra_app::serve_on_addr(addr).await })?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a string that may be hex (`0x...`) or decimal into a `u64`.
fn parse_hex_or_decimal(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16)
            .map_err(|e| anyhow::anyhow!("Invalid hex value '{}': {}", s, e))
    } else {
        s.parse::<u64>()
            .map_err(|e| anyhow::anyhow!("Invalid numeric value '{}': {}", s, e))
    }
}

/// Export the program in the requested format.
fn export_in_format(program: &ghidra_core::program::Program, output: &PathBuf, format: &str) -> anyhow::Result<()> {
    match format {
        "c" => ghidra_app::export_c(program, output)?,
        "json" => ghidra_app::export_json(program, output)?,
        "html" => ghidra_app::export_html(program, output)?,
        "csv" => ghidra_app::export_csv(program, output)?,
        "sqlite" => ghidra_app::export_sqlite(program, output)?,
        "header" => ghidra_app::export_header(program, output)?,
        "project" => ghidra_app::export_ghidra_project(program, output)?,
        "idapython" => ghidra_app::export_ida_python(program, output)?,
        other => {
            anyhow::bail!(
                "Unknown export format '{}'. Supported formats: c, json, html, csv, sqlite, header, project, idapython",
                other
            );
        }
    }
    Ok(())
}
