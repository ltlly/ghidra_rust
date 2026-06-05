//! VT100 terminal emulator internals.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.terminal.vt` package.
//!
//! This module implements a full VT100/VT220-compatible terminal emulator,
//! including:
//!
//! - **ANSI color model** with standard, bright, 256-index, and RGB colors
//! - **VT attributes** (SGR) for styling terminal output
//! - **VtLine** -- a single line of cells in the terminal display
//! - **VtBuffer** -- the full screen buffer with scrollback, viewport, cursor management
//! - **VtCharset** -- character set designation (G0..G3, DEC special graphics, etc.)
//! - **VtState** -- the parser state machine (CHAR, ESC, CSI, OSC, CHARSET, etc.)
//! - **VtParser** -- byte-by-byte parser that delegates to a [`VtHandler`]
//! - **VtHandler** -- trait for handling parsed VT sequences

pub mod attributes;
pub mod buffer;
pub mod charset;
pub mod color_resolver;
pub mod handler;
pub mod line;
pub mod output;
pub mod parser;
pub mod state;

pub use attributes::{AnsiColor, AnsiFont, Blink, Intensity, ReverseVideo, Underline, VtAttributes};
pub use buffer::VtBuffer;
pub use charset::{GSet, VtCharset};
pub use color_resolver::{
    resolve_color, ReverseVideo as ColorReverseVideo, WhichGround,
};
pub use handler::VtHandler;
pub use line::VtLine;
pub use output::{
    CollectingOutput, DefaultResponseEncoder, EncoderWithOutput, VtOutput, VtResponseEncoder,
    PASTE_END, PASTE_START,
};
pub use parser::VtParser;
pub use state::VtState;
