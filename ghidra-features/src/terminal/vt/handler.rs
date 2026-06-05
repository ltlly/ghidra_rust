//! The handler trait for VT100 terminal events.
//!
//! Ported from `ghidra.app.plugin.core.terminal.vt.VtHandler`.
//!
//! The parser separates escape sequences from normal characters.
//! All state not related to parsing is handled by implementors of [`VtHandler`].

use super::charset::{GSet, VtCharset};

/// Which ground (foreground/background) is being modified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhichGround {
    /// Foreground color.
    Foreground,
    /// Background color.
    Background,
}

/// Key mode for keyboard input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMode {
    /// Normal mode.
    Normal,
    /// Application cursor mode.
    Application,
}

/// Trait for handling VT100/VT220 terminal sequences.
///
/// The parser calls these methods as it encounters escape sequences
/// and normal characters. Implementors typically drive a [`VtBuffer`](super::buffer::VtBuffer).
pub trait VtHandler {
    /// Handle a normal printable character.
    fn handle_char(&mut self, b: u8);

    /// Handle a CSI (Control Sequence Introducer) sequence.
    ///
    /// `params` are the numeric parameters, `inter` are intermediate bytes,
    /// and `final_byte` is the final character (e.g., `m` for SGR, `H` for CUP).
    fn handle_csi(&mut self, params: &[u16], inter: &[u8], final_byte: u8);

    /// Handle an OSC (Operating System Command) sequence.
    fn handle_osc(&mut self, data: &[u8]);

    /// Handle save cursor position (ESC 7).
    fn handle_save_cursor_pos(&mut self);

    /// Handle restore cursor position (ESC 8).
    fn handle_restore_cursor_pos(&mut self);

    /// Handle a character set designation.
    fn handle_set_charset(&mut self, gset: GSet, charset: VtCharset);

    /// Handle keyboard mode change.
    fn handle_key_mode(&mut self, mode: KeyMode, application: bool);

    /// Handle a device status report request.
    fn handle_device_status_report(&mut self);
}

/// Default no-op handler that discards all events.
#[derive(Debug, Clone)]
pub struct NullVtHandler;

impl VtHandler for NullVtHandler {
    fn handle_char(&mut self, _b: u8) {}
    fn handle_csi(&mut self, _params: &[u16], _inter: &[u8], _final_byte: u8) {}
    fn handle_osc(&mut self, _data: &[u8]) {}
    fn handle_save_cursor_pos(&mut self) {}
    fn handle_restore_cursor_pos(&mut self) {}
    fn handle_set_charset(&mut self, _gset: GSet, _charset: VtCharset) {}
    fn handle_key_mode(&mut self, _mode: KeyMode, _application: bool) {}
    fn handle_device_status_report(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_handler() {
        let mut handler = NullVtHandler;
        handler.handle_char(b'A');
        handler.handle_csi(&[1], &[], b'm');
        handler.handle_osc(b"title");
        handler.handle_save_cursor_pos();
        handler.handle_restore_cursor_pos();
        handler.handle_set_charset(GSet::G0, VtCharset::ASCII);
        handler.handle_key_mode(KeyMode::Normal, false);
        handler.handle_device_status_report();
    }

    #[test]
    fn test_which_ground_variants() {
        assert_ne!(WhichGround::Foreground, WhichGround::Background);
    }
}
