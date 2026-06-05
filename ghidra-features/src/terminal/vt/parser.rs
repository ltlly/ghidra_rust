//! VT100 escape sequence parser.
//!
//! Ported from `ghidra.app.plugin.core.terminal.vt.VtParser`.
//!
//! The parser processes bytes one at a time, delegating to the state machine
//! in [`VtState`](super::state::VtState) and calling methods on a
//! [`VtHandler`](super::handler::VtHandler) for each recognized event.

use super::charset::{GSet, VtCharset};
use super::handler::VtHandler;
use super::state::{VtState, VtTransition};

/// The VT100 escape sequence parser.
///
/// Processes input bytes one at a time, maintaining a state machine
/// that separates escape sequences from normal characters.
#[derive(Debug)]
pub struct VtParser {
    state: VtState,
    /// Current charset group for designation sequences.
    cs_g: GSet,
    /// CSI parameter buffer (numeric values separated by semicolons).
    csi_param_buf: Vec<u8>,
    /// CSI intermediate byte buffer.
    csi_inter_buf: Vec<u8>,
    /// OSC parameter string buffer.
    osc_param_buf: Vec<u8>,
    /// Whether we are in a private CSI mode (`?` prefix).
    csi_private: bool,
}

impl VtParser {
    /// Create a new parser.
    pub fn new() -> Self {
        Self {
            state: VtState::Char,
            cs_g: GSet::G0,
            csi_param_buf: Vec::with_capacity(64),
            csi_inter_buf: Vec::with_capacity(8),
            osc_param_buf: Vec::with_capacity(256),
            csi_private: false,
        }
    }

    /// Process a buffer of bytes, calling handler methods as appropriate.
    pub fn process<H: VtHandler>(&mut self, handler: &mut H, buf: &[u8]) {
        for &byte in buf {
            self.process_byte(handler, byte);
        }
    }

    /// Process a single byte.
    pub fn process_byte<H: VtHandler>(&mut self, handler: &mut H, byte: u8) {
        let transition = self.state.next(byte);
        match transition {
            VtTransition::ToState(new_state) => {
                self.state = new_state;
            }
            VtTransition::Char(b) => {
                handler.handle_char(b);
                self.state = VtState::Char;
            }
            VtTransition::EscChar(b) => {
                handler.handle_char(0x1b);
                handler.handle_char(b);
                self.state = VtState::Char;
            }
            VtTransition::SaveCursor => {
                handler.handle_save_cursor_pos();
                self.state = VtState::Char;
            }
            VtTransition::RestoreCursor => {
                handler.handle_restore_cursor_pos();
                self.state = VtState::Char;
            }
            VtTransition::KeyModeApp => {
                handler.handle_key_mode(super::handler::KeyMode::Normal, true);
                self.state = VtState::Char;
            }
            VtTransition::KeyModeNormal => {
                handler.handle_key_mode(super::handler::KeyMode::Normal, false);
                self.state = VtState::Char;
            }
            VtTransition::CsiParamByte(b) => {
                self.csi_param_buf.push(b);
                self.state = VtState::CsiParams;
            }
            VtTransition::CsiInterByte(b) => {
                self.csi_inter_buf.push(b);
                // Stay in current CSI state.
            }
            VtTransition::CsiFinal(final_byte) => {
                let params = parse_csi_params(&self.csi_param_buf);
                handler.handle_csi(&params, &self.csi_inter_buf, final_byte);
                self.csi_param_buf.clear();
                self.csi_inter_buf.clear();
                self.csi_private = false;
                self.state = VtState::Char;
            }
            VtTransition::CsiFinalPrivate(final_byte) => {
                let params = parse_csi_params(&self.csi_param_buf);
                handler.handle_csi(&params, &self.csi_inter_buf, final_byte);
                self.csi_param_buf.clear();
                self.csi_inter_buf.clear();
                self.csi_private = false;
                self.state = VtState::Char;
            }
            VtTransition::OscByte(b) => {
                self.osc_param_buf.push(b);
                self.state = VtState::Osc;
            }
            VtTransition::OscEnd => {
                handler.handle_osc(&self.osc_param_buf);
                self.osc_param_buf.clear();
                self.state = VtState::Char;
            }
            VtTransition::CharsetSingle(_gset, byte) => {
                let charset = byte_to_charset(byte);
                handler.handle_set_charset(self.cs_g, charset);
                self.state = VtState::Char;
            }
            VtTransition::CharsetDouble(_gset, _first, byte) => {
                let charset = double_byte_to_charset(byte);
                handler.handle_set_charset(self.cs_g, charset);
                self.state = VtState::Char;
            }
        }
    }

    /// Get the current parser state.
    pub fn state(&self) -> VtState {
        self.state
    }
}

impl Default for VtParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a CSI parameter byte buffer (e.g., "1;31") into a list of u16 values.
/// Missing or empty values become 0.
fn parse_csi_params(buf: &[u8]) -> Vec<u16> {
    if buf.is_empty() {
        return vec![0];
    }
    let s = std::str::from_utf8(buf).unwrap_or("");
    let mut params = Vec::new();
    for part in s.split(';') {
        if part.is_empty() {
            params.push(0);
        } else {
            params.push(part.parse::<u16>().unwrap_or(0));
        }
    }
    if params.is_empty() {
        params.push(0);
    }
    params
}

/// Map a single charset designation byte to a VtCharset.
fn byte_to_charset(b: u8) -> VtCharset {
    match b {
        b'A' => VtCharset::UK,
        b'B' => VtCharset::ASCII,
        b'0' => VtCharset::DEC_SPECIAL_GRAPHICS,
        b'1' => VtCharset::DEC_SUPPLEMENTAL,
        b'2' => VtCharset::DEC_SUPPLEMENTAL,
        b'<' => VtCharset::DEC_SUPPLEMENTAL,
        b'>' => VtCharset::DEC_TECHNICAL,
        b'4' => VtCharset::DUTCH,
        b'5' => VtCharset::FINNISH,
        b'C' | b'K' => VtCharset::FINNISH,
        b'R' => VtCharset::FRENCH,
        b'Q' => VtCharset::FRENCH_CANADIAN,
        b'Y' => VtCharset::ITALIAN,
        b'E' | b'6' => VtCharset::NORWEGIAN_DANISH,
        b'Z' => VtCharset::SPANISH,
        b'H' | b'7' => VtCharset::SWEDISH,
        b'=' => VtCharset::SWISS,
        _ => VtCharset::ASCII,
    }
}

/// Map a double-byte charset designation to a VtCharset.
fn double_byte_to_charset(b: u8) -> VtCharset {
    match b {
        b'>' => VtCharset::GREEK,
        b'4' => VtCharset::DEC_HEBREW,
        b'?' => VtCharset::DEC_SUPPLEMENTAL,
        b'2' => VtCharset::TURKISH,
        b'6' => VtCharset::PORTUGESE,
        _ => VtCharset::ASCII,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::handler::NullVtHandler;

    #[test]
    fn test_parse_normal_chars() {
        let mut parser = VtParser::new();
        let mut handler = NullVtHandler;
        parser.process(&mut handler, b"Hello");
        assert_eq!(parser.state(), VtState::Char);
    }

    #[test]
    fn test_parse_csi_sgr() {
        let mut parser = VtParser::new();
        let mut handler = NullVtHandler;
        // ESC[1;31m = bold red
        parser.process(&mut handler, b"\x1b[1;31m");
        assert_eq!(parser.state(), VtState::Char);
    }

    #[test]
    fn test_parse_csi_cursor() {
        let mut parser = VtParser::new();
        let mut handler = NullVtHandler;
        // ESC[5;10H = cursor to row 5, col 10
        parser.process(&mut handler, b"\x1b[5;10H");
        assert_eq!(parser.state(), VtState::Char);
    }

    #[test]
    fn test_parse_osc_title() {
        let mut parser = VtParser::new();
        let mut handler = NullVtHandler;
        // ESC]0;title BEL
        parser.process(&mut handler, b"\x1b]0;title\x07");
        assert_eq!(parser.state(), VtState::Char);
    }

    #[test]
    fn test_parse_save_restore() {
        let mut parser = VtParser::new();
        let mut handler = NullVtHandler;
        parser.process(&mut handler, b"\x1b7");
        assert_eq!(parser.state(), VtState::Char);
        parser.process(&mut handler, b"\x1b8");
        assert_eq!(parser.state(), VtState::Char);
    }

    #[test]
    fn test_parse_charset_designation() {
        let mut parser = VtParser::new();
        let mut handler = NullVtHandler;
        // ESC(0 = designate G0 as DEC Special Graphics
        parser.process(&mut handler, b"\x1b(0");
        assert_eq!(parser.state(), VtState::Char);
    }

    #[test]
    fn test_parse_csi_params_empty() {
        assert_eq!(parse_csi_params(b""), vec![0]);
        assert_eq!(parse_csi_params(b"1"), vec![1]);
        assert_eq!(parse_csi_params(b"1;31"), vec![1, 31]);
        assert_eq!(parse_csi_params(b";;"), vec![0, 0, 0]);
    }

    #[test]
    fn test_byte_to_charset() {
        assert_eq!(byte_to_charset(b'B'), VtCharset::ASCII);
        assert_eq!(byte_to_charset(b'A'), VtCharset::UK);
        assert_eq!(byte_to_charset(b'0'), VtCharset::DEC_SPECIAL_GRAPHICS);
    }

    #[test]
    fn test_mixed_input() {
        let mut parser = VtParser::new();
        let mut handler = NullVtHandler;
        // Normal text, then SGR, then more text
        parser.process(&mut handler, b"Hello \x1b[1mBold\x1b[0m Normal");
        assert_eq!(parser.state(), VtState::Char);
    }

    #[test]
    fn test_csi_private_mode() {
        let mut parser = VtParser::new();
        let mut handler = NullVtHandler;
        // ESC[?25l = hide cursor
        parser.process(&mut handler, b"\x1b[?25l");
        assert_eq!(parser.state(), VtState::Char);
    }

    #[test]
    fn test_incomplete_sequence_then_esc() {
        let mut parser = VtParser::new();
        let mut handler = NullVtHandler;
        // Start CSI, then raw ESC. The ESC (0x1b) is treated as a CSI final
        // byte (it falls through the param/intermediate checks), which
        // completes the CSI and returns to Char state.
        parser.process(&mut handler, b"\x1b[\x1b");
        assert_eq!(parser.state(), VtState::Char);
    }
}
