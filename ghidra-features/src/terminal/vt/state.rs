//! VT100 parser state machine.
//!
//! Ported from `ghidra.app.plugin.core.terminal.vt.VtState`.
//!
//! Each variant is a state in the parser's state machine. The parser
//! delegates byte-by-byte processing to the current state, which returns
//! the next state. This design closely mirrors the Java enum with
//! abstract `handleNext` methods.

use super::charset::GSet;

/// The parser state machine.
///
/// Each variant represents a state in the VT100 escape-sequence parser.
/// The state machine is driven by [`VtParser::process`](super::parser::VtParser::process).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtState {
    /// Normal character processing -- the initial state.
    /// Feeds printable characters to the handler; transitions to
    /// `Esc` on receiving byte `0x1b`.
    Char,
    /// We have just received an ESC byte.
    Esc,
    /// We have received ESC and are processing an intermediate byte
    /// that determines the kind of escape (CSI, OSC, etc.).
    EscIntermediate,
    /// Inside a CSI (Control Sequence Introducer) sequence.
    /// Collecting numeric parameters.
    CsiParams,
    /// Inside a CSI with a private-mode prefix (`?`).
    CsiPrivate,
    /// Inside an OSC (Operating System Command) sequence.
    /// Collecting the string parameter until ST or BEL.
    Osc,
    /// Inside a DCS (Device Control String) sequence.
    Dcs,
    /// Charset designation: waiting for the charset identifier byte.
    Charset(GSet),
    /// Charset designation with a two-byte identifier, first byte `"` seen.
    CharsetQuote(GSet),
    /// Charset designation with a two-byte identifier, first byte `%` seen.
    CharsetPercent(GSet),
    /// Charset designation with a two-byte identifier, first byte `&` seen.
    CharsetAmpersand(GSet),
}

impl VtState {
    /// Process a single byte in this state, returning the next state.
    ///
    /// `byte` is the input byte. `csi_buf` is the CSI parameter buffer.
    /// `osc_buf` is the OSC parameter buffer. The handler methods on the
    /// caller are invoked as appropriate.
    ///
    /// Returns (next_state, action) where action describes what the caller
    /// should do with the byte.
    pub fn next(self, byte: u8) -> VtTransition {
        match self {
            Self::Char => match byte {
                0x1b => VtTransition::ToState(Self::Esc),
                _ => VtTransition::Char(byte),
            },
            Self::Esc => match byte {
                b'[' => VtTransition::ToState(Self::CsiParams),
                b']' => VtTransition::ToState(Self::Osc),
                b'P' => VtTransition::ToState(Self::Dcs),
                b'7' => VtTransition::SaveCursor,
                b'8' => VtTransition::RestoreCursor,
                b'(' => VtTransition::ToState(Self::Charset(GSet::G0)),
                b')' => VtTransition::ToState(Self::Charset(GSet::G1)),
                b'*' => VtTransition::ToState(Self::Charset(GSet::G2)),
                b'+' => VtTransition::ToState(Self::Charset(GSet::G3)),
                b'=' => VtTransition::KeyModeApp,
                b'>' => VtTransition::KeyModeNormal,
                _ => VtTransition::EscChar(byte),
            },
            Self::CsiParams => {
                if byte == b'?' {
                    VtTransition::ToState(Self::CsiPrivate)
                } else if is_csi_param(byte) {
                    VtTransition::CsiParamByte(byte)
                } else if is_csi_intermediate(byte) {
                    VtTransition::CsiInterByte(byte)
                } else {
                    VtTransition::CsiFinal(byte)
                }
            }
            Self::CsiPrivate => {
                if is_csi_param(byte) {
                    VtTransition::CsiParamByte(byte)
                } else if is_csi_intermediate(byte) {
                    VtTransition::CsiInterByte(byte)
                } else {
                    VtTransition::CsiFinalPrivate(byte)
                }
            }
            Self::Osc => {
                if byte == 0x07 || byte == 0x1b {
                    // BEL or start of ST terminator
                    VtTransition::OscEnd
                } else {
                    VtTransition::OscByte(byte)
                }
            }
            Self::Dcs => {
                // Consume DCS until ST (ESC \)
                if byte == 0x1b {
                    VtTransition::ToState(Self::Esc)
                } else {
                    VtTransition::ToState(Self::Dcs)
                }
            }
            Self::Charset(gset) => match byte {
                b'"' => VtTransition::ToState(Self::CharsetQuote(gset)),
                b'%' => VtTransition::ToState(Self::CharsetPercent(gset)),
                b'&' => VtTransition::ToState(Self::CharsetAmpersand(gset)),
                _ => VtTransition::CharsetSingle(gset, byte),
            },
            Self::CharsetQuote(gset) => VtTransition::CharsetDouble(gset, b'"', byte),
            Self::CharsetPercent(gset) => VtTransition::CharsetDouble(gset, b'%', byte),
            Self::CharsetAmpersand(gset) => VtTransition::CharsetDouble(gset, b'&', byte),
            Self::EscIntermediate => {
                // Consume and ignore ESC intermediate sequences.
                if byte == 0x1b {
                    VtTransition::ToState(Self::Esc)
                } else {
                    VtTransition::ToState(Self::Char)
                }
            }
        }
    }
}

/// Actions the parser should take when transitioning between states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VtTransition {
    /// Transition to a new state (no handler call needed).
    ToState(VtState),
    /// A normal printable character.
    Char(u8),
    /// A character after ESC that should be forwarded as ESC + char.
    EscChar(u8),
    /// Save cursor position.
    SaveCursor,
    /// Restore cursor position.
    RestoreCursor,
    /// Enter application key mode.
    KeyModeApp,
    /// Enter normal key mode.
    KeyModeNormal,
    /// A CSI parameter byte (digits, semicolons).
    CsiParamByte(u8),
    /// A CSI intermediate byte (space through /).
    CsiInterByte(u8),
    /// The final byte of a CSI sequence (public mode).
    CsiFinal(u8),
    /// The final byte of a CSI sequence (private `?` mode).
    CsiFinalPrivate(u8),
    /// An OSC data byte.
    OscByte(u8),
    /// The OSC sequence has ended (BEL or ST received).
    OscEnd,
    /// Single-byte charset designation.
    CharsetSingle(GSet, u8),
    /// Two-byte charset designation.
    CharsetDouble(GSet, u8, u8),
}

/// Check if a byte is a valid CSI parameter (digit 0-9 or semicolon).
fn is_csi_param(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b';')
}

/// Check if a byte is a valid CSI intermediate byte (space through /).
fn is_csi_intermediate(b: u8) -> bool {
    b >= 0x20 && b <= 0x2F
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_char_state_normal() {
        let t = VtState::Char.next(b'A');
        assert_eq!(t, VtTransition::Char(b'A'));
    }

    #[test]
    fn test_char_state_esc() {
        let t = VtState::Char.next(0x1b);
        assert_eq!(t, VtTransition::ToState(VtState::Esc));
    }

    #[test]
    fn test_esc_csi() {
        let t = VtState::Esc.next(b'[');
        assert_eq!(t, VtTransition::ToState(VtState::CsiParams));
    }

    #[test]
    fn test_esc_osc() {
        let t = VtState::Esc.next(b']');
        assert_eq!(t, VtTransition::ToState(VtState::Osc));
    }

    #[test]
    fn test_esc_save_restore() {
        assert_eq!(VtState::Esc.next(b'7'), VtTransition::SaveCursor);
        assert_eq!(VtState::Esc.next(b'8'), VtTransition::RestoreCursor);
    }

    #[test]
    fn test_esc_charset() {
        let t = VtState::Esc.next(b'(');
        assert_eq!(t, VtTransition::ToState(VtState::Charset(GSet::G0)));
    }

    #[test]
    fn test_csi_params_digit() {
        let t = VtState::CsiParams.next(b'1');
        assert_eq!(t, VtTransition::CsiParamByte(b'1'));
    }

    #[test]
    fn test_csi_params_semicolon() {
        let t = VtState::CsiParams.next(b';');
        assert_eq!(t, VtTransition::CsiParamByte(b';'));
    }

    #[test]
    fn test_csi_params_final() {
        let t = VtState::CsiParams.next(b'm');
        assert_eq!(t, VtTransition::CsiFinal(b'm'));
    }

    #[test]
    fn test_csi_params_private() {
        let t = VtState::CsiParams.next(b'?');
        assert_eq!(t, VtTransition::ToState(VtState::CsiPrivate));
    }

    #[test]
    fn test_csi_private_final() {
        let t = VtState::CsiPrivate.next(b'h');
        assert_eq!(t, VtTransition::CsiFinalPrivate(b'h'));
    }

    #[test]
    fn test_osc_end_bel() {
        let t = VtState::Osc.next(0x07);
        assert_eq!(t, VtTransition::OscEnd);
    }

    #[test]
    fn test_osc_data() {
        let t = VtState::Osc.next(b't');
        assert_eq!(t, VtTransition::OscByte(b't'));
    }

    #[test]
    fn test_charset_single() {
        let t = VtState::Charset(GSet::G0).next(b'B');
        assert_eq!(t, VtTransition::CharsetSingle(GSet::G0, b'B'));
    }

    #[test]
    fn test_charset_quote() {
        let t = VtState::Charset(GSet::G0).next(b'"');
        assert_eq!(t, VtTransition::ToState(VtState::CharsetQuote(GSet::G0)));
    }

    #[test]
    fn test_charset_quote_double() {
        let t = VtState::CharsetQuote(GSet::G1).next(b'>');
        assert_eq!(t, VtTransition::CharsetDouble(GSet::G1, b'"', b'>'));
    }

    #[test]
    fn test_esc_key_modes() {
        assert_eq!(VtState::Esc.next(b'='), VtTransition::KeyModeApp);
        assert_eq!(VtState::Esc.next(b'>'), VtTransition::KeyModeNormal);
    }

    #[test]
    fn test_is_csi_param() {
        assert!(is_csi_param(b'0'));
        assert!(is_csi_param(b'9'));
        assert!(is_csi_param(b';'));
        assert!(!is_csi_param(b'm'));
    }

    #[test]
    fn test_is_csi_intermediate() {
        assert!(is_csi_intermediate(b' '));
        assert!(is_csi_intermediate(b'/'));
        assert!(!is_csi_intermediate(b'm'));
    }

    #[test]
    fn test_esc_unknown_passthrough() {
        let t = VtState::Esc.next(b'Z');
        assert_eq!(t, VtTransition::EscChar(b'Z'));
    }
}
