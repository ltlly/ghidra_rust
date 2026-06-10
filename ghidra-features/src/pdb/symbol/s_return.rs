//! S_RETURN -- Return value descriptor symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.ReturnDescriptionMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

// ---------------------------------------------------------------------------
// ReturnStyle -- mirrors Java ReturnDescriptionMsSymbol.Style
// ---------------------------------------------------------------------------

/// The return style of a function, describing how the return value is
/// delivered.
///
/// This mirrors Ghidra's `ReturnDescriptionMsSymbol.Style` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnStyle {
    /// Unknown return style.
    Unknown,
    /// Function returns void (no value).
    Void,
    /// Return data is placed in registers.
    ReturnDataInRegisters,
    /// Indirect caller-allocated near return.
    IndirectCallerAllocatedNear,
    /// Indirect caller-allocated far return.
    IndirectCallerAllocatedFar,
    /// Indirect returnee-allocated near return.
    IndirectReturneeAllocatedNear,
    /// Indirect returnee-allocated far return.
    IndirectReturneeAllocatedFar,
    /// Unused / reserved.
    Unused,
}

impl ReturnStyle {
    /// Convert a raw byte value to a `ReturnStyle`.
    pub fn from_u8(val: u8) -> Self {
        match val {
            0x00 => Self::Void,
            0x01 => Self::ReturnDataInRegisters,
            0x02 => Self::IndirectCallerAllocatedNear,
            0x03 => Self::IndirectCallerAllocatedFar,
            0x04 => Self::IndirectReturneeAllocatedNear,
            0x05 => Self::IndirectReturneeAllocatedFar,
            0x06 => Self::Unused,
            _ => Self::Unknown,
        }
    }

    /// Return a human-readable label for this style.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unknown => "unknown return",
            Self::Void => "void return",
            Self::ReturnDataInRegisters => "return data in registers",
            Self::IndirectCallerAllocatedNear => "indirected caller-allocated near",
            Self::IndirectCallerAllocatedFar => "indirect caller-allocated far",
            Self::IndirectReturneeAllocatedNear => "indirect returnee allocated near",
            Self::IndirectReturneeAllocatedFar => "indirect returnee allocated far",
            Self::Unused => "unused",
        }
    }
}

impl fmt::Display for ReturnStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ---------------------------------------------------------------------------
// SReturn
// ---------------------------------------------------------------------------

/// A return value descriptor symbol (`S_RETURN`).
///
/// This symbol describes how a function returns its value. It records whether
/// varargs are pushed right-to-left, whether the returnee cleans up the stack,
/// the return style, and any remaining method data bytes.
///
/// # PDB Binary Layout
///
/// ```text
/// flags  : u16
///   bit 0: varargs pushed right-to-left
///   bit 1: returnee cleans up stack
/// style  : u8 (ReturnStyle)
/// remaining : variable (remaining bytes of method data)
/// ```
///
/// This corresponds to `S_RETURN` (0x000D) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SReturn {
    /// Whether varargs are pushed right-to-left.
    pub varargs_pushed_right_to_left: bool,

    /// Whether the returnee (callee) is responsible for cleaning up the stack.
    pub returnee_cleans_up_stack: bool,

    /// The return style.
    pub style: ReturnStyle,

    /// Byte length of remaining method data after the style byte.
    pub bytes_remaining: u32,
}

impl SReturn {
    /// Create a new S_RETURN symbol.
    pub fn new(
        varargs_pushed_right_to_left: bool,
        returnee_cleans_up_stack: bool,
        style: ReturnStyle,
        bytes_remaining: u32,
    ) -> Self {
        Self {
            varargs_pushed_right_to_left,
            returnee_cleans_up_stack,
            style,
            bytes_remaining,
        }
    }

    /// Parse an S_RETURN symbol from a byte slice.
    ///
    /// Expects the layout: `flags(u16) + style(u8) + remaining_data(...)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }
        let flags = u16::from_le_bytes([data[0], data[1]]);
        let varargs_pushed_right_to_left = (flags & 0x0001) != 0;
        let returnee_cleans_up_stack = ((flags >> 1) & 0x0001) != 0;
        let style = ReturnStyle::from_u8(data[2]);
        let bytes_remaining = if data.len() > 3 {
            (data.len() - 3) as u32
        } else {
            0
        };
        Some(Self {
            varargs_pushed_right_to_left,
            returnee_cleans_up_stack,
            style,
            bytes_remaining,
        })
    }
}

impl AbstractMsSymbol for SReturn {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_RETURN
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_RETURN"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RETURN, {}", self.style)?;
        if self.varargs_pushed_right_to_left {
            write!(f, ", varargs right-to-left")?;
        } else {
            write!(f, ", varargs left-to-right")?;
        }
        if self.returnee_cleans_up_stack {
            write!(f, ", returnee cleans stack")?;
        } else {
            write!(f, ", caller cleans stack")?;
        }
        write!(
            f,
            "; byte length of remaining method data = {}",
            self.bytes_remaining
        )
    }
}

impl fmt::Display for SReturn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_return_bytes(flags: u16, style: u8) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&flags.to_le_bytes());
        data.push(style);
        data
    }

    // --- ReturnStyle tests ---

    #[test]
    fn test_return_style_from_u8() {
        assert_eq!(ReturnStyle::from_u8(0x00), ReturnStyle::Void);
        assert_eq!(ReturnStyle::from_u8(0x01), ReturnStyle::ReturnDataInRegisters);
        assert_eq!(ReturnStyle::from_u8(0x02), ReturnStyle::IndirectCallerAllocatedNear);
        assert_eq!(ReturnStyle::from_u8(0x03), ReturnStyle::IndirectCallerAllocatedFar);
        assert_eq!(ReturnStyle::from_u8(0x04), ReturnStyle::IndirectReturneeAllocatedNear);
        assert_eq!(ReturnStyle::from_u8(0x05), ReturnStyle::IndirectReturneeAllocatedFar);
        assert_eq!(ReturnStyle::from_u8(0x06), ReturnStyle::Unused);
        assert_eq!(ReturnStyle::from_u8(0xFF), ReturnStyle::Unknown);
    }

    #[test]
    fn test_return_style_display() {
        assert_eq!(format!("{}", ReturnStyle::Void), "void return");
        assert_eq!(
            format!("{}", ReturnStyle::ReturnDataInRegisters),
            "return data in registers"
        );
    }

    // --- SReturn tests ---

    #[test]
    fn test_parse_basic() {
        // flags=0x01 (varargs RTL), style=0x01 (register)
        let data = make_return_bytes(0x01, 0x01);
        let sym = SReturn::parse(&data).unwrap();
        assert!(sym.varargs_pushed_right_to_left);
        assert!(!sym.returnee_cleans_up_stack);
        assert_eq!(sym.style, ReturnStyle::ReturnDataInRegisters);
        assert_eq!(sym.bytes_remaining, 0);
    }

    #[test]
    fn test_parse_flags_only() {
        // flags=0x00, style=0x00 (void) -- minimum 3 bytes
        let data = make_return_bytes(0x00, 0x00);
        let sym = SReturn::parse(&data).unwrap();
        assert!(!sym.varargs_pushed_right_to_left);
        assert!(!sym.returnee_cleans_up_stack);
        assert_eq!(sym.style, ReturnStyle::Void);
    }

    #[test]
    fn test_parse_with_remaining_data() {
        let mut data = make_return_bytes(0x03, 0x01);
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // remaining data
        let sym = SReturn::parse(&data).unwrap();
        assert!(sym.varargs_pushed_right_to_left);
        assert!(sym.returnee_cleans_up_stack);
        assert_eq!(sym.style, ReturnStyle::ReturnDataInRegisters);
        assert_eq!(sym.bytes_remaining, 3);
    }

    #[test]
    fn test_parse_returnee_cleans_stack() {
        // flags=0x02 (returnee cleans up), style=0x05 (indirect returnee far)
        let data = make_return_bytes(0x02, 0x05);
        let sym = SReturn::parse(&data).unwrap();
        assert!(!sym.varargs_pushed_right_to_left);
        assert!(sym.returnee_cleans_up_stack);
        assert_eq!(sym.style, ReturnStyle::IndirectReturneeAllocatedFar);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short (need 3)
        assert!(SReturn::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SReturn::new(true, false, ReturnStyle::ReturnDataInRegisters, 0);
        assert_eq!(sym.pdb_id(), 0x000D);
        assert_eq!(sym.symbol_type_name(), "S_RETURN");
        assert!(sym.varargs_pushed_right_to_left);
        assert!(!sym.returnee_cleans_up_stack);
        assert_eq!(sym.style, ReturnStyle::ReturnDataInRegisters);
    }

    #[test]
    fn test_display() {
        let sym = SReturn::new(true, false, ReturnStyle::ReturnDataInRegisters, 4);
        let s = format!("{}", sym);
        assert!(s.contains("RETURN"));
        assert!(s.contains("return data in registers"));
        assert!(s.contains("varargs right-to-left"));
        assert!(s.contains("caller cleans stack"));
        assert!(s.contains("4"));
    }

    #[test]
    fn test_display_void_return() {
        let sym = SReturn::new(false, true, ReturnStyle::Void, 0);
        let s = format!("{}", sym);
        assert!(s.contains("RETURN"));
        assert!(s.contains("void return"));
        assert!(s.contains("varargs left-to-right"));
        assert!(s.contains("returnee cleans stack"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SReturn::new(true, false, ReturnStyle::ReturnDataInRegisters, 4);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
