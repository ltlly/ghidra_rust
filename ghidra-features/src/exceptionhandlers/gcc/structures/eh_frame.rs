//! EH Frame Structures
//!
//! Ported from `ghidra.app.plugin.exceptionhandlers.gcc.structures.ehFrame`.
//!
//! Contains data structures for the DWARF `.eh_frame` and `.debug_frame` sections.

use crate::exceptionhandlers::gcc::decode::read_uleb128;

/// DWARF Call Frame instruction opcodes (from DWARF specification / dwarf2.h).
///
/// These drive the call frame state machine used for stack unwinding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DwCfa {
    /// No operation
    Nop = 0x00,
    /// Set location to a specific address
    SetLoc = 0x01,
    /// Advance location by 1 byte operand
    AdvanceLoc1 = 0x02,
    /// Advance location by 2 byte operand
    AdvanceLoc2 = 0x03,
    /// Advance location by 4 byte operand
    AdvanceLoc4 = 0x04,
    /// Extended register offset
    OffsetExtended = 0x05,
    /// Restore extended register
    RestoreExtended = 0x06,
    /// Register undefined
    Undefined = 0x07,
    /// Register same value
    SameValue = 0x08,
    /// Register in another register
    Register = 0x09,
    /// Remember state
    RememberState = 0x0a,
    /// Restore state
    RestoreState = 0x0b,
    /// Define CFA
    DefCfa = 0x0c,
    /// Define CFA register
    DefCfaRegister = 0x0d,
    /// Define CFA offset
    DefCfaOffset = 0x0e,
    /// DWARF 3+: Define CFA expression
    DefCfaExpression = 0x0f,
    /// DWARF 3+: Expression
    Expression = 0x10,
    /// DWARF 3+: Signed offset extended
    OffsetExtendedSf = 0x11,
    /// DWARF 3+: Signed define CFA
    DefCfaSf = 0x12,
    /// DWARF 3+: Signed define CFA offset
    DefCfaOffsetSf = 0x13,
}

/// A call frame instruction parsed from CIE/FDE initial instructions.
#[derive(Debug, Clone, PartialEq)]
pub enum CfaInstruction {
    /// No operation
    Nop,
    /// Advance the location counter
    AdvanceLoc(u32),
    /// Set the rule for a register to "offset(N)"
    Offset { register: u32, offset: i64 },
    /// Restore a register rule to its initial state
    Restore(u32),
    /// Set the location to an absolute address
    SetLoc(u64),
    /// Mark register as undefined
    Undefined(u32),
    /// Mark register as same-value
    SameValue(u32),
    /// Register stored in another register
    Register { register: u32, target_register: u32 },
    /// Remember current state
    RememberState,
    /// Restore saved state
    RestoreState,
    /// Define the CFA rule
    DefCfa { register: u32, offset: u64 },
    /// Change the CFA register
    DefCfaRegister(u32),
    /// Change the CFA offset
    DefCfaOffset(u64),
    /// DWARF 3+: Define CFA by expression
    DefCfaExpression(Vec<u8>),
    /// DWARF 3+: Expression-based rule
    Expression { register: u32, expression: Vec<u8> },
    /// Unknown/unimplemented opcode
    Unknown(u8, Vec<u8>),
}

/// Parse CFA instructions from a byte buffer.
pub fn parse_cfa_instructions(data: &[u8]) -> Vec<CfaInstruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let byte = data[offset];
        offset += 1;

        let high_bits = byte & 0xC0;
        match high_bits {
            0x40 => {
                // DW_CFA_advance_loc
                let delta = byte & 0x3F;
                instructions.push(CfaInstruction::AdvanceLoc(delta as u32));
            }
            0x80 => {
                // DW_CFA_offset
                let register = (byte & 0x3F) as u32;
                if let Some((value, consumed)) = read_uleb128(&data[offset..]) {
                    instructions.push(CfaInstruction::Offset {
                        register,
                        offset: value as i64,
                    });
                    offset += consumed;
                }
            }
            0xC0 => {
                // DW_CFA_restore
                let register = (byte & 0x3F) as u32;
                instructions.push(CfaInstruction::Restore(register));
            }
            _ => match byte {
                0x00 => instructions.push(CfaInstruction::Nop),
                0x01 => {
                    // DW_CFA_set_loc
                    if offset + 8 <= data.len() {
                        let addr = u64::from_le_bytes(
                            data[offset..offset + 8].try_into().unwrap(),
                        );
                        instructions.push(CfaInstruction::SetLoc(addr));
                        offset += 8;
                    }
                }
                0x02 => {
                    // DW_CFA_advance_loc1
                    if offset < data.len() {
                        let delta = data[offset] as u32;
                        instructions.push(CfaInstruction::AdvanceLoc(delta));
                        offset += 1;
                    }
                }
                0x03 => {
                    // DW_CFA_advance_loc2
                    if offset + 2 <= data.len() {
                        let delta = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
                        instructions.push(CfaInstruction::AdvanceLoc(delta));
                        offset += 2;
                    }
                }
                0x04 => {
                    // DW_CFA_advance_loc4
                    if offset + 4 <= data.len() {
                        let delta = u32::from_le_bytes([
                            data[offset],
                            data[offset + 1],
                            data[offset + 2],
                            data[offset + 3],
                        ]);
                        instructions.push(CfaInstruction::AdvanceLoc(delta));
                        offset += 4;
                    }
                }
                0x05 => {
                    // DW_CFA_offset_extended
                    if let Some((register, c1)) = read_uleb128(&data[offset..]) {
                        offset += c1;
                        if let Some((value, c2)) = read_uleb128(&data[offset..]) {
                            instructions.push(CfaInstruction::Offset {
                                register: register as u32,
                                offset: value as i64,
                            });
                            offset += c2;
                        }
                    }
                }
                0x07 => {
                    // DW_CFA_undefined
                    if let Some((register, consumed)) = read_uleb128(&data[offset..]) {
                        instructions.push(CfaInstruction::Undefined(register as u32));
                        offset += consumed;
                    }
                }
                0x08 => {
                    // DW_CFA_same_value
                    if let Some((register, consumed)) = read_uleb128(&data[offset..]) {
                        instructions.push(CfaInstruction::SameValue(register as u32));
                        offset += consumed;
                    }
                }
                0x09 => {
                    // DW_CFA_register
                    if let Some((register, c1)) = read_uleb128(&data[offset..]) {
                        offset += c1;
                        if let Some((target, c2)) = read_uleb128(&data[offset..]) {
                            instructions.push(CfaInstruction::Register {
                                register: register as u32,
                                target_register: target as u32,
                            });
                            offset += c2;
                        }
                    }
                }
                0x0a => instructions.push(CfaInstruction::RememberState),
                0x0b => instructions.push(CfaInstruction::RestoreState),
                0x0c => {
                    // DW_CFA_def_cfa
                    if let Some((register, c1)) = read_uleb128(&data[offset..]) {
                        offset += c1;
                        if let Some((offset_val, c2)) = read_uleb128(&data[offset..]) {
                            instructions.push(CfaInstruction::DefCfa {
                                register: register as u32,
                                offset: offset_val,
                            });
                            offset += c2;
                        }
                    }
                }
                0x0d => {
                    // DW_CFA_def_cfa_register
                    if let Some((register, consumed)) = read_uleb128(&data[offset..]) {
                        instructions.push(CfaInstruction::DefCfaRegister(register as u32));
                        offset += consumed;
                    }
                }
                0x0e => {
                    // DW_CFA_def_cfa_offset
                    if let Some((offset_val, consumed)) = read_uleb128(&data[offset..]) {
                        instructions.push(CfaInstruction::DefCfaOffset(offset_val));
                        offset += consumed;
                    }
                }
                0x0f => {
                    // DW_CFA_def_cfa_expression
                    if let Some((expr_len, c1)) = read_uleb128(&data[offset..]) {
                        offset += c1;
                        let end = (offset + expr_len as usize).min(data.len());
                        let expr = data[offset..end].to_vec();
                        instructions.push(CfaInstruction::DefCfaExpression(expr));
                        offset = end;
                    }
                }
                0x10 => {
                    // DW_CFA_expression
                    if let Some((register, c1)) = read_uleb128(&data[offset..]) {
                        offset += c1;
                        if let Some((expr_len, c2)) = read_uleb128(&data[offset..]) {
                            offset += c2;
                            let end = (offset + expr_len as usize).min(data.len());
                            let expr = data[offset..end].to_vec();
                            instructions.push(CfaInstruction::Expression {
                                register: register as u32,
                                expression: expr,
                            });
                            offset = end;
                        }
                    }
                }
                _ => {
                    // Unknown opcode; skip remaining bytes as we can't know the operand size
                    instructions.push(CfaInstruction::Unknown(byte, data[offset..].to_vec()));
                    break;
                }
            },
        }
    }

    instructions
}

/// Exception for invalid frame data (analogous to Java's ExceptionHandlerFrameException).
#[derive(Debug, Clone)]
pub struct ExceptionHandlerFrameException(pub String);

impl std::fmt::Display for ExceptionHandlerFrameException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Exception handler frame error: {}", self.0)
    }
}

impl std::error::Error for ExceptionHandlerFrameException {}

/// The FDE table structure used in `.eh_frame_hdr`.
///
/// Each entry pairs an initial location with an FDE data pointer,
/// enabling binary search for exception handling information.
#[derive(Debug, Clone)]
pub struct FdeTable {
    /// The entries in the FDE table.
    pub entries: Vec<FdeTableEntry>,
}

/// A single entry in the FDE table (initial_loc + data_loc pair).
#[derive(Debug, Clone, Copy)]
pub struct FdeTableEntry {
    /// The initial code address covered by the FDE.
    pub initial_loc: u64,
    /// The address of the FDE data in `.eh_frame`.
    pub data_loc: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nop() {
        let instrs = parse_cfa_instructions(&[0x00]);
        assert_eq!(instrs, vec![CfaInstruction::Nop]);
    }

    #[test]
    fn test_parse_advance_loc() {
        // DW_CFA_advance_loc with delta=2 (0x40 | 0x02 = 0x42)
        let instrs = parse_cfa_instructions(&[0x42]);
        assert_eq!(instrs, vec![CfaInstruction::AdvanceLoc(2)]);
    }

    #[test]
    fn test_parse_offset() {
        // DW_CFA_offset, register=4 (0x80 | 0x04 = 0x84), offset=8 (ULEB128)
        let instrs = parse_cfa_instructions(&[0x84, 0x08]);
        assert_eq!(
            instrs,
            vec![CfaInstruction::Offset {
                register: 4,
                offset: 8
            }]
        );
    }

    #[test]
    fn test_parse_restore() {
        // DW_CFA_restore, register=3 (0xC0 | 0x03 = 0xC3)
        let instrs = parse_cfa_instructions(&[0xC3]);
        assert_eq!(instrs, vec![CfaInstruction::Restore(3)]);
    }

    #[test]
    fn test_parse_def_cfa() {
        // DW_CFA_def_cfa, register=7 (ULEB128), offset=16 (ULEB128)
        let instrs = parse_cfa_instructions(&[0x0c, 0x07, 0x10]);
        assert_eq!(
            instrs,
            vec![CfaInstruction::DefCfa {
                register: 7,
                offset: 16
            }]
        );
    }

    #[test]
    fn test_parse_advance_loc1() {
        // DW_CFA_advance_loc1, delta=42
        let instrs = parse_cfa_instructions(&[0x02, 42]);
        assert_eq!(instrs, vec![CfaInstruction::AdvanceLoc(42)]);
    }

    #[test]
    fn test_parse_remember_restore_state() {
        let instrs = parse_cfa_instructions(&[0x0a, 0x0b]);
        assert_eq!(
            instrs,
            vec![CfaInstruction::RememberState, CfaInstruction::RestoreState]
        );
    }

    #[test]
    fn test_parse_def_cfa_register() {
        // DW_CFA_def_cfa_register, register=13 (ULEB128)
        let instrs = parse_cfa_instructions(&[0x0d, 0x0d]);
        assert_eq!(instrs, vec![CfaInstruction::DefCfaRegister(13)]);
    }

    #[test]
    fn test_parse_def_cfa_offset() {
        // DW_CFA_def_cfa_offset, offset=128 (ULEB128: 0x80, 0x01)
        let instrs = parse_cfa_instructions(&[0x0e, 0x80, 0x01]);
        assert_eq!(instrs, vec![CfaInstruction::DefCfaOffset(128)]);
    }

    #[test]
    fn test_parse_multiple_instructions() {
        // A typical initial instruction sequence:
        // DW_CFA_def_cfa r7, 8
        // DW_CFA_offset r16, 1
        let instrs = parse_cfa_instructions(&[0x0c, 0x07, 0x08, 0x90, 0x01]);
        assert_eq!(instrs.len(), 2);
        assert_eq!(
            instrs[0],
            CfaInstruction::DefCfa {
                register: 7,
                offset: 8
            }
        );
        assert_eq!(
            instrs[1],
            CfaInstruction::Offset {
                register: 16,
                offset: 1
            }
        );
    }

    #[test]
    fn test_empty_instructions() {
        let instrs = parse_cfa_instructions(&[]);
        assert!(instrs.is_empty());
    }

    #[test]
    fn test_fde_table() {
        let table = FdeTable {
            entries: vec![
                FdeTableEntry {
                    initial_loc: 0x1000,
                    data_loc: 0x2000,
                },
                FdeTableEntry {
                    initial_loc: 0x2000,
                    data_loc: 0x3000,
                },
            ],
        };
        assert_eq!(table.entries.len(), 2);
        assert_eq!(table.entries[0].initial_loc, 0x1000);
        assert_eq!(table.entries[1].data_loc, 0x3000);
    }

    #[test]
    fn test_exception_handler_frame_exception() {
        let err = ExceptionHandlerFrameException("test error".into());
        assert_eq!(err.to_string(), "Exception handler frame error: test error");
    }
}
