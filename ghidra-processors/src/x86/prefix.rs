//! x86 Prefix Decoding
//!
//! Handles all x86 prefix bytes as defined in the Ghidra SLEIGH `ia.sinc`
//! context register layout (lines 398-472).  The context register carries
//! fields such as `addrsize`, `opsize`, `segover`, `rexWRXBprefix`,
//! `vexMode`, `vexMMMMM`, `evexAAA`, etc.
//!
//! Prefix categories (from Intel SDM Vol. 2, Section 2.1.1):
//! - Legacy prefixes:  LOCK (F0), REPNE (F2), REP (F3),
//!   operand-size override (66), address-size override (67)
//! - Segment overrides: 2E (CS), 36 (SS), 3E (DS), 26 (ES), 64 (FS), 65 (GS)
//! - REX prefixes: 40-4F (64-bit mode only)
//! - VEX prefixes: C5 (2-byte VEX), C4 (3-byte VEX)
//! - EVEX prefix: 62 (EVEX)
//! - XOP prefix: 8F (XOP)

use crate::x86::instructions::SegmentRegister;

/// Segment override prefix byte -> SegmentRegister mapping.
/// Mirrors the SLEIGH `segover` context field (values 0-6).
pub const SEGMENT_OVERRIDE_BYTES: &[(u8, SegmentRegister)] = &[
    (0x26, SegmentRegister::ES),
    (0x2E, SegmentRegister::CS),
    (0x36, SegmentRegister::SS),
    (0x3E, SegmentRegister::DS),
    (0x64, SegmentRegister::FS),
    (0x65, SegmentRegister::GS),
];

/// REX prefix: byte 0x40-0x4F, only valid in 64-bit mode.
///
/// Fields (matching SLEIGH `rexWRXBprefix`):
/// - W (bit 3): 1 = 64-bit operand size
/// - R (bit 2): extends ModR/M reg field
/// - X (bit 1): extends SIB index field
/// - B (bit 0): extends ModR/M r/m, SIB base, or opcode reg field
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RexPrefix {
    pub raw: u8,
}

impl RexPrefix {
    pub fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// True if the byte is a REX prefix (0x40..=0x4F).
    pub fn is_rex(byte: u8) -> bool {
        (byte & 0xF0) == 0x40
    }

    /// REX.W: 64-bit operand size override.
    /// In SLEIGH: `rexWprefix=(15,15)` -> `opsize=2` when set.
    pub fn w(&self) -> bool {
        (self.raw & 0x08) != 0
    }

    /// REX.R: extends the ModR/M `reg` field to 4 bits.
    /// In SLEIGH: `rexRprefix=(16,16)` extends reg to `r32_x`/`r64_x`.
    pub fn r(&self) -> bool {
        (self.raw & 0x04) != 0
    }

    /// REX.X: extends the SIB `index` field to 4 bits.
    /// In SLEIGH: `rexXprefix=(17,17)` extends index to `index_x`/`index64_x`.
    pub fn x(&self) -> bool {
        (self.raw & 0x02) != 0
    }

    /// REX.B: extends ModR/M `r/m`, SIB `base`, or opcode `reg` to 4 bits.
    /// In SLEIGH: `rexBprefix=(18,18)` extends r/m to `r32_x`/`r64_x`.
    pub fn b(&self) -> bool {
        (self.raw & 0x01) != 0
    }
}

/// VEX prefix information, decoded from either 2-byte (C5) or 3-byte (C4) form.
///
/// Maps to the SLEIGH context fields:
/// - `vexMode=1` (set when VEX prefix is present)
/// - `vexMMMMM` = map select (0=invalid, 1=0F, 2=0F38, 3=0F3A)
/// - `vex_pp` = implied legacy prefix (0=none, 1=66, 2=F3, 3=F2)
/// - `vexVVVV` = inverted vvvv field for 2nd source register
/// - `vexL` = vector length (0=128-bit, 1=256-bit)
/// - `rexR`, `rexX`, `rexB` = inverted extension bits
/// - `rexW` = 64-bit operand size
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VexPrefix {
    /// Raw bytes of the VEX prefix (2 or 3 bytes).
    pub raw: [u8; 3],
    /// Number of prefix bytes consumed (2 for C5, 3 for C4).
    pub length: u8,
    /// Map select (vexMMMMM): 1=0F, 2=0F38, 3=0F3A.
    pub map: u8,
    /// Implied legacy prefix (pp): 0=none, 1=66, 2=F3, 3=F2.
    pub pp: u8,
    /// Inverted vvvv field: register index for 2nd source (0-15).
    pub vvvv: u8,
    /// Vector length: 0=128-bit (XMM), 1=256-bit (YMM).
    pub l: bool,
    /// REX.W equivalent: 1=64-bit operand size.
    pub w: bool,
    /// Inverted REX.R: extends ModR/M reg.
    pub r: bool,
    /// Inverted REX.X: extends SIB index (3-byte only).
    pub x: bool,
    /// Inverted REX.B: extends ModR/M r/m or SIB base (3-byte only).
    pub b: bool,
}

impl VexPrefix {
    /// Decode a 2-byte VEX prefix (0xC5).
    ///
    /// Format: C5 R'X'B'W vvvvLpp
    /// The R, X, B bits are inverted. W is only in 3-byte form.
    /// 2-byte VEX implies map=1 (0F) and REX.W=0.
    pub fn decode_2byte(byte1: u8, byte2: u8) -> Self {
        // byte1 = C5, byte2 = R'X'B'pp + vvvvL (actually: RvvvvLpp)
        // 2-byte: ~R is bit 7 of byte2
        let r = (byte2 & 0x80) == 0; // inverted
        let vvvv = (byte2 >> 3) & 0x0F;
        let l = (byte2 & 0x04) != 0;
        let pp = byte2 & 0x03;

        Self {
            raw: [byte1, byte2, 0],
            length: 2,
            map: 1, // 2-byte VEX always implies 0F map
            pp,
            vvvv,
            l,
            w: false, // 2-byte VEX has no W bit
            r,
            x: true, // 2-byte: no X, treated as 1 (not extended)
            b: true, // 2-byte: no B, treated as 1 (not extended)
        }
    }

    /// Decode a 3-byte VEX prefix (0xC4).
    ///
    /// Format: C4 R'X'B'mmmmm WvvvvLpp
    pub fn decode_3byte(byte1: u8, byte2: u8, byte3: u8) -> Self {
        let r = (byte2 & 0x80) == 0;
        let x = (byte2 & 0x40) == 0;
        let b = (byte2 & 0x20) == 0;
        let map = byte2 & 0x1F;
        let w = (byte3 & 0x80) != 0;
        let vvvv = (byte3 >> 3) & 0x0F;
        let l = (byte3 & 0x04) != 0;
        let pp = byte3 & 0x03;

        Self {
            raw: [byte1, byte2, byte3],
            length: 3,
            map,
            pp,
            vvvv,
            l,
            w,
            r,
            x,
            b,
        }
    }

    /// The operand size implied by the VEX prefix.
    /// Maps to SLEIGH `opsize` context field.
    pub fn operand_size(&self) -> u8 {
        if self.w {
            64
        } else {
            32
        }
    }

    /// The vector length in bytes (16 or 32).
    pub fn vector_length_bytes(&self) -> u16 {
        if self.l {
            32
        } else {
            16
        }
    }

    /// Implied legacy prefix from `pp` field.
    /// Maps to SLEIGH `mandover` context: prefix_66, prefix_f3, prefix_f2.
    pub fn implied_legacy_prefix(&self) -> Option<u8> {
        match self.pp {
            0 => None,
            1 => Some(0x66),
            2 => Some(0xF3),
            3 => Some(0xF2),
            _ => None,
        }
    }
}

/// EVEX prefix information, decoded from 4-byte form (0x62).
///
/// Maps to SLEIGH context fields:
/// - `vexMode=2`
/// - `evexRp`, `evexB`, `evexZ`, `evexAAA`
/// - `evexL` (vector length: 0=128, 1=256, 2=512)
/// - `evexV5` (extended vvvv + V')
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvexPrefix {
    pub raw: [u8; 4],
    /// Map select (mmmm, 3 bits).
    pub map: u8,
    /// Implied legacy prefix (pp).
    pub pp: u8,
    /// REX.W equivalent.
    pub w: bool,
    /// Inverted REX.R extension.
    pub r: bool,
    /// Inverted REX.B extension.
    pub b: bool,
    /// Inverted REX.R' extension (EVEX.Rp).
    pub rp: bool,
    /// Inverted REX.X extension.
    pub x: bool,
    /// Inverted vvvv (4 bits).
    pub vvvv: u8,
    /// Inverted V' bit (EVEX.Vp, extends vvvv to 5 bits).
    pub vp: bool,
    /// Vector length: 0=128, 1=256, 2=512.
    pub l: u8,
    /// Broadcast (EVEX.b): 1 = {1toN} broadcast.
    pub bcast: bool,
    /// Zeroing-masking (EVEX.z): 1 = zeroing, 0 = merging.
    pub z: bool,
    /// Opmask register selector (EVEX.aaa, 3 bits). 0 = no mask.
    pub aaa: u8,
}

impl EvexPrefix {
    /// Decode a 4-byte EVEX prefix starting with 0x62.
    ///
    /// Byte layout (Intel SDM Vol. 2, Table 2-32):
    ///   Byte 0: 0x62
    ///   Byte 1: ~R ~X ~B ~R' 0 mmm
    ///   Byte 2: W ~vvvv 0 ~pp
    ///   Byte 3: ~V' L'L b ~aaa z
    ///
    /// Note: some bits are inverted relative to their logical meaning.
    pub fn decode(byte0: u8, byte1: u8, byte2: u8, byte3: u8) -> Self {
        let r = (byte1 & 0x80) == 0;
        let x = (byte1 & 0x40) == 0;
        let b = (byte1 & 0x20) == 0;
        let rp = (byte1 & 0x10) == 0;
        let map = byte1 & 0x07;

        let w = (byte2 & 0x80) != 0;
        let vvvv = (byte2 >> 3) & 0x0F;
        let pp = byte2 & 0x03;

        let vp = (byte3 & 0x80) == 0;
        let l = (byte3 >> 5) & 0x03;
        let bcast = (byte3 & 0x10) != 0;
        let aaa = byte3 & 0x07;
        let z = (byte3 & 0x08) != 0;

        Self {
            raw: [byte0, byte1, byte2, byte3],
            map,
            pp,
            w,
            r,
            b,
            rp,
            x,
            vvvv,
            vp,
            l,
            bcast,
            z,
            aaa,
        }
    }

    /// Combined 5-bit vvvv register index (V' : vvvv).
    pub fn vvvv5(&self) -> u8 {
        let v5 = if self.vp { 0x10 } else { 0x00 };
        v5 | self.vvvv
    }

    /// Vector length in bytes: 16 (128-bit), 32 (256-bit), or 64 (512-bit).
    pub fn vector_length_bytes(&self) -> u16 {
        match self.l {
            0 => 16,
            1 => 32,
            2 => 64,
            _ => 64, // reserved, treat as 512
        }
    }

    /// Operand size in bits.
    pub fn operand_size(&self) -> u8 {
        if self.w {
            64
        } else {
            32
        }
    }

    /// Implied legacy prefix.
    pub fn implied_legacy_prefix(&self) -> Option<u8> {
        match self.pp {
            0 => None,
            1 => Some(0x66),
            2 => Some(0xF3),
            3 => Some(0xF2),
            _ => None,
        }
    }
}

/// Complete decoded prefix state.
///
/// This corresponds to the accumulated context register values after all
/// prefix bytes have been processed in Ghidra's SLEIGH decoder.
#[derive(Debug, Clone)]
pub struct PrefixState {
    /// Segment override (maps to `segover` context field, values 0-6).
    pub segment_override: Option<SegmentRegister>,
    /// Operand size override prefix (0x66).
    /// Maps to `prefix_66` in SLEIGH context.
    pub operand_size_override: bool,
    /// Address size override prefix (0x67).
    /// Maps to `addrsize` context field.
    pub address_size_override: bool,
    /// LOCK prefix (0xF0).
    /// Maps to `lockprefx` in SLEIGH context.
    pub lock: bool,
    /// REP prefix (0xF3).
    /// Maps to `repprefx` in SLEIGH context.
    pub rep: bool,
    /// REPNE prefix (0xF2).
    /// Maps to `repneprefx` in SLEIGH context.
    pub repne: bool,
    /// REX prefix (64-bit mode only).
    /// Maps to `rexprefix`, `rexWRXBprefix` in SLEIGH context.
    pub rex: Option<RexPrefix>,
    /// VEX prefix, if present.
    /// Maps to `vexMode=1` in SLEIGH context.
    pub vex: Option<VexPrefix>,
    /// EVEX prefix, if present.
    /// Maps to `vexMode=2` in SLEIGH context.
    pub evex: Option<EvexPrefix>,
    /// Total number of prefix bytes consumed.
    pub prefix_length: u8,
}

impl PrefixState {
    pub fn new() -> Self {
        Self {
            segment_override: None,
            operand_size_override: false,
            address_size_override: false,
            lock: false,
            rep: false,
            repne: false,
            rex: None,
            vex: None,
            evex: None,
            prefix_length: 0,
        }
    }

    /// True if a REX prefix is present.
    /// In SLEIGH: `rexprefix=(19,19)` set to 1.
    pub fn has_rex(&self) -> bool {
        self.rex.is_some()
    }

    /// True if REX.W is set (64-bit operand size).
    /// In SLEIGH: `rexWprefix=(15,15)` -> opsize=2.
    pub fn rex_w(&self) -> bool {
        self.rex.map_or(false, |r| r.w())
    }

    /// True if REX.R is set (extends reg field).
    pub fn rex_r(&self) -> bool {
        self.rex.map_or(false, |r| r.r())
    }

    /// True if REX.X is set (extends SIB index).
    pub fn rex_x(&self) -> bool {
        self.rex.map_or(false, |r| r.x())
    }

    /// True if REX.B is set (extends r/m or base).
    pub fn rex_b(&self) -> bool {
        self.rex.map_or(false, |r| r.b())
    }

    /// True if in VEX mode.
    pub fn is_vex(&self) -> bool {
        self.vex.is_some()
    }

    /// True if in EVEX mode.
    pub fn is_evex(&self) -> bool {
        self.evex.is_some()
    }

    /// Compute the effective operand size (in bits).
    ///
    /// Mirrors SLEIGH `opsize` context field logic:
    /// - 64-bit mode + REX.W -> 64
    /// - 64-bit mode + no REX.W + 0x66 -> 16
    /// - 64-bit mode + no REX.W + no 0x66 -> 32
    /// - 32-bit mode + 0x66 -> 16
    /// - 32-bit mode + no 0x66 -> 32
    pub fn effective_operand_size(&self, is_64bit: bool) -> u8 {
        if let Some(vex) = self.vex {
            return vex.operand_size();
        }
        if let Some(evex) = self.evex {
            return evex.operand_size();
        }
        if is_64bit {
            if self.rex_w() {
                64
            } else if self.operand_size_override {
                16
            } else {
                32
            }
        } else if self.operand_size_override {
            16
        } else {
            32
        }
    }

    /// Compute the effective address size (in bits).
    ///
    /// Mirrors SLEIGH `addrsize` context field:
    /// - 64-bit mode + 0x67 -> 32
    /// - 64-bit mode + no 0x67 -> 64
    /// - 32-bit mode + 0x67 -> 16
    /// - 32-bit mode + no 0x67 -> 32
    pub fn effective_address_size(&self, is_64bit: bool) -> u8 {
        if is_64bit {
            if self.address_size_override {
                32
            } else {
                64
            }
        } else if self.address_size_override {
            16
        } else {
            32
        }
    }

    /// Whether VEX/EVEX mode is active.
    pub fn vex_mode(&self) -> u8 {
        if self.evex.is_some() {
            2
        } else if self.vex.is_some() {
            1
        } else {
            0
        }
    }
}

/// Decode all legacy and REX prefix bytes from a byte stream.
///
/// Returns the decoded `PrefixState` and the number of bytes consumed.
/// This handles the prefix loop from the SLEIGH spec where prefixes can
/// appear in any order and repeat.
pub fn decode_prefixes(data: &[u8], is_64bit: bool) -> (PrefixState, usize) {
    let mut state = PrefixState::new();
    let mut pos = 0;

    // Phase 1: Legacy prefixes (can repeat, any order)
    loop {
        if pos >= data.len() {
            break;
        }
        let b = data[pos];
        match b {
            // LOCK
            0xF0 => {
                state.lock = true;
                pos += 1;
            }
            // REPNE / XACQUIRE
            0xF2 => {
                state.repne = true;
                pos += 1;
            }
            // REP / REPE / XRELEASE
            0xF3 => {
                state.rep = true;
                pos += 1;
            }
            // Segment overrides
            0x26 => {
                state.segment_override = Some(SegmentRegister::ES);
                pos += 1;
            }
            0x2E => {
                state.segment_override = Some(SegmentRegister::CS);
                pos += 1;
            }
            0x36 => {
                state.segment_override = Some(SegmentRegister::SS);
                pos += 1;
            }
            0x3E => {
                state.segment_override = Some(SegmentRegister::DS);
                pos += 1;
            }
            0x64 => {
                state.segment_override = Some(SegmentRegister::FS);
                pos += 1;
            }
            0x65 => {
                state.segment_override = Some(SegmentRegister::GS);
                pos += 1;
            }
            // Operand size override
            0x66 => {
                state.operand_size_override = true;
                pos += 1;
            }
            // Address size override
            0x67 => {
                state.address_size_override = true;
                pos += 1;
            }
            _ => break,
        }
    }

    // Phase 2: REX prefix (64-bit mode only, must immediately precede opcode)
    if is_64bit && pos < data.len() {
        let b = data[pos];
        if RexPrefix::is_rex(b) {
            state.rex = Some(RexPrefix::new(b));
            pos += 1;
        }
    }

    state.prefix_length = pos as u8;
    (state, pos)
}

/// Decode VEX/EVEX prefix from the byte stream at the given position.
///
/// Returns `Some((VexOrEvex, bytes_consumed))` or `None`.
/// This is called after legacy prefixes have been consumed, when the
/// next byte is 0xC4, 0xC5, or 0x62.
pub fn decode_vex_evex(data: &[u8]) -> Option<(VexOrEvex, usize)> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        // 3-byte VEX (C4)
        0xC4 if data.len() >= 3 => {
            let vex = VexPrefix::decode_3byte(data[0], data[1], data[2]);
            Some((VexOrEvex::Vex(vex), 3))
        }
        // 2-byte VEX (C5)
        0xC5 if data.len() >= 2 => {
            let vex = VexPrefix::decode_2byte(data[0], data[1]);
            Some((VexOrEvex::Vex(vex), 2))
        }
        // EVEX (62)
        0x62 if data.len() >= 4 => {
            let evex = EvexPrefix::decode(data[0], data[1], data[2], data[3]);
            Some((VexOrEvex::Evex(evex), 4))
        }
        _ => None,
    }
}

/// Either a VEX or EVEX prefix.
#[derive(Debug, Clone, Copy)]
pub enum VexOrEvex {
    Vex(VexPrefix),
    Evex(EvexPrefix),
}

impl VexOrEvex {
    pub fn map(&self) -> u8 {
        match self {
            VexOrEvex::Vex(v) => v.map,
            VexOrEvex::Evex(e) => e.map,
        }
    }

    pub fn pp(&self) -> u8 {
        match self {
            VexOrEvex::Vex(v) => v.pp,
            VexOrEvex::Evex(e) => e.pp,
        }
    }

    pub fn vvvv(&self) -> u8 {
        match self {
            VexOrEvex::Vex(v) => v.vvvv,
            VexOrEvex::Evex(e) => e.vvvv5(),
        }
    }

    pub fn l(&self) -> u8 {
        match self {
            VexOrEvex::Vex(v) => u8::from(v.l),
            VexOrEvex::Evex(e) => e.l,
        }
    }

    pub fn w(&self) -> bool {
        match self {
            VexOrEvex::Vex(v) => v.w,
            VexOrEvex::Evex(e) => e.w,
        }
    }

    pub fn is_evex(&self) -> bool {
        matches!(self, VexOrEvex::Evex(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rex_prefix() {
        assert!(RexPrefix::is_rex(0x48));
        assert!(RexPrefix::is_rex(0x40));
        assert!(RexPrefix::is_rex(0x4F));
        assert!(!RexPrefix::is_rex(0x3F));
        assert!(!RexPrefix::is_rex(0x50));

        let rex = RexPrefix::new(0x48); // REX.W
        assert!(rex.w());
        assert!(!rex.r());
        assert!(!rex.x());
        assert!(!rex.b());

        let rex = RexPrefix::new(0x4C); // REX.WR
        assert!(rex.w());
        assert!(rex.r());
        assert!(!rex.b());

        let rex = RexPrefix::new(0x49); // REX.WB
        assert!(rex.w());
        assert!(!rex.r());
        assert!(rex.b());
    }

    #[test]
    fn test_vex_2byte() {
        // Example: VEX 2-byte prefix C5 F1 -> R=0 (extended), vvvv=0 (XMM0), L=0, pp=1 (66h)
        let vex = VexPrefix::decode_2byte(0xC5, 0xF1);
        assert_eq!(vex.length, 2);
        assert_eq!(vex.map, 1);
        assert_eq!(vex.pp, 1); // 66h
        assert_eq!(vex.vvvv, 0); // XMM0 (inverted: 1111 -> 0000)
        assert!(!vex.l); // 128-bit
        assert!(!vex.w); // 2-byte VEX has no W
        assert!(!vex.r); // R'=0 (inverted from bit 7=1)
    }

    #[test]
    fn test_vex_3byte() {
        // C4 E1 78 -> 3-byte VEX: map=1 (0F), W=0, vvvv=0, L=0, pp=0
        let vex = VexPrefix::decode_3byte(0xC4, 0xE1, 0x78);
        assert_eq!(vex.length, 3);
        assert_eq!(vex.map, 1);
        assert!(!vex.w);
        assert_eq!(vex.vvvv, 0);
        assert!(!vex.l);
        assert_eq!(vex.pp, 0);
        assert!(vex.r); // ~R = bit 7 of E1 = 0, so R=true
    }

    #[test]
    fn test_evex() {
        // 62 F1 7C 48 -> EVEX: map=1, W=0, vvvv=0, L=2(512), pp=0, z=0, aaa=0
        let evex = EvexPrefix::decode(0x62, 0xF1, 0x7C, 0x48);
        assert_eq!(evex.map, 1);
        assert!(!evex.w);
        assert_eq!(evex.vvvv, 0);
        assert_eq!(evex.l, 2); // 512-bit
        assert_eq!(evex.vector_length_bytes(), 64);
        assert!(!evex.z);
        assert_eq!(evex.aaa, 0);
    }

    #[test]
    fn test_decode_prefixes_64bit() {
        // REX.W (0x48) followed by opcode
        let data = [0x48, 0x89, 0xE5];
        let (state, consumed) = decode_prefixes(&data, true);
        assert_eq!(consumed, 1);
        assert!(state.has_rex());
        assert!(state.rex_w());
        assert_eq!(state.effective_operand_size(true), 64);
    }

    #[test]
    fn test_decode_legacy_prefixes() {
        // LOCK + REP + segment override
        let data = [0xF0, 0xF3, 0x26, 0x89, 0xC3];
        let (state, consumed) = decode_prefixes(&data, false);
        assert_eq!(consumed, 3);
        assert!(state.lock);
        assert!(state.rep);
        assert_eq!(state.segment_override, Some(SegmentRegister::ES));
    }

    #[test]
    fn test_address_size_override() {
        // 67 prefix in 64-bit mode -> 32-bit addressing
        let data = [0x67, 0x89, 0xC3];
        let (state, consumed) = decode_prefixes(&data, true);
        assert_eq!(consumed, 1);
        assert!(state.address_size_override);
        assert_eq!(state.effective_address_size(true), 32);
    }

    #[test]
    fn test_operand_size_in_32bit() {
        // 0x66 prefix in 32-bit mode -> 16-bit operands
        let data = [0x66, 0x89, 0xC3];
        let (state, consumed) = decode_prefixes(&data, false);
        assert_eq!(consumed, 1);
        assert!(state.operand_size_override);
        assert_eq!(state.effective_operand_size(false), 16);
    }
}
