//! CV register name mapping for x86, x64, ARM, ARM64, MIPS, IA-64, PowerPC, and other
//! architectures.  Ported from Ghidra's RegisterName.java.

/// Get the register name for a given CV register ID.
pub fn register_name(id: u32) -> &'static str {
    // x86 registers (0x0000..=0x0079)
    match id {
        0x0000 => "None",
        // x86 integer
        0x0001 => "AL", 0x0002 => "CL", 0x0003 => "DL", 0x0004 => "BL",
        0x0005 => "AH", 0x0006 => "CH", 0x0007 => "DH", 0x0008 => "BH",
        0x0009 => "AX", 0x000A => "CX", 0x000B => "DX", 0x000C => "BX",
        0x000D => "SP", 0x000E => "BP", 0x000F => "SI", 0x0010 => "DI",
        0x0011 => "EAX", 0x0012 => "ECX", 0x0013 => "EDX", 0x0014 => "EBX",
        0x0015 => "ESP", 0x0016 => "EBP", 0x0017 => "ESI", 0x0018 => "EDI",
        // x86 segment
        0x0019 => "ES", 0x001A => "CS", 0x001B => "SS", 0x001C => "DS",
        0x001D => "FS", 0x001E => "GS",
        // x86 flags
        0x001F => "EIP", 0x0020 => "EFLAGS",
        // x87 ST registers
        0x0021 => "ST0", 0x0022 => "ST1", 0x0023 => "ST2", 0x0024 => "ST3",
        0x0025 => "ST4", 0x0026 => "ST5", 0x0027 => "ST6", 0x0028 => "ST7",
        // x87 control/status
        0x0029 => "CTRL", 0x002A => "STAT", 0x002B => "TAG",
        0x002C => "FPIP", 0x002D => "FPCS", 0x002E => "FPDO", 0x002F => "FPDS",
        0x0030 => "ISEM", 0x0031 => "FPEIP", 0x0032 => "FPEDO",
        // MMX
        0x0033 => "MM0", 0x0034 => "MM1", 0x0035 => "MM2", 0x0036 => "MM3",
        0x0037 => "MM4", 0x0038 => "MM5", 0x0039 => "MM6", 0x003A => "MM7",
        // XMM (SSE)
        0x003B => "XMM0", 0x003C => "XMM1", 0x003D => "XMM2", 0x003E => "XMM3",
        0x003F => "XMM4", 0x0040 => "XMM5", 0x0041 => "XMM6", 0x0042 => "XMM7",
        0x0043 => "XMM00", 0x0044 => "XMM01", 0x0045 => "XMM02", 0x0046 => "XMM03",
        0x0047 => "XMM10", 0x0048 => "XMM11", 0x0049 => "XMM12", 0x004A => "XMM13",
        0x004B => "XMM20", 0x004C => "XMM21", 0x004D => "XMM22", 0x004E => "XMM23",
        0x004F => "XMM30", 0x0050 => "XMM31", 0x0051 => "XMM32", 0x0052 => "XMM33",
        0x0053 => "XMM40", 0x0054 => "XMM41", 0x0055 => "XMM42", 0x0056 => "XMM43",
        0x0057 => "XMM50", 0x0058 => "XMM51", 0x0059 => "XMM52", 0x005A => "XMM53",
        0x005B => "XMM60", 0x005C => "XMM61", 0x005D => "XMM62", 0x005E => "XMM63",
        0x005F => "XMM70", 0x0060 => "XMM71", 0x0061 => "XMM72", 0x0062 => "XMM73",
        0x0063 => "YMM0", 0x0064 => "YMM1", 0x0065 => "YMM2", 0x0066 => "YMM3",
        0x0067 => "YMM4", 0x0068 => "YMM5", 0x0069 => "YMM6", 0x006A => "YMM7",
        0x006B => "YMM00", 0x006C => "YMM01", 0x006D => "YMM02", 0x006E => "YMM03",
        0x006F => "YMM10", 0x0070 => "YMM11", 0x0071 => "YMM12", 0x0072 => "YMM13",
        0x0073 => "YMM20", 0x0074 => "YMM21", 0x0075 => "YMM22", 0x0076 => "YMM23",
        0x0077 => "YMM30", 0x0078 => "YMM31", 0x0079 => "YMM32", 0x007A => "YMM33",
        0x007B => "YMM40", 0x007C => "YMM41", 0x007D => "YMM42", 0x007E => "YMM43",
        0x007F => "YMM50", 0x0080 => "YMM51", 0x0081 => "YMM52", 0x0082 => "YMM53",
        0x0083 => "YMM60", 0x0084 => "YMM61", 0x0085 => "YMM62", 0x0086 => "YMM63",
        0x0087 => "YMM70", 0x0088 => "YMM71", 0x0089 => "YMM72", 0x008A => "YMM73",
        // BND registers
        0x008B => "BND0", 0x008C => "BND1", 0x008D => "BND2", 0x008E => "BND3",
        // x64 integer (continue from 0x008F)
        0x008F => "RAX", 0x0090 => "RBX", 0x0091 => "RCX", 0x0092 => "RDX",
        0x0093 => "RSI", 0x0094 => "RDI", 0x0095 => "RBP", 0x0096 => "RSP",
        0x0097 => "R8", 0x0098 => "R9", 0x0099 => "R10", 0x009A => "R11",
        0x009B => "R12", 0x009C => "R13", 0x009D => "R14", 0x009E => "R15",
        0x009F => "RIP",
        // x64 XMM8..15
        0x00A0 => "XMM8",  0x00A1 => "XMM9",  0x00A2 => "XMM10", 0x00A3 => "XMM11",
        0x00A4 => "XMM12", 0x00A5 => "XMM13", 0x00A6 => "XMM14", 0x00A7 => "XMM15",
        // x64 YMM8..15
        0x00A8 => "YMM8",  0x00A9 => "YMM9",  0x00AA => "YMM10", 0x00AB => "YMM11",
        0x00AC => "YMM12", 0x00AD => "YMM13", 0x00AE => "YMM14", 0x00AF => "YMM15",
        // YMM sub-elements 8..15
        0x00B0 => "YMM80",  0x00B1 => "YMM81",  0x00B2 => "YMM82",  0x00B3 => "YMM83",
        0x00B4 => "YMM90",  0x00B5 => "YMM91",  0x00B6 => "YMM92",  0x00B7 => "YMM93",
        0x00B8 => "YMM100", 0x00B9 => "YMM101", 0x00BA => "YMM102", 0x00BB => "YMM103",
        0x00BC => "YMM110", 0x00BD => "YMM111", 0x00BE => "YMM112", 0x00BF => "YMM113",
        0x00C0 => "YMM120", 0x00C1 => "YMM121", 0x00C2 => "YMM122", 0x00C3 => "YMM123",
        0x00C4 => "YMM130", 0x00C5 => "YMM131", 0x00C6 => "YMM132", 0x00C7 => "YMM133",
        0x00C8 => "YMM140", 0x00C9 => "YMM141", 0x00CA => "YMM142", 0x00CB => "YMM143",
        0x00CC => "YMM150", 0x00CD => "YMM151", 0x00CE => "YMM152", 0x00CF => "YMM153",
        // XMM sub-elements 8..15
        0x00D0 => "XMM80",  0x00D1 => "XMM81",  0x00D2 => "XMM82",  0x00D3 => "XMM83",
        0x00D4 => "XMM90",  0x00D5 => "XMM91",  0x00D6 => "XMM92",  0x00D7 => "XMM93",
        0x00D8 => "XMM100", 0x00D9 => "XMM101", 0x00DA => "XMM102", 0x00DB => "XMM103",
        0x00DC => "XMM110", 0x00DD => "XMM111", 0x00DE => "XMM112", 0x00DF => "XMM113",
        0x00E0 => "XMM120", 0x00E1 => "XMM121", 0x00E2 => "XMM122", 0x00E3 => "XMM123",
        0x00E4 => "XMM130", 0x00E5 => "XMM131", 0x00E6 => "XMM132", 0x00E7 => "XMM133",
        0x00E8 => "XMM140", 0x00E9 => "XMM141", 0x00EA => "XMM142", 0x00EB => "XMM143",
        0x00EC => "XMM150", 0x00ED => "XMM151", 0x00EE => "XMM152", 0x00EF => "XMM153",
        // ZMM registers (0x00F0..0x010F)
        0x00F0 => "ZMM0",  0x00F1 => "ZMM1",  0x00F2 => "ZMM2",  0x00F3 => "ZMM3",
        0x00F4 => "ZMM4",  0x00F5 => "ZMM5",  0x00F6 => "ZMM6",  0x00F7 => "ZMM7",
        0x00F8 => "ZMM8",  0x00F9 => "ZMM9",  0x00FA => "ZMM10", 0x00FB => "ZMM11",
        0x00FC => "ZMM12", 0x00FD => "ZMM13", 0x00FE => "ZMM14", 0x00FF => "ZMM15",
        0x0100 => "ZMM16", 0x0101 => "ZMM17", 0x0102 => "ZMM18", 0x0103 => "ZMM19",
        0x0104 => "ZMM20", 0x0105 => "ZMM21", 0x0106 => "ZMM22", 0x0107 => "ZMM23",
        0x0108 => "ZMM24", 0x0109 => "ZMM25", 0x010A => "ZMM26", 0x010B => "ZMM27",
        0x010C => "ZMM28", 0x010D => "ZMM29", 0x010E => "ZMM30", 0x010F => "ZMM31",
        // K mask registers (0x0110..0x0117)
        0x0110 => "K0", 0x0111 => "K1", 0x0112 => "K2", 0x0113 => "K3",
        0x0114 => "K4", 0x0115 => "K5", 0x0116 => "K6", 0x0117 => "K7",
        // ARM64 (AArch64) integer registers (0x0180+)
        0x0180 => "X0",  0x0181 => "X1",  0x0182 => "X2",  0x0183 => "X3",
        0x0184 => "X4",  0x0185 => "X5",  0x0186 => "X6",  0x0187 => "X7",
        0x0188 => "X8",  0x0189 => "X9",  0x018A => "X10", 0x018B => "X11",
        0x018C => "X12", 0x018D => "X13", 0x018E => "X14", 0x018F => "X15",
        0x0190 => "X16", 0x0191 => "X17", 0x0192 => "X18", 0x0193 => "X19",
        0x0194 => "X20", 0x0195 => "X21", 0x0196 => "X22", 0x0197 => "X23",
        0x0198 => "X24", 0x0199 => "X25", 0x019A => "X26", 0x019B => "X27",
        0x019C => "X28", 0x019D => "FP",  0x019E => "LR",  0x019F => "SP",
        0x01A0 => "PC",  0x01A1 => "CPSR",
        // MIPS registers (0x0200+)
        0x0200 => "ZERO", 0x0201 => "AT", 0x0202 => "V0", 0x0203 => "V1",
        0x0204 => "A0", 0x0205 => "A1", 0x0206 => "A2", 0x0207 => "A3",
        0x0208 => "T0", 0x0209 => "T1", 0x020A => "T2", 0x020B => "T3",
        0x020C => "T4", 0x020D => "T5", 0x020E => "T6", 0x020F => "T7",
        0x0210 => "S0", 0x0211 => "S1", 0x0212 => "S2", 0x0213 => "S3",
        0x0214 => "S4", 0x0215 => "S5", 0x0216 => "S6", 0x0217 => "S7",
        0x0218 => "T8", 0x0219 => "T9", 0x021A => "K0", 0x021B => "K1",
        0x021C => "GP", 0x021D => "SP", 0x021E => "S8", 0x021F => "RA",
        0x0220 => "LO", 0x0221 => "HI",
        // PowerPC registers (0x0300+)
        0x0300 => "R0",  0x0301 => "R1",  0x0302 => "R2",  0x0303 => "R3",
        0x0304 => "R4",  0x0305 => "R5",  0x0306 => "R6",  0x0307 => "R7",
        0x0308 => "R8",  0x0309 => "R9",  0x030A => "R10", 0x030B => "R11",
        0x030C => "R12", 0x030D => "R13", 0x030E => "R14", 0x030F => "R15",
        0x0310 => "R16", 0x0311 => "R17", 0x0312 => "R18", 0x0313 => "R19",
        0x0314 => "R20", 0x0315 => "R21", 0x0316 => "R22", 0x0317 => "R23",
        0x0318 => "R24", 0x0319 => "R25", 0x031A => "R26", 0x031B => "R27",
        0x031C => "R28", 0x031D => "R29", 0x031E => "R30", 0x031F => "R31",
        0x0320 => "CR", 0x0321 => "FPSCR", 0x0322 => "MSR",
        // SH4 registers (0x0400+)
        0x0400 => "R0",  0x0401 => "R1",  0x0402 => "R2",  0x0403 => "R3",
        0x0404 => "R4",  0x0405 => "R5",  0x0406 => "R6",  0x0407 => "R7",
        0x0408 => "R8",  0x0409 => "R9",  0x040A => "R10", 0x040B => "R11",
        0x040C => "R12", 0x040D => "R13", 0x040E => "R14", 0x040F => "R15",
        0x0410 => "SR", 0x0411 => "GBR", 0x0412 => "MACH", 0x0413 => "MACL",
        0x0414 => "PR", 0x0415 => "PC", 0x0416 => "FPUL", 0x0417 => "FPSCR",
        _ => "Unknown",
    }
}

/// Get the register name for a CV register ID, returning a machine-friendly string.
pub fn register_name_for_id(id: u16) -> &'static str {
    register_name(id as u32)
}
